---
id: GM-21
status: open
severity: medium
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, logic, moves, rsync, shares, drift, gemini-audit]
found: 2026-10-29
---
# GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift

## Location
- `storageforge_index/moves.py:605-625` (`verify_step()`, `cutover_step()`)
- `storageforge_index/shares.py:638-650` (`client_mount()`)
- `storageforge_index/remote.py:268-269` (`INVENTORY_SCRIPT`)

## Mechanics & Root Cause
### 1. `moves.py` `verify_step()` Suppresses `rsync` Exit Code and Reports Success on Failure (`moves.py:605-614`)
```bash
verify_step() { # -> 0 if destination matches source
  local i=$1 out n
  dst_guard "$i" || return 1
  [[ ${S_METHOD[$i]} == git ]] && { git_step "$i" verify; return; }
  rsync_args "$i" -n -i
  out=$("${RS[@]}" | grep -v '^\.d' | grep -v '^cd' || true)
  n=$(grep -c . <<<"$out" || true)
  if ((n == 0)); then ok "destination matches the source$( { has "$i" checksum || ((CHECKSUM)); } && echo ' (checksums)')"; return 0; fi
  conflict "$n difference(s); first ones:"; head -10 <<<"$out" | sed 's/^/            /'; return 1
}
```
- Because `|| true` is placed at the end of the pipeline `out=$("${RS[@]}" | grep -v '^\.d' | grep -v '^cd' || true)`, Bash's `set -o pipefail` is neutralized for the entire pipeline.
- If `"${RS[@]}"` fails completely (for example, SSH connection refused, permission denied, or source path missing), `rsync` writes its error message to `stderr` and outputs **0 lines to `stdout`**.
- `out` becomes `""`, `n` evaluates to `0`, and `verify_step()` prints `ok "destination matches the source"` and returns `0`!
- Worse still, `cutover_step()` (`moves.py:619`) calls `verify_step "$i"` as its safety gate before renaming the source folder to `.migrated-<date>`!
- Note: The same pattern also exists in `jobscript.py:265` (`verify_job()`):
  ```bash
  out=$("${RS[@]}" 2>&1 | grep -v '^\.d' | grep -v '^cd' | grep -v '^skipping' || true)
  ```
  where `|| true` masks a non-zero `rsync` exit status if `rsync` produces no non-skipped output lines.

### 2. `shares.py` Preserving Existing `/etc/fstab` Options Causes Permanent False-Positive Drift Alerts (`shares.py:638-650`)
```bash
  local have; have=$(awk -v t="${t// /\\040}" '!/^[[:space:]]*#/ && $2 == t' /etc/fstab)
  if [[ $have == "$line" ]]; then ok "fstab line"
  elif [[ -n $have && $(awk '{print $1, $3}' <<<"$have") == "$(awk '{print $1, $3}' <<<"$line")" ]]; then ok "fstab line (its own options kept)"
  elif [[ -n $have ]]; then conflict "fstab already has a different line for $t: $have"
  elif ((APPLY)); then
    backup /etc/fstab; mkdir -p "$t"; printf '# storageforge share %s:%s\n%s\n' "$SERVER" "$t" "$line" >>/etc/fstab; doing "appended to /etc/fstab"
    if ! findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1; then conflict "findmnt --verify complains about /etc/fstab; the backup is /etc/fstab.storageforge-$STAMP"; return 1; fi
    systemctl daemon-reload
  else missing "fstab: $line"; fi
  if mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then doing "mount $t"; mount "$t" && ok "mounted" || conflict "mount $t failed"
  else missing "not mounted"; fi
  WANT_LINES+=("$line")
```
- When `/etc/fstab` already mounts `${C_SOURCE[$i]}` at `$t` with the same fstype using custom mount options (or tabs instead of spaces), line 640 prints `ok "fstab line (its own options kept)"` and leaves `/etc/fstab` untouched, **but line 649 still appends StorageForge's generated `$line` to `WANT_LINES`** (`/var/lib/storageforge/managed/shares-$SERVER.lines`).
- On the next scan, `INVENTORY_SCRIPT` (`remote.py:269`) runs `grep -Fxq -- "$l" /etc/fstab`, which fails because `/etc/fstab` has `$have` rather than `$line`, firing a false-positive `LINE-MISSING` (`fstab line gone`) drift alert on every scan.

## Impact
1. A failed `rsync` during `--verify` or `--cutover` in a Move plan is falsely reported as `"destination matches the source"`, allowing `--cutover` to rename the source directory even when verification failed.
2. Keeping existing `/etc/fstab` options during a Shares deploy triggers perpetual false-positive drift alerts.

## Remediation
1. In `moves.py:610`, run `raw=$("${RS[@]}") || { conflict "rsync verify failed"; return 1; }` before filtering `$raw` with `grep`.
2. In `shares.py:640-649`, when keeping `$have`, append `WANT_LINES+=("$have")` instead of `WANT_LINES+=("$line")`.

## Done when
- [ ] `verify_step` fails whenever `rsync` exits non-zero.
- [ ] `shares.py` records the actual kept `/etc/fstab` line (`$have`) in `WANT_LINES`.
