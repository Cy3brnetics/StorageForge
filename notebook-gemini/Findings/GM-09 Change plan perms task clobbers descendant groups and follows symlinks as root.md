---
id: GM-09
status: open
severity: high
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, security, logic, changes, gemini-audit]
found: 2026-10-29
---
# GM-09 Change plan perms task clobbers descendant groups, ignores recursive on chmod, and follows symlinks as root

## Location
- `storageforge_index/changes.py:668-680` (`owner_mode()`)

## Mechanics & Root Cause
In `changes.py:668-680`, the generated Bash helper for the `perms` ("Permissions and owner") and `dir` ("Create folder") tasks runs as `root`:
```bash
owner_mode() { # path owner group mode recursive
  local p=$1 o=$2 g=$3 m=$4 r=$5
  [[ -e $p ]] || return 0
  if [[ -n $o || -n $g ]]; then
    local want="${o:-$(stat -c %U "$p")}:${g:-$(stat -c %G "$p")}" off=
    if [[ $r == 1 ]]; then off=$(find "$p" \( ! -user "${want%%:*}" -o ! -group "${want##*:}" \) -print -quit 2>/dev/null)
    elif [[ $(stat -c %U:%G "$p") != "$want" ]]; then off=$p; fi
    if [[ -z $off ]]; then ok "owner $want"; elif act "chown ${r:+-R }$want $p"; then try chown ${r:+-R} -- "$want" "$p" && ok "owner $want"; fi
  fi
  if [[ -n $m ]]; then
    if (( 8#$(stat -c %a "$p") == 8#$m )); then ok "mode $m"; elif act "chmod $m $p"; then try chmod -- "$m" "$p" && ok "mode $m"; fi
  fi
}
```
1. **Unintended Recursive Group Clobbering (`lines 672-675`)**: When an operator sets `owner="alice"`, leaves `group=""` blank, and sets `recursive=True` (`r=1`), line 672 fills in the missing group using the **top-level directory's current group**: `want="${o:-$(stat -c %U "$p")}:${g:-$(stat -c %G "$p")}"`. Line 673 then checks if any descendant file has a different group (`! -group "${want##*:}"`), and line 675 executes `chown -R -- "alice:<top_group>" "$p"`, **overwriting the group of every file and subdirectory in the entire tree** even though `group` was left blank! (Conversely, setting `group` and leaving `owner` blank overwrites every descendant's owner with the top directory's owner.)
2. **`chmod` Completely Ignores `recursive` (`r=1`) (`lines 677-679`)**: Look at line 678: `try chmod -- "$m" "$p"`. Unlike `chown ${r:+-R}`, the `chmod` branch never checks `$r` at all—neither in the pre-check (`stat -c %a "$p"`) nor in `chmod -- "$m" "$p"`—so a recursive permission change only ever changes the top directory's mode!
3. **Symlink Traversal as Root (`chown` and `chmod`)**:
   - `chown` without `-h` (and `chown -R` without `-P`/`-h`) dereferences `$p` if `$p` is a symlink, and `chmod` dereferences symlinks.
   - If `$p` is inside a directory writable by a non-root user on the target host, that user can place a symlink pointing to `/etc/shadow` or `/etc/sudoers`. When the change plan runs as `root`, `chown` or `chmod` modifies the target of the symlink.

## Impact
Data/permission corruption across multi-owner or multi-group directory trees when changing only `owner` or `group` recursively, silent failure to apply `mode` recursively, and local privilege escalation on target hosts if `owner_mode` runs on paths controlled by non-root users.

## Remediation
1. When `g` is empty, only check `! -user "$o"` and run `chown -h ${r:+-R -P} -- "$o" "$p"`. When `o` is empty, only check `! -group "$g"` and run `chgrp -h ${r:+-R -P} -- "$g" "$p"`.
2. For `chmod`, never dereference symlinks; when `r == 1`, use `find "$p" -xdev ! -type l ! -perm "$m"` to check and `find "$p" -xdev ! -type l -exec chmod -- "$m" {} +` to apply.

## Done when
- [ ] `owner_mode` in `changes.py` does not touch groups when `g` is empty (or owners when `o` is empty), applies `mode` recursively when `r=1` without touching symlinks, and passes `-h`/`-P` to `chown`.
