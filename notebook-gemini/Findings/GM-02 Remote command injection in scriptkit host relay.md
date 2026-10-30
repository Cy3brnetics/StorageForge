---
id: GM-02
status: open
severity: high
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, security, scripts, ssh, gemini-audit]
found: 2026-10-29
---
# GM-02 Remote command injection in scriptkit host relay

## Location
- `storageforge_index/scriptkit.py:43-57` (`REMOTE`)
- Included in `moves.py:486`, `changes.py:570`, `shares.py:466`, `tasks.py:613`

## Mechanics & Root Cause
Every generated Bash script (`moves.py`, `changes.py`, `shares.py`, `tasks.py`) embeds `scriptkit.REMOTE` (`scriptkit.py:43-57`), which supports `--host <target>` to copy the script to a remote host and execute it under `sudo`:
```bash
REMOTE = r"""# ── remote: copy this script over, run it there with sudo, clean up (like storage-setup.sh --host) ──
if [[ -n $HOST ]]; then
  CTL=$(mktemp -d); trap 'ssh -o ControlPath="$CTL/s" -O exit "$HOST" 2>/dev/null; rm -rf "$CTL"' EXIT
  SSHO=(-o ControlMaster=auto -o ControlPath="$CTL/s" -o ControlPersist=60 -o ConnectTimeout=10)
  REST=(); skipnext=0
  for a in "${ARGS[@]}"; do if ((skipnext)); then skipnext=0; continue; fi; if [[ $a == --host ]]; then skipnext=1; continue; fi; REST+=("$a"); done
  tmp=$(ssh "${SSHO[@]}" "$HOST" 'mktemp -d /tmp/sf-move.XXXXXX')
  scp -q -o ControlPath="$CTL/s" "$0" "$HOST:$tmp/move.sh"
  # Your SSH agent is forwarded only with --forward-agent: while it runs, root on that host can use it to log in
  # wherever your keys work. A step that pulls from a third host needs it (or a key on that host).
  FWD=(); ((${FWD_AGENT:-0})) && FWD=(-A)
  ssh "${SSHO[@]}" ${FWD[@]+"${FWD[@]}"} -t "$HOST" "cd $tmp && if [ \$(id -u) = 0 ]; then bash ./move.sh ${REST[*]:-}; else sudo --preserve-env=SSH_AUTH_SOCK bash ./move.sh ${REST[*]:-}; fi; rc=\$?; rm -rf $tmp; exit \$rc"
  exit $?
fi
"""
```
1. **Unquoted `${REST[*]:-}` Expansion (`line 54`)**: `ssh` concatenates its remote command string and passes it to the remote user's login shell (`sh -c ...`). Because `${REST[*]:-}` is expanded directly inside double quotes without shell-escaping each element (`printf '%q'`), any argument in `ARGS` containing spaces or shell metacharacters is evaluated by the remote shell and by `sudo`.
2. **Unquoted `$tmp` (`line 54`)**: `$tmp` (returned by `ssh ... mktemp -d`) is expanded unquoted into `cd $tmp` and `rm -rf $tmp`.
3. **Unvalidated `$HOST` Leading Hyphen (`lines 45, 49, 50, 54`)**: In the caller option loops (`moves.py:475`, `changes.py:602`, `shares.py:456`, `tasks.py:701`), `--host` sets `HOST=${2:?--host needs [user@]host}` without checking that `$HOST` does not start with `-`. If `$HOST` starts with `-` (e.g., `-oProxyCommand=...`), `ssh` and `scp` interpret `$HOST` as an option flag.

## Impact
Passing any argument containing spaces or shell metacharacters alongside `--host` causes arbitrary command execution on the remote host as `root` (via `sudo`), and a leading-hyphen `--host` injects arbitrary OpenSSH client options.

## Remediation
1. Validate `[[ $HOST != -* ]]` before running `ssh`/`scp`.
2. Escape `REST` and `$tmp` with `printf '%q'` before interpolating them into the remote `ssh` command string:
   ```bash
   qrest=; for a in "${REST[@]+"${REST[@]}"}"; do qrest+=" $(printf '%q' "$a")"; done
   qtmp=$(printf '%q' "$tmp")
   ssh "${SSHO[@]}" ${FWD[@]+"${FWD[@]}"} -t -- "$HOST" "cd -- $qtmp && if [ \$(id -u) = 0 ]; then bash ./move.sh$qrest; else sudo --preserve-env=SSH_AUTH_SOCK bash ./move.sh$qrest; fi; rc=\$?; rm -rf -- $qtmp; exit \$rc"
   ```

## Done when
- [ ] `scriptkit.py:REMOTE` shell-escapes `REST` and `$tmp` with `printf '%q'` and rejects leading-hyphen `--host` values.
