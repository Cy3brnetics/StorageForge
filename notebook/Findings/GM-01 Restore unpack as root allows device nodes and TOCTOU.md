---
id: GM-01
status: open
severity: critical
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, security, deploy, restore, gemini-audit]
found: 2026-10-29
---
# GM-01 Restore unpack as root allows device nodes and TOCTOU

## Location
- `storageforge_index/jobscript.py:338-351` (`unpack()`)
- `storageforge_index/jobs.py:475-496` (`restore()`)

## Mechanics & Root Cause
When restoring a snapshot or backup in `jobscript.py:338-351`, `unpack()` runs as `root` on the source host (`need_root` at line 364) and extracts the incoming tar stream directly from `stdin`:
```bash
unpack() { # id target -> extracts tar from stdin into target (a new folder under the job's root)
  serve_load "$1"; local t=$2
  under "$t" "$ROOT" || die "$t is outside this job's source"
  [[ -e $t ]] && die "$t already exists"
  mkdir -p -- "$t" || return
  local rc n; tar -C "$t" -xpf -; rc=$?
  # The archive comes from the backup host. GNU tar already refuses ../, absolute names and writes through links, but
  # keeps setuid/setgid bits: a backup host that was taken over could restore a setuid-root binary here. Stripped
  # whether or not tar finished, since a failed extraction can still have written some files.
  n=$(find "$t" -xdev -type f -perm /6000 -print -exec chmod ug-s {} + | wc -l)
  ((n)) && echo "removed setuid/setgid from $n restored file(s); set them again by hand if they need it"
  ((rc == 0)) && echo "restored into $t"
  return "$rc"
}
```
While `SF-25` added the post-extraction `find ... chmod ug-s` pass on regular files (`-type f`), three critical vulnerabilities remain:
1. **Device Node Creation (`mknod`)**: When GNU `tar` runs as `root` (`EUID == 0`) with `-p` (`--preserve-permissions`), `--devices` and `--specials` are enabled by default. A tar stream from a compromised backup/runner host can include block or character device nodes (such as major `8`, minor `0` for `/dev/sda` or `/dev/mem`) with mode `0666`. `find "$t" -xdev -type f -perm /6000` completely ignores block (`b`) and character (`c`) devices.
2. **Multi-Hour TOCTOU Window & Timeout `SIGKILL`**: `find ... -exec chmod ug-s` only runs **after** `tar -C "$t" -xpf -` finishes reading the entire stream (which has up to a 6-hour timeout in `jobs.py:495`). Any setuid-root binary placed at the start of a large archive remains live and executable on disk for the entire duration of the transfer—or permanently if the transfer exceeds the timeout and `deploy.py:399` kills the runner process with `p.kill()` (`SIGKILL`).
3. **Unstripped Setgid Directories & File Capabilities**: `-type f` ignores setgid directories (`-type d -perm /6000`) and file capabilities (`security.capability` in extended attributes if extracted).

## Impact
A compromised backup server or runner host can escalate privileges on the source host being restored into by planting world-accessible raw disk device nodes (`mknod`) or exploiting the multi-hour TOCTOU window where setuid-root binaries exist on disk before `find` strips them.

## Remediation
1. Pass `--no-devices --no-specials --no-same-permissions` (or `--mode='ug-s'`) and `--no-xattrs --no-acls --no-selinux` directly to `tar` so special files and setuid/setgid bits are prevented at extraction time rather than cleaned up afterward:
   ```bash
   tar -C "$t" --no-devices --no-specials --no-xattrs -xpf -
   ```
2. Keep the post-extraction `find` pass as defense-in-depth inside an `EXIT`/`INT`/`TERM` trap, and include `-type d` for `/6000` and `\( -type b -o -type c -o -type p -o -type s \) -delete`.

## Done when
- [ ] `tar` invocation in `jobscript.py:unpack` passes `--no-devices --no-specials` and prevents setuid/setgid creation during extraction.
- [ ] Defense-in-depth cleanup strips `/6000` on directories as well as files and deletes any special files.
- [ ] Regression test in `tests/test_platform.py` verifies device nodes cannot be extracted by `unpack`.
