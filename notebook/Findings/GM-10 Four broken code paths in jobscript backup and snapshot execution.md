---
id: GM-10
status: open
severity: high
effort: M
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, logic, jobs, btrfs, git, rsnapshot, gemini-audit]
found: 2026-10-29
---
# GM-10 Four broken code paths in jobscript backup and snapshot execution

## Location
- `storageforge_index/jobscript.py:59-67, 105-109, 126, 132-136, 184-196, 216-245`

## Mechanics & Root Cause
Direct code-path analysis of `jobscript.py` revealed four distinct bugs that cause backup/snapshot jobs to fail in production:

### 1. `snap_path()` Concatenates Invalid Path When Btrfs Subvolume Mountpoint Is `/` (`jobscript.py:59-62`)
```bash
snap_path() { # -> where the job's snapshot of ROOT is (or will be)
  local root sv; root=$(realpath -m "$ROOT"); sv=$(subvol_of "$root") || return 1
  echo "$sv/.storageforge-snap/$SID${root#"$sv"}"
}
```
When `$ROOT` (e.g. `/var/lib/data`) sits on a Btrfs root filesystem where `subvol_of` returns `sv=/`, `${root#"$sv"}` strips the leading `/` from `/var/lib/data`, yielding `var/lib/data`. `snap_path()` then outputs:
`//.storageforge-snap/p1-s1var/lib/data` (missing the `/` between `$SID` and `var/lib/data`)!

### 2. `under()` Rejects Every Child Path When Allowed Root Is `/` (`jobscript.py:63-67`)
```bash
under() { # path allowed... -> 0 if path is one of them or inside one
  local p a; p=$(realpath -m "$1"); shift
  for a; do [[ -n $a ]] || continue; a=$(realpath -m "$a"); [[ $p == "$a" || $p == "$a"/* ]] && return 0; done
  return 1
}
```
When `$a` is `/`, `"$a"/*` evaluates to `"//*"`. Because `realpath -m "$1"` returns paths with a single leading slash (e.g. `/srv/file`), `[[ "/srv/file" == "/" || "/srv/file" == "//*" ]]` is **always false**.

### 3. Remote `git` Job With `snapshot=True` (`SNAP=1`) Is Rejected by `serve()` (`jobscript.py:105-109, 216-245`)
```bash
# serve() lines 105-109:
    'git-upload-pack '*)
      path=${cmd#git-upload-pack }; path=${path#\'}; path=${path%\'}
      under "$path" "$ROOT" || die "$path is outside this job's source"
```
When `SNAP=1` on a remote `git` backup job, `run_job()` (`line 218`) sets `src=$(hook snap)` (e.g. `/srv/.storageforge-snap/p1-s1/repo.git`) and line 240 sets `url="ssh://storageforge-deploy@$SRC_HOST:$SRC_PORT${src}"`. When `git clone --mirror "$url"` connects to the source host, `serve()` (`line 107`) checks `under "$path" "$ROOT"` (`/srv/repo.git`). Because the snapshot path `/srv/.storageforge-snap/p1-s1/repo.git` is outside `/srv/repo.git` (and `serve()` does not pass `$( ((SNAP)) && snap_path )` to `under`), `serve()` refuses the connection with `"$path is outside this job's source"`.

### 4. Remote `rsnapshot` (`SRC_LOCAL=0`) Emits `user@host::module/` Which `rsnapshot` Rejects (`jobscript.py:126, 132-136, 188-195`)
```bash
# load() line 126:
export RSYNC_CONNECT_PROG="ssh ${SSHO[*]} storageforge-deploy@%H rsync --server --daemon ."
# src_spec() lines 132-136:
src_spec() { # path -> what rsync reads: the path here, or a module of the source's chrooted rsync (see serve)
  if ((SRC_LOCAL)); then printf '%s/' "${1%/}"
  elif [[ ${1%/} == "${SRC%/}" ]]; then printf 'storageforge-deploy@%s::src/' "$SRC_HOST"
  else printf 'storageforge-deploy@%s::snap/' "$SRC_HOST"; fi
}
# rsnapshot_conf() line 194:
printf 'backup\t%s\t%s/\n' "$(src_spec "$src")" "$(basename "${SRC%/}")"
```
While direct `rsync` accepts `user@host::module/` with `RSYNC_CONNECT_PROG`, `rsnapshot` (`/usr/bin/rsnapshot`, a Perl script) validates the `backup` source column with its own parser (`is_real_local_abs_path`, `is_ssh_path`, `is_anon_rsync_path`): `rsnapshot` only recognizes `rsync://...` for rsync daemon paths and `user@host:/path` (single colon) for SSH paths, so it rejects `storageforge-deploy@<host>::src/` as an invalid backup path!

## Impact
1. Btrfs snapshot-before-backup (`SNAP=1`) fails whenever the Btrfs subvolume mountpoint is `/`.
2. Any job whose root is `/` fails `under()` path validation.
3. Remote `git` backups with `SNAP=1` always fail with `"outside this job's source"`.
4. Remote `rsnapshot` jobs (`SRC_LOCAL=0`) fail `rsnapshot` config validation.

## Remediation
1. In `snap_path()`: `local rel=${root#"$sv"}; rel=/${rel#/}; echo "${sv%/}/.storageforge-snap/$SID${rel%/}"`.
2. In `under()`: `[[ $a == / || $p == "$a" || $p == "$a"/* ]]`.
3. In `serve()` (`git-upload-pack`): `under "$path" "$ROOT" "$( ((SNAP)) && snap_path )" || die "$path is outside this job's source"`.
4. In `rsnapshot_conf()`, emit `rsync://storageforge-deploy@$SRC_HOST/src/` (or `snap/`) so `rsnapshot`'s `is_anon_rsync_path()` accepts it while `rsync` still honors `RSYNC_CONNECT_PROG`.

## Done when
- [ ] All four code paths in `jobscript.py` are fixed and covered by unit tests in `tests/test_platform.py`.
