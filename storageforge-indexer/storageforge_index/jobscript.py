"""storageforge-job: the program StorageForge installs on hosts to run rsync, rsnapshot and git jobs and to serve
their sources. Deploys install and update it; it is static, and everything per job is in /etc/storageforge.

  on the host that runs a job (its destination):
    storageforge-job run <id> [level]     one run: window, bandwidth, pre, btrfs snapshot, post, transfer, report
    storageforge-job verify <id>          rsync --checksum dry run: report every file that differs
    storageforge-job cutover <id>         move steps: rename the source after a clean verify
    storageforge-job test <id>            can this host reach the source with the job's key?
    storageforge-job status               every job here as JSON lines (timers, last run)
    storageforge-job snapshots|ls|pack    rsnapshot jobs: list snapshots, list a folder in one, tar a path out of one
  on the source host, through the job key's forced SSH command (sudo, see deploy.py):
    storageforge-job --serve <id> "<ssh command>"
        pre | post | snap | unsnap | ping, rsync --server --daemon . (chrooted into the job's root: modules src and snap),
        git-upload-pack '<path>' (under the root only)
  restores, on the source host (run through storageforge-run):
    storageforge-job unpack <id> <target>   tar on stdin into <target>, a new folder under the job's root
"""

JOB_SCRIPT = r"""#!/bin/bash
# storageforge-job — runs StorageForge rsync/rsnapshot/git jobs and serves their sources.
# Installed by StorageForge deploys: do not edit, the next deploy replaces it. Job settings: /etc/storageforge.
set -uo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ETC=/etc/storageforge VAR=/var/lib/storageforge LOCKS=/run/lock TMPD=/run
if ((EUID != 0)); then   # tests only: root ignores these
  ETC=${STORAGEFORGE_JOB_ETC:-$ETC} VAR=${STORAGEFORGE_JOB_VAR:-$VAR} LOCKS=${STORAGEFORGE_JOB_VAR:-$LOCKS} TMPD=${STORAGEFORGE_JOB_VAR:-$TMPD}
fi
SELF=$(readlink -f "$0")
die() { echo "storageforge-job: $*" >&2; exit 2; }
idok() { [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "bad job id: $1"; }
jesc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/}; s=${s//$'\t'/ }; printf '%s' "$s"; }
mins() { local h=${1%%:*} m=${1##*:}; echo $((10#$h * 60 + 10#$m)); }
in_window() { # "HH:MM-HH:MM" -> 0 if now is inside (windows may cross midnight)
  local a b now; a=$(mins "${1%-*}"); b=$(mins "${1#*-}"); now=$(mins "$(date +%H:%M)")
  if ((a <= b)); then ((now >= a && now < b)); else ((now >= a || now < b)); fi
}
until_end() { # window -> seconds until it ends
  local b now left; b=$(mins "${1#*-}"); now=$(mins "$(date +%H:%M)"); left=$(((b - now + 1440) % 1440))
  echo $((left * 60 - 10#$(date +%S)))
}

# ── source side: what a job key may do (forced command, as root) ──
serve_load() {
  idok "$1"; [[ -f $ETC/serve/$1.conf ]] || die "this host does not serve job $1"
  ROOT= SNAP=0; PRE=(); POST=()
  # shellcheck disable=SC1090
  source "$ETC/serve/$1.conf"
  SID=$1
}
subvol_of() { # path -> the btrfs subvolume root holding it (inode 256)
  local d; d=$(realpath -m "$1")
  [[ $(stat -f -c %T "$d" 2>/dev/null) == btrfs ]] || return 1
  while :; do
    [[ $(stat -c %i "$d" 2>/dev/null) == 256 ]] && { echo "$d"; return 0; }
    [[ $d == / ]] && return 1
    d=$(dirname "$d")
  done
}
snap_path() { # -> where the job's snapshot of ROOT is (or will be)
  local root sv; root=$(realpath -m "$ROOT"); sv=$(subvol_of "$root") || return 1
  echo "${sv%/}/.storageforge-snap/$SID${root#"${sv%/}"}"     # ${sv%/}: the subvolume can be / itself
}
under() { # path allowed... -> 0 if path is one of them or inside one
  local p a; p=$(realpath -m "$1"); shift
  for a; do [[ -n $a ]] || continue; a=$(realpath -m "$a"); [[ $p == "$a" || $p == "${a%/}"/* ]] && return 0; done
  return 1
}
run_cmds() { local c; for c; do echo "+ $c" >&2; bash -c "$c" >&2 || { echo "failed (exit $?): $c" >&2; return 1; }; done; }
serve() { # id "ssh command"
  serve_load "$1"
  local cmd=${2:-} sv snap
  case $cmd in
    ping) echo pong ;;
    pre) run_cmds "${PRE[@]}" ;;
    post) run_cmds "${POST[@]}" ;;
    snap)
      ((SNAP)) || die "job $SID does not snapshot its source"
      command -v btrfs >/dev/null || die "btrfs-progs is not installed"
      sv=$(subvol_of "$ROOT") || die "$ROOT is not on btrfs"
      snap="${sv%/}/.storageforge-snap/$SID"
      mkdir -p "${sv%/}/.storageforge-snap"
      [[ -d $snap ]] && btrfs subvolume delete "$snap" >/dev/null
      btrfs subvolume snapshot -r "$sv" "$snap" >/dev/null || die "btrfs snapshot of $sv failed"
      snap_path ;;
    unsnap)
      sv=$(subvol_of "$ROOT") || exit 0
      [[ -d ${sv%/}/.storageforge-snap/$SID ]] && btrfs subvolume delete "${sv%/}/.storageforge-snap/$SID" >/dev/null
      rmdir "${sv%/}/.storageforge-snap" 2>/dev/null; exit 0 ;;
    'rsync --server --daemon .')
      # rsync's daemon mode over this SSH session, chrooted into the job's root: every path, filter or merge rule
      # (they come over the connection, not on this command line) and symlink a client sends resolves inside it, so
      # a job key reads that folder (module src) or its snapshot (module snap) and nothing else on this host.
      local conf chroot=yes rc; ((EUID)) && chroot=no     # tests run unprivileged and cannot chroot
      conf=$(mktemp "$TMPD/storageforge-serve.XXXXXX") || die "no temporary file"
      trap 'rm -f "$conf"' EXIT
      snap=$( ((SNAP)) && snap_path || true)
      { printf 'use chroot = %s\nread only = yes\nwrite only = no\nlist = no\nuid = 0\ngid = 0\nnumeric ids = yes\n' "$chroot"
        printf 'refuse options = delete* remove-* write-batch only-write-batch log-file*\n'
        printf '[src]\npath = %s\n' "$(realpath -m "$ROOT")"
        [[ -n $snap && -d $snap ]] && printf '[snap]\npath = %s\n' "$snap"
      } >"$conf"
      rsync --server --daemon --config="$conf" .; exit $? ;;
    'rsync --server '*)
      die "this source serves jobs through rsync's daemon mode only: redeploy the plan, so the runner gets the same storageforge-job" ;;
    'git-upload-pack '*)
      path=${cmd#git-upload-pack }; path=${path#\'}; path=${path%\'}
      snap=$( ((SNAP)) && snap_path || true)     # a snapshot-first job clones from the snapshot of its root
      under "$path" "$ROOT" "$snap" || die "$path is outside this job's source"
      printf '[safe]\n\tdirectory = *\n' >"$VAR/git-safe.conf"
      GIT_CONFIG_GLOBAL=$VAR/git-safe.conf exec git-upload-pack --strict "$path" ;;
    *) die "not allowed: ${cmd:0:80}" ;;
  esac
}

# ── runner side ──
load() {
  idok "$1"; [[ -f $ETC/jobs/$1.conf ]] || die "no job $1 on $(uname -n)"
  ID= NAME= METHOD= SRC_LOCAL=1 SRC_HOST= SRC_PORT=22 SRC= DST= DST_MOUNT=/ FLAGS= KEEP= LOWEST= WINDOW= BW_DAY= BW_NIGHT=
  NIGHT= SNAP=0 HOOKS=0 REPORT_URL=; EXCLUDES=()
  # shellcheck disable=SC1090
  source "$ETC/jobs/$1.conf"
  KEY=$ETC/jobs/$ID.key
  SSHO=(-o BatchMode=yes -o ConnectTimeout=15 -o IdentitiesOnly=yes -o "UserKnownHostsFile=$VAR/known_hosts"
        -o StrictHostKeyChecking=accept-new -i "$KEY" -p "$SRC_PORT")
  # rsnapshot accepts a daemon source only as rsync://host/module (it rejects host::module) and passes no -e: this
  # makes rsync reach the source's chrooted daemon (see serve) over the same SSH command
  export RSYNC_CONNECT_PROG="ssh ${SSHO[*]} storageforge-deploy@%H rsync --server --daemon ."
}
has() { [[ " $FLAGS " == *" $1 "* ]]; }
hook() { # verb -> runs it where the source is
  if ((SRC_LOCAL)); then "$SELF" --serve "$ID" "$1"; else ssh "${SSHO[@]}" "storageforge-deploy@$SRC_HOST" "$1"; fi
}
src_spec() { # path -> what rsync reads: the path here, or a module of the source's chrooted rsync (see serve)
  if ((SRC_LOCAL)); then printf '%s/' "${1%/}"
  elif [[ ${1%/} == "${SRC%/}" ]]; then printf 'rsync://storageforge-deploy@%s/src/' "$SRC_HOST"
  else printf 'rsync://storageforge-deploy@%s/snap/' "$SRC_HOST"; fi
}
bwlimit() { if [[ -n $NIGHT ]] && in_window "$NIGHT"; then echo "$BW_NIGHT"; else echo "$BW_DAY"; fi; }
rsync_cmd() { # source-path extra... -> RS
  local src=$1; shift
  RS=(rsync -aHAX --numeric-ids --partial --partial-dir=.rsync-partial)
  has onefs && RS+=(-x)
  has checksum && RS+=(-c)
  has delete && RS+=(--delete-after)
  local bw; bw=$(bwlimit); [[ -n $bw ]] && RS+=(--bwlimit="$bw")
  ((SRC_LOCAL)) || RS+=(-e "ssh ${SSHO[*]}")
  local x; for x in "${EXCLUDES[@]}"; do RS+=(--exclude="$x"); done
  RS+=(--exclude=.storageforge-snap "$@" "$(src_spec "$src")" "${DST%/}/")
}
num() { tr -d ',' <<<"${1:-0}" | grep -o '^[0-9]*' || echo 0; }
dst_guard() { [[ $DST_MOUNT == / ]] || mountpoint -q "$DST_MOUNT"; }

RUN_KIND=run RUN_LEVEL= RUN_START=0 RUN_UUID= BYTES=0 FILES=0
report() { # rc message
  local rc=$1 msg=$2 end line tok hdr
  end=$(date +%s)
  line=$(printf '{"run":"%s","job":"%s","kind":"%s","level":"%s","start":%s,"end":%s,"rc":%s,"bytes":%s,"files":%s,"host":"%s","message":"%s"}' \
    "$RUN_UUID" "$ID" "$RUN_KIND" "$RUN_LEVEL" "$RUN_START" "$end" "$rc" "${BYTES:-0}" "${FILES:-0}" "$(jesc "$(uname -n)")" "$(jesc "${msg:0:2000}")")
  mkdir -p "$VAR/jobs/$ID" && chmod 0755 "$VAR/jobs/$ID"
  printf '%s\n' "$line" >>"$VAR/jobs/$ID/runs.jsonl"; chmod 0644 "$VAR/jobs/$ID/runs.jsonl"
  if (($(wc -l <"$VAR/jobs/$ID/runs.jsonl") > 600)); then tail -n 500 "$VAR/jobs/$ID/runs.jsonl" >"$VAR/jobs/$ID/runs.tmp" && mv "$VAR/jobs/$ID/runs.tmp" "$VAR/jobs/$ID/runs.jsonl"; fi
  echo "result: rc=$rc ${msg}"
  [[ -n $REPORT_URL && -r $ETC/jobs/$ID.token ]] || return 0
  tok=$(<"$ETC/jobs/$ID.token")
  if command -v curl >/dev/null; then
    hdr=$(mktemp); printf 'Authorization: Bearer %s\n' "$tok" >"$hdr"
    local ca=(); [[ -r $ETC/report-ca.pem ]] && ca=(--cacert "$ETC/report-ca.pem")   # StorageForge's self-signed certificate
    curl -fsS -m 20 ${ca[@]+"${ca[@]}"} -H @"$hdr" -H 'Content-Type: application/json' --data-binary "$line" "$REPORT_URL/api/jobs/report" >/dev/null 2>&1; local ok=$?
    rm -f "$hdr"; ((ok == 0)) && return 0
  elif command -v python3 >/dev/null; then
    TOKEN_FILE=$ETC/jobs/$ID.token CA_FILE=$ETC/report-ca.pem python3 - "$REPORT_URL/api/jobs/report" "$line" <<'PY' && return 0
import os, ssl, sys, urllib.request
t = open(os.environ['TOKEN_FILE']).read().strip()
ca = os.environ['CA_FILE'] if os.access(os.environ['CA_FILE'], os.R_OK) else None
r = urllib.request.Request(sys.argv[1], sys.argv[2].encode(), {'Authorization': 'Bearer ' + t, 'Content-Type': 'application/json'})
urllib.request.urlopen(r, timeout=20, context=ssl.create_default_context(cafile=ca))
PY
  fi
  echo "could not report to $REPORT_URL; the next scan of $(uname -n) picks this run up" >&2
}
transfer_stats() { # rsync --stats output file -> BYTES FILES
  FILES=$(num "$(sed -n 's/^Number of regular files transferred: //p' "$1" | tail -1)")
  BYTES=$(num "$(sed -n 's/^Total transferred file size: //p' "$1" | tail -1)")
}
rsnapshot_conf() { # source -> path of a run-time config
  local src=$1 c lv cnt
  c=$(mktemp "$TMPD/storageforge-rsnapshot.XXXXXX")
  {
    printf 'config_version\t1.2\nsnapshot_root\t%s/\nno_create_root\t1\ncmd_rsync\t%s\n' "${DST%/}" "$(command -v rsync)"
    printf 'cmd_ssh\t%s\nssh_args\t%s\n' "$(command -v ssh)" "${SSHO[*]}"
    printf 'rsync_long_args\t--delete --numeric-ids --delete-excluded%s\n' "$(has onefs && echo ' --one-file-system')"
    printf 'lockfile\t%s/storageforge-rsnapshot-%s.pid\n' "$TMPD" "$ID"
    for lv in $KEEP; do cnt=${lv#*=}; ((cnt > 0)) && printf 'retain\t%s\t%s\n' "${lv%=*}" "$cnt"; done
    local x; for x in "${EXCLUDES[@]}" .storageforge-snap; do printf 'exclude\t%s\n' "$x"; done
    printf 'backup\t%s\t%s/\n' "$(src_spec "$src")" "$(basename "${SRC%/}")"
  } >"$c"
  echo "$c"
}
run_job() { # id [level]
  load "$1"; RUN_LEVEL=${2:-}; RUN_KIND=run
  RUN_UUID=$(cat /proc/sys/kernel/random/uuid); RUN_START=$(date +%s)
  exec 9>"$LOCKS/storageforge-job-$ID.lock" || die "cannot open $LOCKS/storageforge-job-$ID.lock"
  flock -n 9 || { echo "another run of $ID is in progress"; exit 0; }
  echo "$NAME${RUN_LEVEL:+ ($RUN_LEVEL)} on $(uname -n)"
  if [[ $METHOD == rsnapshot && -n $RUN_LEVEL && $RUN_LEVEL != "$LOWEST" ]]; then   # higher levels only rotate
    local c; c=$(rsnapshot_conf "$SRC"); rsnapshot -c "$c" "$RUN_LEVEL"; local rc=$?; rm -f "$c"
    report "$rc" "rotated $RUN_LEVEL"; exit "$rc"
  fi
  if [[ -n $WINDOW ]] && ! in_window "$WINDOW"; then report 0 "skipped: outside the run window $WINDOW"; exit 0; fi
  dst_guard || { report 3 "$DST_MOUNT is not mounted: not copying onto the root filesystem"; exit 3; }
  local src=$SRC rc=0 msg= posted=0 snapped=0 log
  log=$(mktemp)
  if ((HOOKS)); then
    echo "pre commands on the source"
    if ! hook pre; then hook post; report 4 "a pre command failed; post commands ran, nothing copied"; exit 4; fi
  fi
  if ((SNAP)); then
    echo "btrfs snapshot of the source"
    if src=$(hook snap) && [[ -n $src ]]; then snapped=1; echo "copying from $src"
    else ((HOOKS)) && hook post; report 5 "the btrfs snapshot of the source failed"; exit 5; fi
    if ((HOOKS)); then hook post && posted=1; fi       # the stack is only stopped for the snapshot itself
  fi
  local stop=()
  [[ -n $WINDOW ]] && stop=(timeout --signal=TERM "$(until_end "$WINDOW")")
  case $METHOD in
    copy|move|mirror)
      mkdir -p "$DST"; rsync_cmd "$src" --stats
      echo "+ ${RS[*]}"
      "${stop[@]}" "${RS[@]}" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}
      transfer_stats "$log"
      case $rc in 0) msg="copied $FILES files" ;; 24) rc=0; msg="copied $FILES files (some vanished while copying)" ;;
        124) msg="stopped at the end of the run window; the next run resumes" ;; *) msg="rsync failed (exit $rc): $(tail -3 "$log" | tr '\n' ' ')" ;; esac ;;
    rsnapshot)
      mkdir -p "$DST"
      local c; c=$(rsnapshot_conf "$src")
      "${stop[@]}" rsnapshot -c "$c" -V "${RUN_LEVEL:-$LOWEST}" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}
      rm -f "$c"
      case $rc in 0) msg="snapshot ${RUN_LEVEL:-$LOWEST}.0 taken" ;; 2) rc=0; msg="snapshot taken with warnings" ;;
        124) msg="stopped at the end of the run window" ;; *) msg="rsnapshot failed (exit $rc): $(tail -3 "$log" | tr '\n' ' ')" ;; esac ;;
    git)
      local url; if ((SRC_LOCAL)); then url=$src; else url="ssh://storageforge-deploy@$SRC_HOST:$SRC_PORT${src}"; fi
      export GIT_SSH_COMMAND="ssh ${SSHO[*]}"
      printf '[safe]\n\tdirectory = *\n' >"$VAR/git-safe.conf"; export GIT_CONFIG_GLOBAL=$VAR/git-safe.conf
      if [[ -d $DST ]]; then git -C "$DST" remote update --prune 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}
      else mkdir -p "$(dirname "$DST")"; git clone --mirror "$url" "$DST" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}; fi
      ((rc == 0)) && msg="archive up to date" || msg="git failed (exit $rc): $(tail -3 "$log" | tr '\n' ' ')" ;;
  esac
  ((snapped)) && hook unsnap
  ((HOOKS && !posted)) && { hook post || msg+=" (a post command failed)"; }
  rm -f "$log"
  report "$rc" "$msg"
  exit "$rc"
}
verify_job() {
  load "$1"; RUN_KIND=verify; RUN_UUID=$(cat /proc/sys/kernel/random/uuid); RUN_START=$(date +%s)
  exec 9>"$LOCKS/storageforge-job-$ID.lock" || die "cannot open the job lock"; flock 9
  dst_guard || { report 3 "$DST_MOUNT is not mounted"; exit 3; }
  local target=$DST
  if [[ $METHOD == rsnapshot ]]; then target="${DST%/}/$LOWEST.0/$(basename "${SRC%/}")"; fi
  [[ $METHOD == git ]] && { report 0 "nothing to verify for git archives (git checks objects itself)"; exit 0; }
  local out n
  local saved_delete=$FLAGS; FLAGS="$FLAGS checksum"; FLAGS=${FLAGS/delete/}
  local DST=$target; rsync_cmd "$SRC" -n -i
  FLAGS=$saved_delete
  echo "+ ${RS[*]}"
  out=$("${RS[@]}" 2>&1 | grep -v '^\.d' | grep -v '^cd' | grep -v '^skipping' || true)
  n=$(grep -c . <<<"$out" || true)
  if ((n == 0)); then report 0 "every file matches the source (checksums)"; exit 0; fi
  echo "$out" | head -50
  report 1 "$n file(s) differ from the source, e.g. $(head -3 <<<"$out" | cut -c13- | paste -sd' ')"
  exit 1
}
dryrun_job() { # what the next run would transfer, from this host, changing nothing (no pre/post, no snapshot)
  load "$1"
  echo "$NAME: dry run on $(uname -n) (pre/post commands and snapshots are not run)"
  dst_guard || echo "note: $DST_MOUNT is not mounted now; a real run would wait for it"
  if [[ -n $WINDOW ]]; then in_window "$WINDOW" && echo "inside the run window $WINDOW" || echo "outside the run window $WINDOW: a scheduled run now would skip"; fi
  local bw; bw=$(bwlimit); echo "bandwidth limit now: ${bw:-none}${bw:+ KB/s}"
  ((SRC_LOCAL)) || { hook ping >/dev/null && echo "source reachable with the job key" || { echo "cannot reach $SRC_HOST with the job key" >&2; exit 1; }; }
  local out rc
  case $METHOD in
    git) export GIT_SSH_COMMAND="ssh ${SSHO[*]}"
      if [[ -d $DST ]]; then git -C "$DST" fetch --dry-run --prune origin 2>&1; else echo "would clone into $DST (first run)"; fi
      exit 0 ;;
    rsnapshot) local DST="${DST%/}/$LOWEST.0/$(basename "${SRC%/}")"; [[ -d $DST ]] || echo "no snapshot yet: the first one copies everything" ;;
  esac
  rsync_cmd "$SRC" -n --stats
  echo "+ ${RS[*]}"
  out=$("${RS[@]}" 2>&1); rc=$?
  grep -E '^(Number of files|Number of created files|Number of deleted files|Number of regular files transferred|Total file size|Total transferred file size)' <<<"$out"
  ((rc == 0 || rc == 24)) || { tail -5 <<<"$out" >&2; exit "$rc"; }
}
cutover_job() {
  load "$1"
  [[ $METHOD == move ]] || die "only move jobs cut over"
  local when old src=${SRC%/}; when=$(date +%Y%m%d); old="$src.migrated-$when"
  "$SELF" verify "$ID" >/dev/null || die "the copy does not match the source yet: run it again, then verify"
  if ((SRC_LOCAL)); then
    [[ -e $old ]] && die "$old already exists"
    mv -- "$src" "$old" && echo "renamed $src to $old"
    has link && ln -s -- "${DST%/}" "$src" && echo "linked $src -> ${DST%/}"
  else
    die "the source is on another host: rename $src there by hand (StorageForge keeps that host read-only)"
  fi
}
status_all() {
  local f id t en act next last
  for f in "$ETC"/jobs/*.conf; do
    [[ -e $f ]] || continue
    id=$(basename "$f" .conf)
    t=sf-job-$id.timer
    en=$(systemctl is-enabled "$t" 2>/dev/null | head -1); act=$(systemctl is-active "$t" 2>/dev/null | head -1)
    en=${en:-none} act=${act:-none}
    next=$(systemctl show "$t" -p NextElapseUSecRealtime --value 2>/dev/null || true)
    last=$(tail -n 1 "$VAR/jobs/$id/runs.jsonl" 2>/dev/null || true)
    printf '{"job":"%s","timer":"%s","active":"%s","next":"%s","last":%s}\n' "$id" "$en" "$act" "$(jesc "$next")" "${last:-null}"
  done
}
snap_ok() { [[ $1 =~ ^[a-z]+\.[0-9]+$ ]] || die "bad snapshot name"; }
rel_ok() { [[ $1 != *..* && $1 != /* ]] || die "bad path"; }
snapshots() {
  load "$1"; [[ $METHOD == rsnapshot ]] || die "not an rsnapshot job"
  local d; for d in "${DST%/}"/*.[0-9]*; do [[ -d $d ]] || continue
    printf '{"name":"%s","time":%s}\n' "$(basename "$d")" "$(stat -c %Y "$d")"; done
}
snap_base() { echo "${DST%/}/$1/$(basename "${SRC%/}")"; }
ls_snap() { # id snapshot relpath
  load "$1"; snap_ok "$2"; rel_ok "${3:-}"
  local d; d="$(snap_base "$2")/${3:-}"; [[ -d $d ]] || die "no such folder in $2"
  find "$d" -mindepth 1 -maxdepth 1 -printf '%y\t%s\t%T@\t%f\n' | sort -t$'\t' -k4 | head -2000
}
pack() { # id snapshot relpath -> tar on stdout
  load "$1"; snap_ok "$2"; rel_ok "$3"; [[ -n $3 ]] || die "pick a file or folder"
  local base; base=$(snap_base "$2")
  [[ -e $base/$3 ]] || die "$3 is not in $2"
  echo "$(du -sb "$base/$3" | cut -f1)" >&2
  tar -C "$(dirname -- "$base/$3")" -cf - -- "$(basename -- "$3")"
}
unpack() { # id target -> extracts tar from stdin into target (a new folder under the job's root)
  serve_load "$1"; local t=$2
  under "$t" "$ROOT" || die "$t is outside this job's source"
  [[ -e $t ]] && die "$t already exists"
  mkdir -p -- "$(dirname -- "$t")" && mkdir -m 0700 -- "$t" || return
  local rc n d; tar -C "$t" -xpf -; rc=$?
  # The archive comes from the backup host. GNU tar already refuses ../, absolute names and writes through links, but
  # as root it keeps setuid/setgid bits and makes device nodes (it has no option against either): a backup host that
  # was taken over could restore a setuid-root binary or a world-writable /dev/sda here. $t stays 0700 until both are
  # gone, so no one else can reach them while a long restore runs, or after one that was killed. Cleaned whether or
  # not tar finished, since a failed extraction can still have written some files.
  d=$(find "$t" -xdev \( -type b -o -type c -o -type p -o -type s \) -print -delete | wc -l)
  ((d)) && echo "removed $d device node(s), pipe(s) or socket(s) from the restore"
  n=$(find "$t" -xdev -type f -perm /6000 -print -exec chmod ug-s {} + | wc -l)
  ((n)) && echo "removed setuid/setgid from $n restored file(s); set them again by hand if they need it"
  chmod 0755 -- "$t"
  ((rc == 0)) && echo "restored into $t"
  return "$rc"
}

case ${1:-} in
  --serve) idok "${2:-}"; serve "$2" "${3:-}" ;;
  run) run_job "${2:?job id}" "${3:-}" ;;
  verify) verify_job "${2:?job id}" ;;
  dryrun) dryrun_job "${2:?job id}" ;;
  cutover) cutover_job "${2:?job id}" ;;
  test) load "${2:?job id}"; if ((SRC_LOCAL)); then echo "source is on this host"; else
          hook ping >/dev/null && echo "reached $SRC_HOST with the job key" || { echo "cannot reach storageforge-deploy@$SRC_HOST with the job key" >&2; exit 1; }; fi ;;
  status) status_all ;;
  snapshots) snapshots "${2:?job id}" ;;
  ls) ls_snap "${2:?job id}" "${3:?snapshot}" "${4:-}" ;;
  pack) pack "${2:?job id}" "${3:?snapshot}" "${4:?path}" ;;
  unpack) unpack "${2:?job id}" "${3:?target}" ;;
  version) echo "storageforge-job 1" ;;
  *) echo "usage: storageforge-job run|verify|cutover|test|status|snapshots|ls|pack|unpack|version ..." >&2; exit 2 ;;
esac
"""
