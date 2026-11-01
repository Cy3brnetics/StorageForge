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
        hashes (hashes of the paths on stdin, under the root), stream-* (btrfs or ZFS snapshot streams of the root)
  restores, on the source host (run through storageforge-run):
    storageforge-job unpack <id> <target>   tar on stdin into <target>, a new folder under the job's root
  maintenance, on the host that runs a job:
    storageforge-job dedupe <id>            duperemove over the destination, in the run window; logs what is shared
    storageforge-job with-lock <folder> [--shared] -- <command...>   wait for sync streams on that volume, then run it
"""

from .syncindex import SYNC_PY

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
syncpy() { # the file index (syncindex.py). The heredoc is python's program, so its stdin moves to fd 3
  python3 -I - "$@" 3<&0 <<'SF_SYNC_PY'
@@SYNC_PY@@
SF_SYNC_PY
}

# ── source side: what a job key may do (forced command, as root) ──
serve_load() {
  idok "$1"; [[ -f $ETC/serve/$1.conf ]] || die "this host does not serve job $1"
  ROOT= SNAP=0 DEDUP=0 HASH=sha256 STREAM=; PRE=(); POST=()
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
stream_name_ok() { [[ $1 =~ ^sf-[0-9]{8}T[0-9]{6}$ ]] || die "bad stream snapshot name"; }
zfs_dataset_at() { zfs list -H -t filesystem -o name,mountpoint 2>/dev/null | awk -F'\t' -v m="$1" '$2 == m { print $1; exit }'; }
stream_source() { # -> STREAM_AT: the btrfs folder of this job's snapshots, or the ZFS dataset. Only a whole subvolume or
  # dataset can be sent, and sending one that merely holds the root would hand the job more than the folder it may read
  local root; root=$(realpath -m "$ROOT")
  if [[ $STREAM == btrfs ]]; then
    command -v btrfs >/dev/null || die "btrfs-progs is not installed"
    local sv; sv=$(subvol_of "$root") || die "$root is not on btrfs"
    [[ ${sv%/} == "${root%/}" ]] || die "$root is not the root of a btrfs subvolume, and only that can be sent"
    STREAM_AT="${sv%/}/.storageforge-snap/stream-$SID"
  else
    command -v zfs >/dev/null || die "zfs is not installed"
    STREAM_AT=$(zfs_dataset_at "$root"); [[ -n $STREAM_AT ]] || die "$root is not the mountpoint of a ZFS dataset"
  fi
}
stream_serve() { # "stream-<verb> [name] [parent]"
  [[ -n $STREAM ]] || die "job $SID does not stream snapshots"
  local verb name= parent= old d
  read -r verb name parent <<<"$1"
  [[ -z $name ]] || stream_name_ok "$name"
  [[ -z $parent || $parent == - ]] || stream_name_ok "$parent"
  [[ $parent == - ]] && parent=
  stream_source
  case $STREAM:$verb in
    btrfs:stream-snap)
      name=sf-$(date -u +%Y%m%dT%H%M%S); mkdir -p "$STREAM_AT"
      btrfs subvolume snapshot -r "$(realpath -m "$ROOT")" "$STREAM_AT/$name" >/dev/null || die "btrfs snapshot failed"
      echo "$name" ;;
    zfs:stream-snap)
      name=sf-$(date -u +%Y%m%dT%H%M%S); zfs snapshot "$STREAM_AT@$name" || die "zfs snapshot failed"; echo "$name" ;;
    btrfs:stream-has) [[ -d $STREAM_AT/$name ]] && echo yes || echo no ;;
    zfs:stream-has) zfs list -H -t snapshot -o name "$STREAM_AT@$name" >/dev/null 2>&1 && echo yes || echo no ;;
    btrfs:stream-send)
      btrfs filesystem sync "$(realpath -m "$ROOT")" >/dev/null 2>&1
      if [[ -n $parent ]]; then exec btrfs send -q -p "$STREAM_AT/$parent" "$STREAM_AT/$name"; else exec btrfs send -q "$STREAM_AT/$name"; fi ;;
    zfs:stream-send)
      if [[ -n $parent ]]; then exec zfs send -i "@$parent" "$STREAM_AT@$name"; else exec zfs send "$STREAM_AT@$name"; fi ;;
    btrfs:stream-size)
      if [[ -n $parent ]]; then echo 0; else du -sxb "$STREAM_AT/$name" | cut -f1; fi ;;
    zfs:stream-size)
      if [[ -n $parent ]]; then zfs send -nvP -i "@$parent" "$STREAM_AT@$name"; else zfs send -nvP "$STREAM_AT@$name"; fi 2>&1 | awk '$1 == "size" { print $2 }' ;;
    btrfs:stream-id) btrfs subvolume show "$STREAM_AT/$name" | awk '$1 == "UUID:" { print $2; exit }' ;;
    zfs:stream-id) zfs get -Hp -o value guid "$STREAM_AT@$name" ;;
    btrfs:stream-keep|btrfs:stream-clean)     # the newest verified one stays: the next send's parent
      for d in "$STREAM_AT"/sf-*; do [[ -d $d && $(basename "$d") != "$name" ]] && btrfs subvolume delete "$d" >/dev/null; done
      [[ -n $name ]] || rmdir "$STREAM_AT" 2>/dev/null; exit 0 ;;
    zfs:stream-keep|zfs:stream-clean)
      zfs list -H -t snapshot -d 1 -o name "$STREAM_AT" | while IFS= read -r old; do
        [[ ${old#*@} == sf-* && ${old#*@} != "$name" ]] && zfs destroy "$old"; done; exit 0 ;;
    *) die "not allowed: ${verb:0:40}" ;;
  esac
}
serve() { # id "ssh command"
  serve_load "$1"
  local cmd=${2:-} sv snap
  case $cmd in
    ping) echo pong ;;
    stream-*) stream_serve "$cmd" ;;
    hashes)
      # the paths are only ever opened below this root and through no link (syncindex.py); the key can read these files anyway
      ((DEDUP)) || die "job $SID does not deduplicate"
      command -v python3 >/dev/null || die "python3 is not installed on $(uname -n)"
      snap=$( ((SNAP)) && snap_path || true)
      syncpy hashes "$VAR/index/$SID.source.db" "${snap:-$(realpath -m "$ROOT")}" "$HASH" ;;
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
      [[ -d $path/.git ]] && path=$path/.git     # --strict takes the repository itself, not its working copy
      under "$path" "$ROOT" "$snap" || die "$path is outside this job's source"     # again: that .git can be a link out
      printf '[safe]\n\tdirectory = *\n' >"$VAR/git-safe.conf"
      GIT_CONFIG_GLOBAL=$VAR/git-safe.conf exec git-upload-pack --strict "$path" ;;
    *) die "not allowed: ${cmd:0:80}" ;;
  esac
}

# ── runner side ──
load() {
  idok "$1"; [[ -f $ETC/jobs/$1.conf ]] || die "no job $1 on $(uname -n)"
  ID= NAME= METHOD= SRC_LOCAL=1 SRC_HOST= SRC_PORT=22 SRC= DST= DST_MOUNT=/ FLAGS= KEEP= LOWEST= WINDOW= BW_DAY= BW_NIGHT=
  NIGHT= SNAP=0 HOOKS=0 REPORT_URL=; EXCLUDES=(); ONLY=(); ROUTES=()
  DEDUP=0 DEDUP_HARDLINK=0 DEDUP_MIN=1048576 HASH=sha256 TRANSPORT=rsync PREFLIGHT=0 RESERVE_GB=1 LOCK_WAIT=3600
  # shellcheck disable=SC1090
  source "$ETC/jobs/$1.conf"
  KEY=$ETC/jobs/$ID.key
  ROUTE_VIA= ROUTE_IFACE=
  ssh_options
}
ssh_options() { # SSHO for the current route
  local wait=15; [[ $ROUTE_VIA == lan ]] && wait=4     # ssh keeps the first value of an option it is given twice
  SSHO=(-o BatchMode=yes -o "ConnectTimeout=$wait" -o IdentitiesOnly=yes -i "$KEY" -p "$SRC_PORT")
  if ((${#ROUTES[@]} == 0)); then
    SSHO+=(-o "UserKnownHostsFile=$VAR/known_hosts" -o StrictHostKeyChecking=accept-new)
  else
    # One key, whichever address answers: a stranger holding the LAN address on another network fails this check, and the
    # job moves on to the mesh. The key StorageForge pinned when it scanned the source, when it has one.
    SSHO+=(-o HostKeyAlias=storageforge-source -o ServerAliveInterval=10 -o ServerAliveCountMax=3)
    if [[ -s $ETC/jobs/$ID.hostkey ]]; then SSHO+=(-o "UserKnownHostsFile=$ETC/jobs/$ID.hostkey" -o StrictHostKeyChecking=yes)
    else SSHO+=(-o "UserKnownHostsFile=$VAR/known_hosts-$ID" -o StrictHostKeyChecking=accept-new); fi
    [[ -n $ROUTE_IFACE ]] && SSHO+=(-o "BindInterface=$ROUTE_IFACE")
  fi
  # rsnapshot accepts a daemon source only as rsync://host/module (it rejects host::module) and passes no -e: this
  # makes rsync reach the source's chrooted daemon (see serve) over the same SSH command
  export RSYNC_CONNECT_PROG="ssh ${SSHO[*]} storageforge-deploy@%H rsync --server --daemon ."
}
resolve_route() { # first route that answers, in the plan's order (LAN before mesh) -> SRC_HOST and SSHO follow it
  ((${#ROUTES[@]})) && ((!SRC_LOCAL)) || return 0
  local r via addr iface
  for r in "${ROUTES[@]}"; do
    IFS='|' read -r via addr iface <<<"$r"
    if [[ -n $iface && ! -e /sys/class/net/$iface ]]; then echo "route $via: no interface $iface here" >&2; continue; fi
    ROUTE_VIA=$via ROUTE_IFACE=$iface; ssh_options
    if [[ $(ssh "${SSHO[@]}" "storageforge-deploy@$addr" ping 2>/dev/null </dev/null) == pong ]]; then
      SRC_HOST=$addr; emit route >&2; return 0
    fi
    echo "route $via ($addr) does not answer" >&2
  done
  ROUTE_VIA=; return 1
}
has() { [[ " $FLAGS " == *" $1 "* ]]; }
hook() { # verb -> runs it where the source is. A route that dropped gets one new try, on whichever route answers now
  if ((SRC_LOCAL)); then "$SELF" --serve "$ID" "$1"; return; fi
  ssh "${SSHO[@]}" "storageforge-deploy@$SRC_HOST" "$1"; local rc=$?
  if ((rc == 255 && ${#ROUTES[@]})) && resolve_route >&2; then
    ssh "${SSHO[@]}" "storageforge-deploy@$SRC_HOST" "$1"; rc=$?
  fi
  return "$rc"
}
url_host() { if [[ $SRC_HOST == *:* ]]; then printf '[%s]' "$SRC_HOST"; else printf '%s' "$SRC_HOST"; fi; }
src_spec() { # path -> what rsync reads: the path here, or a module of the source's chrooted rsync (see serve)
  if ((SRC_LOCAL)); then printf '%s/' "${1%/}"
  elif [[ ${1%/} == "${SRC%/}" ]]; then printf 'rsync://storageforge-deploy@%s/src/' "$(url_host)"
  else printf 'rsync://storageforge-deploy@%s/snap/' "$(url_host)"; fi
}
bwlimit() { # the LAN path runs unthrottled: a limit is there for the WAN link under the mesh
  [[ $ROUTE_VIA == lan ]] && return 0
  if [[ -n $NIGHT ]] && in_window "$NIGHT"; then echo "$BW_NIGHT"; else echo "$BW_DAY"; fi
}

# ── what other tools can watch: one JSON line per state on stdout, state.json on disk, and the API ──
EVENT_POSTED=0 EVENT_STATE= DEDUP_SAVED=0 DEDUP_FILES=0
dedup_ratio() { # transferred bytes -> 0.00-1.00 of the data this run did not have to send
  local total=$((DEDUP_SAVED + ${1:-0})) r=0
  ((total > 0)) && r=$((DEDUP_SAVED * 100 / total))
  ((r >= 100)) && echo 1.00 || printf '0.%02d' "$r"
}
emit() { # state [percent] [speed] [transferred bytes]
  [[ $RUN_KIND == run && -n $RUN_UUID ]] || return 0      # verifies and dry runs are not the state of the sync
  local state=$1 pct=${2:-null} speed=${3:-} sent=${4:-0} now line tok hdr node=
  now=$(date +%s); ((SRC_LOCAL)) || node=$SRC_HOST
  line=$(printf '{"event":"sync","job":"%s","run":"%s","state":"%s","percent":%s,"speed":"%s","dedup_ratio":%s,"route":"%s","node":"%s","at":%s}' \
    "$ID" "$RUN_UUID" "$state" "$pct" "$(jesc "$speed")" "$(dedup_ratio "$sent")" "$ROUTE_VIA" "$(jesc "$node")" "$now")
  printf '%s\n' "$line"
  mkdir -p "$VAR/jobs/$ID" && printf '%s\n' "$line" >"$VAR/jobs/$ID/state.tmp" && mv "$VAR/jobs/$ID/state.tmp" "$VAR/jobs/$ID/state.json"
  # at most every 30 seconds, and never for long: a run does not wait on StorageForge
  [[ $state != "$EVENT_STATE" ]] || ((now - EVENT_POSTED >= 30)) || return 0
  EVENT_STATE=$state EVENT_POSTED=$now
  [[ -n $REPORT_URL && -r $ETC/jobs/$ID.token ]] && command -v curl >/dev/null || return 0
  tok=$(<"$ETC/jobs/$ID.token"); hdr=$(mktemp); printf 'Authorization: Bearer %s\n' "$tok" >"$hdr"
  local ca=(); [[ -r $ETC/report-ca.pem ]] && ca=(--cacert "$ETC/report-ca.pem")
  curl -fsS -m 5 ${ca[@]+"${ca[@]}"} -H @"$hdr" -H 'Content-Type: application/json' --data-binary "$line" "$REPORT_URL/api/jobs/state" >/dev/null 2>&1
  rm -f "$hdr"; return 0
}
watch_rsync() { # log: rsync's output on stdin (--info=progress2 ends its lines in \r) -> progress events; the rest to the log and stdout
  local chunk line last=0 now sent
  while IFS= read -r -d $'\r' chunk || [[ -n $chunk ]]; do
    while IFS= read -r line; do
      if [[ $line =~ ^[[:space:]]*([0-9,]+)[[:space:]]+([0-9]+)%[[:space:]]+([0-9.]+[kKMGT]?B/s) ]]; then
        now=$SECONDS
        if ((now - last >= 10)); then last=$now; sent=${BASH_REMATCH[1]//,/}; emit transferring "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "$sent"; fi
      elif [[ -n $line ]]; then printf '%s\n' "$line" | tee -a "$1"; fi
    done <<<"$chunk"
  done
}

# ── one lock per destination volume: sync streams share it; rsnapshot rotations and git take it alone ──
storage_lock() { # folder -> the lock file of its volume (the root filesystem's stays out of /)
  if [[ ${1%/} == '' ]]; then mkdir -p "$VAR/locks"; echo "$VAR/locks/.storage.lock"; else echo "${1%/}/.storage.lock"; fi
}
volume_lock() { # -s|-x: held on fd 8 until this run ends, and the kernel lets go if it dies
  local f; f=$(storage_lock "$DST_MOUNT")
  exec 8>>"$f" || return 1
  flock -w "$LOCK_WAIT" "$1" 8
}
with_lock() { # folder [--shared] -- command...: for what StorageForge does not run, such as a git auto-commit on a timer
  local dir=$1 mode=-x; shift
  [[ -d $dir ]] || die "no folder $dir"
  [[ ${1:-} == --shared ]] && { mode=-s; shift; }
  [[ ${1:-} == -- ]] && shift
  (($#)) || die "with-lock needs a command"
  exec 8>>"$(storage_lock "$(stat -c %m -- "$dir")")" || die "cannot open the lock for $dir"     # the volume's, as jobs take it
  flock -w "${LOCK_WAIT:-3600}" "$mode" 8 || { echo "storageforge-job: $dir is busy with a sync" >&2; exit 75; }
  exec "$@"
}

# ── room to receive: data and metadata, before a large transfer rather than halfway ──
headroom() { # folder bytes-needed -> 0, or why not on stdout
  local dir=$1 need=${2:-0} reserve=$((RESERVE_GB * 1024 * 1024 * 1024)) type u free unalloc msize mused meta
  type=$(stat -f -c %T "$dir" 2>/dev/null)
  case $type in
    btrfs)
      u=$(btrfs filesystem usage -b "$dir" 2>/dev/null) || { echo "btrfs filesystem usage failed on $dir"; return 1; }
      free=$(awk '/Free \(estimated\):/ { print $3; exit }' <<<"$u")
      unalloc=$(awk '/Device unallocated:/ { print $3; exit }' <<<"$u")
      msize=$(sed -n 's/^Metadata,[^:]*: *Size:\([0-9]*\).*/\1/p' <<<"$u" | head -1)
      mused=$(sed -n 's/^Metadata,.*Used:\([0-9]*\).*/\1/p' <<<"$u" | head -1)
      # new metadata comes from free space in its chunks, or from new chunks; unallocated counts half, for DUP or RAID1
      meta=$(( ${msize:-0} - ${mused:-0} + ${unalloc:-0} / 2 ))
      local want=$((need / 100)); ((want < 268435456)) && want=268435456
      ((meta >= want)) || { echo "$dir has $meta bytes of metadata room, under the $want this needs: balance or free space first"; return 1; } ;;
    zfs)
      local ds pool cap; ds=$(zfs list -H -o name "$dir" 2>/dev/null) || { echo "zfs list failed on $dir"; return 1; }
      free=$(zfs list -Hp -o avail "$ds"); pool=${ds%%/*}; cap=$(zpool list -Hp -o capacity "$pool" 2>/dev/null); cap=${cap%\%}
      ((${cap:-0} < 90)) || { echo "pool $pool is ${cap}% full; ZFS slows badly and can stall above 90%"; return 1; } ;;
    *)
      read -r free meta < <(df -B1 --output=avail,iavail "$dir" 2>/dev/null | tail -1)
      [[ -n $free ]] || { echo "cannot read free space on $dir"; return 1; }
      [[ $meta == 0 || $meta == - ]] || ((meta >= 1000)) || { echo "$dir has only $meta inodes left"; return 1; } ;;
  esac
  ((${free:-0} >= need + reserve)) || { echo "$dir has ${free:-0} bytes free; this needs $need plus the $RESERVE_GB GiB kept in reserve"; return 1; }
}
preflight() { # bytes-needed -> reports and exits when there is no room
  ((PREFLIGHT)) || return 0
  local why; why=$(headroom "$DST" "$1") && return 0
  ((HOOKS && !posted)) && hook post
  report 6 "not enough room: $why"; exit 6
}

# ── pre-transfer dedup: files already here under another name are made from local data, and rsync then skips them ──
dedup_stage() { # source path. Everything here only saves work: on any failure rsync copies as it would have anyway
  ((DEDUP)) || return 0
  command -v python3 >/dev/null || { echo "dedup skipped: no python3 here" >&2; return 0; }
  local w c m st db=$VAR/index/$ID.db a b
  w=$(mktemp) c=$(mktemp) m=$(mktemp)
  rsync_cmd "$1" -n -8 --out-format='%l %n'
  if "${RS[@]}" >"$w" 2>/dev/null </dev/null; then
    if ((SRC_LOCAL)) && st=$(syncpy clone "$1" "$DST" "$w" </dev/null); then
      read -r a b <<<"$st"; DEDUP_FILES=$((DEDUP_FILES + a)) DEDUP_SAVED=$((DEDUP_SAVED + b))
    fi
    syncpy candidates "$db" "$DST" "$w" "$DEDUP_MIN" </dev/null >"$c" || : >"$c"
    if [[ -s $c ]]; then
      if ((SRC_LOCAL)); then "$SELF" --serve "$ID" hashes <"$c" >"$m"
      else ssh "${SSHO[@]}" "storageforge-deploy@$SRC_HOST" hashes <"$c" >"$m"; fi
      if (($? == 0)) && st=$(syncpy apply "$db" "$DST" "$m" "$HASH" "$DEDUP_MIN" "$DEDUP_HARDLINK" </dev/null); then
        read -r a b _ <<<"$st"; DEDUP_FILES=$((DEDUP_FILES + a)) DEDUP_SAVED=$((DEDUP_SAVED + b))
      else echo "dedup skipped: the source gave no hashes" >&2; fi
    fi
  else echo "dedup skipped: rsync could not list the changes" >&2; fi
  rm -f "$w" "$c" "$m"
  ((DEDUP_FILES)) && echo "dedup: $DEDUP_FILES file(s), $DEDUP_SAVED bytes made from local data"
  return 0
}
transfer_need() { # source path -> bytes rsync would send
  rsync_cmd "$1" -n --stats
  "${RS[@]}" 2>/dev/null </dev/null | sed -n 's/^Total transferred file size: //p' | tail -1 | { read -r n _; num "${n:-0}"; }
}

# ── btrfs or ZFS snapshot streams instead of walking the tree ──
stream_received() { # name -> what the copy here says it was sent from
  if [[ $TRANSPORT == btrfs ]]; then btrfs subvolume show "$STREAM_DIR/$1" 2>/dev/null | awk '$1 == "Received" && $2 == "UUID:" { print $3; exit }'
  else zfs get -Hp -o value guid "$STREAM_DIR@$1" 2>/dev/null; fi
}
stream_list() { # names here, oldest first
  if [[ $TRANSPORT == btrfs ]]; then local d; for d in "$STREAM_DIR"/sf-*; do [[ -d $d ]] && basename "$d"; done
  else zfs list -H -t snapshot -d 1 -s creation -o name "$STREAM_DIR" 2>/dev/null | sed -n 's/^.*@\(sf-.*\)$/\1/p'; fi
}
stream_target() { # -> STREAM_DIR: a folder for btrfs, a child dataset for ZFS (receive never uses -F, nothing is overwritten)
  if [[ $TRANSPORT == btrfs ]]; then
    command -v btrfs >/dev/null || { echo "btrfs-progs is not installed here"; return 1; }
    [[ $(stat -f -c %T "$DST" 2>/dev/null) == btrfs ]] || { echo "$DST is not on btrfs"; return 1; }
    STREAM_DIR="${DST%/}/.storageforge-stream"; mkdir -p "$STREAM_DIR"
  else
    command -v zfs >/dev/null || { echo "zfs is not installed here"; return 1; }
    local ds; ds=$(zfs_dataset_at "$(realpath -m "$DST")")
    [[ -n $ds ]] || { echo "$DST is not the mountpoint of a ZFS dataset"; return 1; }
    STREAM_DIR="$ds/sf-$ID"
  fi
}
stream_run() { # -> rc, msg; pre and post are the caller's, the snapshot is taken here so post can run straight after it
  local why name parent= n id got size sent cnt attempt=0 r=()
  why=$(stream_target) || { rc=7 msg=$why; return; }
  stream_target
  if [[ $TRANSPORT == btrfs ]]; then   # a receive that was cut off: rw, with no received UUID. Only this job's own folder
    for n in $(stream_list); do [[ -n $(stream_received "$n") ]] || btrfs subvolume delete "$STREAM_DIR/$n" >/dev/null; done
  fi
  name=$(hook stream-snap 2>&1); [[ $name =~ ^sf-[0-9]{8}T[0-9]{6}$ ]] || { rc=7 msg="the source could not make a snapshot to send: ${name:0:300}"; return; }
  if ((HOOKS && !posted)); then hook post && posted=1; fi
  parent=$(stream_list | tail -1)
  if [[ -n $parent && $(hook "stream-has $parent") != yes ]]; then
    [[ $TRANSPORT == zfs ]] && { rc=7 msg="the source no longer has $parent, the last snapshot both sides share: a full ZFS receive would need $STREAM_DIR gone, which is yours to decide"; return; }
    echo "the source no longer has $parent: sending in full"; parent=
  fi
  size=$(hook "stream-size $name ${parent:--}"); [[ $size =~ ^[0-9]+$ ]] || size=0
  # btrfs cannot price an incremental send in advance: twice the last one is the guide
  if [[ -n $parent && $size == 0 ]]; then size=$(($(cat "$VAR/jobs/$ID/stream.bytes" 2>/dev/null || echo 0) * 2)); fi
  preflight "$size"
  cnt=$(mktemp); local bw; bw=$(bwlimit); local limit=(cat)
  if [[ -n $bw ]]; then if command -v pv >/dev/null; then limit=(pv -q -L "${bw}k"); else echo "note: pv is not installed, so this stream is not limited to $bw KB/s"; fi; fi
  if [[ $TRANSPORT == btrfs ]]; then r=(btrfs receive -C "$STREAM_DIR"); else r=(zfs receive -u "$STREAM_DIR"); fi
  while :; do
    emit streaming
    if ((SRC_LOCAL)); then "$SELF" --serve "$ID" "stream-send $name ${parent:--}"
    else ssh "${SSHO[@]}" "storageforge-deploy@$SRC_HOST" "stream-send $name ${parent:--}"; fi \
      | tee >(wc -c >"$cnt") | "${limit[@]}" | "${r[@]}"
    local st=("${PIPESTATUS[@]}"); rc=0; for n in "${st[@]}"; do ((n)) && rc=$n; done
    ((rc == 0)) && break
    # this attempt's copy never verified, however whole it looks: it must not become the next send's parent
    [[ $TRANSPORT == btrfs && -d $STREAM_DIR/$name ]] && btrfs subvolume delete "$STREAM_DIR/$name" >/dev/null
    if ((${st[0]} == 255 && ${#ROUTES[@]} && attempt < 4)); then
      attempt=$((attempt + 1)); sleep $((attempt * 5))
      if resolve_route; then emit failover; continue; fi
    fi
    rm -f "$cnt"; msg="the snapshot stream failed (exit $rc); the last good copy is untouched"; return
  done
  sleep 1; sent=$(cat "$cnt" 2>/dev/null || echo 0); rm -f "$cnt"; BYTES=${sent:-0}
  id=$(hook "stream-id $name"); got=$(stream_received "$name")
  if [[ -z $id || $id != "$got" ]]; then rc=7 msg="sent $name, but its copy does not check out (source ${id:-unknown}, here ${got:-none}): it is kept, nothing older was removed"; return; fi
  mkdir -p "$VAR/jobs/$ID"; echo "$BYTES" >"$VAR/jobs/$ID/stream.bytes"
  # verified: the new one is the copy and the next send's parent, and what they replace can go
  if [[ $TRANSPORT == btrfs ]]; then
    ln -sfn ".storageforge-stream/$name" "${DST%/}/latest.tmp" && mv -T "${DST%/}/latest.tmp" "${DST%/}/latest"
    for n in $(stream_list); do [[ $n == "$name" ]] || btrfs subvolume delete "$STREAM_DIR/$n" >/dev/null; done
  else
    for n in $(stream_list); do [[ $n == "$name" ]] || zfs destroy "$STREAM_DIR@$n"; done
  fi
  hook "stream-keep $name"
  msg="snapshot $name received${parent:+ (incremental on $parent)}, ids match"
}
stream_verify() {
  local n id got; stream_target >/dev/null || { report 7 "$(stream_target)"; exit 7; }
  stream_target; n=$(stream_list | tail -1)
  [[ -n $n ]] || { report 1 "no snapshot has been received yet"; exit 1; }
  id=$(hook "stream-id $n"); got=$(stream_received "$n")
  if [[ -n $id && $id == "$got" ]]; then report 0 "$n matches the source's snapshot (the stream carries checksums)"; exit 0; fi
  report 1 "$n does not match the source's snapshot (source ${id:-unknown}, here ${got:-none})"; exit 1
}

# ── out-of-band extent dedup on archives ──
space_shared() { # folder -> total exclusive shared in bytes (btrfs), or just what df says is used
  sync -f "$1" 2>/dev/null     # data still in memory has no extents yet, and counts as nothing
  if [[ $(stat -f -c %T "$1" 2>/dev/null) == btrfs ]]; then
    btrfs filesystem du -s --raw "$1" 2>/dev/null | awk 'NR == 2 { print $1, $2, $3 }'
  else df -B1 --output=used "$1" 2>/dev/null | tail -1 | awk '{ print $1, 0, 0 }'; fi
}
dedupe_job() {
  load "$1"; RUN_KIND=dedupe; RUN_UUID=$(cat /proc/sys/kernel/random/uuid); RUN_START=$(date +%s)
  command -v duperemove >/dev/null || { report 127 "duperemove is not installed"; exit 127; }
  exec 9>"$LOCKS/storageforge-job-$ID.lock" || die "cannot open the job lock"
  flock -n 9 || { echo "another run of $ID is in progress"; exit 0; }
  if [[ -n $WINDOW ]] && ! in_window "$WINDOW"; then report 0 "skipped: outside the run window $WINDOW"; exit 0; fi
  dst_guard || { report 3 "$DST_MOUNT is not mounted"; exit 3; }
  volume_lock -x || { report 75 "$DST_MOUNT is busy with a sync: try again later"; exit 75; }
  mkdir -p "$VAR/index"; chmod 0700 "$VAR/index"
  local t0 e0 s0 t1 e1 s1 rc saved stop=()
  read -r t0 e0 s0 <<<"$(space_shared "$DST")"
  [[ -n $WINDOW ]] && stop=(timeout --signal=TERM "$(until_end "$WINDOW")")
  # the kernel compares the bytes before it shares any, and the hash file means a later run only reads what changed
  "${stop[@]}" duperemove -dr --hashfile="$VAR/index/$ID.dupehash" -- "$DST"; rc=$?
  read -r t1 e1 s1 <<<"$(space_shared "$DST")"
  # on disk, a folder takes its exclusive bytes plus its shared bytes once: two copies made one go 8->0 exclusive, 0->4 shared
  saved=$(( ${e0:-0} + ${s0:-0} - ${e1:-0} - ${s1:-0} )); ((saved < 0)) && saved=0
  [[ $(stat -f -c %T "$DST" 2>/dev/null) == btrfs ]] || saved=$(( ${t0:-0} > ${t1:-0} ? ${t0:-0} - ${t1:-0} : 0 ))
  local msg="duperemove: $saved bytes freed; ${s1:-0} of ${t1:-0} bytes shared"
  ((rc == 124)) && { rc=0; msg+=" (stopped at the end of the run window; the next run goes on)"; }
  ((rc == 0)) || msg="duperemove failed (exit $rc)"
  BYTES=$saved
  command -v python3 >/dev/null && syncpy metric "$VAR/index/$ID.db" dedupe \
    "{\"total\":${t1:-0},\"exclusive\":${e1:-0},\"shared\":${s1:-0},\"saved\":$saved,\"message\":\"$(jesc "$msg")\"}" </dev/null
  report "$rc" "$msg"; exit "$rc"
}
rsync_cmd() { # source-path extra... -> RS
  local src=$1; shift
  # a label belongs to the host holding the file: asking an SELinux destination to change one fails with exit 23
  # (rsnapshot's --delete-excluded makes these sender-only, so its config also names the receiver with -xr). -S: a sparse
  # file stays sparse, or a 1 GiB image holding nothing fills the destination
  RS=(rsync -aHAXS '--filter=-x_system.*' --filter=-x_security.selinux --numeric-ids --partial --partial-dir=.rsync-partial)
  has onefs && RS+=(-x)
  has checksum && RS+=(-c)
  has delete && RS+=(--delete-after)
  local bw; bw=$(bwlimit); [[ -n $bw ]] && RS+=(--bwlimit="$bw")
  ((SRC_LOCAL)) || RS+=(-e "ssh ${SSHO[*]}")
  ((${#ROUTES[@]})) && RS+=(--timeout=120)     # a path that went quiet ends the attempt, and the next one finds another
  local x; for x in "${EXCLUDES[@]}"; do RS+=(--exclude="$x"); done
  RS+=("${ONLY[@]}")
  # never --inplace: dedup can leave two names on one inode or shared extents, and only a write to a new file keeps them apart
  RS+=(--exclude=.storageforge-snap --exclude=.storage.lock --exclude='.sf-dedup-*' "$@" "$(src_spec "$src")" "${DST%/}/")
}
num() { tr -d ',' <<<"${1:-0}" | grep -o '^[0-9]*' || echo 0; }
dst_guard() { [[ $DST_MOUNT == / ]] || mountpoint -q "$DST_MOUNT"; }

RUN_KIND=run RUN_LEVEL= RUN_START=0 RUN_UUID= BYTES=0 FILES=0
report() { # rc message
  local rc=$1 msg=$2 end line tok hdr
  end=$(date +%s)
  ((DEDUP_SAVED)) && msg+=" · dedup kept $DEDUP_SAVED bytes off the network (ratio $(dedup_ratio "${BYTES:-0}"))"
  emit "$( ((rc == 0)) && echo finished || echo failed)" "$( ((rc == 0)) && echo 100 || echo null)" '' "${BYTES:-0}"
  line=$(printf '{"run":"%s","job":"%s","kind":"%s","level":"%s","start":%s,"end":%s,"rc":%s,"bytes":%s,"files":%s,"dedup_bytes":%s,"host":"%s","message":"%s"}' \
    "$RUN_UUID" "$ID" "$RUN_KIND" "$RUN_LEVEL" "$RUN_START" "$end" "$rc" "${BYTES:-0}" "${FILES:-0}" "$DEDUP_SAVED" "$(jesc "$(uname -n)")" "$(jesc "${msg:0:2000}")")
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
    printf 'rsync_short_args\t-aHAXS\n'    # what a mirror keeps, and what verify compares
    printf 'rsync_long_args\t--delete --numeric-ids --delete-excluded --filter=-x_system.* --filter=-x_security.selinux --filter=-xr_system.* --filter=-xr_security.selinux%s\n' "$(has onefs && echo ' --one-file-system')"
    printf 'lockfile\t%s/storageforge-rsnapshot-%s.pid\n' "$TMPD" "$ID"
    for lv in $KEEP; do cnt=${lv#*=}; ((cnt > 0)) && printf 'retain\t%s\t%s\n' "${lv%=*}" "$cnt"; done
    local x; for x in "${EXCLUDES[@]}" .storageforge-snap .storage.lock; do printf 'exclude\t%s\n' "$x"; done
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
    dst_guard || { report 3 "$DST_MOUNT is not mounted"; exit 3; }
    volume_lock -x || { report 75 "$DST_MOUNT is busy with a sync: this rotation did not run"; exit 75; }
    local c; c=$(rsnapshot_conf "$SRC"); rsnapshot -c "$c" "$RUN_LEVEL"; local rc=$?; rm -f "$c"
    report "$rc" "rotated $RUN_LEVEL"; exit "$rc"
  fi
  if [[ -n $WINDOW ]] && ! in_window "$WINDOW"; then report 0 "skipped: outside the run window $WINDOW"; exit 0; fi
  dst_guard || { report 3 "$DST_MOUNT is not mounted: not copying onto the root filesystem"; exit 3; }
  # after the guard, so an unmounted disk does not get a lock file on the folder under it
  local lockmode=-s; [[ $METHOD == rsnapshot || $METHOD == git ]] && lockmode=-x
  volume_lock "$lockmode" || { report 75 "$DST_MOUNT is busy with another sync or rotation: this run did not start"; exit 75; }
  resolve_route || { report 8 "no route to the source answers: tried ${ROUTES[*]}"; exit 8; }
  local src=$SRC rc=0 msg= posted=0 snapped=0 log
  log=$(mktemp)
  emit starting
  if ((HOOKS)); then
    echo "pre commands on the source"
    if ! hook pre; then hook post; report 4 "a pre command failed; post commands ran, nothing copied"; exit 4; fi
  fi
  if [[ $TRANSPORT != rsync ]]; then
    mkdir -p "$DST"
    preflight 0
    stream_run
    ((HOOKS && !posted)) && { hook post || msg+=" (a post command failed)"; }
    rm -f "$log"; report "$rc" "$msg"; exit "$rc"
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
      mkdir -p "$DST"
      preflight 0
      dedup_stage "$src"
      ((PREFLIGHT)) && preflight "$(transfer_need "$src")"
      local attempt=0
      while :; do
        rsync_cmd "$src" --stats --info=progress2 --no-inc-recursive
        echo "+ ${RS[*]}"
        emit transferring 0
        : >"$log"
        ((${#stop[@]})) && stop=(timeout --signal=TERM "$(until_end "$WINDOW")")
        "${stop[@]}" "${RS[@]}" 2>&1 | watch_rsync "$log"; rc=${PIPESTATUS[0]}
        # the route went away mid-session (ssh 255, rsync's timeouts and broken streams): --partial-dir resumes on the next one
        case $rc in 10|12|30|35|255) ;; *) break ;; esac
        ((${#ROUTES[@]} && attempt < 5)) || break
        attempt=$((attempt + 1)); echo "connection lost (rsync exit $rc): looking for a route, try $attempt of 5"
        sleep $((attempt * 5))
        if resolve_route; then emit failover; else echo "no route answers yet"; fi
      done
      transfer_stats "$log"
      case $rc in 0) msg="copied $FILES files" ;; 24) rc=0; msg="copied $FILES files (some vanished while copying)" ;;
        124) msg="stopped at the end of the run window; the next run resumes" ;; *) msg="rsync failed (exit $rc): $(tail -3 "$log" | tr '\n' ' ')" ;; esac ;;
    rsnapshot)
      mkdir -p "$DST"
      preflight 0
      local c; c=$(rsnapshot_conf "$src")
      "${stop[@]}" rsnapshot -c "$c" -V "${RUN_LEVEL:-$LOWEST}" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}
      rm -f "$c"
      case $rc in 0) msg="snapshot ${RUN_LEVEL:-$LOWEST}.0 taken" ;; 2) rc=0; msg="snapshot taken with warnings" ;;
        124) msg="stopped at the end of the run window" ;; *) msg="rsnapshot failed (exit $rc): $(tail -3 "$log" | tr '\n' ' ')" ;; esac ;;
    git)
      local url; if ((SRC_LOCAL)); then url=$src; else url="ssh://storageforge-deploy@$(url_host):$SRC_PORT${src}"; fi
      export GIT_SSH_COMMAND="ssh ${SSHO[*]}"
      printf '[safe]\n\tdirectory = *\n' >"$VAR/git-safe.conf"; export GIT_CONFIG_GLOBAL=$VAR/git-safe.conf
      # the archive remembers the address of its first clone, and today's route may be another
      if [[ -d $DST ]] && ((${#ROUTES[@]})); then git -C "$DST" remote set-url origin "$url"; fi
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
  volume_lock -s || { report 75 "$DST_MOUNT is busy: verify did not run"; exit 75; }
  resolve_route || { report 8 "no route to the source answers"; exit 8; }
  [[ $TRANSPORT == rsync ]] || stream_verify
  local target=$DST
  if [[ $METHOD == rsnapshot ]]; then target="${DST%/}/$LOWEST.0/$(basename "${SRC%/}")"; fi
  [[ $METHOD == git ]] && { report 0 "nothing to verify for git archives (git checks objects itself)"; exit 0; }
  local out n err rc=0
  local saved_delete=$FLAGS; FLAGS="$FLAGS checksum"; FLAGS=${FLAGS/delete/}
  local DST=$target; rsync_cmd "$SRC" -n -i
  FLAGS=$saved_delete
  echo "+ ${RS[*]}"
  # The list is on stdout. ssh warnings are on stderr, so stderr counts only when rsync itself failed
  err=$(mktemp) || die "cannot make a temporary file"
  out=$("${RS[@]}" 2>"$err") || rc=$?
  if ((rc != 0 && rc != 24)); then
    cat "$err" >&2; n=$(tail -n 3 "$err" | paste -sd' '); rm -f "$err"
    report 1 "could not compare with the source (rsync exit $rc): $n"
    exit 1
  fi
  rm -f "$err"
  out=$(grep -v '^\.d' <<<"$out" | grep -v '^cd' | grep -v '^skipping' || true)
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
  resolve_route || { echo "no route to the source answers: ${ROUTES[*]}" >&2; exit 1; }
  [[ -z $ROUTE_VIA ]] || echo "route now: $ROUTE_VIA ($SRC_HOST${ROUTE_IFACE:+ on $ROUTE_IFACE})"
  local bw; bw=$(bwlimit); echo "bandwidth limit now: ${bw:-none}${bw:+ KB/s}"
  if ((PREFLIGHT)); then local why; why=$(headroom "$DST_MOUNT" 0) && echo "room to receive: ok" || echo "room to receive: $why"; fi
  if [[ $TRANSPORT != rsync ]]; then
    echo "transport: $TRANSPORT snapshot stream"; hook "stream-has sf-00000000T000000" >/dev/null && echo "the source can stream" || exit 1
    stream_target && echo "stream target: $STREAM_DIR"; exit $?
  fi
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
  ((rc == 0)) || rmdir -- "$t" 2>/dev/null       # nothing arrived: no empty folder left beside the original
  return "$rc"
}

case ${1:-} in
  --serve) idok "${2:-}"; serve "$2" "${3:-}" ;;
  run) run_job "${2:?job id}" "${3:-}" ;;
  verify) verify_job "${2:?job id}" ;;
  dryrun) dryrun_job "${2:?job id}" ;;
  cutover) cutover_job "${2:?job id}" ;;
  test) load "${2:?job id}"; if ((SRC_LOCAL)); then echo "source is on this host"; else
          resolve_route || { echo "no route to the source answers: ${ROUTES[*]}" >&2; exit 1; }
          hook ping >/dev/null && echo "reached $SRC_HOST with the job key" || { echo "cannot reach storageforge-deploy@$SRC_HOST with the job key" >&2; exit 1; }; fi ;;
  status) status_all ;;
  snapshots) snapshots "${2:?job id}" ;;
  ls) ls_snap "${2:?job id}" "${3:?snapshot}" "${4:-}" ;;
  pack) pack "${2:?job id}" "${3:?snapshot}" "${4:?path}" ;;
  unpack) unpack "${2:?job id}" "${3:?target}" ;;
  dedupe) dedupe_job "${2:?job id}" ;;
  with-lock) shift; with_lock "$@" ;;
  version) echo "storageforge-job 1" ;;
  *) echo "usage: storageforge-job run|verify|cutover|test|status|snapshots|ls|pack|unpack|dedupe|with-lock|version ..." >&2; exit 2 ;;
esac
""".replace('@@SYNC_PY@@', SYNC_PY.strip('\n'))
