"""Shared pieces of the Bash scripts StorageForge writes (moves, share deployment): output in storage-setup.sh's
style (ok / missing / conflict / ->), and --host, which copies the script to another machine and runs it there
with sudo, forwarding your SSH agent."""
import datetime as dt
import re

from .db import Conn, loads

# A host as plans name it: hostname, IPv4, [IPv6] or IPv6%zone. Never a line break, space or leading '-'.
HOST_RE = re.compile(r'[A-Za-z0-9_.:\[\]%-]{1,253}')
# Bash ends a comment at a line break, and terminals act on escape sequences when a script is read with cat or less.
_BREAKS = re.compile('[\x00-\x08\x0a-\x1f\x7f\x85\u2028\u2029]+')


def host_name(value, what: str) -> str:
    h = str(value or '').strip()
    if not HOST_RE.fullmatch(h) or h.startswith('-'):
        raise ValueError(f'{what} must be a host name or address')
    return h


def longest_gap(day_matches, minutes: list[int]) -> int | None:
    """Seconds between the two furthest-apart runs of a schedule, over four years so leap days count. day_matches(date) says
    whether it runs that day, minutes when in the day. None when it never runs."""
    first = dt.date(2024, 1, 1).toordinal()
    span = 1461
    days = [o for o in range(first, first + span) if day_matches(dt.date.fromordinal(o))]
    times = sorted(set(minutes))
    if not days or not times:
        return None
    within = max((b - a for a, b in zip(times, times[1:])), default=0)
    # a day that comes once in the four years waits for its next time round; otherwise the window's own seam is no real gap
    pairs = zip(days, days[1:]) if len(days) > 1 else [(days[0], days[0] + span)]
    across = max((b - a) * 1440 + times[0] - times[-1] for a, b in pairs)
    return max(within, across) * 60


def one_line(text) -> str:
    """Text safe to put after # in a generated script: control characters and line breaks become spaces."""
    return _BREAKS.sub(' ', str(text))


def comments(lines, empty: str) -> str:
    """Header comment lines, each forced onto one line, so no value can end the comment and start a command."""
    return '\n'.join(one_line(l) for l in lines) or empty


HELPERS = r"""label_exec() { # label_exec <file>... for a script a systemd unit runs: under /usr/local/lib it is lib_t, which is not an entry point, so with SELinux enforcing the unit stays in init_t and cannot run ssh, btrfs or rsync (SF-48, found in the lab on Fedora). bin_t it is, and it is kept across a relabel when semanage is there
  [[ -d ${SF_SELINUX_FS:-/sys/fs/selinux} ]] && command -v chcon >/dev/null 2>&1 || return 0
  chcon -t bin_t -- "$@" 2>/dev/null || true
  command -v semanage >/dev/null 2>&1 && semanage fcontext -a -t bin_t '/usr/local/lib/storageforge(/.*)?\.sh' 2>/dev/null || true
  return 0
}
other_fs_dirs() { # path -> the folders under it that are another filesystem: a held snapshot is read-only, and is not for relabelling
  local dev; dev=$(stat -c %d -- "$1") || return 0
  find "$1" -xdev -type d -printf '%D\t%p\n' 2>/dev/null | awk -F'\t' -v d="$dev" '$1 != d {print $2}'
}
relabel_tree() { # path: restorecon, leaving out what other_fs_dirs finds
  local d skip=(); while IFS= read -r d; do skip+=(-e "$d"); done < <(other_fs_dirs "$1")
  restorecon -R -x ${skip[@]+"${skip[@]}"} -- "$1"
}
durable() { # to disk now: a config file written moments before a power cut can otherwise come back empty
  sync -- "$@" 2>/dev/null || sync
}
reload_systemd() { # a reload waits on a hard network mount whose server is gone, and every new login then waits on systemd
  local t fs rc
  while read -r _ t fs _; do
    case $fs in nfs|nfs4|cifs|smb3) ;; *) continue ;; esac
    t=$(printf '%b' "$t")
    timeout -k 1 5 stat -t -- "$t" >/dev/null 2>&1; rc=$?
    if ((rc == 124 || rc == 137)); then
      conflict "$t is not answering: reloading systemd now would block logins here until it does. Bring its server back, or: umount -l $t"
      return 1
    fi
  done </proc/self/mounts
  systemctl daemon-reload
}
if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[34m' H=$'\e[1m' N0=$'\e[0m'; else G= Y= R= B= H= N0=; fi
section()  { printf '\n%s== %s ==%s\n' "$H" "$*" "$N0"; }
ok()       { printf '  %-9s %s\n' "${G}ok${N0}" "$*"; }
missing()  { printf '  %-9s %s\n' "${Y}missing${N0}" "$*"; MISSING=$((MISSING + 1)); }
conflict() { printf '  %-9s %s\n' "${R}conflict${N0}" "$*"; PROBLEMS=$((PROBLEMS + 1)); }
info()     { printf '  %-9s %s\n' "" "$*"; }
doing()    { printf '  %-9s %s\n' "${Y}->${N0}" "$*"; }
skip()     { printf '  %-9s %s\n' "${B}other${N0}" "$*"; }
PROBLEMS=0 MISSING=0
finished() { if ((${APPLY:-0} && MISSING)); then echo "${Y}$MISSING step(s) not finished${N0}"; else echo "${G}done${N0}"; fi; }
host_slug() { local n=${1%%.*}; n=$(tr 'A-Z' 'a-z' <<<"$n" | tr -cd 'a-z0-9_-'); echo "${n:-unknown}"; }
human() { numfmt --to=iec-i --suffix=B "${1:-0}" 2>/dev/null || echo "$1 B"; }
"""

# The receiving side of a btrfs or ZFS send. In storageforge-job (needs ETC, VAR, LOCKS) this is all a send's job key can reach, through its
# forced command, as root. A send on the same host runs the same verbs here, with RECV_LOCAL=1. A signed deploy wrote the conf, which says
# the tool, the folder or dataset and the retention: a sender names a verb, a nonce and a snapshot, and never a path, an option or a command.
RECEIVE_KIT = r"""RECV_LOCAL=0 RID= TOOL= ROOT= PREFIX= KEEP=0 RECURSIVE=0 EXPIRES=0 SENDER=
recv_esc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s" | tr -d '\000-\037\177'; }
recv_tail() { if (($(wc -l <"$1") > 600)); then tail -n 500 "$1" >"$1.tmp" && mv "$1.tmp" "$1"; fi; chmod 0644 "$1" 2>/dev/null; return 0; }
recv_record() { # verb nonce name rc started message: the own record of this send, and a line where scans read task runs
  ((RECV_LOCAL)) && return 0
  [[ -n $RID ]] || return 0
  local line dir=$VAR/receive/$RID
  line=$(printf '{"task":"receive-%s","verb":"%s","nonce":"%s","name":"%s","rc":%d,"started":%d,"finished":%d,"sender":"%s","host":"%s","message":"%s"}' \
    "$RID" "$1" "$(recv_esc "$2")" "$(recv_esc "$3")" "$4" "$5" "$(date +%s)" "$(recv_esc "$SENDER")" "$(recv_esc "$(uname -n)")" "$(recv_esc "${6:0:400}")")
  mkdir -p "$dir" "$VAR/tasks" 2>/dev/null; chmod 0755 "$VAR" "$VAR/receive" "$dir" "$VAR/tasks" 2>/dev/null
  printf '%s\n' "$line" >>"$dir/runs.jsonl" && recv_tail "$dir/runs.jsonl"
  printf '%s\n' "$line" >>"$VAR/tasks/runs.jsonl" && recv_tail "$VAR/tasks/runs.jsonl"
}
recv_refuse() { # why [nonce]: exit 97, as the runner does for a request it will not run
  printf 'storageforge-job: refused: %s\n' "$1" >&2
  recv_record refused "${2:-}" '' 97 "$(date +%s)" "$1"
  exit 97
}
recv_name_ok() { # a snapshot name. Between hosts a strict word. On one host there is no boundary to guard, only a path not to leave
  if ((RECV_LOCAL)); then [[ -n $1 && $1 != */* && $1 != . && $1 != .. ]]; else [[ $1 =~ ^[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}$ ]]; fi
}
recv_load() { # id: read line by line and never run, so nothing in the conf can be a command. A signed deploy wrote it; a hand edit is still checked
  local conf=$ETC/receive/$1.conf line
  [[ -f $conf ]] || recv_refuse "this host has no send $1"
  while IFS= read -r line; do
    case $line in
      TOOL=*) TOOL=${line#TOOL=} ;; ROOT=*) ROOT=${line#ROOT=} ;; PREFIX=*) PREFIX=${line#PREFIX=} ;; KEEP=*) KEEP=${line#KEEP=} ;;
      RECURSIVE=*) RECURSIVE=${line#RECURSIVE=} ;; EXPIRES=*) EXPIRES=${line#EXPIRES=} ;; SENDER=*) SENDER=${line#SENDER=} ;;
    esac
  done <"$conf"
  RID=$1
  case $TOOL in
    btrfs|vm) [[ $ROOT == /?* && /$ROOT/ != */../* && /$ROOT/ != */./* ]] || recv_refuse "send $1: not a folder to receive into" ;;
    zfs) [[ $ROOT =~ ^[A-Za-z0-9_][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)+$ && $ROOT != *..* ]] || recv_refuse "send $1: not a dataset to receive into" ;;
    *) recv_refuse "send $1: no tool I know" ;;
  esac
  [[ $KEEP =~ ^[0-9]{1,4}$ && $RECURSIVE =~ ^[01]$ && $EXPIRES =~ ^[0-9]{1,11}$ && $PREFIX =~ ^([A-Za-z0-9_][A-Za-z0-9_.-]{0,39})?$ ]] || recv_refuse "send $1: its settings are not valid"
  ((EXPIRES == 0 || $(date +%s) < EXPIRES)) || recv_refuse "send $1 has ended: deploy it again"
}
recv_lock() { # -n or -w seconds, and what to say: one change at a time in a folder or dataset, whichever send asks. Two sends may share one
  ((RECV_LOCAL)) && return 0   # the plan or task holds its own lock, and no key is involved
  exec 7>"$LOCKS/sf-recv-$(printf '%s' "$ROOT" | sha256sum | cut -c1-16).lock" || recv_refuse "cannot open the lock"
  flock "$@" 7 || recv_refuse "another send is receiving into $ROOT"
}
recv_probe() {
  if [[ $TOOL == vm ]]; then command -v sha256sum >/dev/null && command -v dd >/dev/null || { echo "dd or sha256sum is missing on $(uname -n)" >&2; exit 3; }; echo "ok vm"; return 0; fi
  command -v "$TOOL" >/dev/null || { echo "$TOOL is not installed on $(uname -n)" >&2; exit 3; }
  if [[ $TOOL == btrfs ]]; then btrfs --version >/dev/null 2>&1; else zfs version >/dev/null 2>&1; fi || { echo "$TOOL does not run on $(uname -n)" >&2; exit 3; }
  echo "ok $TOOL"
}
recv_root() { # is the folder or dataset there yet?
  if [[ $TOOL == btrfs || $TOOL == vm ]]; then [[ -d $ROOT ]] && echo present || echo absent
  elif zfs list -H -o name -- "$ROOT" >/dev/null 2>&1; then echo present; else echo absent; fi
  return 0
}
recv_list() { # what is there: by name for btrfs, oldest first for ZFS. VM disks: the files a receive finished, by name
  local d n
  if [[ $TOOL == vm ]]; then
    shopt -s nullglob
    for d in "$ROOT"/.*.sf-sha256; do
      n=${d##*/}; n=${n#.}; n=${n%.sf-sha256}
      if recv_name_ok "$n" && [[ -f $ROOT/$n && ! -L $ROOT/$n ]]; then printf '%s\n' "$n"; fi
    done | sort
  elif [[ $TOOL == btrfs ]]; then
    shopt -s dotglob nullglob
    for d in "$ROOT"/*; do
      [[ -d $d && ! -L $d ]] || continue
      n=${d##*/}
      if recv_name_ok "$n"; then printf '%s\n' "$n"; fi
    done | sort
  else
    zfs list -H -t snapshot -o name -s creation -d 1 -- "$ROOT" 2>/dev/null | while IFS= read -r n; do
      n=${n#*@}
      if recv_name_ok "$n"; then printf '%s\n' "$n"; fi
    done
  fi
  return 0
}
recv_state() { # name -> done <what it came from> | partial | other | absent
  local n=$1 show id
  if [[ $TOOL == vm ]]; then     # a disk: finished once its checksum is beside it, as the receive writes it last
    if [[ -e $ROOT/.$n.sf-part ]]; then echo partial
    elif [[ -e $ROOT/$n || -L $ROOT/$n ]]; then
      id=$(cut -c1-64 "$ROOT/.$n.sf-sha256" 2>/dev/null) || id=
      if [[ -f $ROOT/$n && ! -L $ROOT/$n && $id =~ ^[0-9a-f]{64}$ ]]; then echo "done $id"; else echo other; fi
    else echo absent; fi
  elif [[ $TOOL == btrfs ]]; then
    [[ -e $ROOT/$n || -L $ROOT/$n ]] || { echo absent; return 0; }
    [[ -d $ROOT/$n && ! -L $ROOT/$n ]] && show=$(btrfs subvolume show -- "$ROOT/$n" 2>/dev/null) || { echo other; return 0; }
    id=$(awk '$1 == "Received" && $2 == "UUID:" { print $3; exit }' <<<"$show")
    if [[ $id =~ ^[0-9a-f][0-9a-f-]*$ ]]; then echo "done $id"; else echo partial; fi
  else
    id=$(zfs get -Hp -o value guid "$ROOT@$n" 2>/dev/null) || id=
    if [[ $id =~ ^[0-9]+$ ]]; then echo "done $id"; else echo absent; fi
  fi
  return 0
}
recv_drop() { # what a failed receive left: it never verified, and the next send must not build on it
  if [[ $TOOL == vm ]]; then rm -f -- "$ROOT/.$1.sf-part"
  elif [[ $TOOL == btrfs ]]; then
    if [[ -d $ROOT/$1 && ! -L $ROOT/$1 ]]; then btrfs subvolume delete -- "$ROOT/$1" >/dev/null 2>&1; fi
  elif zfs list -H -o name -t snapshot -- "$ROOT@$1" >/dev/null 2>&1; then zfs destroy -- "$ROOT@$1" >/dev/null 2>&1; fi
  return 0
}
recv_receive() { # nonce name, the stream on stdin. It only ever makes something new under the folder or dataset of the conf
  local nonce=$1 n=$2 started st err before extra x rc=0 msg=
  started=$(date +%s)
  recv_name_ok "$n" || recv_refuse "not a snapshot name" "$nonce"
  if ((!RECV_LOCAL)); then
    [[ $nonce =~ ^[0-9a-f]{32}$ ]] || recv_refuse "bad nonce"
    mkdir -p "$VAR/receive/$RID/seen" || recv_refuse "cannot write $VAR/receive/$RID"
    find "$VAR/receive/$RID/seen" -type f -mtime +30 -delete 2>/dev/null
    ( set -o noclobber; : >"$VAR/receive/$RID/seen/$nonce" ) 2>/dev/null || recv_refuse "this request was already used" "$nonce"   # atomic: one receive per nonce
    trap '' HUP      # a dropped connection is an end of stream: the tool fails on it, and this still cleans up and records why
  fi
  recv_lock -w 3600
  st=$(recv_state "$n")
  [[ $st == absent ]] || recv_refuse "$n is already there (${st%% *})" "$nonce"
  err=$(mktemp) || recv_refuse "no temporary file" "$nonce"
  before=$(recv_list)
  # -C: btrfs receive runs chrooted into the folder, so a path in the stream cannot leave it. ZFS: -x leaves mountpoint, sharenfs and sharesmb
  # to what the parent gives (a stream cannot mount itself over a folder or export itself), and -o sets setuid, devices and canmount here whatever
  # the stream says (no setuid file or device node works, and nothing mounts at boot: mount it by hand to look). Not lab-tested (SF-72).
  # btrfs: the files keep the owner, mode and setuid bits the stream carries; see docs/security.md for what that leaves.
  if [[ $TOOL == vm ]]; then
    # a disk image, written as a new file of its own and readable by root alone: it holds all a VM holds. dd conv=sparse keeps
    # runs of zeros as holes, and the checksum is of what arrived, for the sender to hold against what it sent
    if mkdir -p -- "$ROOT" >"$err" 2>&1 && ( umask 077; set -o noclobber; : >"$ROOT/.$n.sf-part" ) 2>>"$err"; then
      dd of="$ROOT/.$n.sf-part" bs=1M conv=sparse,notrunc status=none 2>>"$err"; rc=$?
      if ((rc == 0)); then
        x=$(sha256sum <"$ROOT/.$n.sf-part" | cut -c1-64) && [[ ! -e $ROOT/$n && ! -L $ROOT/$n ]] && mv -n -- "$ROOT/.$n.sf-part" "$ROOT/$n" \
          && ( umask 077; printf '%s\n' "$x" >"$ROOT/.$n.sf-sha256" ) || rc=5
      fi
    else rc=5; fi
  elif [[ $TOOL == btrfs ]]; then
    mkdir -p -- "$ROOT" >"$err" 2>&1 && btrfs receive -C "$ROOT" >"$err" 2>&1; rc=$?
  else
    zfs receive -u -x mountpoint -x sharenfs -x sharesmb -o setuid=off -o devices=off -o canmount=noauto -- "$ROOT" >"$err" 2>&1; rc=$?
  fi
  cat "$err" >&2          # never hidden: a corrupt stream says so here, and over ssh on the sender
  msg=$(tail -n 3 "$err" | tr '\n' ' '); rm -f "$err"
  st=$(recv_state "$n")
  # names that were not there before: a stream can hold any number of subvolumes. A plain folder is not a stream's doing
  extra=
  while IFS= read -r x; do
    if [[ -n $x && $x != "$n" && $(recv_state "$x") != other ]]; then extra+="$x "; fi
  done < <(comm -13 <(printf '%s\n' "$before" | sort) <(recv_list | sort))
  if ((rc == 0)) && [[ $st != done\ * ]]; then rc=6; msg="the stream ended, but $n is not a finished copy here (${st%% *})"; fi
  if ((rc == 0)) && [[ -n $extra ]]; then rc=6; msg="the stream held more than $n, and what else it made is left for you to look at: ${extra:0:300}"; fi
  if ((rc)); then
    recv_drop "$n"     # absent before, and under the lock: this is what this receive made, and nothing else is
    printf 'storageforge-job: the receive of %s failed (exit %d): %s\n' "$n" "$rc" "$msg" >&2
  fi
  recv_record receive "$nonce" "$n" "$rc" "$started" "${msg:-received}"
  ((rc)) && exit "$rc"
  echo "received $n ${st#done }"
}
recv_discard() { # name: an unfinished copy an interrupted receive left. A finished one is refused: only retention removes those
  local n=$1 st started rc=0
  started=$(date +%s)
  recv_name_ok "$n" || recv_refuse "not a snapshot name"
  [[ $TOOL == btrfs || $TOOL == vm ]] || recv_refuse "a ZFS receive that was cut off leaves nothing to discard"
  recv_lock -n          # one being received right now also looks unfinished
  st=$(recv_state "$n")
  [[ $st == partial ]] || recv_refuse "$n is not an unfinished copy (${st%% *})"
  if [[ $TOOL == vm ]]; then rm -f -- "$ROOT/.$n.sf-part" || rc=$?; else btrfs subvolume delete -- "$ROOT/$n" >/dev/null || rc=$?; fi
  recv_record discard '' "$n" "$rc" "$started" "unfinished copy removed"
  exit "$rc"
}
recv_prune() { # [dry]: the newest KEEP stay. The conf says how many and which names: a sender cannot ask for more
  local dry=${1:-} n old=() rc=0 started gone=
  started=$(date +%s)
  [[ -z $dry || $dry == dry ]] || recv_refuse "prune takes only: dry"
  ((KEEP > 0)) && [[ -n $PREFIX ]] || recv_refuse "this send keeps everything: nothing may be pruned"
  [[ $dry == dry ]] || recv_lock -w 3600
  # only <prefix>-YYYY-MM-DD_HHMMSS: another send's daily-db-... or a hand-made daily-notes is never this send's to prune
  mapfile -t old < <(recv_list | while IFS= read -r n; do r=${n#"$PREFIX-"}; if [[ $n == "$PREFIX-"* && $r =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$ ]]; then printf '%s\n' "$n"; fi; done | head -n "-$KEEP")
  for n in ${old[@]+"${old[@]}"}; do
    if [[ $dry == dry ]]; then echo "would remove $n"; continue; fi
    if [[ $TOOL == vm ]]; then rm -f -- "$ROOT/$n" "$ROOT/.$n.sf-sha256" || { rc=$?; continue; }
    elif [[ $TOOL == btrfs ]]; then btrfs subvolume delete -- "$ROOT/$n" >/dev/null || { rc=$?; continue; }
    elif ((RECURSIVE)); then zfs destroy -r -- "$ROOT@$n" || { rc=$?; continue; }
    else zfs destroy -- "$ROOT@$n" || { rc=$?; continue; }; fi
    echo "removed $n"; gone+="$n "
  done
  if [[ $dry != dry && ( -n $gone || $rc != 0 ) ]]; then recv_record prune '' '' "$rc" "$started" "removed ${gone:-nothing}"; fi
  exit "$rc"
}
recv_verb() { # verb [word] [word]: only these, each with only what it takes
  local verb=$1 a=${2:-} b=${3:-}
  case $verb in
    recv-probe|recv-root|recv-list|recv-mkdir) [[ -z $a ]] || recv_refuse "$verb takes nothing" ;;
    recv-state|recv-discard) [[ -n $a && -z $b ]] || recv_refuse "$verb takes a snapshot name" ;;
    recv-receive) [[ -n $b ]] || recv_refuse "$verb takes a nonce and a snapshot name" ;;
    recv-prune) [[ -z $b ]] || recv_refuse "$verb takes at most: dry" ;;
    *) recv_refuse "not allowed: ${verb:0:40}" ;;
  esac
  case $verb in
    recv-probe) recv_probe ;;
    recv-root) recv_root ;;
    recv-list) recv_list ;;
    recv-state) recv_name_ok "$a" || recv_refuse "not a snapshot name"; recv_state "$a" ;;
    recv-mkdir) if [[ $TOOL == btrfs || $TOOL == vm ]]; then mkdir -p -- "$ROOT"; fi ;;
    recv-receive) recv_receive "$a" "$b" ;;
    recv-discard) recv_discard "$a" ;;
    recv-prune) recv_prune "$a" ;;
  esac
}
recv_serve() { # id "ssh command": the whole line is checked before it is split, so nothing past this point can hold what a shell treats as special
  local re='^recv-[a-z]+( [A-Za-z0-9_.:+-]{1,128}){0,2}$' verb= a= b=
  recv_load "$1"
  [[ ${2:-} =~ $re ]] || recv_refuse "not allowed: $(printf '%s' "${2:0:80}" | tr -cd '[:alnum:] ._:+/=@-')"
  read -r verb a b <<<"$2"
  recv_verb "$verb" "$a" "$b"
}
"""

# A send's other side, for the scripts on the sending host (needs RECEIVE_KIT). On this host the verbs run here. On another each is one line
# over this send's own key, which that host's forced command takes and nothing else; the host key is the one StorageForge pinned.
SEND_KIT = r"""SENDS=/etc/storageforge/sends
S_TOOL= S_ID=local S_ADDR= S_PORT=22 S_ROOT= S_PREFIX= S_KEEP=0 S_REC=0
send_to() { S_TOOL=$1 S_ID=$2 S_ADDR=$3 S_PORT=$4 S_ROOT=$5 S_PREFIX=${6:-} S_KEEP=${7:-0} S_REC=${8:-0}; }
there_ssh() { # one line. The forced command over there checks it, runs it, and can run nothing else
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=4 -o IdentitiesOnly=yes -i "$SENDS/$S_ID.key" -p "$S_PORT" \
    -o HostKeyAlias=storageforge-source -o "UserKnownHostsFile=$SENDS/$S_ID.hostkey" -o StrictHostKeyChecking=yes -- "storageforge-deploy@$S_ADDR" "$1"
}
there() { # verb [word...]. Only a receive takes what is on stdin
  if [[ $S_ID == local ]]; then
    ( RECV_LOCAL=1 RID=local TOOL=$S_TOOL ROOT=$S_ROOT PREFIX=$S_PREFIX KEEP=$S_KEEP RECURSIVE=$S_REC; recv_verb "$@" )
  elif [[ $1 == recv-receive ]]; then there_ssh "$*"
  else there_ssh "$*" </dev/null; fi
}
there_name() { if [[ $S_ID == local ]]; then echo "this host"; else echo "$S_ADDR"; fi; }
send_state() { # can this send reach its other side from here? There is no root key to fall back on
  [[ $S_ID == local ]] && { echo ready; return; }
  [[ $S_ID == none ]] && { echo "not-enrolled"; return; }
  [[ -r $SENDS/$S_ID.key && -s $SENDS/$S_ID.hostkey ]] && echo ready || echo no-key
}
NOT_ENROLLED='is not enrolled, and a send reaches only an enrolled host: there is no unsigned way. Set up deploy access on it (Deploy tab), check the plan again and deploy'
NO_KEY='this send has no job key on this host yet. It comes with a deploy from StorageForge: a script run by hand cannot reach the other host'
send_nonce() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }
send_why() { printf '%s' "$1" | tail -c 300 | tr '\n' ' '; }    # the end of what ssh or the other side said: where the reason is
send_id_btrfs() { # snapshot -> what the Received UUID of its copy will say: what it came from, if it was received itself, or else its own UUID
  local show id
  show=$(btrfs subvolume show -- "$1" 2>/dev/null) || return 0
  id=$(awk '$1 == "Received" && $2 == "UUID:" { print $3; exit }' <<<"$show")
  [[ $id =~ ^[0-9a-f][0-9a-f-]*$ ]] || id=$(awk '$1 == "UUID:" { print $2; exit }' <<<"$show")
  printf '%s' "$id"
}
send_id_zfs() { zfs get -Hp -o value guid "$1" 2>/dev/null || true; }
send_stream() { # name what-it-should-be-on-the-other-side stream-command...: true only when both ends finished and the copy there is this snapshot
  local name=$1 want=$2 got rc id
  shift 2
  got=$(set -o pipefail; "$@" | there recv-receive "$(send_nonce)" "$name"); rc=$?
  if ((rc)); then echo "the stream did not finish: exit $rc from one of its ends, whatever it says above" >&2; return "$rc"; fi
  [[ $got == "received $name "* ]] || { echo "the other side did not say it finished: ${got:0:200}" >&2; return 7; }
  id=${got##* }
  if [[ -n $want && $id != "$want" ]]; then echo "$name arrived, but it is not this snapshot (sent $want, there $id)" >&2; return 7; fi
}
"""

# Needs ARGS (the original arguments) and HOST set by the caller's option parsing; FWD_AGENT=1 with --forward-agent.
REMOTE = r"""# ── remote: copy this script over, run it there with sudo, clean up (like storage-setup.sh --host) ──
if [[ -n $HOST ]]; then
  [[ $HOST == -* ]] && { echo "--host: not a host name: $HOST" >&2; exit 2; }
  CTL=$(mktemp -d); trap 'ssh -o ControlPath="$CTL/s" -O exit "$HOST" 2>/dev/null; rm -rf "$CTL"' EXIT
  SSHO=(-o ControlMaster=auto -o ControlPath="$CTL/s" -o ControlPersist=60 -o ConnectTimeout=10)
  REST=(); skipnext=0
  for a in "${ARGS[@]}"; do if ((skipnext)); then skipnext=0; continue; fi; if [[ $a == --host ]]; then skipnext=1; continue; fi; REST+=("$a"); done
  # Your SSH agent is forwarded only with --forward-agent: while it runs, root on that host can use it to log in
  # wherever your keys work. A step that pulls from a third host needs it (or a key on that host). The first ssh opens
  # the shared connection, and a session over it gets the agent only if that connection was opened with it
  FWD=(); ((${FWD_AGENT:-0})) && FWD=(-A)
  tmp=$(ssh "${SSHO[@]}" ${FWD[@]+"${FWD[@]}"} -- "$HOST" 'mktemp -d /tmp/sf-move.XXXXXX')
  scp -q -o ControlPath="$CTL/s" -- "$0" "$HOST:$tmp/move.sh"
  # ssh hands the remote side one command line, which its shell splits again: every argument goes quoted
  qtmp=$(printf %q "$tmp") qrest=; ((${#REST[@]})) && printf -v qrest ' %q' "${REST[@]}"
  ssh "${SSHO[@]}" ${FWD[@]+"${FWD[@]}"} -t -- "$HOST" "cd $qtmp && if [ \$(id -u) = 0 ]; then bash ./move.sh$qrest; else sudo --preserve-env=SSH_AUTH_SOCK bash ./move.sh$qrest; fi; rc=\$?; rm -rf $qtmp; exit \$rc"
  exit $?
fi
"""


# what deploys need on a host: the program that shows it is there, and its package per package manager
NEEDS = {'NFS server': ('exportfs', {'apt-get': 'nfs-kernel-server', 'dnf': 'nfs-utils', 'yum': 'nfs-utils', 'pacman': 'nfs-utils', 'zypper': 'nfs-kernel-server'}),
         'Samba': ('smbd', {'apt-get': 'samba', 'dnf': 'samba', 'yum': 'samba', 'pacman': 'samba', 'zypper': 'samba'}),
         'NFS client': ('mount.nfs', {'apt-get': 'nfs-common', 'dnf': 'nfs-utils', 'yum': 'nfs-utils', 'pacman': 'nfs-utils', 'zypper': 'nfs-client'}),
         'SMB client': ('mount.cifs', {'apt-get': 'cifs-utils', 'dnf': 'cifs-utils', 'yum': 'cifs-utils', 'pacman': 'cifs-utils', 'zypper': 'cifs-utils'}),
         'rsync': ('rsync', {'apt-get': 'rsync', 'dnf': 'rsync', 'yum': 'rsync', 'pacman': 'rsync', 'zypper': 'rsync'}),
         'rsnapshot': ('rsnapshot', {'apt-get': 'rsnapshot', 'dnf': 'rsnapshot', 'yum': 'rsnapshot', 'pacman': 'rsnapshot', 'zypper': 'rsnapshot'}),
         'git': ('git', {'apt-get': 'git', 'dnf': 'git', 'yum': 'git', 'pacman': 'git', 'zypper': 'git'}),
         'python3': ('python3', {'apt-get': 'python3', 'dnf': 'python3', 'yum': 'python3', 'pacman': 'python', 'zypper': 'python3'}),
         'duperemove': ('duperemove', {'apt-get': 'duperemove', 'dnf': 'duperemove', 'yum': 'duperemove', 'pacman': 'duperemove', 'zypper': 'duperemove'}),
         'snapper': ('snapper', {'apt-get': 'snapper', 'dnf': 'snapper', 'yum': 'snapper', 'pacman': 'snapper', 'zypper': 'snapper'}),
         'btrfs-progs': ('btrfs', {'apt-get': 'btrfs-progs', 'dnf': 'btrfs-progs', 'yum': 'btrfs-progs', 'pacman': 'btrfs-progs', 'zypper': 'btrfsprogs'}),
         'auditd': ('auditctl', {'apt-get': 'auditd', 'dnf': 'audit', 'yum': 'audit', 'pacman': 'audit', 'zypper': 'audit'}),
         'aide': ('aide', {'apt-get': 'aide', 'dnf': 'aide', 'yum': 'aide', 'pacman': 'aide', 'zypper': 'aide'}),
         'lynis': ('lynis', {'apt-get': 'lynis', 'dnf': 'lynis', 'yum': 'lynis', 'pacman': 'lynis', 'zypper': 'lynis'}),
         'nftables': ('nft', {'apt-get': 'nftables', 'dnf': 'nftables', 'yum': 'nftables', 'pacman': 'nftables', 'zypper': 'nftables'}),
         'yara': ('yara', {'apt-get': 'yara', 'dnf': 'yara', 'yum': 'yara', 'pacman': 'yara', 'zypper': 'yara'}),
         'chrony': ('chronyc', {'apt-get': 'chrony', 'dnf': 'chrony', 'yum': 'chrony', 'pacman': 'chrony', 'zypper': 'chrony'}),
         'inotify-tools': ('inotifywait', {'apt-get': 'inotify-tools', 'dnf': 'inotify-tools', 'yum': 'inotify-tools', 'pacman': 'inotify-tools', 'zypper': 'inotify-tools'})}


def package_check(conn: Conn, h: dict, what: str) -> tuple[str, str]:
    """From the host's last scan: is this installed, and if not, what would a deploy install with what?"""
    inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']})) or {}
    text = inv.get('packages')
    if not text:
        return 'note', f'rescan {h["name"]} to see whether it needs the {what} installed'
    words = [line.split(None, 1) for line in text.splitlines() if ' ' in line]
    have = {v for k, v in words if k == 'have'}
    manager = next((v for k, v in words if k == 'pm'), None)
    cmd, packages = NEEDS[what]
    if cmd in have:
        return 'ok', f'{what} is installed on {h["name"]}'
    if manager not in packages:
        return 'crit', (f'{what} is not installed on {h["name"]}, and it has no package manager StorageForge knows '
                        f'(apt, dnf, yum, zypper, pacman): install it by hand and rescan')
    epel = ' (from EPEL, which it enables if it has to)' if what == 'rsnapshot' and manager in ('dnf', 'yum') else ''
    return 'note', f'{what} is not installed on {h["name"]}: the deploy installs {packages[manager]} with {manager}{epel}'


def need_line(what: str) -> str:
    """The script line that checks for this and, on --apply, installs it. The script needs PACKAGES."""
    cmd, p = NEEDS[what]
    return f'need_cmd {cmd} "{what}" {p["apt-get"]} {p["dnf"]} {p["pacman"]} {p["zypper"]}\n'


# Needs APPLY and the HELPERS. The host decides when the script runs: the scan only predicts it.
PACKAGES = r"""pm() { for m in apt-get dnf yum zypper pacman; do command -v $m >/dev/null && { echo $m; return; }; done; echo none; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq "$1" 2>&1; }
install_pkg() { # manager package
  case $1 in
    apt-get) apt_install "$2" || { apt-get -o DPkg::Lock::Timeout=120 update -qq 2>&1 && apt_install "$2"; } ;;   # the package lists may be stale
    dnf|yum) "$1" install -y -q "$2" 2>&1 && return 0
      # some packages only come from EPEL on RHEL and its rebuilds. Rocky and Alma carry epel-release in their own repos.
      case $2 in rsnapshot|lynis|yara|inotify-tools|clamav) ;; *) return 1 ;; esac
      "$1" install -y -q epel-release 2>&1 && "$1" install -y -q "$2" 2>&1 ;;
    zypper) zypper -nq install "$2" 2>&1 ;;
    pacman) pacman -S --needed --noconfirm "$2" 2>&1 || { echo "(the pacman package lists may be out of date: run pacman -Syu on the host, reboot if the kernel changed, then deploy again)"; return 1; } ;;   # no -Sy: refreshing without upgrading is a partial upgrade
  esac
}
need_cmd() { # command what apt rpm arch suse
  if command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  local m pkg out; m=$(pm)
  case $m in apt-get) pkg=$3 ;; dnf|yum) pkg=$4 ;; pacman) pkg=$5 ;; zypper) pkg=$6 ;;
    *) conflict "$2 is missing and this host has no package manager I know (apt, dnf, yum, zypper, pacman): install it yourself"; return 1 ;;
  esac
  if ((!APPLY)); then missing "$2 (would install $pkg with $m)"; return 0; fi
  doing "install $2: $pkg with $m"
  if out=$(install_pkg "$m" "$pkg") && command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  out=$(tail -n 3 <<<"$out" | tr '\n' ' ')
  conflict "could not install $pkg with $m: ${out:-it stopped without saying why; if the host is short of memory, it may have been killed (dmesg)}"; return 1
}
"""

# Needs PACKAGES
CIFS_KERNEL = r"""cifs_kernel() { # the mount needs cifs and, for iocharset=utf8, nls_utf8. Cloud images keep them in another package
  command -v modprobe >/dev/null || return 0
  if modprobe -n cifs 2>/dev/null && modprobe -n nls_utf8 2>/dev/null; then ok "kernel has cifs and nls_utf8"; return 0; fi
  local m pkg pkgs=() kernel; m=$(pm); kernel=$(uname -r)
  case $m in
    apt-get) pkgs=("linux-modules-extra-$kernel") ;;
    dnf|yum) pkgs=("kernel-modules-$kernel" "kernel-modules-extra-$kernel") ;;
    zypper) pkgs=(kernel-default-optional) ;;
    *) conflict "kernel $kernel has no cifs or nls_utf8, and no package I know has them here: install it yourself"; return 1 ;;
  esac
  if ((!APPLY)); then missing "kernel modules cifs and nls_utf8 (would install ${pkgs[*]} with $m)"; return 0; fi
  for pkg in "${pkgs[@]}"; do
    doing "install kernel modules: $pkg with $m"
    install_pkg "$m" "$pkg" >/dev/null 2>&1 || true
    if modprobe -n cifs 2>/dev/null && modprobe -n nls_utf8 2>/dev/null; then ok "kernel has cifs and nls_utf8"; return 0; fi
  done
  conflict "kernel $kernel still has no cifs or nls_utf8 after installing ${pkgs[*]}: if the host has a newer kernel waiting, reboot into it"; return 1
}
"""
