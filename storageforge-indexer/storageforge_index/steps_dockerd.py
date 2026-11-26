"""The Docker engine's settings as a plan step: daemon.json is merged, not replaced, and the data directory can move.

docker-daemon   data-root, log driver and options, live-restore, registry mirrors, storage driver. Empty means leave as it is.

The script reads the file, merges only the keys given with python3 (or jq when python3 is not there), asks dockerd to validate the result, backs the
old file up beside it, writes it and restarts docker. Moving the data directory stops docker first, copies with rsync, writes the file only then
and starts docker; when the copy fails the file is not touched and docker starts on the old directory, which is kept in every case.
"""
from __future__ import annotations

import re

from . import changes
from .changes import F

LOG_DRIVERS = ['', 'json-file', 'local', 'journald', 'syslog', 'none']
STORAGE_DRIVERS = ['', 'overlay2', 'btrfs', 'zfs', 'fuse-overlayfs']
SETTINGS = ('data_root', 'log_driver', 'log_max_size', 'log_max_file', 'live_restore', 'registry_mirrors', 'storage_driver')
ARGS = ('data_root', 'move_data', 'log_driver', 'log_max_size', 'log_max_file', 'live_restore', 'registry_mirrors', 'storage_driver')
SYSTEM_DIRS = ('/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr', '/var', '/var/lib')
NETWORK_FS = ('nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', '9p', 'sshfs', 'fuse.sshfs', 'ceph', 'glusterfs', 'fuse.glusterfs', 'afs', 'lustre')

# https URLs with no login in them (a login would reach the plan and daemon.json in the clear), separated by spaces
changes.CHECKS['dockersize'] = re.compile(r'[0-9]{1,9}[kmg]')
changes.CHECKS['httpsurls'] = re.compile(r'https://[A-Za-z0-9._~:/?#%+=&,-]{1,200}( +https://[A-Za-z0-9._~:/?#%+=&,-]{1,200}){0,9}')

# No apostrophes: the script text is checked for values that could end a quoted word. The functions read the locals of t_docker_daemon, as bash allows.
# The values reach python3 as environment words and jq as --arg words, never inside the program text.
BASH = r"""
# dd_merge BASE NEW SUMMARY: the wanted keys merged into the JSON object in BASE, written to NEW. SUMMARY gets a line for each key this changes, before and after
# with the secrets masked (with jq, the key only). Exit 3: BASE is not a JSON object (the reason is printed).
dd_merge() { local base=$1 new=$2 summary=$3 flt
  if [[ $DD_TOOL == python3 ]]; then
    DD_ROOT=$eff_root DD_LOGDRV=$logdrv DD_LOGSIZE=$logsize DD_LOGFILE=$logfile DD_LIVE=$live DD_MIRRORS=$mirrors DD_STOR=$stor python3 - "$base" "$new" "$summary" <<"PY"
import json, os, re, sys
@MASKRULE@
base, new, summary = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(base) as fh:
        doc = json.load(fh)
except ValueError as exc:
    print(str(exc)[:120])
    sys.exit(3)
if not isinstance(doc, dict):
    print("the top level is not an object")
    sys.exit(3)
orig = json.loads(json.dumps(doc))
env = os.environ
if env.get("DD_ROOT"):
    doc["data-root"] = env["DD_ROOT"]
if env.get("DD_LOGDRV"):
    doc["log-driver"] = env["DD_LOGDRV"]
if env.get("DD_LOGSIZE") or env.get("DD_LOGFILE"):
    opts = doc.get("log-opts")
    opts = dict(opts) if isinstance(opts, dict) else {}
    if env.get("DD_LOGSIZE"):
        opts["max-size"] = env["DD_LOGSIZE"]
    if env.get("DD_LOGFILE"):
        opts["max-file"] = env["DD_LOGFILE"]
    doc["log-opts"] = opts
if env.get("DD_LIVE"):
    doc["live-restore"] = env["DD_LIVE"] == "on"
if env.get("DD_MIRRORS"):
    doc["registry-mirrors"] = env["DD_MIRRORS"].split()
if env.get("DD_STOR"):
    doc["storage-driver"] = env["DD_STOR"]
with open(new, "w") as fh:
    # the same content in another layout is no change: the file is then kept as it is, and nothing restarts
    if doc == orig:
        fh.write(open(base).read())
    else:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
lines = []
for key in ("data-root", "log-driver", "log-opts", "live-restore", "registry-mirrors", "storage-driver"):
    if doc.get(key) != orig.get(key):
        was = json.dumps(_mask_known(key, orig[key])) if key in orig else "(not set)"
        lines.append("  %s: %s \u2192 %s" % (key, was, json.dumps(_mask_known(key, doc[key]))))
with open(summary, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n" if lines else "")
PY
  else
    jq -e "type == \"object\"" "$base" >/dev/null 2>&1 || { echo "not a JSON object"; return 3; }
    flt="(if \$root != \"\" then .[\"data-root\"] = \$root else . end)
      | (if \$ldrv != \"\" then .[\"log-driver\"] = \$ldrv else . end)
      | (if \$lsize != \"\" then .[\"log-opts\"] = ((.[\"log-opts\"] // {}) + {\"max-size\": \$lsize}) else . end)
      | (if \$lfile != \"\" then .[\"log-opts\"] = ((.[\"log-opts\"] // {}) + {\"max-file\": \$lfile}) else . end)
      | (if \$live == \"on\" then .[\"live-restore\"] = true elif \$live == \"off\" then .[\"live-restore\"] = false else . end)
      | (if \$mirrors != \"\" then .[\"registry-mirrors\"] = (\$mirrors | split(\" \") | map(select(. != \"\"))) else . end)
      | (if \$stor != \"\" then .[\"storage-driver\"] = \$stor else . end)"
    jq --arg root "$eff_root" --arg ldrv "$logdrv" --arg lsize "$logsize" --arg lfile "$logfile" --arg live "$live" --arg mirrors "$mirrors" --arg stor "$stor" \
      "$flt" "$base" >"$new" || return 3
    # the same content in another layout is no change: the file is then kept as it is, and nothing restarts
    if [[ $(jq -cS . "$base") == "$(jq -cS . "$new")" ]]; then cp -- "$base" "$new"
    else
      jq -rn --slurpfile a "$base" --slurpfile b "$new" "[\"data-root\", \"log-driver\", \"log-opts\", \"live-restore\", \"registry-mirrors\", \"storage-driver\"] | .[]
        | select(\$a[0][.] != \$b[0][.]) | \"  \" + . + \": changes (the value is not shown: python3 is not here)\"" >"$summary" || true
    fi
    return 0
  fi
}

# dd_why TEXT: the reason a helper failed, kept in a file because the helper may run in a subshell. The caller says it with dd_conflict, once docker is running again.
dd_why() { echo "$*" >"$tmp/why"; }
# dd_conflict TEXT: the temporary folder goes first, since conflict ends an Ansible run.
dd_conflict() { local m=$*; rm -rf -- "$tmp"; conflict "$m"; }
# dd_fail: dd_conflict with the reason a helper left in dd_why.
dd_fail() { dd_conflict "$(cat -- "$tmp/why" 2>/dev/null || echo "the step stopped")"; }

# dd_write NEW: NEW becomes daemon.json, the old file kept as daemon.json.storageforge-STAMP. Sets dd_bak to the backup, or empty when there was no file.
# It never calls conflict (that may end the run): on failure it returns 1 with the reason in dd_why, and the file is as it was.
dd_write() { local tmpf=$f.storageforge-new
  STAMP=${STAMP:-$(date +%Y%m%d-%H%M%S)}
  dd_bak=
  mkdir -p -- "$etc" || { dd_why "could not make $etc"; return 1; }
  if [[ -e $f ]]; then
    dd_bak=$f.storageforge-$STAMP
    cp -p -- "$f" "$dd_bak" || { dd_bak=; dd_why "could not back up $f"; return 1; }
    cp -p -- "$f" "$tmpf" && cat -- "$1" >"$tmpf" || { rm -f -- "$tmpf"; dd_why "could not write $tmpf"; return 1; }
  else
    install -m 0644 -- "$1" "$tmpf" || { dd_why "could not write $tmpf"; return 1; }
  fi
  mv -f -- "$tmpf" "$f" || { rm -f -- "$tmpf"; dd_why "could not replace $f"; return 1; }
  ok "wrote $f${dd_bak:+ (the old one is kept as $dd_bak)}"
}

# dd_undo: the file as it was before dd_write, when docker would not start with the new one.
dd_undo() {
  if [[ -n ${dd_bak:-} ]]; then cp -p -- "$dd_bak" "$f"; else rm -f -- "$f"; fi
}

# dd_expect LABEL FORMAT WANT: docker info agrees with what was asked.
dd_expect() { local got
  [[ -n $3 ]] || return 0
  got=$(docker info --format "$2" 2>/dev/null </dev/null) || got=
  if [[ ${got%/} == "${3%/}" ]]; then ok "docker reports $1 $3"; else dd_conflict "docker reports $1 ${got:-nothing}, not $3"; return 1; fi
}

# dd_back: waits for docker to answer, then says which of the containers that ran before are running again.
dd_back() { local i name now missing=
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    docker info >/dev/null 2>&1 </dev/null && break
    sleep 1
  done
  docker info >/dev/null 2>&1 </dev/null || { dd_conflict "docker does not answer after the restart: look at systemctl status docker"; return 1; }
  [[ -n $running ]] || return 0
  now=$(docker ps --format "{{.Names}}" 2>/dev/null </dev/null) || now=
  while IFS= read -r name; do
    [[ -n $name ]] && ! grep -qxF -- "$name" <<<"$now" && missing+=" $name"
  done <<<"$running"
  if [[ -z $missing ]]; then ok "all $nrun containers that were running are running again"
  else ok "containers not running again:$missing (no restart policy: start them by hand with docker start)"; fi
  return 0
}

# dd_move: docker stopped, the data copied, the file written, docker started. Runs in a subshell: its EXIT trap starts docker unless it was started here,
# so no failure and no conflict that ends an Ansible run can leave it stopped. Failures return 1 with the reason in dd_why; the caller says it.
dd_move() {
  started=0      # not local: the EXIT trap runs after this function has returned
  trap "((started)) || systemctl start docker >/dev/null 2>&1" EXIT
  systemctl stop docker.socket docker || { dd_why "docker did not stop: the data was not copied and daemon.json is unchanged"; return 1; }
  rsync -aHAX --numeric-ids --info=progress2 "$cur/" "$want/" </dev/null || { dd_why "rsync failed: daemon.json is unchanged and docker was started on $cur; $want holds what was copied, empty it before trying again"; return 1; }
  dd_write "$new" || return 1
  if systemctl start docker; then started=1
  else
    dd_undo
    dd_why "docker did not start with the new daemon.json: the old one is back (kept as ${dd_bak:-none}); the data is copied to $want"
    return 1
  fi
}

# dd_system PATH: true for the root and the folders the system itself lives in, whole paths only (/var/lib/docker2 is not one).
dd_system() { case $1 in @SYSDIRS@) return 0 ;; esac; return 1; }

# dd_walk PATH: PATH and every folder above it that exists must be owned by root and writable by no one else. The copy follows links minutes after the
# decision, and whoever can change a folder on the way can turn it into a link to /. Prints the first folder that is not, and returns 1.
# A user that is not root (the tests) has SF_DOCKER_UID for the owner, and SF_DOCKER_TRUST for the folder where the walk ends.
dd_walk() { local p=$1 owner=0 trust= st u m
  if ((EUID != 0)); then owner=${SF_DOCKER_UID:-0}; trust=${SF_DOCKER_TRUST:+$(readlink -m -- "$SF_DOCKER_TRUST")}; fi
  while :; do
    if [[ -e $p ]]; then
      st=$(stat -c "%u %a" -- "$p" 2>/dev/null) || st=
      u=${st%% *}; m=${st##* }
      if [[ -z $st || $u != "$owner" ]] || ((8#$m & 0022)); then echo "$p"; return 1; fi
    fi
    if [[ $p == / ]] || [[ -n $trust && $p == "$trust" ]]; then break; fi
    p=$(dirname -- "$p")
  done
  return 0
}

# dd_work: the whole step, reading and setting the locals of t_docker_daemon. tmp is its own temporary folder.
dd_work() { local base new cur eff_root want rwant d out vout help used avail par l hid drv_before= want_drv stopped=
  local dd_bak= moving=0 drift=0 changed=0
  want=${data_root%/}
  cur=$(docker info --format "{{.DockerRootDir}}" 2>/dev/null </dev/null) || cur=
  if [[ -z $cur ]]; then
    cur=/var/lib/docker
    info "docker did not answer as $(id -un): its data directory is taken as $cur"
  fi
  cur=${cur%/}
  # a plan from the Changes page or the API is not stopped by a crit of the check, so the script itself refuses a folder docker must not be pointed at.
  # Links are followed first: every decision below, the copy and the file use the resolved path, which is the folder that would really be used.
  if [[ -n $data_root ]]; then
    if [[ -z $want ]]; then dd_conflict "the data directory cannot be /"; return 0; fi
    if [[ $data_root != /* || "$want/" == *//* || "$want/" == */../* || "$want/" == */./* ]]; then
      dd_conflict "the data directory $data_root is not an absolute path without .., . or double slashes"; return 0
    fi
    rwant=$(readlink -m -- "$want") || rwant=
    if [[ -z $rwant || -L $rwant ]]; then dd_conflict "could not resolve $want"; return 0; fi
    # the folder itself or any link on the way to it may lead to the root or to a system folder
    par=$want
    while [[ $par != / && -n $par ]]; do
      if [[ -L $par ]]; then
        l=$(readlink -m -- "$par") || l=
        if dd_system "$l"; then dd_conflict "$want leads through $par to $l, a system folder: pick a folder of its own"; return 0; fi
      fi
      par=$(dirname -- "$par")
    done
    if dd_system "$want"; then dd_conflict "$want is a system folder: pick a folder of its own"; return 0; fi
    if dd_system "$rwant"; then
      if [[ $rwant == "$want" ]]; then dd_conflict "$want is a system folder: pick a folder of its own"
      else dd_conflict "$want resolves to $rwant, a system folder: pick a folder of its own"; fi
      return 0
    fi
    if [[ $rwant != "$want" ]]; then info "$want resolves to $rwant: that is the folder used"; fi
    want=$rwant
  fi
  l=$(readlink -m -- "$cur") && cur=$l
  # the current directory asked for again is no change: no key is written for it, so nothing restarts
  eff_root=$want
  [[ -n $want && $want == "$cur" ]] && eff_root=
  if [[ -n $want && $want != "$cur" ]]; then drift=1; [[ -n $move ]] && moving=1; fi
  if [[ -n $data_root ]]; then
    if ((drift)); then
      l=$(dd_walk "$want") || { dd_conflict "$l is writable by other users or not owned by root: pick a folder only root can change"; return 0; }
      case "$want/" in "$cur/"*) dd_conflict "$want is inside the current data directory $cur"; return 0 ;; esac
      case "$cur/" in "$want/"*) dd_conflict "the current data directory $cur is inside $want"; return 0 ;; esac
    fi
    if ((drift && !moving)) && [[ -e $want ]]; then
      [[ -d $want ]] || { dd_conflict "$want is not a folder"; return 0; }
      if [[ -n $(find "$want" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) && ! ( -d $want/image && ( -d $want/overlay2 || -d $want/containers || -e $want/engine-id ) ) ]]; then
        dd_conflict "$want is not empty and does not look like a Docker data directory (no image folder with overlay2, containers or engine-id beside it): pick an empty folder"; return 0
      fi
    fi
  fi
  if [[ -s $f ]]; then
    [[ -r $f ]] || { if ((APPLY)); then dd_conflict "$f is not readable"; else missing "$f was not readable as $(id -un): --apply, as root, reads it"; fi; return 0; }
    base=$f
  elif [[ -e $f && ! -r $f ]]; then
    dd_conflict "$f is not readable"; return 0
  else
    base=$tmp/empty.json; echo "{}" >"$base"
  fi
  new=$tmp/new.json
  out=$(dd_merge "$base" "$new" "$tmp/summary") && d=0 || d=$?
  if ((d)); then dd_conflict "$f is not valid JSON ($out): it is left as it is, fix it by hand"; return 0; fi
  if command -v cmp >/dev/null; then cmp -s -- "$base" "$new" || changed=1
  elif command -v diff >/dev/null; then diff -q -- "$base" "$new" >/dev/null 2>&1 || changed=1
  else changed=1; fi
  # only the keys this step sets, masked by the one rule that also masks the scan: the whole file may hold a token or a login
  if [[ -s $tmp/summary ]]; then
    while IFS= read -r l; do [[ -n $l ]] && info "$l"; done <"$tmp/summary"
  fi
  if ((!changed && !drift)); then ok "$f already holds these values"; return 0; fi
  if [[ -n $want && $want == "$cur" ]]; then info "$want is where docker keeps its data now: no move needed"; fi

  if command -v dockerd >/dev/null; then help=$(dockerd --help 2>&1 </dev/null) || true; else help=; fi
  if grep -q -- "--validate" <<<"$help"; then
    vout=$(dockerd --validate --config-file "$new" 2>&1 </dev/null) || { vout=$(tr "\n" " " <<<"$vout"); dd_conflict "dockerd rejects the new daemon.json: $vout" >&2; return 0; }
    ok "dockerd accepts the new daemon.json"
  else
    info "this Docker cannot validate a config; checked as JSON only"
  fi

  running=$(docker ps --format "{{.Names}}" 2>/dev/null </dev/null) || running=
  nrun=0; nopol=0
  while IFS= read -r l; do
    [[ -n $l ]] || continue
    nrun=$((nrun + 1))
    hid=$(docker inspect --format "{{.HostConfig.RestartPolicy.Name}}" "$l" 2>/dev/null </dev/null) || hid=
    [[ -z $hid || $hid == no ]] && nopol=$((nopol + 1))
  done <<<"$running"
  if ((nrun)); then
    info "$nrun containers are running; $nopol of them has no restart policy and stays stopped after docker is stopped or restarted, until it is started by hand"
  fi

  if ((moving)); then
    command -v rsync >/dev/null || { dd_conflict "rsync is not installed: it copies the data directory"; return 0; }
    [[ -d $cur ]] || { dd_conflict "the current data directory $cur is not a folder here"; return 0; }
    drv_before=$(docker info --format "{{.Driver}}" 2>/dev/null </dev/null) || drv_before=
    case $drv_before in zfs|btrfs) dd_conflict "docker uses the $drv_before storage driver: its data lives in datasets or subvolumes that rsync does not copy as they are, so this step does not move it"; return 0 ;; esac
    if [[ -e $want ]]; then
      [[ -d $want ]] || { dd_conflict "$want is not a folder"; return 0; }
      [[ -z $(find "$want" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]] || { dd_conflict "$want is not empty: move its content away first, or pick an empty folder"; return 0; }
    fi
    used=$(du -sx --block-size=1 -- "$cur" 2>/dev/null | cut -f1) || used=
    par=$want
    while [[ ! -d $par && $par != / ]]; do par=$(dirname -- "$par"); done
    avail=$(df --output=avail -B1 -- "$par" 2>/dev/null | tail -n 1 | tr -d " ") || avail=
    if [[ $used =~ ^[0-9]+$ && $avail =~ ^[0-9]+$ ]]; then
      if ((avail < used + used / 20)); then dd_conflict "no room: $cur holds $used bytes and $par has $avail free"; return 0; fi
      ok "room for $cur ($used bytes) in $par ($avail free)"
    else
      info "the room for $cur in $par could not be measured as $(id -un)"
    fi
  elif ((drift)); then
    info "data-root changes without the data: docker starts on an empty $want and does not see its images and containers until they are copied there"
  fi

  if ((moving)); then
    act "stop docker, copy $cur to $want, write $f and start docker again (the old folder is kept)" || return 0
    mkdir -p -- "$want" || { dd_conflict "could not make $want"; return 0; }
    # with live-restore the containers outlive docker: stopped here, or rsync copies live data and they keep running on the old folder
    if [[ $(docker info --format "{{.LiveRestoreEnabled}}" 2>/dev/null </dev/null) == true && $nrun -gt 0 ]]; then
      info "live-restore is on: stopping the $nrun running containers first ($(tr "\n" " " <<<"$running")), so that the copy is whole"
      while IFS= read -r l; do
        [[ -n $l ]] || continue
        if ! docker stop "$l" >/dev/null </dev/null; then
          if [[ -z $stopped ]]; then dd_conflict "could not stop the container $l: nothing was changed"
          else dd_conflict "could not stop the container $l: already stopped:$stopped, which stay stopped (start them with docker start); docker and daemon.json were not touched"; fi
          return 0
        fi
        stopped+=" $l"
      done <<<"$running"
    fi
    # the part with docker stopped runs in a subshell whose exit starts docker again, whatever ends it
    ( dd_move ) || { dd_fail; return 0; }
  else
    act "write $f, then restart docker" || return 0
    dd_write "$new" || { dd_fail; return 0; }
    if ! systemctl restart docker; then
      dd_undo; systemctl restart docker || true
      dd_conflict "docker did not restart with the new daemon.json: the old one is back"; return 0
    fi
  fi
  dd_back || return 0
  dd_expect "data directory" "{{.DockerRootDir}}" "$eff_root" || return 0
  dd_expect "log driver" "{{.LoggingDriver}}" "$logdrv" || return 0
  # a move that changed the driver would leave every image unseen, so the driver from before the move is expected too
  want_drv=$stor; ((moving)) && want_drv=${stor:-$drv_before}
  dd_expect "storage driver" "{{.Driver}}" "$want_drv" || return 0
  [[ -z $live ]] || dd_expect "live-restore" "{{.LiveRestoreEnabled}}" "$([[ $live == on ]] && echo true || echo false)" || return 0
  if ((moving)); then ok "moved to $want. The old folder $cur is kept: once the containers are checked, remove it as root with rm -rf $cur"; fi
  return 0
}

# t_docker_daemon DATA_ROOT MOVE_DATA LOG_DRIVER LOG_MAX_SIZE LOG_MAX_FILE LIVE_RESTORE REGISTRY_MIRRORS STORAGE_DRIVER
t_docker_daemon() { local data_root=$1 move=$2 logdrv=$3 logsize=$4 logfile=$5 live=$6 mirrors=$7 stor=$8
  local etc=/etc/docker f tmp ver bin running= nrun=0 nopol=0 DD_TOOL
  ((EUID != 0)) && etc=${SF_DOCKER_ETC:-$etc}
  f=$etc/daemon.json
  command -v docker >/dev/null || { conflict "docker is not on this host"; return 0; }
  bin=$(readlink -f -- "$(command -v docker)") || bin=
  if [[ $bin == */snap/* ]]; then conflict "docker here is a snap: its settings are under /var/snap/docker, which this step does not edit"; return 0; fi
  ver=$(docker --version 2>&1 </dev/null) || ver=
  if [[ ${ver,,} == *podman* ]]; then conflict "docker here is Podman: its settings are not in daemon.json, and this step does not change them"; return 0; fi
  if [[ $(docker info --format "{{.OperatingSystem}}" 2>/dev/null </dev/null) == *"Docker Desktop"* ]]; then conflict "this is Docker Desktop, which keeps its settings in its own app"; return 0; fi
  command -v systemctl >/dev/null || { conflict "this host does not use systemd; change daemon.json by hand"; return 0; }
  if command -v python3 >/dev/null; then DD_TOOL=python3
  elif command -v jq >/dev/null; then DD_TOOL=jq
  else conflict "neither python3 nor jq is here, and daemon.json is not edited by hand: install one of them"; return 0; fi
  tmp=$(mktemp -d) || { conflict "could not make a temporary folder"; return 0; }
  dd_work || true
  rm -rf -- "$tmp"
  return 0
}
"""


def _mask_rule() -> str:
    """The scan's masking functions as the text of the python helper, so that one rule decides what a secret is. The script holds no apostrophe."""
    import inspect
    from .runtimes import docker
    src = (f'SECRET_KEY = re.compile(r"{docker.SECRET_KEY.pattern}", re.I)\nURL_AUTH = re.compile(r"{docker.URL_AUTH.pattern}")\n\n\n'
           + inspect.getsource(docker._mask_mirror) + '\n\n' + inspect.getsource(docker._mask_known))
    return src.replace("'", '"').rstrip()


BASH = BASH.replace('@MASKRULE@', _mask_rule()).replace('@SYSDIRS@', '|'.join(SYSTEM_DIRS))


def _title(p):
    bits = [x for x in (p['data_root'] and f'data directory {p["data_root"]}', p['log_driver'] and f'log driver {p["log_driver"]}',
                        p['log_max_size'] and f'log size {p["log_max_size"]}', p['log_max_file'] and f'{p["log_max_file"]} log files',
                        p['live_restore'] and f'live-restore {p["live_restore"]}', p['registry_mirrors'] and 'registry mirrors',
                        p['storage_driver'] and f'storage driver {p["storage_driver"]}') if x]
    return 'Docker engine settings: ' + ', '.join(bits)


def _validate(p: dict, where: str):
    if not any(p.get(k) for k in SETTINGS):
        raise ValueError(f'{where}: set at least one engine setting')


def _check(conn, c, h, p, say):
    from .runtimes import docker
    view = next(iter(docker.listing(conn, h['name'])), None)
    engine = (view or {}).get('engine')
    if engine == 'podman':
        say('crit', f'{h["name"]} runs Podman: its storage is not in daemon.json, and this version only reads it. Change it by hand in storage.conf')
        return
    if not engine:
        say('note', f'Docker was not read on {h["name"]} yet: the script looks when it runs')
    st = (view or {}).get('engine_settings') or {}
    cur = (st.get('root_dir') or '').rstrip('/') or ('/var/lib/docker' if engine else '')
    if '/snap/' in cur + '/':
        say('crit', f'Docker on {h["name"]} is a snap (its data is in {cur}): its settings are not in /etc/docker/daemon.json')
        return
    want = (p.get('data_root') or '').rstrip('/')
    if want in SYSTEM_DIRS[1:]:
        say('crit', f'{want} is a system folder: pick a folder of its own (the check cannot follow links, the script resolves them when it runs)')
    if p.get('data_root') and p['data_root'] == '/':
        say('crit', 'the data directory cannot be /')
    elif want and cur and want == cur:
        say('note', f'{want} is where Docker keeps its data now: no move needed')
    elif want and cur:
        say('note', f'the script also checks that {want} and every folder above it is owned by root and writable by no one else, since the copy follows links')
        if want.startswith(cur + '/'):
            say('crit', f'{want} is inside the current data directory {cur}: the copy would copy into itself')
        elif cur.startswith(want + '/'):
            say('crit', f'the current data directory {cur} is inside {want}: the copy would copy into itself')
        where, fs = c.mount_at(want)
        if where == '/':
            say('warn', f'{want} is on the system disk (/): a full Docker folder fills the disk the system runs from')
        elif fs and fs.lower() in NETWORK_FS:
            say('warn', f'{want} is on a network filesystem ({fs}): Docker\'s overlay2 does not work on one, and every container waits on the network')
        if p.get('move_data') and st.get('storage_driver') in ('zfs', 'btrfs'):
            say('crit', f'Docker on {h["name"]} uses the {st["storage_driver"]} storage driver: its data is in datasets or subvolumes that rsync does not copy as they are, so this step does not move it')
        if p.get('move_data'):
            say('note', f'docker is stopped, {cur} is copied to {want} with rsync (it must be empty or absent, with room), daemon.json is written, docker starts; {cur} is kept')
        else:
            say('warn', f'without the data moved, Docker starts on an empty {want}: its images and containers are not seen there until copied')
    if p.get('log_max_file') and not 1 <= int(p['log_max_file']) <= 100:
        say('crit', 'the number of log files is 1 to 100')
    if p.get('log_driver') == 'none' and (p.get('log_max_size') or p.get('log_max_file')):
        say('crit', 'the log driver none keeps no logs: it takes no max-size or max-file')
    if p.get('storage_driver') and p['storage_driver'] != st.get('storage_driver'):
        say('warn', f'another storage driver does not read the images and containers of {st.get("storage_driver") or "the current one"}: they stay on disk, unseen')
    running = (view or {}).get('running') or 0
    if running:
        none = sum(1 for s in view['stacks'] for x in s['containers'] if x['state'] == 'running' and (x.get('restart') or 'no') == 'no')
        left = (f'{none} of them {"has" if none == 1 else "have"} no restart policy and stay{"s" if none == 1 else ""} stopped until started by hand '
                '(so does any with unless-stopped, when it was stopped by this step)')
        n = f'{running} running container{"s" if running != 1 else ""}'
        if want and cur and want != cur and p.get('move_data'):
            say('warn', f'moving the data stops its {n}, whatever live-restore says (they would keep running on the old folder otherwise); {left}')
        elif not st.get('live_restore'):
            say('warn', f'docker is stopped or restarted: its {n} stop (live-restore is off); {left}')


def _ansible(t):
    import shlex
    from .steps_proxmox import ANSIBLE_HEAD     # here, not at the top: changes.py imports both modules, and either may be the first
    p = t['params']
    words = [('1' if p.get(a) else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in ARGS]
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': ANSIBLE_HEAD + BASH + '\nt_docker_daemon ' + ' '.join(shlex.quote(w) for w in words) + '\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.VALIDATE['docker-daemon'] = _validate
changes.LONG_RUN['docker-daemon'] = lambda p: bool(p.get('data_root') and p.get('move_data'))
changes.register('docker-daemon', {'group': 'Workloads', 'label': 'Change the Docker engine settings', 'fields': [
    F('data_root', 'path', 'Data directory (empty: as it is)', placeholder='/srv/docker'),
    F('move_data', 'bool', 'Move the data there (docker is stopped for the copy)', default=True),
    F('log_driver', 'choice', 'Log driver', options=LOG_DRIVERS, default=''),
    F('log_max_size', 'dockersize', 'Log size per file (with json-file or local)', placeholder='10m'),
    F('log_max_file', 'number', 'Log files kept, 1 to 100', placeholder='3'),
    F('live_restore', 'choice', 'Live restore (containers keep running while docker restarts)', options=['', 'on', 'off'], default=''),
    F('registry_mirrors', 'httpsurls', 'Registry mirrors (https URLs, spaces between)', placeholder='https://mirror.example.com'),
    F('storage_driver', 'choice', 'Storage driver', options=STORAGE_DRIVERS, default='')],
    'help': 'Merges only the settings given into /etc/docker/daemon.json and keeps every other key; empty leaves a setting as it is. dockerd validates the result, the old file is kept beside it, '
            'and docker restarts: running containers without a restart policy stay stopped. A new data directory is copied with rsync while docker is stopped, and the old one is kept.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)
