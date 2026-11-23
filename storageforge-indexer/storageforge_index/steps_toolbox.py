"""Toolbox installs as plan steps (roadmap section 4.1; toolbox.py, docs/toolbox.md).

tool-install       a catalog entry by one of its methods. The step holds the tool, the method, the SHA-256 of the entry it was staged
                   from, the SHA-256 of the host's override, and the exposure; everything else (the image, the Quadlet unit, the packages,
                   the binary and its hash) comes from the catalog when the script is written (toolbox.install_words), and only from an
                   entry that is still trusted and still the one staged. Otherwise the host is told why and nothing is done.
  container        rootless Podman: an account of its own (sf-<tool>, no shell), subordinate ids, lingering, and a Quadlet unit in its
                   home. Its folders under /srv/toolbox/<tool> belong to that account.
  quadlet          the same unit run by root's Podman, from /etc/containers/systemd.
  compose          a compose stack made from the entry (t_stack of steps_workloads.py), kept in /srv/toolbox/<tool>/compose.
  package          the distribution's packages, from the sources the host already has; units enabled; a socket bound to the address
                   the exposure says with a drop-in.
  binary           downloaded over HTTPS and checked by SHA-256. An optional tar.gz member is checked separately before install.
tool-remove        stops and takes away what the install made, from its record. Data folders stay, and the report lists them.
tool-data-remove   moves those folders into the host's trash. Destructive: type the tool's name again.

No apostrophes in the Bash below: the script text is checked for values that could end a quoted word.
"""
from __future__ import annotations

import shlex

from . import changes, steps_runtime, steps_workloads, toolbox
from .changes import F

INSTALL_ARGS = ('tool', 'method', 'sha', 'override', 'exposure', 'bind', 'allow_from')
REMOVE_ARGS = ('tool', 'method')
DATA_ARGS = ('tool', 'confirm')

BASH = r"""
# ── Toolbox installs (steps_toolbox.py) ─
tb_owned() { # folders owner: each folder made when missing, owned by owner when one is given
  local d
  for d in ${1//,/ }; do
    if [[ -d $d ]]; then ok "$d is there"; continue; fi
    act "make $d${2:+, owned by $2}" || continue
    install -d -m 0750 -- "$d" && { [[ -z $2 ]] || chown "$2:$2" -- "$d"; }
  done
  return 0
}
tb_account() { # account tool: the account that runs one rootless tool, with no shell
  if id -u "$1" >/dev/null 2>&1; then ok "the account $1 is there"; return 0; fi
  act "make the account $1, which runs $2 and nothing else (no shell, home @HOME@/$2)" || return 0
  try useradd --system --user-group --create-home --home-dir "@HOME@/$2" --shell /usr/sbin/nologin --comment "StorageForge Toolbox $2" "$1"
}
tb_podman_ok() { # Quadlet came with Podman 4.4
  local v maj min
  v=$(podman --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -n 1)
  maj=${v%%.*} min=${v#*.}
  [[ -n $v ]] && { ((maj > 4)) || ((maj == 4 && min >= 4)); }
}
tb_files() { # folder owner name=base64,...: the small files the entry gives its container, mounted read-only into it
  local dir=$1 owner=$2 item name f new
  TB_FILES_CHANGED=0
  [[ -n $dir && -n $3 ]] || return 0
  for item in ${3//,/ }; do
    name=${item%%=*} f=$dir/${item%%=*}
    [[ $name =~ ^[a-z][a-z0-9_.-]*$ ]] || { conflict "the file name $name is not one an entry may give"; continue; }
    new=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
    if ! printf "%s" "${item#*=}" | base64 -d >"$new" 2>/dev/null; then rm -f -- "$new"; conflict "the file $name of the entry could not be read"; continue; fi
    if [[ -f $f ]] && cmp -s "$new" "$f"; then ok "$f is the file this entry gives"
    elif act "write $f, which the container reads"; then
      install -d -m 0750 -- "$dir"; cp -f -- "$new" "$f"; chmod 0640 -- "$f"
      [[ -z $owner ]] || chown "$owner:$owner" -- "$dir" "$f"
      durable "$f"; TB_FILES_CHANGED=1
    fi
    rm -f -- "$new"
  done
  return 0
}
tb_container() { local tool=$1 rootless=$2 unit=$3 acct=$4 dirs=$5 ports=$6 image=$7 allow=$8 sock=${9:-} fdir=${10:-} files=${11:-}
  local file home new owner= svc=$1.service changed=0 sc
  if ! command -v podman >/dev/null; then later "podman is not installed: a runtime-install step before this one installs it"; return 0; fi
  if ! tb_podman_ok; then conflict "this Podman ($(podman --version 2>/dev/null)) has no Quadlet, which came with 4.4: use the compose method"; return 0; fi
  info "image $image"
  if ((rootless)); then
    tb_account "$acct" "$tool" || return 0
    rt_subids "$acct"; rt_linger "$acct"
    home=@HOME@/$tool owner=$acct
    file=$home/.config/containers/systemd/$tool.container
    sc=(systemctl --user -M "$acct@")
  else
    file=/etc/containers/systemd/$tool.container
    sc=(systemctl)
  fi
  tb_owned "$dirs" "$owner"
  if [[ -n $sock ]] && ((rootless)); then # a panel that runs containers: the Podman socket of its own account, never root
    if "${sc[@]}" is-active --quiet podman.socket 2>/dev/null; then ok "the Podman socket of $acct is on"
    elif act "switch on the Podman socket of $acct (podman.socket), which only that account and $tool reach"; then
      "${sc[@]}" enable --now podman.socket >/dev/null 2>&1 || { conflict "could not switch on podman.socket for $acct"; return 0; }
    fi
  fi
  tb_files "$fdir" "$owner" "$files"; changed=$TB_FILES_CHANGED
  new=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
  printf "%s" "$unit" >"$new"
  if [[ -f $file ]] && cmp -s "$new" "$file"; then ok "$file is the unit this entry makes"
  else
    if [[ -f $file ]]; then
      info "what changes in $file:"
      { diff -u "$file" "$new" || true; } | tail -n +3 | head -n 60 | while IFS= read -r line; do info "  $line"; done
    fi
    if act "write $file"; then
      mkdir -p -- "${file%/*}"
      [[ -z $owner ]] || chown -R "$owner:$owner" -- "$home/.config"
      cp -f -- "$new" "$file"; chmod 0644 -- "$file"
      [[ -z $owner ]] || chown "$owner:$owner" -- "$file"
      durable "$file"
      changed=1
    fi
  fi
  rm -f -- "$new"
  if ((!APPLY)); then
    if "${sc[@]}" is-active --quiet "$svc" 2>/dev/null; then ok "$svc is running"; else missing "would start $svc, pulling $image first"; fi
  elif ((!changed)) && "${sc[@]}" is-active --quiet "$svc" 2>/dev/null; then ok "$svc is running"
  else
    doing "start $svc (the first start pulls the image)"
    try "${sc[@]}" daemon-reload || return 0
    if ! "${sc[@]}" cat "$svc" >/dev/null 2>&1; then conflict "Quadlet made no $svc from $file: podman-system-generator --dryrun says why"; return 0; fi
    if "${sc[@]}" restart "$svc" && "${sc[@]}" is-active --quiet "$svc"; then ok "$svc is running"
    else conflict "$svc did not start: journalctl ${acct:+--user -M $acct@ }-u $svc says why"; return 0; fi
  fi
  if [[ -n $allow && -n $ports ]]; then
    if ((rootless)); then wl_fw tool "sf-$tool" input "$ports" "$allow"; else conflict "a container of root Podman publishes past the host firewall: bind it to one address instead"; fi
  fi
  return 0
}
tb_compose() { local tool=$1 runtime=$2 name=$3 compose=$4 dir=$5 override=$6 ports=$7 dirs=$8 allow=$9 owner=${10:-} fdir=${11:-} files=${12:-}
  tb_owned "$dirs" "$owner"
  tb_files "$fdir" "$owner" "$files"
  t_stack "$runtime" "$name" "$compose" "$dir" "" "$allow" "$override" "$ports" forward
}
tb_pkg_has() { # package: installed, as the package manager of this host says
  case $RT_PM in
    apt-get) dpkg-query -W -f="\${Status}" "$1" 2>/dev/null | grep -q "install ok installed" ;;
    dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
tb_list() { # apt dnf zypper pacman: the list for this host
  case $RT_PM in apt-get) echo "$1" ;; dnf|yum) echo "$2" ;; zypper) echo "$3" ;; pacman) echo "$4" ;; *) echo ;; esac
}
tb_package() { local tool=$1 apt=$2 dnf=$3 zypper=$4 pacman=$5 units=$6 sock=$7 listen=$8 port=$9
  local list p rc out want=() drop body u
  rt_os
  list=$(tb_list "$apt" "$dnf" "$zypper" "$pacman")
  [[ -n $list ]] || { conflict "$tool has no package for ${RT_ID:-this system} ($RT_PM): choose another method"; return 0; }
  for p in ${list//,/ }; do
    if tb_pkg_has "$p"; then ok "$p is installed"; else want+=("$p"); fi
  done
  if ((${#want[@]})); then
    for p in "${want[@]}"; do
      rc=0; rt_avail "$p" || rc=$?
      ((rc == 1)) && { conflict "$p is not in the package sources this host has: add the source that has it, or choose another method"; return 0; }
    done
    if act "install ${want[*]} with $RT_PM, from the sources this host already has"; then
      if [[ $RT_PM == apt-get ]] && ! rt_apt_lists; then apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1 || true; fi
      if ! out=$(rt_install "${want[@]}"); then conflict "could not install ${want[*]}: $(tail -n 3 <<<"$out" | tr "\n" " ")"; return 0; fi
      ok "installed ${want[*]}"
    fi
  fi
  if [[ -n $sock ]]; then
    drop=/etc/systemd/system/$sock.d/storageforge-listen.conf
    body=$(printf "[Socket]\nListenStream=\nListenStream=%s" "$listen")
    if [[ -f $drop && $(cat "$drop") == "$body" ]]; then ok "$sock listens on $listen only"
    elif act "make $sock listen on $listen only ($drop)"; then
      mkdir -p -- "${drop%/*}"; printf "%s\n" "$body" >"$drop"; durable "$drop"
      systemctl daemon-reload >/dev/null 2>&1 || true
      if systemctl is-active --quiet "$sock" 2>/dev/null; then try systemctl restart "$sock" || return 0; fi
    fi
  fi
  if [[ -n $units ]]; then
    for u in ${units//,/ }; do rt_enable "$u"; done
  fi
  return 0
}
tb_archive_member() {
  python3 - "$1" "$2" "$3" <<\PYARCHIVE
import gzip
import shutil
import sys
import tarfile

archive, member, destination = sys.argv[1:]
limit = 512 * 1024 * 1024

class Bounded:
    def __init__(self, source):
        self.source = source
        self.left = limit

    def read(self, size):
        data = self.source.read(min(size, self.left + 1))
        self.left -= len(data)
        if self.left < 0:
            raise ValueError("archive exceeds the uncompressed size limit")
        return data

try:
    with gzip.open(archive, "rb") as gzip_file, tarfile.open(fileobj=Bounded(gzip_file), mode="r|") as tar:
        found = False
        for item in tar:
            name = item.name[2:] if item.name.startswith("./") else item.name
            if name != member:
                continue
            if found or item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or item.issparse() or not 0 < item.size <= limit:
                raise ValueError("the selected member must be one nonempty regular file")
            with tar.extractfile(item) as source, open(destination, "wb") as output:
                shutil.copyfileobj(source, output)
            found = True
        if not found:
            raise ValueError("archive member was not found")
except (OSError, ValueError, EOFError, tarfile.TarError) as exc:
    sys.exit(str(exc))
PYARCHIVE
}
tb_binary() { local tool=$1 name=$2 u86=$3 s86=$4 uarm=$5 sarm=$6 url= sha= member= payload_sha= dest=/usr/local/bin/$2 tmp have payload verifier= sig= key= matches=0 sig_limit=16384
  case $(uname -m) in
    x86_64) url=$u86 sha=$s86 member=${7:-} payload_sha=${8:-$s86} verifier=${11:-} sig=${12:-} key=${13:-} ;;
    aarch64) url=$uarm sha=$sarm member=${9:-} payload_sha=${10:-$sarm} verifier=${14:-} sig=${15:-} key=${16:-} ;;
  esac
  [[ -n $url ]] || { conflict "$tool has no binary for $(uname -m)"; return 0; }
  if [[ -f $dest ]] && [[ $(sha256sum "$dest" | cut -c1-64) == "$payload_sha" ]]; then matches=1; fi
  if ((matches)) && [[ -z $verifier ]]; then ok "$dest is there, SHA-256 $payload_sha"; return 0; fi
  if ((!matches)) && [[ -e $dest && ! -e @HOME@/.binaries/$name ]]; then conflict "$dest is there and StorageForge did not put it there: it is left as it is"; return 0; fi
  if [[ -n $member ]] && ! command -v python3 >/dev/null; then conflict "python3 is needed to read the binary archive"; return 0; fi
  case $verifier in
    "") ;;
    cosign|minisign)
      command -v "$verifier" >/dev/null || { conflict "$verifier is needed to verify the publisher signature"; return 0; }
      info "verify the download against the catalog $verifier public key" ;;
    *) conflict "unknown publisher signature verifier"; return 0 ;;
  esac
  if ((matches)); then
    act "verify the publisher signature for $dest" || return 0
  else
    [[ -e $dest ]] && info "$dest is the one this tool installed before: it is replaced"
    act "download $url and install ${member:-it} as $dest, once the download SHA-256 is $sha" || return 0
  fi
  command -v curl >/dev/null || { conflict "curl is not installed"; return 0; }
  tmp=$(mktemp -d) || { conflict "could not make a temporary directory"; return 0; }
  payload=$tmp/download
  if ! curl -fsSL --proto =https --tlsv1.2 --retry 3 --max-filesize 536870912 -o "$payload" "$url"; then rm -rf -- "$tmp"; conflict "could not download $url"; return 0; fi
  have=$(sha256sum "$payload" | cut -c1-64)
  if [[ $have != "$sha" ]]; then rm -rf -- "$tmp"; conflict "$url has SHA-256 $have, not $sha: nothing was installed"; return 0; fi
  if [[ -n $verifier ]]; then
    [[ $verifier == cosign ]] && sig_limit=1048576
    if ! curl -fsSL --proto =https --tlsv1.2 --retry 3 --max-filesize "$sig_limit" -o "$tmp/signature" "$sig" ||
       [[ $(wc -c <"$tmp/signature") -gt $sig_limit ]]; then
      rm -rf -- "$tmp"; conflict "could not download the $verifier signature"; return 0
    fi
    local verified=0
    case $verifier in
      minisign)
        minisign -Vm "$payload" -x "$tmp/signature" -P "$key" -q >/dev/null 2>&1 && verified=1 ;;
      cosign)
        if printf "%s" "$key" >"$tmp/publisher.pub" &&
           cosign verify-blob --bundle "$tmp/signature" --key "$tmp/publisher.pub" "$payload" >/dev/null 2>&1; then
          verified=1
        fi ;;
    esac
    if ((!verified)); then
      rm -rf -- "$tmp"; conflict "the $verifier publisher signature did not verify"; return 0
    fi
    info "$verifier publisher signature verified"
  fi
  if [[ -n $member ]]; then
    if ! tb_archive_member "$payload" "$member" "$tmp/program"; then rm -rf -- "$tmp"; conflict "could not read archive member $member"; return 0; fi
    payload=$tmp/program
    have=$(sha256sum "$payload" | cut -c1-64)
    if [[ $have != "$payload_sha" ]]; then rm -rf -- "$tmp"; conflict "$member has SHA-256 $have, not $payload_sha: nothing was installed"; return 0; fi
  fi
  if ((matches)); then
    rm -rf -- "$tmp"
    ok "$dest is there, SHA-256 $payload_sha"
    return 0
  fi
  if ! install -d -m 0755 -- @HOME@/.binaries || ! install -m 0755 -- "$payload" "$dest"; then
    rm -rf -- "$tmp"; conflict "could not install $dest"; return 0
  fi
  rm -rf -- "$tmp"
  if ! : >"@HOME@/.binaries/$name"; then conflict "could not record ownership of $dest"; return 0; fi
  ok "$dest installed, SHA-256 $payload_sha"
}
tb_verify_images() { # image/key pairs from the catalog
  [[ -n ${1:-} ]] || return 0
  command -v cosign >/dev/null || { conflict "cosign is needed to verify the images before installation"; return 1; }
  local ref key repository digest pub
  while [[ -n ${1:-} ]]; do
    ref=$1 key=$2; shift 2
    if ((!APPLY)); then
      info "on apply, verify $ref with the catalog Cosign public key"
      continue
    fi
    # The catalog and runtime use tag@digest. Verify the same digest without its informational tag.
    repository=${ref%@sha256:*}
    digest=${ref##*@}
    pub=$(mktemp) || { conflict "could not make a temporary public key file"; return 1; }
    if ! printf "%s" "$key" >"$pub" ||
       ! cosign verify --key "$pub" "${repository%:*}@$digest" >/dev/null 2>&1; then
      rm -f -- "$pub"
      conflict "Cosign could not verify $ref with the catalog publisher key"
      return 1
    fi
    rm -f -- "$pub"
    ok "Cosign verified $ref"
  done
  return 0
}
t_tool_install() { local tool=$1 method=$2 sha=$3 ovr=$4 exposure=$5 bind=$6 allow=$7 verdict=$8 why=$9
  shift 9
  if [[ $verdict != ok ]]; then conflict "$why"; return 0; fi
  info "$why"
  info "exposure: ${exposure:-as the entry says}${bind:+, bound to $bind}${allow:+, reached only from $allow}"
  case $method in
    container|quadlet) tb_verify_images "${@:9}" || return 0 ;;
    compose) tb_verify_images "${@:11}" || return 0 ;;
  esac
  case $method in
    container) tb_container "$tool" 1 "$1" "$2" "$3" "$4" "$5" "$allow" "${6:-}" "${7:-}" "${8:-}" ;;
    quadlet) tb_container "$tool" 0 "$1" "$2" "$3" "$4" "$5" "$allow" "${6:-}" "${7:-}" "${8:-}" ;;
    compose) tb_compose "$tool" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$allow" "${8:-}" "${9:-}" "${10:-}" ;;
    package) tb_package "$tool" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" ;;
    binary) tb_binary "$tool" "$@" ;;
    *) conflict "$method is not an install method" ;;
  esac
  return 0
}

tb_kept() { # folders: said, never touched
  local d
  for d in ${1//,/ }; do [[ -e $d ]] && info "kept: $d"; done
  [[ -z $1 ]] || ok "its data stays: ${1//,/, }"
  return 0
}
tb_remove_container() { local tool=$1 acct=$2 unit=$3 quadlet=$4 keep=$5 sc=(systemctl)
  [[ -z $acct ]] || sc=(systemctl --user -M "$acct@")
  if [[ ! -e $quadlet ]]; then ok "$quadlet is not there"
  elif act "stop $unit and remove $quadlet"; then
    "${sc[@]}" stop "$unit" >/dev/null 2>&1 || true
    rm -f -- "$quadlet"
    "${sc[@]}" daemon-reload >/dev/null 2>&1 || true
    ok "$unit is stopped and its unit is gone"
  fi
  [[ -z $acct ]] || info "the account $acct stays, with its images: userdel -r $acct takes it and them away"
  tb_kept "$keep"
}
tb_remove_compose() { local tool=$1 runtime=$2 stack=$3 dir=$4 keep=$5
  if [[ ! -f $dir/compose.yaml ]]; then ok "there is no stack in $dir"
  elif ! wl_compose "$runtime"; then conflict "no compose for $runtime here to take $stack down"; return 0
  elif act "take stack $stack down (its volumes stay)"; then
    if (cd "$dir" && "${WL_C[@]}" -p "$stack" -f compose.yaml -f storageforge.yaml down >/dev/null 2>&1); then ok "stack $stack is down; its compose files stay in $dir"
    else conflict "compose down of $stack failed"; return 0; fi
  fi
  tb_kept "$keep"
}
tb_remove_package() { local tool=$1 apt=$2 dnf=$3 zypper=$4 pacman=$5 units=$6 sock=$7 keep=$8 list p u have=() drop
  rt_os
  for u in ${units//,/ }; do
    if systemctl is-enabled --quiet "$u" 2>/dev/null || systemctl is-active --quiet "$u" 2>/dev/null; then
      act "systemctl disable --now $u" && { systemctl disable --now "$u" >/dev/null 2>&1 || true; }
    else ok "$u is not running"; fi
  done
  if [[ -n $sock ]]; then
    drop=/etc/systemd/system/$sock.d/storageforge-listen.conf
    [[ -e $drop ]] && act "remove $drop" && { rm -f -- "$drop"; systemctl daemon-reload >/dev/null 2>&1 || true; }
  fi
  list=$(tb_list "$apt" "$dnf" "$zypper" "$pacman")
  for p in ${list//,/ }; do tb_pkg_has "$p" && have+=("$p"); done
  if ((!${#have[@]})); then ok "none of its packages is installed"
  elif act "remove ${have[*]} with $RT_PM (configuration files stay)"; then
    case $RT_PM in
      apt-get) try env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 remove -y -qq "${have[@]}" >/dev/null ;;
      dnf|yum) try "$RT_PM" remove -y -q "${have[@]}" >/dev/null ;;
      zypper) try zypper -n -q remove "${have[@]}" >/dev/null ;;
      pacman) try pacman -R --noconfirm "${have[@]}" >/dev/null ;;
    esac
  fi
  tb_kept "$keep"
}
tb_remove_binary() { local tool=$1 path=$2 keep=$3
  if [[ ! -e $path ]]; then ok "$path is not there"
  elif [[ ! -e @HOME@/.binaries/${path##*/} ]]; then conflict "$path is not one StorageForge installed: it is left as it is"; return 0
  elif act "remove $path"; then rm -f -- "$path" "@HOME@/.binaries/${path##*/}"; ok "$path is gone"; fi
  tb_kept "$keep"
}
t_tool_remove() { local tool=$1 method=$2 verdict=$3 why=$4
  shift 4
  if [[ $verdict != ok ]]; then conflict "$why"; return 0; fi
  info "$why"
  case $method in
    container|quadlet) tb_remove_container "$tool" "$1" "$2" "$3" "$4" ;;
    compose) tb_remove_compose "$tool" "$1" "$2" "$3" "$4" ;;
    package) tb_remove_package "$tool" "$1" "$2" "$3" "$4" "$5" "$6" "$7" ;;
    binary) tb_remove_binary "$tool" "$1" "$2" ;;
    *) conflict "$method is not an install method" ;;
  esac
  return 0
}
t_tool_data_remove() { local tool=$1 confirm=$2 verdict=$3 why=$4 dirs=$5 d
  if [[ $verdict != ok ]]; then conflict "$why"; return 0; fi
  [[ -n $dirs ]] || { ok "$tool kept no data folders"; return 0; }
  for d in ${dirs//,/ }; do t_trash "$d"; done
  return 0
}
""".replace('@HOME@', toolbox.TOOLS_HOME)


def _label(method: str) -> str:
    return {'container': 'rootless container', 'quadlet': 'Quadlet', 'compose': 'compose', 'package': 'packages', 'binary': 'binary'}.get(method, method)


def _install_extra(conn, t) -> list[str]:
    return toolbox.install_words(conn, t)


def _remove_extra(conn, t) -> list[str]:
    return toolbox.remove_words(conn, t)


def _data_extra(conn, t) -> list[str]:
    return toolbox.remove_words(conn, t, data=True)


def check_install(conn, c, h, p, say):
    words = toolbox.install_words(conn, {'host': h['name'], 'params': p})
    if words[0] != 'ok':
        say('crit', words[1])
        return
    say('ok', words[1])
    row = toolbox.find(conn, p['tool'])
    if row['lab'] != 'lab-tested':
        say('note', f'{row["name"]} is not lab-tested')
    for r in toolbox.risks(row['entry'], p['method'], p.get('exposure') or None):
        say('warn', f'risk: {r["title"]}: {r["means"]}. {r["mitigation"]}')
    if p['method'] == 'container':
        say('note', f'runs rootless under the account {toolbox.account_of(p["tool"])}, made for it, with no shell')
    say('note', 'the report shows the unit, packages or file before anything changes; removing the tool later keeps its data')


def check_remove(conn, c, h, p, say):
    words = toolbox.remove_words(conn, {'host': h['name'], 'params': p})
    if words[0] != 'ok':
        say('crit', words[1])
        return
    kept = (toolbox.install_of(conn, h['name'], p['tool']) or {}).get('params', {}).get('data') or []
    say('ok', words[1])
    say('note', ('its data stays: ' + ', '.join(kept)) if kept else 'it kept no data folders')


def check_data_remove(conn, c, h, p, say):
    words = toolbox.remove_words(conn, {'host': h['name'], 'params': p}, data=True)
    if words[0] != 'ok':
        say('crit', words[1])
        return
    say('warn', f'moves {words[2] or "nothing"} into the host trash: the tool loses what it kept. Back it up first if you may want it again')


ANSIBLE_HEAD = steps_workloads.ANSIBLE_HEAD + 'DESTRUCTIVE=1; CUR_DESTRUCTIVE=1\nt_trash() { local d=/.storageforge-trash/$STAMP; mkdir -p "$d${1%/*}" && mv -- "$1" "$d$1" && echo "changed: $1 moved to $d$1"; }\n'


def _ansible(fn: str, args: tuple, extra):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        words = [str(p.get(a) or '') for a in args] + (extra(conn, t) if conn is not None else ['refused', 'written without the index'])
        body = ANSIBLE_HEAD + steps_runtime.BASH + steps_workloads.BASH + BASH
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': body + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


METHOD = F('method', 'choice', 'Method', options=list(toolbox.METHODS), required=True)
changes.register('tool-install', {'group': 'Toolbox', 'label': 'Install a tool from the catalog', 'fields': [
    F('tool', 'name', 'Tool', required=True, placeholder='uptime-kuma'), METHOD, F('sha', 'sha', 'SHA-256 of the entry', required=True),
    F('override', 'sha', 'SHA-256 of the override on this host'), F('exposure', 'choice', 'Exposure', options=['', *toolbox.EXPOSURES], default=''),
    F('bind', 'ipv4', 'Address to bind to (management exposure)'), F('allow_from', 'cidrs', 'Only these may reach it', placeholder='192.168.1.0/24')],
    'help': 'Staged from the Toolbox. What runs comes from the catalog entry when the script is written, and only from an entry that is still trusted '
            'and still the one staged: a step whose entry or override changed is refused on the host.'},
    INSTALL_ARGS, lambda p: f'Install {p["tool"]} ({_label(p["method"])})', check_install, _ansible('t_tool_install', INSTALL_ARGS, _install_extra),
    args_of=_install_extra)

changes.register('tool-remove', {'group': 'Toolbox', 'label': 'Remove a tool, keeping its data', 'fields': [
    F('tool', 'name', 'Tool', required=True), METHOD],
    'help': 'Stops it and takes away what its install made: the unit, the packages or the program. Its data folders stay, and the report lists them.'},
    REMOVE_ARGS, lambda p: f'Remove {p["tool"]}, keeping its data', check_remove, _ansible('t_tool_remove', REMOVE_ARGS, _remove_extra), args_of=_remove_extra)

changes.register('tool-data-remove', {'group': 'Toolbox', 'label': 'Move the data of a removed tool to the trash', 'destructive': True, 'confirm_of': 'tool', 'fields': [
    F('tool', 'name', 'Tool', required=True), F('confirm', 'confirm', 'Type the tool again to confirm', required=True)],
    'help': 'Moves each data folder the install made into the host trash. Run it only with --destructive.'},
    DATA_ARGS, lambda p: f'Move the data of {p["tool"]} to the trash', check_data_remove, _ansible('t_tool_data_remove', DATA_ARGS, _data_extra),
    args_of=_data_extra)

changes.EXTRA_BASH.append(BASH)

from . import steps_restoretest  # noqa: E402,F401  (restore tests of the backup entries: they use the Toolbox folders above)
from . import steps_offline  # noqa: E402,F401  (registry-mirror and apt-proxy steps for the offline entries)
