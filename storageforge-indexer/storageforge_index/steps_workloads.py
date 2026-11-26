"""Workloads as plan steps (roadmap section 6): a compose stack, a plain LXC container and an Incus instance, each with its labels and
the firewall rule for what it publishes.

stack     a compose file, kept in a folder of its own (/srv/stacks/NAME by default) and brought up with docker compose, docker-compose,
          podman compose or podman-compose. Labels go in a second file beside it, storageforge.yaml, which compose merges in: the
          compose file stays as it was given. The report validates the file with compose itself, shows the diff against the file deployed
          before, the volumes it uses and whether the stack is up. A stack of that name run from another folder is a conflict.
lxc       a container from the LXC download template (images.linuxcontainers.org), always unprivileged: root gets subordinate ids if it
          has none. LXC has no labels of its own, so they are kept in storageforge.labels in the container folder.
incus     an Incus container or VM, its profiles checked and listed first, the image fingerprint said when the image server answers.
          Labels are user.* keys, and published ports are proxy devices.

The firewall rule: allow_from names who may reach the published ports, and nobody else can. Ports Docker or Podman publish are
forwarded, past the host INPUT chain, so the rule goes in DOCKER-USER (a deny for the port and an allow for each source, through
storageforge-fwrules as fw-rule writes them). A host without DOCKER-USER gets a conflict, not a rule that does nothing. Ports an Incus
proxy device or an LXC container on the host network listen on are fenced on input, as fw-fence fences a share. A container behind
lxcbr0 is not reachable from outside, and one bridged onto the LAN bypasses the host firewall: the report says so for each.

Every value reaches the script through the field checks and as a quoted word. The compose file is a value like any other, written by
printf into a file and never run; values that look like secrets in it are refused by the check (a vault secret and the secret-file step
give a service its secret through env_file instead).
"""
from __future__ import annotations

import ipaddress
import json
import re
import shlex

import yaml

from . import changes, pvenode
from .changes import F

LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}=[A-Za-z0-9_.:/@+-]{0,200}')
PROJECT = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}')
SECRETISH = re.compile(r'(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credentials?)$', re.I)
RESERVED_INCUS = ('user-data', 'vendor-data', 'meta-data', 'network-config')     # cloud-init reads these user.* keys
STACKS_DIR = '/srv/stacks'

STACK_ARGS = ('runtime', 'name', 'compose', 'dir', 'labels', 'allow_from')
LXC_ARGS = ('name', 'distro', 'release', 'arch', 'network', 'bridge', 'autostart', 'labels', 'ports', 'allow_from')
INCUS_ARGS = ('name', 'image', 'type', 'profiles', 'cpus', 'memory_mb', 'pool', 'network', 'publish', 'nesting', 'autostart', 'labels', 'allow_from')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
# ── stacks, LXC containers and Incus instances (steps_workloads.py) ─
wl_compose() { # runtime -> WL_C, the compose command for it; 1 when there is none
  WL_C=()
  if [[ $1 == docker ]]; then
    if docker compose version >/dev/null 2>&1; then WL_C=(docker compose)
    elif command -v docker-compose >/dev/null; then WL_C=(docker-compose); fi
  else
    if command -v podman-compose >/dev/null; then WL_C=(podman-compose)
    elif podman compose version >/dev/null 2>&1; then WL_C=(podman compose); fi
  fi
  ((${#WL_C[@]}))
}
wl_fw() { # what name hook ports allow: only the sources in allow reach the published ports
  local what=$1 name=$2 hook=$3 ports=$4 allow=$5 p port proto c id nums= r f need=()
  [[ -n $allow && -n $ports ]] || return 0
  fw_tool || return 0
  if [[ $hook == input ]]; then
    for p in ${ports//,/ }; do nums+=${nums:+,}${p%/*}; done
    fw_need_nft || return 0
    if "$FW" fence-has "wl-$name" "$nums" "$allow" -; then ok "only $allow reach ports $nums of $what $name"; return 0; fi
    act "let only $allow reach ports $nums of $what $name" || return 0
    if "$FW" fence-set "wl-$name" "$nums" "$allow" -; then ok "ports $nums of $name take only $allow"; else conflict "nft refused the fence of $name"; fi
    return 0
  fi
  if ! { command -v iptables >/dev/null && iptables -S DOCKER-USER >/dev/null 2>&1; }; then
    conflict "no DOCKER-USER chain here, so the ports $name publishes cannot be fenced: publish them on one address (127.0.0.1:8080:80) instead"
    return 0
  fi
  for p in ${ports//,/ }; do
    port=${p%/*}; proto=tcp; [[ $p == */* ]] && proto=${p#*/}
    id=$(fw_id deny "$proto" "$port" - - forward)
    "$FW" has "$id" deny "$proto" "$port" - - forward || need+=("$id deny $proto $port -")
    for c in ${allow//,/ }; do
      id=$(fw_id allow "$proto" "$port" "$c" - forward)
      "$FW" has "$id" allow "$proto" "$port" "$c" - forward || need+=("$id allow $proto $port $c")
    done
  done
  if ((!${#need[@]})); then ok "only $allow reach the ports $name publishes"; return 0; fi
  act "let only $allow reach ports $ports of $name, in DOCKER-USER" || return 0
  # each deny goes in before the allows for its port: the firewall inserts at the top, so they end above it
  for r in "${need[@]}"; do
    read -r -a f <<<"$r"
    "$FW" ensure "${f[0]}" "${f[1]}" "${f[2]}" "${f[3]}" "${f[4]}" - forward || { conflict "the firewall refused ${f[1]} ${f[2]}/${f[3]}"; return 0; }
  done
  ok "ports $ports of $name take only $allow"
}

t_stack() { local runtime=$1 name=$2 compose=$3 dir=${4:-@STACKS@/$2} labels=$5 allow=$6 override=$7 ports=$8 hook=${9:-forward}
  local new id wd same=0 n up verb=deploy
  command -v "$runtime" >/dev/null || { later "$runtime is not installed: add a runtime-install step before this one"; return 0; }
  wl_compose "$runtime" || { later "no compose for $runtime here: install the compose plugin, docker-compose or podman-compose"; return 0; }
  for id in $("$runtime" ps -aq --filter "label=com.docker.compose.project=$name" 2>/dev/null); do
    wd=$("$runtime" inspect -f "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}" "$id" 2>/dev/null) || continue
    if [[ -n $wd && $wd != "$dir" ]]; then conflict "a stack named $name runs from $wd, and this step keeps it in $dir: adopt that one, or choose another name"; return 0; fi
  done
  new=$(mktemp -d)
  printf "%s\n" "$compose" >"$new/compose.yaml"
  printf "%s\n" "$override" >"$new/storageforge.yaml"
  if ! "${WL_C[@]}" -f "$new/compose.yaml" -f "$new/storageforge.yaml" config -q 2>"$new/err"; then
    conflict "compose refuses this file: $(tr "\n" " " <"$new/err" | head -c 400)"; rm -rf "$new"; return 0
  fi
  info "labels: storageforge.managed=true, storageforge.stack=$name${labels:+, ${labels//,/, }}"
  info "volumes it uses: $("${WL_C[@]}" -f "$new/compose.yaml" -f "$new/storageforge.yaml" config --volumes 2>/dev/null | tr "\n" " " || true)"
  if [[ -f $dir/compose.yaml && -f $dir/storageforge.yaml ]] && cmp -s "$dir/compose.yaml" "$new/compose.yaml" && cmp -s "$dir/storageforge.yaml" "$new/storageforge.yaml"; then
    same=1; verb=start
  elif [[ -f $dir/compose.yaml ]]; then
    info "what changes in $dir/compose.yaml:"
    { diff -u "$dir/compose.yaml" "$new/compose.yaml" || true; } | tail -n +3 | head -n 80 | while IFS= read -r line; do info "  $line"; done
  else
    info "a new stack, kept in $dir"
  fi
  n=$("$runtime" ps -aq --filter "label=com.docker.compose.project=$name" 2>/dev/null | wc -l)
  up=$("$runtime" ps -q --filter "label=com.docker.compose.project=$name" --filter status=running 2>/dev/null | wc -l)
  if ((same && n > 0 && up == n)); then
    ok "stack $name is up, from this compose file"
  elif act "$verb stack $name with ${WL_C[*]}"; then
    install -d -m 0750 -- "$dir"
    if [[ -f $dir/compose.yaml ]] && ((!same)); then cp -f -- "$dir/compose.yaml" "$dir/compose.yaml.prev"; fi
    cp -f -- "$new/compose.yaml" "$new/storageforge.yaml" "$dir/"
    if (cd "$dir" && "${WL_C[@]}" -p "$name" -f compose.yaml -f storageforge.yaml up -d >"$new/up" 2>&1); then ok "stack $name is up"
    else conflict "compose up failed: $(tail -n 5 "$new/up" | tr "\n" " ")"; rm -rf "$new"; return 0; fi
  fi
  rm -rf "$new"
  wl_fw stack "$name" "$hook" "$ports" "$allow"
}

t_managed_workload_remove() { local runtime=$1 name=$2 ids id labels expected path
  if [[ $runtime == lxc ]]; then
    not_on_pve || return 0
    path=$(lxc-config lxc.lxcpath) && [[ $path == /* && -d $path && -x $path ]] || { conflict "cannot read the LXC container folder"; return 0; }
    if [[ ! -e $path/$name && ! -L $path/$name ]]; then ok "no LXC container named $name"; return 0; fi
    if [[ -L $path/$name || ! -f $path/$name/storageforge.made || -L $path/$name/storageforge.made ]]; then
      conflict "StorageForge did not make the LXC container $name"; return 0
    fi
    act "destroy LXC container $name and its root filesystem" || return 0
    try lxc-destroy -P "$path" -n "$name" -f && ok "destroyed LXC container $name"
    return 0
  fi
  ids=$("$runtime" ps -aq --no-trunc --filter "label=com.docker.compose.project=$name") || { conflict "cannot list $runtime containers"; return 0; }
  [[ -n $ids ]] || { ok "no containers in stack $name"; return 0; }
  expected="true:$name"
  local members=()
  while IFS= read -r id; do
    labels=$("$runtime" inspect -f "{{index .Config.Labels \"storageforge.managed\"}}:{{index .Config.Labels \"storageforge.stack\"}}" "$id") || { conflict "cannot inspect stack member $id"; return 0; }
    [[ $labels == "$expected" ]] || { conflict "stack $name includes a container StorageForge did not deploy"; return 0; }
    members+=("$id")
  done <<<"$ids"
  act "remove ${#members[@]} containers from stack $name, keeping its volumes and networks" || return 0
  try "$runtime" rm -f "${members[@]}" && ok "removed stack $name"
}

wl_lxc_rest() { # name dir labels network bridge ports allow: the labels file, and the firewall
  local l
  if ((APPLY)) && [[ -d $2 ]]; then
    { echo "storageforge.managed=true"; for l in ${3//,/ }; do echo "$l"; done; } >"$2/storageforge.labels.new"
    if ! cmp -s "$2/storageforge.labels.new" "$2/storageforge.labels" 2>/dev/null; then mv -f "$2/storageforge.labels.new" "$2/storageforge.labels"; ok "labels of $1: ${3:-none of your own}"
    else rm -f "$2/storageforge.labels.new"; fi
  fi
  case $4 in
    host) wl_fw "LXC container" "$1" input "$6" "$7" ;;
    bridge) [[ -n $7 ]] && info "bridged on $5: the host firewall does not see its traffic, so no rule here can fence it" ;;
    *) [[ -n $7 ]] && info "behind NAT on lxcbr0: nothing outside reaches it, so no rule is needed" ;;
  esac
  return 0
}
t_lxc() { local name=$1 distro=$2 release=$3 arch=${4:-amd64} network=$5 bridge=$6 autostart=$7 labels=$8 ports=$9 allow=${10}
  not_on_pve || return 0
  local root=${WL_ROOT:-} path dir state sub= gsub= conf b c how
  command -v lxc-create >/dev/null || { later "LXC is not installed: add a runtime-install step (lxc) before this one"; return 0; }
  path=$(lxc-config lxc.lxcpath 2>/dev/null || true); dir=${path:-/var/lib/lxc}/$name
  if lxc-info -n "$name" >/dev/null 2>&1; then
    [[ -e $dir/storageforge.made ]] || { conflict "a container named $name exists, and StorageForge did not make it: choose another name"; return 0; }
    state=$(lxc-info -n "$name" -sH 2>/dev/null || true)
    if [[ $state == RUNNING ]]; then ok "$name exists, made by StorageForge, and runs"
    elif act "start $name"; then try lxc-start -n "$name" && ok "$name started"; fi
    wl_lxc_rest "$name" "$dir" "$labels" "$network" "$bridge" "$ports" "$allow"
    return 0
  fi
  if [[ $network == bridge ]] && [[ ! -d $root/sys/class/net/$bridge/bridge ]]; then conflict "there is no bridge $bridge here"; return 0; fi
  sub=$(awk -F: -v u=root '$1 == u {print $2, $3; exit}' "$root/etc/subuid" 2>/dev/null || true)
  gsub=$(awk -F: -v u=root '$1 == u {print $2, $3; exit}' "$root/etc/subgid" 2>/dev/null || true)
  how="on lxcbr0, behind NAT"; [[ $network == bridge ]] && how="bridged on $bridge"; [[ $network == host ]] && how="on the host network"
  info "$name: $distro $release ($arch) from images.linuxcontainers.org, unprivileged, $how${autostart:+, started with the host}"
  [[ -n $sub && -n $gsub ]] || info "root has no subordinate ids: root:1000000:65536 is added to /etc/subuid and /etc/subgid"
  act "create LXC container $name" || { wl_lxc_rest "$name" "$dir" "$labels" "$network" "$bridge" "$ports" "$allow"; return 0; }
  if [[ -z $sub ]]; then echo "root:1000000:65536" >>"$root/etc/subuid"; sub="1000000 65536"; fi
  if [[ -z $gsub ]]; then echo "root:1000000:65536" >>"$root/etc/subgid"; gsub="1000000 65536"; fi
  conf=$(mktemp)
  {
    case $network in
      host) echo "lxc.net.0.type = none" ;;
      bridge) printf "lxc.net.0.type = veth\nlxc.net.0.link = %s\nlxc.net.0.flags = up\n" "$bridge" ;;
      *) if [[ -r $root/etc/lxc/default.conf ]]; then echo "lxc.include = /etc/lxc/default.conf"
         else printf "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n"; fi ;;
    esac
    read -r b c <<<"$sub"; echo "lxc.idmap = u 0 $b $c"
    read -r b c <<<"$gsub"; echo "lxc.idmap = g 0 $b $c"
    [[ -n $autostart ]] && echo "lxc.start.auto = 1"
    echo "# made by StorageForge"
  } >"$conf"
  try lxc-create -n "$name" -f "$conf" -t download -- --dist "$distro" --release "$release" --arch "$arch" >/dev/null || { rm -f "$conf"; return 0; }
  rm -f "$conf"
  touch "$dir/storageforge.made"
  try lxc-start -n "$name" && ok "$name is made and runs"
  wl_lxc_rest "$name" "$dir" "$labels" "$network" "$bridge" "$ports" "$allow"
}

wl_incus_rest() { # name publish labels: proxy devices and user keys, made to match
  local name=$1 p spec proto ip hp cp dev l k v
  for p in ${2//,/ }; do
    proto=tcp; spec=$p; [[ $p == */* ]] && { proto=${p#*/}; spec=${p%/*}; }
    IFS=: read -r ip hp cp <<<"$spec"; [[ -z $cp ]] && { cp=$hp; hp=$ip; ip=0.0.0.0; }
    dev=sf-port-$proto-$hp
    if incus config device get "$name" "$dev" listen >/dev/null 2>&1; then ok "$name publishes $proto/$hp"; continue; fi
    act "publish $proto port $hp of this host to $cp in $name, listening on $ip" || continue
    try incus config device add "$name" "$dev" proxy "listen=$proto:$ip:$hp" "connect=$proto:127.0.0.1:$cp" >/dev/null && ok "$name publishes $proto/$hp"
  done
  for l in ${3//,/ }; do
    k=${l%%=*}; v=${l#*=}
    [[ $(incus config get "$name" "user.$k" 2>/dev/null || true) == "$v" ]] && continue
    act "label $name with $k=$v" || continue
    try incus config set "$name" "user.$k=$v" && ok "label $k=$v on $name"
  done
  return 0
}
t_incus() { local name=$1 image=${2:-images:debian/13} type=${3:-container} profiles=${4:-default} cpus=$5 mem=$6 pool=$7 network=$8 publish=$9 nesting=${10} autostart=${11} labels=${12} allow=${13} ports=${14}
  not_on_pve || return 0
  local args=() p l fp state
  command -v incus >/dev/null || { later "Incus is not installed: add a runtime-install step (incus) before this one"; return 0; }
  if ! incus info >/dev/null 2>&1; then
    if ((APPLY)); then conflict "cannot reach the Incus daemon"; else missing "cannot reach Incus as $(id -un): --apply, as root, looks"; fi
    return 0
  fi
  if incus config show "$name" >/dev/null 2>&1; then
    [[ $(incus config get "$name" user.storageforge.managed 2>/dev/null || true) == true ]] || { conflict "an instance named $name exists, and StorageForge did not make it: choose another name"; return 0; }
    state=$(incus list -f csv -c s "$name" 2>/dev/null || true); state=${state%%$'\n'*}
    if [[ $state == RUNNING ]]; then ok "$name exists, made by StorageForge, and runs"
    elif act "start $name"; then try incus start "$name" && ok "$name started"; fi
    wl_incus_rest "$name" "$publish" "$labels"
    wl_fw "Incus instance" "$name" input "$ports" "$allow"
    return 0
  fi
  for p in ${profiles//,/ }; do
    incus profile show "$p" >/dev/null 2>&1 || { conflict "there is no Incus profile $p here"; return 0; }
    info "profile $p brings: $(incus profile device list "$p" 2>/dev/null | tr "\n" " ")"
    args+=(-p "$p")
  done
  if [[ -n $pool ]]; then incus storage show "$pool" >/dev/null 2>&1 || { conflict "there is no Incus storage pool $pool here"; return 0; }; args+=(-s "$pool"); fi
  if [[ -n $network ]]; then incus network show "$network" >/dev/null 2>&1 || { conflict "there is no Incus network $network here"; return 0; }; args+=(-n "$network"); fi
  [[ $type == vm ]] && args+=(--vm)
  [[ -n $cpus ]] && args+=(-c "limits.cpu=$cpus")
  [[ -n $mem ]] && args+=(-c "limits.memory=${mem}MiB")
  [[ -n $nesting ]] && args+=(-c security.nesting=true)
  [[ -n $autostart ]] && args+=(-c boot.autostart=true)
  args+=(-c user.storageforge.managed=true)
  for l in ${labels//,/ }; do args+=(-c "user.${l%%=*}=${l#*=}"); done
  fp=$(incus image info "$image" 2>/dev/null | sed -n "s/^Fingerprint: //p" | head -n 1 || true)
  if [[ -n $fp ]]; then info "image $image, fingerprint $fp"; else info "image $image: its fingerprint is known once the image server answers"; fi
  info "incus init $image $name ${args[*]}"
  act "create Incus $type $name from $image" || { wl_fw "Incus instance" "$name" input "$ports" "$allow"; return 0; }
  try incus init "$image" "$name" "${args[@]}" >/dev/null || return 0
  wl_incus_rest "$name" "$publish" ""
  try incus start "$name" && ok "$name is made and runs"
  wl_fw "Incus instance" "$name" input "$ports" "$allow"
}

# ── image updates, with the images before kept to go back to ─────────
wl_ids() { # runtime stack service unit container: the containers it is about, one id a line
  if [[ -n $2 ]]; then "$1" ps -aq --filter "label=com.docker.compose.project=$2" ${3:+--filter "label=com.docker.compose.service=$3"} 2>/dev/null
  elif [[ -n $5 ]]; then "$1" ps -aq --filter "name=^$5\$" 2>/dev/null
  else "$1" ps -aq --filter "label=PODMAN_SYSTEMD_UNIT=$4" 2>/dev/null; fi
  return 0
}
wl_health() { # runtime id: state, restart count, health (none without a healthcheck)
  local f
  if [[ $1 == docker ]]; then f="{{.State.Status}} {{.RestartCount}} {{with index .State \"Health\"}}{{index . \"Status\"}}{{else}}none{{end}}"
  else f="{{.State.Status}} {{.RestartCount}} {{with .State.Health}}{{.Status}}{{else}}none{{end}}"; fi
  "$1" inspect -f "$f" "$2" 2>/dev/null || echo "gone 0 none"
}
wl_wait() { # runtime seconds ids...: 0 once all are healthy (or running and not restarted for WL_SETTLE seconds without a healthcheck); 1 and WL_WHY
  local rt=$1 secs=$2 id st rc hs t=0 all; shift 2
  local -A rc0=()
  WL_WHY=
  # no container at all is not a healthy one: the loops below would pass with nothing to look at
  (($#)) || { WL_WHY="no container of it is here"; return 1; }
  for id; do read -r st rc hs < <(wl_health "$rt" "$id"); rc0[$id]=${rc:-0}; done
  while :; do
    all=1
    for id; do
      read -r st rc hs < <(wl_health "$rt" "$id"); hs=${hs:-none}
      case $st in
        running)
          if ((${rc:-0} > ${rc0[$id]})); then WL_WHY="$("$rt" inspect -f "{{.Name}}" "$id" 2>/dev/null) restarted"
          elif [[ $hs == unhealthy ]]; then WL_WHY="$("$rt" inspect -f "{{.Name}}" "$id" 2>/dev/null) is unhealthy"
          elif [[ $hs == starting ]] || { [[ $hs == none ]] && ((t < ${WL_SETTLE:-10})); }; then all=0; fi ;;
        created) all=0 ;;
        *) WL_WHY="$("$rt" inspect -f "{{.Name}}" "$id" 2>/dev/null) is $st" ;;
      esac
      [[ -n $WL_WHY ]] && return 1
    done
    ((all)) && return 0
    ((t >= secs)) && { WL_WHY="not healthy after ${secs}s"; return 1; }
    sleep "${WL_TICK:-2}"; t=$((t + ${WL_TICK:-2}))
  done
}
wl_tagof() { local t=${1//[^A-Za-z0-9_.-]/-}; echo "${t:0:100}"; }
wl_recreate() { # runtime stack service unit dir force compose-args...
  local rt=$1 stack=$2 service=$3 unit=$4 wd=$5 force=$6; shift 6
  if [[ -n $stack ]]; then (cd "$wd" && "${WL_C[@]}" "$@" up -d ${force:+--force-recreate} ${service:+"$service"}) >/dev/null 2>&1
  else systemctl restart "$unit"; fi
}
t_image_update() { local runtime=$1 stack=$2 service=$3 unit=$4 container=$5 wait=${6:-120}
  local ids=() id ref img refs=() olds=() i changed=() wd= files f args=() new what keep=() why
  command -v "$runtime" >/dev/null || { conflict "$runtime is not on this host"; return 0; }
  what="stack $stack${service:+, service $service}"; [[ -n $stack ]] || what="unit $unit"
  mapfile -t ids < <(wl_ids "$runtime" "$stack" "$service" "$unit" "$container")
  ((${#ids[@]})) || { conflict "no container of $what here"; return 0; }
  if [[ -n $stack ]]; then
    wd=$("$runtime" inspect -f "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}" "${ids[0]}" 2>/dev/null || true)
    files=$("$runtime" inspect -f "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}" "${ids[0]}" 2>/dev/null || true)
    [[ -n $wd && -d $wd ]] || { conflict "the folder stack $stack was started from (${wd:-none recorded}) is not here: update it where its compose file is"; return 0; }
    wl_compose "$runtime" || { conflict "no compose for $runtime here"; return 0; }
    args=(-p "$stack"); for f in ${files//,/ }; do args+=(-f "$f"); done
  else
    systemctl cat "$unit" >/dev/null 2>&1 || { conflict "there is no unit $unit here"; return 0; }
  fi
  for id in "${ids[@]}"; do
    ref=$("$runtime" inspect -f "{{.Config.Image}}" "$id" 2>/dev/null) || continue
    img=$("$runtime" inspect -f "{{.Image}}" "$id" 2>/dev/null) || continue
    [[ " ${refs[*]} " == *" $ref "* ]] && continue
    if [[ $ref == *@sha256:* ]]; then info "$ref is pinned by digest: nothing to update"; continue; fi
    refs+=("$ref"); olds+=("$img")
    info "$ref runs image ${img#sha256:}"
  done
  ((${#refs[@]})) || { ok "every image of $what is pinned by digest: nothing to update"; return 0; }
  info "healthy means: each container passes its healthcheck, or runs ${WL_SETTLE:-10}s without restarting where it has none, within ${wait}s"
  act "pull ${refs[*]} for $what, recreate what changed, and go back to the images it had if it is not healthy within ${wait}s" || return 0
  for i in "${!refs[@]}"; do keep+=("localhost/storageforge-rollback:$(wl_tagof "${refs[$i]}")-$STAMP"); try "$runtime" tag "${olds[$i]}" "${keep[$i]}" || return 0; done
  if [[ -n $stack ]]; then
    if ! (cd "$wd" && "${WL_C[@]}" "${args[@]}" pull ${service:+"$service"}) >/dev/null 2>&1; then conflict "the pull failed: nothing was changed"; "$runtime" rmi "${keep[@]}" >/dev/null 2>&1; return 0; fi
  else
    for ref in "${refs[@]}"; do "$runtime" pull -q "$ref" >/dev/null 2>&1 || { conflict "could not pull $ref: nothing was changed"; "$runtime" rmi "${keep[@]}" >/dev/null 2>&1; return 0; }; done
  fi
  for i in "${!refs[@]}"; do
    new=$("$runtime" image inspect -f "{{.Id}}" "${refs[$i]}" 2>/dev/null || true)
    if [[ -n $new && $new != "${olds[$i]}" ]]; then changed+=("$i"); info "${refs[$i]}: new image ${new#sha256:}"; fi
  done
  if ((!${#changed[@]})); then "$runtime" rmi "${keep[@]}" >/dev/null 2>&1; ok "the images of $what are current: nothing changed"; return 0; fi
  wl_recreate "$runtime" "$stack" "$service" "$unit" "$wd" "" "${args[@]}" || info "recreating $what did not finish cleanly: its health decides"
  mapfile -t ids < <(wl_ids "$runtime" "$stack" "$service" "$unit" "$container")
  if wl_wait "$runtime" "$wait" "${ids[@]}"; then
    ok "updated $what, and it is healthy. The images before are kept as ${keep[*]}"
    return 0
  fi
  why=$WL_WHY
  for i in "${changed[@]}"; do try "$runtime" tag "${olds[$i]}" "${refs[$i]}"; done
  wl_recreate "$runtime" "$stack" "$service" "$unit" "$wd" force "${args[@]}" || true
  mapfile -t ids < <(wl_ids "$runtime" "$stack" "$service" "$unit" "$container")
  if wl_wait "$runtime" "$wait" "${ids[@]}"; then conflict "rolled back: $why on the new image, so $what runs the images it had before again, and is healthy"
  else conflict "rolled back after $why, and $what is still not healthy on the images it had before: $WL_WHY"; fi
}

# ── quiesced snapshots of a stack ────────────────────────────────────
wl_snap_target() { # path -> "zfs DATASET" or "btrfs SUBVOLUME" or "none FSTYPE"
  local fs src p
  read -r fs src < <(findmnt -n -o FSTYPE,SOURCE -T "$1" 2>/dev/null) || { echo "none unknown"; return 0; }
  case $fs in
    zfs) echo "zfs ${src%%[*}" ;;
    btrfs) p=$1
      while [[ $p != / && $(stat -c %i -- "$p" 2>/dev/null) != 256 ]]; do p=$(dirname -- "$p"); done
      echo "btrfs $p" ;;
    *) echo "none ${fs:-unknown}" ;;
  esac
}
t_stack_snapshot() { local runtime=$1 stack=$2 method=${3:-stop} ids=() id src t kind what targets=() bad=() made=() log=${WL_LOG:-/var/lib/storageforge/quiesce.log} rc=0 how
  command -v "$runtime" >/dev/null || { conflict "$runtime is not on this host"; return 0; }
  mapfile -t ids < <("$runtime" ps -aq --filter "label=com.docker.compose.project=$stack" 2>/dev/null)
  ((${#ids[@]})) || { conflict "no container of stack $stack here"; return 0; }
  for id in "${ids[@]}"; do
    while IFS= read -r src; do
      [[ $src == /* ]] || continue
      t=$(wl_snap_target "$src")
      [[ " ${targets[*]} " == *" ${t// /:} "* ]] && continue
      case $t in none*) bad+=("$src (${t#none })") ;; *) targets+=("${t// /:}") ;; esac
    done < <("$runtime" inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$id" 2>/dev/null)
  done
  ((${#bad[@]})) && info "not snapshotted, as their filesystem has no snapshots: ${bad[*]}"
  ((${#targets[@]})) || { conflict "nothing stack $stack keeps is on ZFS or btrfs, so there is nothing to snapshot"; return 0; }
  case $method in stop) how=stop-snapshot-start ;; pause) how=pause-snapshot-unpause ;; live) how="live, crash-consistent" ;; *) conflict "the method is stop, pause or live"; return 0 ;; esac
  info "${#ids[@]} container(s) of $stack; snapshots of ${targets[*]//:/ }; method $how"
  act "snapshot stack $stack ($how)" || return 0
  case $method in
    stop) try "$runtime" stop -t 30 "${ids[@]}" >/dev/null || return 0 ;;
    pause) try "$runtime" pause "${ids[@]}" >/dev/null || return 0 ;;
  esac
  for t in "${targets[@]}"; do
    kind=${t%%:*}; what=${t#*:}
    if [[ $kind == zfs ]]; then
      zfs snapshot -o "storageforge:quiesce=$method" "$what@sf-$stack-$STAMP" && made+=("$what@sf-$stack-$STAMP") || rc=1
    else
      mkdir -p -- "$what/.storageforge-snapshots" && btrfs subvolume snapshot -r -- "$what" "$what/.storageforge-snapshots/$stack-$STAMP" >/dev/null && made+=("$what/.storageforge-snapshots/$stack-$STAMP") || rc=1
    fi
  done
  # whatever happened to the snapshots, the stack runs again
  case $method in
    stop) "$runtime" start "${ids[@]}" >/dev/null || conflict "stack $stack did not start again: start it by hand" ;;
    pause) "$runtime" unpause "${ids[@]}" >/dev/null || conflict "stack $stack did not unpause: unpause it by hand" ;;
  esac
  mkdir -p -- "$(dirname -- "$log")" && printf "%s\t%s\t%s\t%s\n" "$STAMP" "$stack" "$how" "${made[*]}" >>"$log"
  if ((rc)); then conflict "some snapshots of $stack failed; made: ${made[*]:-none}"
  else ok "snapshots of $stack, $how: ${made[*]}. The method is recorded in $log"; fi
}
""".replace('@STACKS@', STACKS_DIR)


# ── reading what was given ──────────────────────────────────────────
def labels_of(text: str | None) -> tuple[dict, list[str]]:
    """'team=web,tier=db' -> ({'team': 'web', ...}, problems)."""
    out, bad = {}, []
    for part in filter(None, (text or '').split(',')):
        if LABEL.fullmatch(part):
            k, _, v = part.partition('=')
            out[k] = v
        else:
            bad.append(part)
    return out, bad


def compose_model(text: str | None) -> dict:
    """What a compose file says that a check or a capture needs: services with their image, published ports, bind mounts and
    confinement, named volumes, and the problems. Never raises: a file that is not compose says so in 'error'."""
    try:
        doc = yaml.safe_load(text or '')
    except yaml.YAMLError as exc:
        return {'error': f'not YAML: {str(exc).splitlines()[0][:200]}', 'services': {}, 'volumes': []}
    if not isinstance(doc, dict) or not isinstance(doc.get('services'), dict) or not doc['services']:
        return {'error': 'not a compose file: it has no services', 'services': {}, 'volumes': []}
    services = {}
    for name, s in doc['services'].items():
        s = s if isinstance(s, dict) else {}
        ports, binds, env = [], [], []
        for p in s.get('ports') or []:
            ports += _ports_of(p)
        for v in s.get('volumes') or []:
            if isinstance(v, str):
                parts = v.split(':')
                if len(parts) >= 2 and parts[0].startswith(('/', './', '../', '~')):
                    binds.append({'source': parts[0], 'target': parts[1], 'options': parts[2] if len(parts) > 2 else ''})
            elif isinstance(v, dict) and v.get('type') == 'bind' and v.get('source'):
                binds.append({'source': str(v['source']), 'target': str(v.get('target') or ''), 'options': 'ro' if v.get('read_only') else ''})
        raw_env = s.get('environment') or {}
        if isinstance(raw_env, list):
            raw_env = dict((str(e).split('=', 1) + [None])[:2] for e in raw_env)
        if isinstance(raw_env, dict):
            for k, v in raw_env.items():
                if SECRETISH.search(str(k).split('__')[-1]) and v not in (None, '') and not str(v).startswith('${') and not str(k).upper().endswith('_FILE'):
                    env.append(str(k))
        services[str(name)] = {'image': str(s['image']) if s.get('image') else None, 'build': bool(s.get('build')), 'ports': ports, 'binds': binds,
                               'privileged': bool(s.get('privileged')), 'network_mode': s.get('network_mode'), 'cap_add': [str(x) for x in s.get('cap_add') or []],
                               'security_opt': [str(x) for x in s.get('security_opt') or []], 'secret_env': env,
                               'healthcheck': isinstance(s.get('healthcheck'), dict) and not s['healthcheck'].get('disable'),
                               'labels': s.get('labels') if isinstance(s.get('labels'), (dict, list)) else {}}
    vols = doc.get('volumes') if isinstance(doc.get('volumes'), dict) else {}
    return {'error': None, 'services': services,
            'volumes': [str(k) for k, v in vols.items() if not (isinstance(v, dict) and v.get('external'))]}


def _ports_of(p) -> list[dict]:
    """One entry of a service's ports, short or long form, as {bind, published, target, proto}. A port with no published side is
    reached only through the container network, and is left out."""
    if isinstance(p, dict):
        if not p.get('published'):
            return []
        return [{'bind': str(p.get('host_ip') or '0.0.0.0'), 'published': str(p['published']), 'target': str(p.get('target') or ''), 'proto': str(p.get('protocol') or 'tcp')}]
    spec, _, proto = str(p).partition('/')
    fields = spec.rsplit(':', 2)
    if len(fields) == 1:
        return []
    bind, pub, target = ('0.0.0.0', fields[0], fields[1]) if len(fields) == 2 else (fields[0].strip('[]') or '0.0.0.0', fields[1], fields[2])
    if not pub:
        return []
    return [{'bind': bind, 'published': pub, 'target': target, 'proto': proto or 'tcp'}]


def _loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return addr == 'localhost'


def fenced_ports(ports: list[dict]) -> str:
    """'8080/tcp,53/udp': the published ports a firewall rule is for. One bound to loopback needs none."""
    seen = []
    for p in ports:
        if _loopback(p['bind']) or not re.fullmatch(r'\d{1,5}(-\d{1,5})?', p['published']):
            continue
        item = f'{p["published"]}/{p["proto"] if p["proto"] in ("tcp", "udp") else "tcp"}'
        if item not in seen:
            seen.append(item)
    return ','.join(seen)


def override(name: str, model: dict, labels: dict, relabel: str = '') -> str:
    """storageforge.yaml: the labels of every service, merged in by compose. JSON is YAML, so every value is quoted.
    relabel 'private' or 'shared': each bind mount again with :Z or :z, which compose puts in place of the one with the same target, so
    SELinux lets the container use it."""
    want = {'storageforge.managed': 'true', 'storageforge.stack': name, **labels}
    flag = {'private': 'Z', 'shared': 'z'}.get(relabel)
    services = {}
    for sname, s in model['services'].items():
        services[sname] = {'labels': want}
        if flag and s['binds']:
            vols = []
            for b in s['binds']:
                opts = [o for o in (b['options'] or '').split(',') if o]
                if not {'z', 'Z'} & set(opts):
                    opts.append(flag)
                vols.append(f'{b["source"]}:{b["target"]}:{",".join(opts)}')
            services[sname]['volumes'] = vols
    return json.dumps({'services': services}, indent=2, sort_keys=False)


SYSTEM_DIRS = ('/', '/etc', '/usr', '/var', '/var/lib', '/boot', '/root', '/home', '/srv', '/opt', '/run', '/tmp', '/mnt', '/media', '/bin', '/sbin', '/lib', '/dev', '/proc', '/sys')


def relabel_findings(binds: list[dict], relabel: str) -> list[str]:
    """Bind mounts whose relabelling would break the host or other services: with :Z SELinux gives the folder to this container alone."""
    out = []
    for b in binds:
        src = (b['source'] or '').rstrip('/') or '/'
        opts = set((b['options'] or '').split(','))
        if src in SYSTEM_DIRS and (relabel or opts & {'z', 'Z'}):
            out.append(f'{src} is a system folder: relabelling it for a container breaks the host. Mount a folder under it instead')
        elif src.startswith('/home/') and src.count('/') == 2 and (relabel == 'private' or 'Z' in opts):
            out.append(f'{src} is a home folder: :Z gives it to this container alone, and its owner loses it')
    return out


def incus_ports(publish: str | None) -> tuple[list[dict], list[str]]:
    """'8080:80/tcp,127.0.0.1:5353:53/udp' -> [{'bind', 'published', 'target', 'proto'}], problems."""
    out, bad = [], []
    for part in filter(None, (publish or '').split(',')):
        m = re.fullmatch(r'(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5}):(\d{1,5})(?:/(tcp|udp))?', part)
        if not m or not (0 < int(m[2]) < 65536 and 0 < int(m[3]) < 65536):
            bad.append(part)
            continue
        out.append({'bind': m[1] or '0.0.0.0', 'published': m[2], 'target': m[3], 'proto': m[4] or 'tcp'})
    return out, bad


# ── checks against the index ────────────────────────────────────────
def _labels_check(p, say, reserved=()):
    labels, bad = labels_of(p.get('labels'))
    if bad:
        say('crit', f'labels are key=value, separated by commas ({", ".join(bad[:3])} is not)')
    for k in labels:
        if k.startswith('storageforge.'):
            say('crit', f'{k}: storageforge.* labels are set by StorageForge itself')
        if k in reserved:
            say('crit', f'user.{k} is read by cloud-init on the instance: it is not a label')
    if labels:
        say('note', 'labels: ' + ', '.join(f'{k}={v}' for k, v in labels.items()))
    return labels


def _published_check(conn, h, ports: list[dict], allow: str, say, how: str):
    from . import netfacts
    busy = {x['port'] for x in (netfacts.reading(conn, h['name']) or {}).get('listeners') or []}
    open_ = []
    for p in ports:
        if p['published'].isdigit() and int(p['published']) in busy:
            say('crit', f'something already listens on {p["published"]} on {h["name"]}')
        if not _loopback(p['bind']):
            open_.append(f'{p["published"]}/{p["proto"]}')
            # fenced_ports skips a port that is not a plain number, so the fence would leave it open to everyone
            if allow and not re.fullmatch(r'\d{1,5}(-\d{1,5})?', p['published']):
                say('crit', f'{p["published"]} is not a plain port number, so the firewall cannot fence it to {allow}: write the number in the compose file')
    if open_ and not allow:
        say('warn', f'publishes {", ".join(open_)} to every network {h["name"]} is on: give the addresses allowed to reach it, or bind it to 127.0.0.1')
    elif open_:
        say('note', f'only {allow} may reach {", ".join(open_)}: {how}')


def _engine_note(conn, h, runtime, say):
    from .runtimes import docker
    views = docker.listing(conn, h['name'])
    engine = views[0]['engine'] if views else None
    if not views:
        say('note', f'the last scan of {h["name"]} saw no container engine: a runtime-install step before this one installs {runtime}')
    elif engine and engine != runtime:
        say('warn', f'the last scan of {h["name"]} saw {engine}, not {runtime}')
    return views


def check_stack(conn, c, h, p, say):
    from .workloads import container_findings
    name = p.get('name') or ''
    if not PROJECT.fullmatch(name):
        say('crit', 'a stack name is lower-case letters, digits, - and _ (compose takes no other)')
    m = compose_model(p.get('compose'))
    if m['error']:
        say('crit', m['error'])
        return
    views = _engine_note(conn, h, p.get('runtime') or 'docker', say)
    where = p.get('dir') or f'{STACKS_DIR}/{name}'
    for v in views:
        for s in v['stacks']:
            if s.get('project') == name and s.get('dir') and s['dir'] != where:
                say('warn', f'a stack named {name} already runs from {s["dir"]}: the script stops there. Adopt it, or choose another name')
    say('note', f'kept in {where}, with your labels in storageforge.yaml beside the compose file')
    ports = []
    for sname, s in m['services'].items():
        if s['build'] and not s['image']:
            say('crit', f'{sname} is built from source: this step runs images only. Build and push it, then name the image')
        elif s['image'] and (':' not in s['image'].rsplit('/', 1)[-1] or s['image'].endswith(':latest')) and '@sha256:' not in s['image']:
            say('note', f'{sname} runs {s["image"]}, with no version: an image update can bring anything')
        if s['secret_env']:
            say('crit', f'{sname} has a secret written into the compose file ({", ".join(s["secret_env"][:4])}): keep it in a vault secret, write it with a secret-file step, and point env_file at that file')
        for f in container_findings({'privileged': s['privileged'], 'network_mode': s['network_mode'], 'cap_add': s['cap_add'], 'security_opt': s['security_opt'],
                                     'mounts': [{'source': b['source']} for b in s['binds']]}):
            say('warn', f'{sname} {f}')
        ports += s['ports']
    if m['volumes']:
        say('note', 'volumes compose makes if they are not there: ' + ', '.join(m['volumes']))
    _mac_check(conn, h, m, p.get('selinux') or '', say)
    _published_check(conn, h, ports, p.get('allow_from') or '', say, 'a deny and allows in DOCKER-USER, where Docker sends published ports')
    _labels_check(p, say)
    from . import placement
    placement.say_for_stack(conn, c, h, m, where, say)
    say('note', 'the report validates the file with compose itself and shows what changes against the file deployed before')


def _mac_check(conn, h, m, relabel, say):
    """MAC at deploy: on an SELinux host a bind mount needs :z or :Z, or the container is denied it; and some folders must never get one."""
    from . import security
    binds = [b for s in m['services'].values() for b in s['binds']]
    for f in relabel_findings(binds, relabel):
        say('crit', f)
    mode = (security.measurement(conn, h['name']) or {}).get('selinux')
    unlabelled = [b['source'] for b in binds if not {'z', 'Z'} & set((b['options'] or '').split(','))]
    if mode in ('Enforcing', 'Permissive') and unlabelled and not relabel:
        say('warn' if mode == 'Enforcing' else 'note', f'{h["name"]} runs SELinux ({mode.lower()}): {", ".join(unlabelled[:4])} has no :z or :Z, so the container is denied it. '
            'Choose private (:Z, this stack alone) or shared (:z) for its bind mounts')
    elif relabel and mode in ('Enforcing', 'Permissive'):
        say('ok', f'its bind mounts get :{"Z" if relabel == "private" else "z"}, so SELinux lets the containers use them')
    elif relabel and not mode:
        say('note', f'the last security reading of {h["name"]} saw no SELinux: :z and :Z do nothing there')


def check_lxc(conn, c, h, p, say):
    from . import inframeasure
    if pvenode.refuse_on_node(conn, h, say):
        return
    r = inframeasure.reading(conn, h['name']) or {}
    if r and 'lxc-ls' not in (r.get('tools') or []):
        say('note', f'the last reading of {h["name"]} saw no LXC: a runtime-install step (lxc) before this one installs it')
    if any(i.get('name') == p['name'] for i in r.get('lxc') or []):
        say('warn', f'a container named {p["name"]} is already on {h["name"]}: the script leaves one StorageForge did not make alone')
    if p.get('network') == 'bridge' and not p.get('bridge'):
        say('crit', 'name the bridge')
    if not (p.get('distro') and p.get('release')):
        say('crit', 'give the distribution and its release, as the download template names them (debian and trixie, ubuntu and noble)')
    if p.get('network') == 'bridge':
        say('warn', f'bridged on {p.get("bridge")}: the host firewall does not see its traffic')
    if p.get('allow_from') and p.get('network') != 'host':
        say('note', 'allow_from fences ports only on the host network: behind lxcbr0 nothing outside reaches it, and a bridged one bypasses the host firewall')
    elif p.get('network') == 'host' and p.get('ports') and not p.get('allow_from'):
        say('warn', f'on the host network, ports {p["ports"]} are open to every network {h["name"]} is on: give the addresses allowed to reach them')
    elif p.get('network') == 'host' and p.get('ports'):
        say('note', f'only {p["allow_from"]} may reach ports {p["ports"]}: a fence on input')
    say('note', 'unprivileged, mapped to subordinate ids of root (added to /etc/subuid and /etc/subgid when root has none)')
    _labels_check(p, say)
    from . import placement
    for level, text in placement.advise(conn, c, h, '/var/lib/lxc', 'data', 'its root filesystem'):
        say(level, text)


def check_incus(conn, c, h, p, say):
    from . import inframeasure
    if pvenode.refuse_on_node(conn, h, say):
        return
    r = inframeasure.reading(conn, h['name']) or {}
    if r and 'incus' not in (r.get('tools') or []):
        say('note', f'the last reading of {h["name"]} saw no Incus: a runtime-install step (incus) before this one installs it')
    if any(i.get('name') == p['name'] for i in r.get('incus') or []):
        say('warn', f'an instance named {p["name"]} is already on {h["name"]}: the script leaves one StorageForge did not make alone')
    ports, bad = incus_ports(p.get('publish'))
    if bad:
        say('crit', f'a published port is [address:]host-port:instance-port[/tcp|udp] ({", ".join(bad[:3])} is not)')
    if ports and p.get('type') == 'vm':
        say('crit', 'Incus forwards ports to a VM only in NAT mode with fixed addresses: publish from a container, or set a network forward by hand')
    _published_check(conn, h, ports, p.get('allow_from') or '', say, 'a fence on input, where the proxy devices listen')
    if p.get('nesting'):
        say('warn', 'nesting lets the instance run containers of its own, and widens what it can reach of the kernel')
    _labels_check(p, say, RESERVED_INCUS)
    say('note', 'profiles, pool and network are checked on the host first; the report lists what each profile brings')


def _incus_extra(conn, t) -> list[str]:
    ports, _ = incus_ports(t['params'].get('publish'))
    return [fenced_ports(ports)]


def _stack_extra(conn, t) -> list[str]:
    p = t['params']
    m = compose_model(p.get('compose'))
    labels, _ = labels_of(p.get('labels'))
    ports = [x for s in m['services'].values() for x in s['ports']]
    return [override(p.get('name') or '', m, labels, p.get('selinux') or '') if not m['error'] else '', fenced_ports(ports), 'forward']


# ── Ansible: the same functions, as one shell task ──────────────────
ANSIBLE_HEAD = (pvenode.NOT_ON_PVE_BASH + '\n' + 'APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
                'doing() { echo "changed: $*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; durable() { sync; }\n'
                'fw_tool() { FW=/usr/local/sbin/storageforge-fwrules; [[ -x $FW ]] || { conflict "storageforge-fwrules is not on this host: run the Bash script of a fw-rule step once"; return 1; }; }\n'
                'fw_need_nft() { command -v nft >/dev/null || { conflict "nftables is not installed"; return 1; }; }; fw_id() { printf "%s" "$*" | sha256sum | cut -c1-12; }\n')


def ansible_of(fn: str, args: tuple, extra=None):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        words = [('1' if p.get(a) else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in args] + (extra(conn, t) if extra else [])
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': ANSIBLE_HEAD + BASH + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


ALLOW = F('allow_from', 'cidrs', 'Only these may reach what it publishes', placeholder='192.168.1.0/24')
LABELS = F('labels', 'word', 'Labels', placeholder='team=web,tier=frontend')

changes.register('stack', {'group': 'Workloads', 'label': 'Run a compose stack', 'fields': [
    F('runtime', 'choice', 'Runtime', options=['docker', 'podman'], required=True), F('name', 'name', 'Stack name', required=True, placeholder='wiki'),
    F('compose', 'lines', 'Compose file', required=True, placeholder='services:\n  web:\n    image: docker.io/library/nginx:1.27\n    ports: ["127.0.0.1:8080:80"]'),
    F('dir', 'path', 'Kept in', placeholder=f'{STACKS_DIR}/<name>'), LABELS, ALLOW,
    F('selinux', 'choice', 'SELinux label for its bind mounts', options=['', 'private', 'shared'], default='')],
    'help': 'The compose file is kept as given, with your labels in a second file beside it. The report validates it with compose and shows what changes. '
            'Only the addresses you allow reach what it publishes, through DOCKER-USER. On SELinux hosts, private adds :Z to its bind mounts and shared :z.'},
    STACK_ARGS, lambda p: f'Stack {p["name"]} on {p["runtime"]}', check_stack, ansible_of('t_stack', STACK_ARGS, _stack_extra), args_of=_stack_extra)

changes.register('lxc', {'group': 'Workloads', 'label': 'Run an LXC container', 'fields': [
    F('name', 'vmname', 'Name', required=True, placeholder='builder'), F('distro', 'word', 'Distribution', required=True, placeholder='debian'),
    F('release', 'word', 'Release', required=True, placeholder='trixie'), F('arch', 'choice', 'Architecture', options=['amd64', 'arm64'], default='amd64'),
    F('network', 'choice', 'Network', options=['', 'bridge', 'host'], default=''), F('bridge', 'iface', 'The bridge (bridged only)', placeholder='br0'),
    F('autostart', 'bool', 'Start with the host'), LABELS, F('ports', 'ports', 'Ports it serves (host network only)', placeholder='8080,8443'), ALLOW],
    'help': 'From the LXC download template, always unprivileged. Behind lxcbr0 unless bridged or on the host network. A container StorageForge did not make is left alone.'},
    LXC_ARGS, lambda p: f'LXC container {p["name"]} ({p["distro"]} {p["release"]})', check_lxc, ansible_of('t_lxc', LXC_ARGS))

changes.register('incus', {'group': 'Workloads', 'label': 'Run an Incus instance', 'fields': [
    F('name', 'vmname', 'Name', required=True, placeholder='web-01'), F('image', 'word', 'Image', placeholder='images:debian/13'),
    F('type', 'choice', 'Kind', options=['container', 'vm'], default='container'), F('profiles', 'word', 'Profiles', placeholder='default'),
    F('cpus', 'number', 'CPUs'), F('memory_mb', 'number', 'Memory, MiB'), F('pool', 'name', 'Storage pool'), F('network', 'name', 'Network'),
    F('publish', 'publish', 'Ports to publish', placeholder='8080:80/tcp'), F('nesting', 'bool', 'Allow containers inside it'),
    F('autostart', 'bool', 'Start with the host'), LABELS, ALLOW],
    'help': 'Profiles, pool and network are checked first. Labels are user.* keys, published ports are proxy devices, and only the addresses you allow reach them.'},
    INCUS_ARGS, lambda p: f'Incus {p["type"] or "container"} {p["name"]} from {p["image"] or "images:debian/13"}', check_incus,
    ansible_of('t_incus', INCUS_ARGS, _incus_extra), args_of=_incus_extra)


REMOVE_ARGS = ('runtime', 'name')


def check_managed_remove(conn, c, h, p, say):
    if p['runtime'] == 'lxc' and pvenode.refuse_on_node(conn, h, say):
        return
    if p['runtime'] == 'lxc':
        say('warn', 'destroying an LXC container deletes its root filesystem')
    else:
        if not PROJECT.fullmatch(p['name']):
            say('crit', 'give the lower-case compose project name')
        say('warn', 'removing the stack deletes its container writable layers and keeps its volumes, networks and compose files')


def ansible_managed_remove(t):
    task = ansible_of('t_managed_workload_remove', REMOVE_ARGS)(t)
    task.update(tags=['destructive'], when='storageforge_destructive | default(false) | bool')
    return task


changes.register('managed-workload-remove', {'group': 'Workloads', 'label': 'Remove a managed stack or LXC container',
    'destructive': True, 'confirm_of': 'name', 'fields': [
        F('runtime', 'choice', 'Runtime', options=['docker', 'podman', 'lxc'], required=True),
        F('name', 'vmname', 'Compose project or LXC container name', required=True),
        F('confirm', 'confirm', 'Type its name again to confirm', required=True)],
    'help': 'Removes every managed container in a compose stack, or destroys a managed LXC container and its root filesystem.'},
    REMOVE_ARGS, lambda p: f'Remove managed {p["runtime"]} {"container" if p["runtime"] == "lxc" else "stack"} {p["name"]}',
    check_managed_remove, ansible_managed_remove)


# ── image updates ───────────────────────────────────────────────────
UPDATE_ARGS = ('runtime', 'stack', 'service', 'unit', 'container', 'wait')


def check_image_update(conn, c, h, p, say):
    from .runtimes import docker
    stack, unit = p.get('stack'), p.get('unit')
    if bool(stack) == bool(unit):
        say('crit', 'name a stack, or the systemd unit that runs the container: one of the two')
        return
    if p.get('container') and not unit:
        say('crit', 'a container name goes with a unit')
    if unit and p.get('runtime') == 'docker' and not p.get('container'):
        say('crit', 'with Docker, name the container the unit runs: only Podman labels its containers with their unit')
    wait = int(p.get('wait') or 120)
    if not 10 <= wait <= 3600:
        say('crit', 'wait between 10 and 3600 seconds for it to be healthy')
    if stack:
        views = docker.listing(conn, h['name'])
        found = [s for v in views for s in v['stacks'] if s.get('project') == stack]
        if not views:
            say('warn', f'the last scan of {h["name"]} saw no container engine')
        elif not found:
            say('warn', f'the last scan of {h["name"]} saw no stack {stack}')
        for s in found:
            cs = [x for x in s['containers'] if not p.get('service') or (x.get('labels') or {}).get('com.docker.compose.service') == p['service']]
            if p.get('service') and not cs:
                say('warn', f'the last scan saw no service {p["service"]} in {stack}')
            for x in cs:
                if '@sha256:' in (x.get('image') or ''):
                    say('note', f'{x["name"]} runs an image pinned by digest: an update changes nothing there')
                elif x.get('detail') and not x.get('health'):
                    say('note', f'{x["name"]} has no healthcheck: healthy then means running without a restart for 10 seconds')
                elif x.get('health'):
                    say('ok', f'{x["name"]} has a healthcheck ({x["health"]} at the last scan)')
    else:
        say('note', f'the unit {unit} recreates the container from its definition, a Quadlet or a unit file, after the pull')
    say('note', 'the images it runs now are tagged localhost/storageforge-rollback:... first, and put back if it is not healthy after the update')


changes.register('image-update', {'group': 'Workloads', 'label': 'Update the images of a stack or a unit', 'fields': [
    F('runtime', 'choice', 'Runtime', options=['docker', 'podman'], required=True), F('stack', 'name', 'Stack (compose project)', placeholder='wiki'),
    F('service', 'name', 'Only this service'), F('unit', 'unit', 'Or the systemd unit that runs it', placeholder='wiki.service'),
    F('container', 'name', 'The container the unit runs (Docker only)'), F('wait', 'number', 'Seconds to wait for it to be healthy', placeholder='120')],
    'help': 'Pulls what the compose file or unit names and recreates what changed. If it is not healthy in time, the images it ran before are put back and it is recreated '
            'again. A container started by hand has nothing to recreate it from: adopt it as compose first.'},
    UPDATE_ARGS, lambda p: f'Update the images of {"stack " + p["stack"] if p["stack"] else p["unit"]}' + (f', service {p["service"]}' if p.get('service') else ''),
    check_image_update, ansible_of('t_image_update', UPDATE_ARGS))

# ── quiesced snapshots ──────────────────────────────────────────────
SNAP_ARGS = ('runtime', 'stack', 'method')


def check_stack_snapshot(conn, c, h, p, say):
    from . import placement
    from .runtimes import docker
    method = p.get('method') or 'stop'
    found = [s for v in docker.listing(conn, h['name']) for s in v['stacks'] if s.get('project') == p.get('stack')]
    if not found:
        say('warn', f'the last scan of {h["name"]} saw no stack {p.get("stack")}')
        return
    db = [x['name'] for s in found for x in s['containers'] if placement.is_database(x.get('image'))]
    sources = sorted({m.get('source') for s in found for x in s['containers'] for m in x.get('mounts') or [] if (m.get('source') or '').startswith('/')})
    snap, none = [], []
    for src in sources:
        where, fs = c.mount_at(src)
        (snap if fs in ('zfs', 'btrfs') else none).append(f'{src} ({fs or "unknown"})')
    if snap:
        say('ok', f'snapshots of what it keeps: {", ".join(snap[:6])}')
    if none:
        say('warn', f'not on ZFS or btrfs, so not snapshotted: {", ".join(none[:6])}')
    if not snap and sources:
        say('crit', 'nothing the stack keeps is on ZFS or btrfs: there is nothing to snapshot')
    if db and method == 'live':
        say('warn', f'{", ".join(db)} is a database: a live snapshot is crash-consistent only. Stop is the safe method for a stateful stack')
    elif method == 'stop':
        say('note', f'the stack stops for as long as the snapshots take (seconds), then starts again whatever happened to them')
    elif method == 'pause':
        say('note', 'its processes are paused, not stopped: writes in flight in memory are not on disk in the snapshot')
    say('note', 'the method is recorded with each snapshot: a ZFS user property (storageforge:quiesce), and a line in /var/lib/storageforge/quiesce.log')


changes.register('stack-snapshot', {'group': 'Workloads', 'label': 'Snapshot a stack, quiesced', 'fields': [
    F('runtime', 'choice', 'Runtime', options=['docker', 'podman'], required=True), F('stack', 'name', 'Stack (compose project)', required=True, placeholder='wiki'),
    F('method', 'choice', 'How to quiesce it', options=['', 'stop', 'pause', 'live'], default='')],
    'help': 'Snapshots the ZFS datasets and btrfs subvolumes its containers keep data on. Stop (the default, for stateful stacks) stops it, snapshots and starts it; '
            'pause pauses it instead; live takes them as it runs. The method is recorded with the snapshots.'},
    SNAP_ARGS, lambda p: f'Snapshot stack {p["stack"]} ({p.get("method") or "stop"})', check_stack_snapshot, ansible_of('t_stack_snapshot', SNAP_ARGS))

changes.EXTRA_BASH.append(BASH)
