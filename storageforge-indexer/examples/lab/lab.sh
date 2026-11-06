#!/usr/bin/env bash
# Disposable KVM lab for StorageForge. Everything it makes is named here and removed by `down`.
#   lab.sh up             pick 7 of the 14 configs at random, then create, start and provision them, ending at golden
#   lab.sh up --seed N    the build that seed picks, to repeat one
#   lab.sh up --pick a,b  exactly these configs
#   lab.sh up vm...       only these VMs of the current build, with no snapshot
#   lab.sh up --join a,b  add configs to the running build: routers and their client VMs join this way
#   lab.sh down           remove the VMs, network, pool and lab state, even while an up is running
#   lab.sh reset          return every VM to the golden snapshot
#   lab.sh snapshot       retake the golden snapshot from the current state
#   lab.sh test           check the running lab against what it should hold
#   lab.sh test --all     tiers 0-14 and 16, resetting around them, and write the report into reports/. Takes a while.
#   lab.sh gauntlet       tier 2 alone: every deploy path on every VM, from golden and back
#   lab.sh appliances     tier 8 alone: Proxmox, TrueNAS and XCP-ng, when the build has them
#   lab.sh controller     rebuild StorageForge from this tree and restart it on sf-ctl, keeping its data
#   lab.sh demo           reset, then scan every host and deploy shares, jobs and an alert through StorageForge
#   lab.sh status [--json]
#   lab.sh ssh <vm> [cmd]
#   lab.sh images         download and check the base images
#   lab.sh install-launcher   add the control panel to the desktop menu
set -euo pipefail

export LIBVIRT_DEFAULT_URI=qemu:///system
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
# SFLAB_INSTANCE=N (1-9) is a second lab beside the first, with nothing shared but the base images: its own network, pool,
# state and VM tag, so its `down` can't touch the first. Two labs can't both hold a config, since VM names are libvirt's.
INSTANCE=${SFLAB_INSTANCE:-}
case $INSTANCE in ''|[1-9]) ;; *) echo 'lab: SFLAB_INSTANCE must be 1-9' >&2; exit 1 ;; esac
LAB_DIR=${SFLAB_DIR:-/mnt/ssd/Data/KVM/sflab$INSTANCE}
IMG_DIR=${SFLAB_IMAGES:-/mnt/ssd/Data/KVM/sflab-images}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/sflab$INSTANCE
LOCK=${XDG_RUNTIME_DIR:-/tmp}/sflab$INSTANCE-$(id -u).lock
NET=sflab$INSTANCE
BRIDGE=sflab${INSTANCE:-0}
PREFIX=10.$((77 + ${INSTANCE:-0})).0
POOL=sflab$INSTANCE
MARKER=.sflab-lab                     # `down` deletes a folder only if this file is in it
META_URI=https://storageforge.invalid/sflab$INSTANCE
export SFLAB_PREFIX=$PREFIX SFLAB_STATE=$STATE SFLAB_META=$META_URI
DISK_NEEDED_GB=30
WAIT_SECS=1200

say() { printf '%s\n' "$*"; }
die() { printf 'lab: %s\n' "$*" >&2; exit 1; }
pool_rows() { grep -vE '^\s*(#|$)' "$HERE/nodes.conf" | sed "s/|10\.77\.0\./|$PREFIX./"; }
selection() { cut -d' ' -f2- "$STATE/selection" 2>/dev/null | tr ' ' '\n'; }
nodes() { if [ -f "$STATE/selection" ]; then pool_rows | grep -E "^($(selection | paste -sd'|'))\|"; else pool_rows; fi; }
field() { pool_rows | awk -F'|' -v k="$1" -v f="$2" '$1==k {print $f}'; }
is_node() { pool_rows | cut -d'|' -f1 | grep -qx -- "$1"; }

# Only a VM carrying our metadata tag is ever stopped or removed.
ours() { virsh metadata "$1" "$META_URI" 2>/dev/null | grep -q '<lab\b'; }
exists() { virsh dominfo "$1" >/dev/null 2>&1; }
state() { virsh domstate "$1" 2>/dev/null | head -1; }
lab_domains() { local d; for d in $(virsh list --all --name); do ours "$d" && echo "$d"; done; return 0; }
domains_required() { local l; l=$(lab_domains); [ -n "$l" ] || die 'no lab is running: use up'; echo "$l"; }

kill_tree() { local c; for c in $(pgrep -P "$1" || true); do kill_tree "$c"; done; kill -TERM "$1" 2>/dev/null || true; }

lock() { exec 9>>"$LOCK"; flock -n 9 || die "another lab command is running (pid $(cat "$LOCK"))"; : >"$LOCK"; echo $$ >&9; }
lock_over() {   # down wins over whatever is running
  exec 9>>"$LOCK"
  flock -n 9 && { : >"$LOCK"; echo $$ >&9; return; }
  local pid; pid=$(cat "$LOCK" 2>/dev/null || true)
  [ -n "$pid" ] && grep -qa lab.sh "/proc/$pid/cmdline" 2>/dev/null && { say "stopping running command (pid $pid)"; kill_tree "$pid"; }
  flock -w 30 9 || die 'the running command did not stop'
  : >"$LOCK"; echo $$ >&9
}

lab_ssh() { local n=$1; shift; lab_pipe "$n" "$@" </dev/null; }
lab_pipe() {   # as lab_ssh, with stdin passed through
  local n=$1; shift
  ssh -i "$STATE/id_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=accept-new \
      -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout="${SSH_TIMEOUT:-5}" -o LogLevel=ERROR "lab@$(field "$n" 7)" "$@"
}

preflight() {
  local need=1536 n ram free_kb
  for c in virsh virt-install qemu-img xorriso openssl curl flock ssh ssh-keygen python3 git docker; do command -v "$c" >/dev/null || die "missing $c"; done
  [ -w /dev/kvm ] || die 'no write access to /dev/kvm'
  virsh uri >/dev/null 2>&1 || die 'cannot reach libvirt (qemu:///system)'
  for n in "$@"; do
    if exists "$n"; then
      ours "$n" || die "a VM named $n already exists and is not part of the lab: not touching it"
    else
      ram=$(field "$n" 5); need=$((need + ram))
    fi
  done
  free_kb=$(awk '/^MemAvailable/ {print $2}' /proc/meminfo)
  [ $((free_kb / 1024)) -ge "$need" ] || die "needs $need MB free, have $((free_kb / 1024)) MB"
  local parent; parent=$(dirname "$LAB_DIR"); [ -d "$parent" ] || die "$parent does not exist"
  [ "$(df -BG --output=avail "$parent" | tail -1 | tr -dc 0-9)" -ge "$DISK_NEEDED_GB" ] || die "needs ${DISK_NEEDED_GB} GB free in $parent"
  if ! virsh net-info "$NET" >/dev/null 2>&1 && ip route | grep -q "^$PREFIX\."; then die "$PREFIX.0/24 is already routed on this machine"; fi
  if virsh pool-info "$POOL" >/dev/null 2>&1 && ! virsh pool-dumpxml "$POOL" | grep -qF "<path>$LAB_DIR</path>"; then
    die "a libvirt pool named $POOL points somewhere else: not touching it"
  fi
  if [ -e "$LAB_DIR" ] && [ ! -e "$LAB_DIR/$MARKER" ]; then die "$LAB_DIR exists and is not a lab folder"; fi
}

ensure_state() {
  mkdir -p "$STATE"; chmod 700 "$STATE"
  [ -f "$STATE/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C sflab -f "$STATE/id_ed25519"
  [ -f "$STATE/admin-password" ] || (umask 077; openssl rand -base64 18 >"$STATE/admin-password")
  [ -f "$STATE/admin-hash" ] || (umask 077; openssl passwd -6 -stdin <"$STATE/admin-password" >"$STATE/admin-hash")
  # lab and scan log in by key only. A real hash nobody knows, because some sshd builds refuse locked accounts.
  [ -f "$STATE/locked-hash" ] || (umask 077; openssl rand -base64 32 | openssl passwd -6 -stdin >"$STATE/locked-hash")
  [ -f "$STATE/ui-password" ] || (umask 077; openssl rand -base64 18 >"$STATE/ui-password")
}

image_path() { local url; url=$(awk -F'|' -v k="$1" '$1==k {print $2}' "$HERE/images.conf"); echo "$IMG_DIR/$(basename "$url")"; }

fetch_image() {
  local key=$1 url sums file want have
  url=$(awk -F'|' -v k="$key" '$1==k {print $2}' "$HERE/images.conf")
  sums=$(awk -F'|' -v k="$key" '$1==k {print $3}' "$HERE/images.conf")
  [ -n "$url" ] || die "$key is not in images.conf"
  file=$(image_path "$key")
  [ -f "$file.ok" ] && [ -f "$file" ] && return 0
  want=$(curl -fsSL --retry 3 "$sums" | { [[ $sums == *.sha512 || $sums == *.sha256 || $sums == *.SHA256 ]] && cat || grep -F "$(basename "$file")"; } \
         | grep -oE '\b[0-9a-f]{64}([0-9a-f]{64})?\b' | head -1) || true
  [ -n "$want" ] || die "$key: no published checksum at $sums"
  say "downloading $(basename "$file")"
  curl -fsSL --retry 3 -C - -o "$file.part" "$url" || die "$key: download failed"
  case ${#want} in 64) have=$(sha256sum "$file.part") ;; *) have=$(sha512sum "$file.part") ;; esac
  if [ "${have%% *}" != "$want" ]; then rm -f "$file.part"; die "$key: checksum mismatch"; fi
  mv "$file.part" "$file"; : >"$file.ok"
  say "verified $(basename "$file")"
}

base_of() {     # a router image comes compressed. The checked download stays, beside the disk image made from it
  local key=$1 file; file=$(image_path "$key")
  case $file in
    *.img.zip) local out=${file%.zip}; [ -f "$out" ] || { python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); open(sys.argv[2]+".part","wb").write(z.read(z.namelist()[0]))' "$file" "$out" && mv "$out.part" "$out"; }; echo "$out" ;;
    *.img.gz) local out=${file%.gz}; [ -f "$out" ] || { gunzip -c "$file" >"$out.part" 2>/dev/null || [ -s "$out.part" ]; mv "$out.part" "$out"; }; echo "$out" ;;
    *) echo "$file" ;;
  esac
}

ensure_images() {
  mkdir -p "$IMG_DIR"; chmod 755 "$IMG_DIR"; chattr +C "$IMG_DIR" 2>/dev/null || true
  local pids=() rc=0 k p
  for k in $(for n in "$@"; do field "$n" 2; done | sort -u); do fetch_image "$k" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  [ $rc = 0 ] || die 'could not get every base image'
}

ensure_network() {
  if ! virsh net-info "$NET" >/dev/null 2>&1; then
    local xml="$STATE/net.xml" line name ip mac
    { echo "<network><name>$NET</name><forward mode='nat'/><bridge name='$BRIDGE' stp='on' delay='0'/><domain name='lab' localOnly='yes'/>"
      echo "<ip address='$PREFIX.1' netmask='255.255.255.0'><dhcp><range start='$PREFIX.100' end='$PREFIX.200'/>"
      while IFS='|' read -r name _ _ _ _ _ ip _; do
        mac=$(mac_of "$ip"); echo "<host mac='$mac' name='$name' ip='$ip'/>"
      done < <(pool_rows)
      echo '</dhcp></ip></network>'; } >"$xml"
    virsh -q net-define "$xml" >/dev/null
  fi
  [ "$(virsh net-info "$NET" | awk '/^Active:/ {print $2}')" = yes ] || virsh -q net-start "$NET" >/dev/null
  # a lab defined before a config joined nodes.conf: its address is reserved now, not at the next define
  while IFS='|' read -r name _ _ _ _ _ ip _; do
    mac=$(mac_of "$ip")
    virsh net-dumpxml "$NET" | grep -qF "mac='$mac'" || virsh -q net-update "$NET" add ip-dhcp-host "<host mac='$mac' name='$name' ip='$ip'/>" --live --config >/dev/null
  done < <(pool_rows)
}

# Router networks: no forward, no address on this machine, no DHCP. Nothing in them can reach anything but each other.
SEGMENTS='wan lan1 dmz'
segment_net() { echo "$NET-$1"; }
segment_bridge() { echo "sflab${INSTANCE:-0}${1:0:1}"; }
ensure_segments() {
  local s n xml="$STATE/segment.xml"
  for s in $SEGMENTS; do
    n=$(segment_net "$s")
    if ! virsh net-info "$n" >/dev/null 2>&1; then
      echo "<network><name>$n</name><bridge name='$(segment_bridge "$s")' stp='off' delay='0'/></network>" >"$xml"
      virsh -q net-define "$xml" >/dev/null
    fi
    [ "$(virsh net-info "$n" | awk '/^Active:/ {print $2}')" = yes ] || virsh -q net-start "$n" >/dev/null
  done
}
remove_segments() {
  local s n
  for s in $SEGMENTS; do
    n=$(segment_net "$s")
    virsh net-info "$n" >/dev/null 2>&1 || continue
    if virsh net-dumpxml "$n" | grep -qF "name='$(segment_bridge "$s")'"; then
      say "removing network $n"
      virsh -q net-destroy "$n" >/dev/null 2>&1 || true
      virsh -q net-undefine "$n" >/dev/null || left=1
    else
      say "a network named $n is not the lab's: left alone"; left=1
    fi
  done
}
segment_mac() { printf '52:54:00:77:%02x:%02x' "$2" "${1##*.}"; }
is_router() { case $(field "$1" 2) in chr|openwrt) return 0 ;; *) return 1 ;; esac; }
mac_of() { printf '52:54:00:77:00:%02x' "${1##*.}"; }

ensure_pool() {
  if [ ! -e "$LAB_DIR" ]; then
    mkdir -p "$LAB_DIR"; chmod 755 "$LAB_DIR"
    : >"$LAB_DIR/$MARKER"
    chattr +C "$LAB_DIR" 2>/dev/null || true     # no copy-on-write under qcow2 on btrfs
  fi
  virsh pool-info "$POOL" >/dev/null 2>&1 || virsh -q pool-define-as "$POOL" dir --target "$LAB_DIR" >/dev/null
  [ "$(virsh pool-info "$POOL" | awk '/^State:/ {print $2}')" = running ] || virsh -q pool-start "$POOL" >/dev/null
}

create_node() {
  local n=$1 image osinfo vcpu ram root ip disks nets base seed i=0 d extra=() seg
  IFS='|' read -r _ image osinfo vcpu ram root ip disks nets < <(pool_rows | awk -F'|' -v k="$n" '$1==k')
  base=$(base_of "$image")
  for seg in ${nets//,/ }; do
    i=$((i + 1))
    extra+=(--network "network=$(segment_net "$seg"),mac=$(segment_mac "$ip" "$i"),model=virtio")
  done
  i=0
  case $image in
    proxmox|truenas|xcp-ng)    # installers, not cloud images: see provision/appliance.py
      python3 "$HERE/provision/appliance.py" "$image" "$n" "$ip" "$NET" "$LAB_DIR" "$base" "$STATE/id_ed25519.pub" "$STATE/admin-password" "$root" "$ram" "$vcpu" "$disks" || die "$n: install failed"
      return ;;
  esac
  local rootdisk="$LAB_DIR/$n-root.qcow2" fmt
  fmt=$(qemu-img info "$base" | sed -n 's/^file format: //p' | head -1)
  qemu-img create -q -f qcow2 -F "$fmt" -b "$base" "$rootdisk" "${root}G"
  case $image in
    chr|openwrt)    # no cloud-init: provision/router.py sets each up over its first boot
      virt-install --print-xml --import --name "$n" --osinfo "$osinfo" --vcpus "$vcpu" --memory "$ram" --cpu host-passthrough \
        --network "network=$NET,mac=$(mac_of "$ip"),model=virtio" "${extra[@]}" --graphics none --video none \
        --serial "tcp,host=127.0.0.1:$(console_port "$ip"),mode=bind,protocol.type=raw" --rng /dev/urandom --noautoconsole \
        --disk "path=$rootdisk,format=qcow2,bus=virtio" >"$STATE/$n.xml" 2>"$STATE/$n.err" \
        || { cat "$STATE/$n.err" >&2; die "$n: virt-install failed"; }
      virsh -q define "$STATE/$n.xml" >/dev/null
      virsh -q metadata "$n" "$META_URI" --key sflab --set '<lab/>' --config >/dev/null
      return ;;
  esac
  local args=(--disk "path=$rootdisk,format=qcow2,bus=virtio")
  for d in ${disks//,/ }; do
    i=$((i + 1))
    qemu-img create -q -f qcow2 "$LAB_DIR/$n-data$i.qcow2" "${d}G"
    args+=(--disk "path=$LAB_DIR/$n-data$i.qcow2,format=qcow2,bus=virtio,serial=sflab-data$i")
  done
  seed=$(make_seed "$n" "$image")
  case $image in
    debian12) args+=(--disk "path=$seed,device=disk,format=raw,bus=virtio,readonly=on") ;;     # its cloud kernel has no SATA driver
    *) args+=(--disk "path=$seed,device=cdrom,bus=sata,readonly=on") ;;
  esac
  virt-install --print-xml --import --name "$n" --osinfo "$osinfo" --vcpus "$vcpu" --memory "$ram" --cpu host-passthrough \
    --network "network=$NET,mac=$(mac_of "$ip"),model=virtio" "${extra[@]}" --graphics none --video vga --console pty,target_type=serial \
    --rng /dev/urandom --noautoconsole "${args[@]}" >"$STATE/$n.xml" 2>"$STATE/$n.err" \
    || { cat "$STATE/$n.err" >&2; die "$n: virt-install failed"; }
  virsh -q define "$STATE/$n.xml" >/dev/null
  virsh -q metadata "$n" "$META_URI" --key sflab --set '<lab/>' --config >/dev/null
}

console_port() { echo $((44000 + ${INSTANCE:-0} * 300 + ${1##*.})); }

make_seed() {
  local n=$1 image=$2 dir="$STATE/seed-$n" packages='' pub
  case $image in alpine*) packages='sudo' ;; esac
  pub=$(cat "$STATE/id_ed25519.pub")
  mkdir -p "$dir"
  sed -e "s|@NAME@|$n|g" -e "s|@PUBKEY@|$pub|g" -e "s|@PACKAGES@|$packages|g" \
      -e "s|@ADMIN_HASH@|$(cat "$STATE/admin-hash")|" -e "s|@LOCKED_HASH@|$(cat "$STATE/locked-hash")|g" \
      "$HERE/user-data.tmpl" >"$dir/user-data"
  [ -n "$packages" ] || sed -i '/^packages: /d' "$dir/user-data"   # an empty list fails cloud-init's schema check
  printf 'instance-id: sflab-%s\nlocal-hostname: %s\n' "$n" "$n" >"$dir/meta-data"
  xorriso -as mkisofs -quiet -volid cidata -joliet -rock -o "$LAB_DIR/$n-seed.iso" "$dir/user-data" "$dir/meta-data" 2>/dev/null
  echo "$LAB_DIR/$n-seed.iso"
}

wait_ready() {   # the first boot's cloud-init finished, and sudo works
  local n=$1 until=$((SECONDS + WAIT_SECS)) rc
  if is_router "$n"; then
    python3 "$HERE/provision/router.py" "$(field "$n" 2)" "$n" "$(field "$n" 7)" "$(console_port "$(field "$n" 7)")" "$STATE" || { say "$n: router setup failed"; return 1; }
    say "$n: ready"
    return 0
  fi
  while [ $SECONDS -lt $until ]; do
    if lab_ssh "$n" true 2>/dev/null; then
      if ! lab_ssh "$n" 'command -v cloud-init' >/dev/null 2>&1; then   # an appliance: appliance.py finished setting it up
        lab_ssh "$n" 'sudo -n true' || { say "$n: sudo does not work for lab"; return 1; }
        say "$n: ready"
        return 0
      fi
      # through sudo once it works: some distros stop a plain user reading cloud-init's runtime files
      rc=0; lab_ssh "$n" 'if sudo -n true 2>/dev/null; then sudo -n cloud-init status --wait; else cloud-init status --wait; fi >/dev/null 2>&1' || rc=$?
      case $rc in
        0) ;;
        2) say "$n: cloud-init finished with warnings" ;;
        255) sleep 3; continue ;;    # the connection dropped
        *) say "$n: cloud-init failed"; lab_ssh "$n" 'sudo -n cloud-init status --long || cloud-init status --long' 2>&1 | tail -15 || true; return 1 ;;
      esac
      lab_ssh "$n" 'sudo -n true' || { say "$n: sudo does not work for lab"; return 1; }
      say "$n: ready"
      return 0
    fi
    sleep 3
  done
  say "$n: not ready after ${WAIT_SECS}s"; return 1
}

wait_all() {
  local pids=() rc=0 p n
  for n in "$@"; do wait_ready "$n" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}

check_identity() {   # deploys check the short host name and /etc/machine-id, so both must be right
  local n dup
  for n in "$@"; do
    is_router "$n" && continue
    [ "$(lab_ssh "$n" uname -n)" = "$n" ] || die "$n: host name is $(lab_ssh "$n" uname -n)"
  done
  dup=$(for n in "$@"; do is_router "$n" || lab_ssh "$n" 'cat /etc/machine-id 2>/dev/null' || true; done | { grep . || true; } | sort | uniq -d)
  [ -z "$dup" ] || die "VMs share a machine-id: $dup"
}

run_layout() {   # the VM's storage layout, once. The script exits 100 when it needs a reboot before it can go on.
  local n=$1 script="$HERE/provision/$n.sh" log="$STATE/provision-$n.log" try rc
  [ -f "$script" ] || return 0
  for try in 1 2 3; do
    rc=0
    cat "$HERE/provision/lib.sh" "$script" | lab_pipe "$n" 'cat >/tmp/sflab-layout.sh && sudo -n sh /tmp/sflab-layout.sh </dev/null' >>"$log" 2>&1 || rc=$?
    case $rc in
      0) return 0 ;;
      100) say "$n: rebooting to continue"; lab_ssh "$n" 'sudo -n reboot' >/dev/null 2>&1 || true; sleep 10; wait_ready "$n" >/dev/null || return 1 ;;
      *) say "$n: layout failed (exit $rc):"; tail -15 "$log"; return 1 ;;
    esac
  done
  say "$n: layout still wants a reboot after $try tries"; return 1
}

run_seed() {
  local n=$1 root profile manifest
  mkdir -p "$STATE/manifests"
  while IFS='|' read -r _ root profile; do
    manifest="$STATE/manifests/$n${root//\//_}.json"
    lab_ssh "$n" "sudo -n mkdir -p '$root'" || return 1
    if [ "$profile" = full ]; then
      python3 "$HERE/provision/seed.py" "$n" "$profile" "$root" "$manifest" | lab_pipe "$n" "sudo -n tar -xpf - -C '$root'" || return 1
      lab_ssh "$n" "sudo -n truncate -s 1G '$root/lab-seed/links/sparse.img'" || return 1
    else        # vfat and exFAT have no owners or modes to restore
      python3 "$HERE/provision/seed.py" "$n" "$profile" "$root" "$manifest" | lab_pipe "$n" "sudo -n tar -xf - --no-same-owner --no-same-permissions -C '$root'" || return 1
    fi
  done < <(grep "^$n|" "$HERE/provision/seed-roots.conf" || true)
}

provision_node() {
  local n=$1
  is_router "$n" && return 0
  lab_ssh "$n" 'test -e /var/lib/sflab/provisioned' && return 0
  run_layout "$n" || return 1
  run_seed "$n" || { say "$n: seeding failed"; return 1; }
  lab_ssh "$n" 'sudo -n mkdir -p /var/lib/sflab && sudo -n touch /var/lib/sflab/provisioned'
  say "$n: provisioned"
  : >"$STATE/needs-snapshot"
}

provision_all() {
  local pids=() rc=0 p n
  for n in "$@"; do provision_node "$n" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}

install_controller() {   # StorageForge from this tree, in the repo's own compose stack, plus ntfy
  local root=$HERE/../.. ntfy compose='sudo -n docker compose -f docker-compose.yml -f compose.lab.yml' sf
  ntfy=$(sed -n 's/^ *image: //p' "$HERE/controller/compose.lab.yml")
  say 'building StorageForge images'
  docker compose --project-directory "$root" -f "$root/docker-compose.yml" -f "$root/docker-compose.remote.yml" build -q storageforge proxy tunnel
  docker image inspect "$ntfy" >/dev/null 2>&1 || docker pull -q "$ntfy" >/dev/null
  say 'loading images on sf-ctl'
  # shellcheck disable=SC2046
  docker save $(sed -n 's/^ *image: //p' "$root/docker-compose.yml" "$root/docker-compose.remote.yml" | sort -u) "$ntfy" | gzip -1 | SSH_TIMEOUT=30 lab_pipe sf-ctl 'gunzip | sudo -n docker load -q >/dev/null'
  tar -C "$root" -c docker-compose.yml docker-compose.remote.yml -C "$HERE/controller" compose.lab.yml | lab_pipe sf-ctl \
    'sudo -n mkdir -p /opt/storageforge/keys /opt/storageforge/secrets && sudo -n tar -x --no-same-owner -C /opt/storageforge'
  say 'starting StorageForge on sf-ctl'
  lab_ssh sf-ctl "cd /opt/storageforge && $compose up -d --no-build --wait --quiet-pull" >"$STATE/controller.log" 2>&1 \
    || { tail -20 "$STATE/controller.log"; return 1; }
  sf="cd /opt/storageforge && $compose exec -T storageforge storageforge-index"
  lab_ssh sf-ctl "$sf user list" | grep -q '^demo ' || lab_pipe sf-ctl "$sf user add demo" <"$STATE/ui-password" >/dev/null
  lab_ssh sf-ctl 'sudo -n touch /var/lib/sflab/controller'
}

node_disks() { ls "$LAB_DIR/$1"-*.qcow2; }
has_golden() { qemu-img snapshot -U -l "$LAB_DIR/$1-root.qcow2" 2>/dev/null | grep -qw golden; }

stop_vm() {  # clean shutdown from inside, so nothing is left in a guest's cache, then force
  local n=$1 i
  [ "$(state "$n")" = running ] || return 0
  if is_router "$n"; then virsh -q shutdown "$n" >/dev/null 2>&1 || true; for i in $(seq 1 15); do [ "$(state "$n")" = 'shut off' ] && return 0; sleep 2; done; virsh -q destroy "$n" >/dev/null; return 0; fi
  lab_ssh "$n" 'sudo -n sync; sudo -n poweroff' >/dev/null 2>&1 || true
  for i in $(seq 1 30); do [ "$(state "$n")" = 'shut off' ] && return 0; sleep 2; done
  virsh -q destroy "$n" >/dev/null
}

snapshot_one() {   # one VM that joined: the others keep the golden they have
  local n=$1 f
  stop_vm "$n"
  for f in $(node_disks "$n"); do qemu-img snapshot -c golden "$f"; done
  virsh -q start "$n" >/dev/null
  wait_ready "$n"
}

cmd_snapshot() {
  local doms pids=() p d f; doms=$(domains_required)
  for d in $doms; do stop_vm "$d" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p"; done
  for d in $doms; do
    for f in $(node_disks "$d"); do
      qemu-img snapshot -l "$f" | grep -qw golden && qemu-img snapshot -d golden "$f"
      qemu-img snapshot -c golden "$f"
    done
    virsh -q start "$d" >/dev/null
  done
  # shellcheck disable=SC2086
  wait_all $doms
  say "golden snapshot taken"
}

cmd_up() {
  local want=() all=0 n seed='' pick='' join=''
  while [ $# -gt 0 ]; do
    case $1 in
      --join) join=${2:?--join needs config names}; shift 2 ;;
      --seed) seed=${2:?--seed needs a number}; shift 2 ;;
      --pick) pick=${2:?--pick needs config names}; shift 2 ;;
      *) want+=("$1"); shift ;;
    esac
  done
  mkdir -p "$STATE"; chmod 700 "$STATE"
  if [ ! -f "$STATE/selection" ] || [ -n "$seed$pick" ]; then
    [ -z "$(lab_domains)" ] || die 'a lab is running: use down before picking another build'
    if [ -n "$pick" ]; then
      echo "pick ${pick//,/ }" >"$STATE/selection"
    else
      seed=${seed:-$(( (RANDOM << 15) | RANDOM ))}
      echo "$seed $(python3 "$HERE/roles.py" pick "$seed")" >"$STATE/selection"
    fi
  fi
  if [ -n "$join" ]; then     # more configs in the running build, which keeps its seed and its golden on the rest
    for n in ${join//,/ }; do is_node "$n" || die "$n is not in nodes.conf"; selection | grep -qx "$n" || sed -i "s/\$/ $n/" "$STATE/selection"; done
    want=(${join//,/ }); all=1
  fi
  say "build $(cut -d' ' -f1 "$STATE/selection"): $(selection | paste -sd' ')"
  if [ ${#want[@]} = 0 ] && [ -z "$join" ]; then mapfile -t want < <(nodes | cut -d'|' -f1); all=1; fi
  for n in "${want[@]}"; do is_node "$n" || die "$n is not in nodes.conf"; done
  preflight "${want[@]}"
  ensure_state; ensure_images "${want[@]}"; ensure_network; ensure_segments; ensure_pool
  for n in "${want[@]}"; do
    exists "$n" || { say "$n: creating"; create_node "$n"; }
    [ "$(state "$n")" = running ] || virsh -q start "$n" >/dev/null
  done
  say "waiting for first boot to finish"
  wait_all "${want[@]}" || die 'some VMs did not come up: see above. Fix or use down.'
  check_identity "${want[@]}"
  say 'provisioning storage and seed data'
  provision_all "${want[@]}" || die 'some VMs were not provisioned: see above. Fix or use down.'
  if printf '%s\n' "${want[@]}" | grep -qx sf-ctl && ! lab_ssh sf-ctl 'test -e /var/lib/sflab/controller'; then
    install_controller || die 'StorageForge did not start on sf-ctl: see above. Run up again, or use down.'
    : >"$STATE/needs-snapshot"
  fi
  if [ -n "$join" ]; then
    for n in "${want[@]}"; do has_golden "$n" || snapshot_one "$n"; done
  elif [ $all = 1 ]; then
    for n in "${want[@]}"; do has_golden "$n" || : >"$STATE/needs-snapshot"; done
    if [ -e "$STATE/needs-snapshot" ]; then cmd_snapshot; rm -f "$STATE/needs-snapshot"; fi
  fi
  cmd_status
}

cmd_reset() {
  local doms pids=() p d f; doms=$(domains_required)
  for d in $doms; do has_golden "$d" || die "$d has no golden snapshot: finish a full up or run snapshot"; done
  for d in $doms; do
    [ "$(state "$d")" = 'shut off' ] || virsh -q destroy "$d" >/dev/null
    for f in $(node_disks "$d"); do qemu-img snapshot -a golden "$f" & pids+=($!); done
  done
  for p in "${pids[@]}"; do wait "$p"; done
  for d in $doms; do virsh -q start "$d" >/dev/null; done
  # shellcheck disable=SC2086
  wait_all $doms
  say "back at golden"
}

cmd_down() {
  local d left=0
  for d in $(lab_domains); do
    say "removing $d"
    [ "$(state "$d")" = 'shut off' ] || virsh -q destroy "$d" >/dev/null || true
    virsh -q undefine "$d" --managed-save --snapshots-metadata >/dev/null || left=1
  done
  if virsh net-info "$NET" >/dev/null 2>&1; then
    if virsh net-dumpxml "$NET" | grep -qF "name='$BRIDGE'"; then
      say "removing network $NET"
      virsh -q net-destroy "$NET" >/dev/null 2>&1 || true
      virsh -q net-undefine "$NET" >/dev/null || left=1
    else
      say "a network named $NET is not the lab's: left alone"; left=1
    fi
  fi
  remove_segments
  if virsh pool-info "$POOL" >/dev/null 2>&1; then
    if virsh pool-dumpxml "$POOL" | grep -qF "<path>$LAB_DIR</path>"; then
      say "removing pool $POOL"
      virsh -q pool-destroy "$POOL" >/dev/null 2>&1 || true
      virsh -q pool-undefine "$POOL" >/dev/null || left=1
    else
      say "a pool named $POOL is not the lab's: left alone"; left=1
    fi
  fi
  for d in $(virsh list --all --name); do   # never pull disks out from under a VM that stayed
    if virsh domblklist "$d" --details | grep -qF "$LAB_DIR/"; then die "$d still uses disks in $LAB_DIR: left the folder in place"; fi
  done
  if [ -e "$LAB_DIR/$MARKER" ]; then rm -rf -- "$LAB_DIR"; elif [ -e "$LAB_DIR" ]; then say "$LAB_DIR has no lab marker: left alone"; left=1; fi
  rm -rf -- "$STATE"
  [ $left = 0 ] || die 'not everything could be removed'
  say 'lab destroyed'
}

probe_node() {   # ssh|root filesystem|swap in use on one line
  if is_router "$1"; then
    if [ "$(field "$1" 2)" = chr ]; then SSH_TIMEOUT=2 lab_ssh "$1" ':put ok' >/dev/null 2>&1 && echo 'yes|routeros|' || echo 'no||'
    else SSH_TIMEOUT=2 lab_ssh "$1" 'true' >/dev/null 2>&1 && echo 'yes|openwrt|' || echo 'no||'; fi
    return
  fi
  SSH_TIMEOUT=2 lab_ssh "$1" 'printf "yes|%s|%s\n" "$(awk "\$2==\"/\" {f=\$3} END {print f}" /proc/mounts)" "$(awk "NR>1 {print \$1}" /proc/swaps | tr "\n" " ")"' 2>/dev/null || echo 'no||'
}

cmd_status() {
  local json=${1:-} tmp n; tmp=$(mktemp -d)
  while IFS='|' read -r n _; do
    if exists "$n" && ours "$n" && [ "$(state "$n")" = running ] && [ -f "$STATE/id_ed25519" ]; then probe_node "$n" >"$tmp/$n" & fi
  done < <(nodes)
  wait
  [ "$json" = --json ] && printf '[' || printf '%-13s %-11s %-10s %-4s %-7s %-7s %s\n' VM IP STATE SSH ROOTFS GOLDEN SWAP
  local first=1 image ip st ssh_ok fs swap golden
  while IFS='|' read -r n image _ _ _ _ ip _; do
    if exists "$n" && ours "$n"; then st=$(state "$n"); else st=absent; fi
    ssh_ok=no fs='' swap=''
    [ -f "$tmp/$n" ] && IFS='|' read -r ssh_ok fs swap <"$tmp/$n"
    golden=no; [ "$st" != absent ] && has_golden "$n" && golden=yes
    if [ "$json" = --json ]; then
      [ $first = 1 ] || printf ','
      first=0
      printf '{"name":"%s","image":"%s","ip":"%s","state":"%s","ssh":"%s","rootfs":"%s","golden":"%s","swap":"%s"}' \
        "$n" "$image" "$ip" "$st" "$ssh_ok" "$fs" "$golden" "${swap% }"
    else
      printf '%-13s %-11s %-10s %-4s %-7s %-7s %s\n' "$n" "$ip" "$st" "$ssh_ok" "${fs:--}" "$golden" "${swap:--}"
    fi
  done < <(nodes)
  [ "$json" = --json ] && printf ']\n'
  rm -rf "$tmp"
  return 0
}

cmd_ssh() {
  local n=${1:-}; [ -n "$n" ] && is_node "$n" || die 'usage: lab.sh ssh <vm> [command]'
  shift
  ssh -i "$STATE/id_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o ConnectTimeout=10 "lab@$(field "$n" 7)" "$@"
}

ensure_venv() {
  # installed, not from source: password logins need its storageforge-askpass program
  [ -x "$STATE/venv/bin/storageforge-askpass" ] || { python3 -m venv "$STATE/venv" && "$STATE/venv/bin/pip" install -q -e "$HERE/../.." ; } || die 'could not install StorageForge for the tests'
}

cmd_appliances() {    # tier 8, on a throwaway database. It needs no sf-ctl, so it also runs in a lab of appliances alone.
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  ensure_venv
  "$STATE/venv/bin/python" "$HERE/../../tests/lab/tiers.py" run 8
}

cmd_gauntlet() {
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  ensure_venv
  cmd_reset
  local rc=0
  "$STATE/venv/bin/python" "$HERE/../../tests/lab/gauntlet.py" "$@" || rc=$?
  cmd_reset
  return $rc
}

cmd_test_all() {
  local tiers="$HERE/../../tests/lab/tiers.py" t rc=0
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  export SFLAB_STATE="$STATE"
  rm -rf "$STATE/results" "$STATE/gauntlet.json"
  cmd_reset
  for t in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 16; do
    say "== tier $t =="
    [ "$t" = 0 ] || [ "$t" = 2 ] || cmd_reset
    case $t in    # the report decides, knowing what is known
      2) cmd_gauntlet || true ;;
      8) cmd_appliances || true ;;
      12) ensure_venv; PYTHONPATH="$HERE/../.." "$STATE/venv/bin/python" "$tiers" run "$t" || true ;;    # it reads with the product's own parsers
      *) python3 "$tiers" run "$t" || true ;;
    esac
  done
  cmd_reset
  python3 "$tiers" report || rc=1
  return $rc
}

cmd_test() {
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  [ "${1:-}" != --all ] || { cmd_test_all; return; }
  cd "$HERE/../.."
  python3 -m unittest discover -s tests/lab -v
}

cmd_controller() {
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  install_controller
  say 'StorageForge updated. Reset goes back to the build in golden: run snapshot to keep this one.'
}

cmd_demo() {
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  cmd_reset
  python3 "$HERE/demo.py"
}

cmd_install_launcher() {
  local dir=${XDG_DATA_HOME:-$HOME/.local/share}/applications
  mkdir -p "$dir"
  cat >"$dir/sflab.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=StorageForge Lab
Comment=Create, reset and destroy the StorageForge test lab
Exec=python3 "$HERE/panel.py" --open
Icon=network-server
Terminal=false
Categories=Development;
EOF
  say "added $dir/sflab.desktop"
}

case ${1:-} in
  up) shift; lock; cmd_up "$@" ;;
  down) lock_over; cmd_down ;;
  reset) lock; cmd_reset ;;
  snapshot) lock; cmd_snapshot ;;
  status) shift; cmd_status "${1:-}" ;;
  ssh) shift; cmd_ssh "$@" ;;
  test) shift; lock; cmd_test "$@" ;;
  gauntlet) shift; lock; cmd_gauntlet "$@" ;;
  appliances) lock; cmd_appliances ;;
  controller) lock; cmd_controller ;;
  demo) lock; cmd_demo ;;
  images) mapfile -t all < <(pool_rows | cut -d'|' -f1); ensure_images "${all[@]}" ;;
  install-launcher) cmd_install_launcher ;;
  *) sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 2 ;;
esac
