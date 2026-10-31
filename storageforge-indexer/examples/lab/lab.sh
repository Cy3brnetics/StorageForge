#!/usr/bin/env bash
# Disposable KVM lab for StorageForge. Everything it makes is named here and removed by `down`.
#   lab.sh up [vm...]     create, start and provision the VMs; a full `up` ends with a golden snapshot
#   lab.sh down           remove the VMs, network, pool and lab state, even while an up is running
#   lab.sh reset          return every VM to the golden snapshot
#   lab.sh snapshot       retake the golden snapshot from the current state
#   lab.sh test           check the running lab against what it should hold
#   lab.sh status [--json]
#   lab.sh ssh <vm> [cmd]
#   lab.sh images         download and check the base images
#   lab.sh install-launcher   add the control panel to the desktop menu
set -euo pipefail

export LIBVIRT_DEFAULT_URI=qemu:///system
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
LAB_DIR=${SFLAB_DIR:-/mnt/ssd/Data/KVM/sflab}
IMG_DIR=${SFLAB_IMAGES:-/mnt/ssd/Data/KVM/sflab-images}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/sflab
LOCK=${XDG_RUNTIME_DIR:-/tmp}/sflab-$(id -u).lock
NET=sflab
BRIDGE=sflab0
PREFIX=10.77.0
POOL=sflab
MARKER=.sflab-lab                     # `down` deletes a folder only if this file is in it
META_URI=https://storageforge.invalid/sflab
DISK_NEEDED_GB=30
WAIT_SECS=1200

say() { printf '%s\n' "$*"; }
die() { printf 'lab: %s\n' "$*" >&2; exit 1; }
nodes() { grep -vE '^\s*(#|$)' "$HERE/nodes.conf"; }
field() { awk -F'|' -v k="$1" -v f="$2" '$1==k {print $f}' "$HERE/nodes.conf"; }
is_node() { nodes | cut -d'|' -f1 | grep -qx -- "$1"; }

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
  for c in virsh virt-install qemu-img xorriso openssl curl flock ssh ssh-keygen python3 git; do command -v "$c" >/dev/null || die "missing $c"; done
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
      done < <(nodes)
      echo '</dhcp></ip></network>'; } >"$xml"
    virsh -q net-define "$xml" >/dev/null
  fi
  [ "$(virsh net-info "$NET" | awk '/^Active:/ {print $2}')" = yes ] || virsh -q net-start "$NET" >/dev/null
}
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
  local n=$1 image osinfo vcpu ram root ip disks base seed i=0 d
  IFS='|' read -r _ image osinfo vcpu ram root ip disks < <(nodes | awk -F'|' -v k="$n" '$1==k')
  base=$(image_path "$image")
  local rootdisk="$LAB_DIR/$n-root.qcow2" fmt
  fmt=$(qemu-img info "$base" | sed -n 's/^file format: //p' | head -1)
  qemu-img create -q -f qcow2 -F "$fmt" -b "$base" "$rootdisk" "${root}G"
  local args=(--disk "path=$rootdisk,format=qcow2,bus=virtio")
  for d in ${disks//,/ }; do
    i=$((i + 1))
    qemu-img create -q -f qcow2 "$LAB_DIR/$n-data$i.qcow2" "${d}G"
    args+=(--disk "path=$LAB_DIR/$n-data$i.qcow2,format=qcow2,bus=virtio,serial=sflab-data$i")
  done
  seed=$(make_seed "$n" "$image")
  args+=(--disk "path=$seed,device=cdrom,bus=sata,readonly=on")
  virt-install --print-xml --import --name "$n" --osinfo "$osinfo" --vcpus "$vcpu" --memory "$ram" --cpu host-passthrough \
    --network "network=$NET,mac=$(mac_of "$ip"),model=virtio" --graphics none --video vga --console pty,target_type=serial \
    --rng /dev/urandom --noautoconsole "${args[@]}" >"$STATE/$n.xml" 2>"$STATE/$n.err" \
    || { cat "$STATE/$n.err" >&2; die "$n: virt-install failed"; }
  virsh -q define "$STATE/$n.xml" >/dev/null
  virsh -q metadata "$n" "$META_URI" --key sflab --set '<lab/>' --config >/dev/null
}

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
  while [ $SECONDS -lt $until ]; do
    if lab_ssh "$n" true 2>/dev/null; then
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
    [ "$(lab_ssh "$n" uname -n)" = "$n" ] || die "$n: host name is $(lab_ssh "$n" uname -n)"
  done
  dup=$(for n in "$@"; do lab_ssh "$n" 'cat /etc/machine-id 2>/dev/null' || true; done | grep . | sort | uniq -d)
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

node_disks() { ls "$LAB_DIR/$1"-*.qcow2; }
has_golden() { qemu-img snapshot -U -l "$LAB_DIR/$1-root.qcow2" 2>/dev/null | grep -qw golden; }

stop_vm() {  # clean shutdown from inside, so nothing is left in a guest's cache, then force
  local n=$1 i
  [ "$(state "$n")" = running ] || return 0
  lab_ssh "$n" 'sudo -n sync; sudo -n poweroff' >/dev/null 2>&1 || true
  for i in $(seq 1 30); do [ "$(state "$n")" = 'shut off' ] && return 0; sleep 2; done
  virsh -q destroy "$n" >/dev/null
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
  local want=("$@") all=0 n
  if [ ${#want[@]} = 0 ]; then mapfile -t want < <(nodes | cut -d'|' -f1); all=1; fi
  for n in "${want[@]}"; do is_node "$n" || die "$n is not in nodes.conf"; done
  preflight "${want[@]}"
  ensure_state; ensure_images "${want[@]}"; ensure_network; ensure_pool
  for n in "${want[@]}"; do
    exists "$n" || { say "$n: creating"; create_node "$n"; }
    [ "$(state "$n")" = running ] || virsh -q start "$n" >/dev/null
  done
  say "waiting for first boot to finish"
  wait_all "${want[@]}" || die 'some VMs did not come up: see above. Fix or use down.'
  check_identity "${want[@]}"
  say 'provisioning storage and seed data'
  provision_all "${want[@]}" || die 'some VMs were not provisioned: see above. Fix or use down.'
  if [ $all = 1 ]; then
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
  SSH_TIMEOUT=2 lab_ssh "$1" 'printf "yes|%s|%s\n" "$(awk "\$2==\"/\" {f=\$3} END {print f}" /proc/mounts)" "$(awk "NR>1 {print \$1}" /proc/swaps | tr "\n" " ")"' 2>/dev/null || echo 'no||'
}

cmd_status() {
  local json=${1:-} tmp n; tmp=$(mktemp -d)
  while IFS='|' read -r n _; do
    if exists "$n" && ours "$n" && [ "$(state "$n")" = running ] && [ -f "$STATE/id_ed25519" ]; then probe_node "$n" >"$tmp/$n" & fi
  done < <(nodes)
  wait
  [ "$json" = --json ] && printf '[' || printf '%-10s %-11s %-10s %-4s %-7s %-7s %s\n' VM IP STATE SSH ROOTFS GOLDEN SWAP
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
      printf '%-10s %-11s %-10s %-4s %-7s %-7s %s\n' "$n" "$ip" "$st" "$ssh_ok" "${fs:--}" "$golden" "${swap:--}"
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

cmd_test() {
  [ -f "$STATE/id_ed25519" ] || die 'no lab is running: use up'
  cd "$HERE/../.."
  SFLAB_STATE="$STATE" python3 -m unittest discover -s tests/lab -v
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
  test) lock; cmd_test ;;
  images) mapfile -t all < <(nodes | cut -d'|' -f1); ensure_images "${all[@]}" ;;
  install-launcher) cmd_install_launcher ;;
  *) sed -n '2,11p' "$0" | sed 's/^# \?//'; exit 2 ;;
esac
