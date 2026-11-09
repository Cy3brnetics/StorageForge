"""Managing libvirt: snapshots, editing a VM, networks and pools, and copying a VM to another libvirt host, as plan steps.

Each is a change plan step like any other: checked against the libvirt host's last infrastructure reading, reported first,
deployed and audited. The script looks at the host when it runs and changes only what differs.

    vm-snapshot          take or delete a snapshot. Disk-only by default, with the guest agent freezing the filesystems
                         first when it answers (or required, or off). Delete merges a disk-only snapshot back.
    vm-revert            back to a snapshot (destructive: what the disks hold since is lost). A disk-only one needs a libvirt that does it (12.9 does, 10.0 does not).
    vm-edit              vCPUs, memory, autostart, a disk added, grown or detached. Detaching keeps the file.
    libvirt-network      define, change or remove a network. A change to a running one applies when it next starts, or now
                         with restart (guests on it lose their network until they are restarted).
    libvirt-pool         define, change or remove a storage pool. Removing undefines it: its files and volumes stay.
    vm-send, vm-define   a copy of a VM as it is on another libvirt host: the source sends each disk through a send of its
                         own (receiving.py: a signed run on each side, a key that can do nothing else, the checksum checked
                         on both ends), live from a disk-only snapshot that is merged back after, or with the VM shut off.
                         The target then defines the VM from what the plan says, never from XML the source sent.

copy_plan() builds the two steps from the source's reading. Values reach the scripts through the field checks, as
shlex-quoted words, and nothing written here holds an apostrophe, which the script check refuses.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}')       # a VM, snapshot, network or pool name this module writes
changes.CHECKS['vmdisks'] = re.compile(r'[a-z]{2,4}:(virtio|sata|scsi|ide|usb):(qcow2|raw):[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}'
                                       r'(,[a-z]{2,4}:(virtio|sata|scsi|ide|usb):(qcow2|raw):[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}){0,15}')
changes.CHECKS['vmnics'] = re.compile(r'(network|bridge)=[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}:(virtio|e1000e|e1000|rtl8139):([0-9a-f]{2}(:[0-9a-f]{2}){5}|new)'
                                      r'(,(network|bridge)=[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}:(virtio|e1000e|e1000|rtl8139):([0-9a-f]{2}(:[0-9a-f]{2}){5}|new)){0,7}')
changes.CHECKS['dhcprange'] = re.compile(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}')
changes.CHECKS['osinfo'] = re.compile(r'[a-z][a-z0-9.]{0,40}')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
vsh() { virsh -c qemu:///system "$@"; }
vq() { vsh "$@" >/dev/null; }      # for try: its own message must still be seen when the command fails
TAB=$(printf "\t")
vm_reach() { # can this run read libvirt at all? A report runs as a user that may not: it says so, and --apply (root) looks
  vsh version >/dev/null 2>&1 && return 0
  if ((APPLY)); then conflict "cannot reach libvirt (qemu:///system) on $(uname -n)"; else missing "cannot read libvirt as $(id -un): --apply, as root, looks"; fi
  return 1
}
vm_exists() { vsh dominfo "$1" >/dev/null 2>&1; }
vm_state() { vsh domstate "$1" 2>/dev/null | head -n 1; }
vm_agent() { vsh qemu-agent-command "$1" "{\"execute\":\"guest-ping\"}" --timeout 5 >/dev/null 2>&1; }
vm_libvirt() { # the version of the libvirt daemon, as major.minor
  local v=
  v=$(vsh version --daemon 2>/dev/null | sed -n "s/^Running against daemon: *\([0-9]*\.[0-9]*\).*/\1/p" | head -n 1)
  [[ -n $v ]] || v=$(vsh version 2>/dev/null | sed -n "s/^Using library: libvirt *\([0-9]*\.[0-9]*\).*/\1/p" | head -n 1)
  echo "${v:-?}"
}
vm_snap_external() { vsh snapshot-dumpxml "$1" "$2" 2>/dev/null | sed "/<domain[ >]/,\$d" | grep -c "snapshot=.external." >/dev/null; }
vm_quiesce() { # name auto|require|off: QUIESCE is the flag for snapshot-create-as. Fails when require cannot be met
  QUIESCE=
  [[ $2 == off ]] && return 0
  [[ $(vm_state "$1") == running ]] || return 0
  if vm_agent "$1"; then QUIESCE=--quiesce; return 0; fi
  [[ $2 != require ]]
}
vm_how() { if [[ -n $QUIESCE ]]; then echo "its filesystems frozen by the guest agent"; elif [[ $(vm_state "$1") == running ]]; then echo "crash-consistent: no guest agent answered"; else echo "while it is off"; fi; }
vm_disks() { # name -> target and source of each disk that is a file or a block device, by tabs
  vsh domblklist "$1" --details 2>/dev/null | awk "\$2 == \"disk\" && (\$1 == \"file\" || \$1 == \"block\") { print \$3 \"\t\" \$4 }"
}
vm_wait_off() { local i=; for ((i = 0; i < ${2:-120}; i += 2)); do [[ $(vm_state "$1") == "shut off" ]] && return 0; sleep 2; done; return 1; }

t_vm_snapshot() { local name=$1 snap=${2:-sf-$STAMP} action=${3:-create} disk=$4 q=${5:-auto} args=(--atomic) how= have= x=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  vm_exists "$name" || { later "there is no VM $name here"; return 0; }
  if [[ $action == delete ]]; then
    vsh snapshot-info "$name" "$snap" >/dev/null 2>&1 || { ok "$name has no snapshot $snap"; return 0; }
    act "delete snapshot $snap of $name (a disk-only one is merged back into its disks)" || return 0
    try vq snapshot-delete "$name" "$snap" && ok "deleted $snap"
    return 0
  fi
  if vsh snapshot-info "$name" "$snap" >/dev/null 2>&1; then ok "$name has a snapshot $snap"; return 0; fi
  # the two kinds do not mix: libvirt cannot delete an internal snapshot over overlays, or a disk-only one with internal ones beside it
  have=$(vsh snapshot-list "$name" --name 2>/dev/null | while read -r x; do [[ -n $x ]] || continue; if vm_snap_external "$name" "$x"; then echo external; else echo internal; fi; done | sort -u | paste -sd" " -)
  if [[ -n $disk && $have == *internal* ]]; then conflict "$name has internal snapshots: delete them first, or take this one with its memory (disk-only off)"; return 0; fi
  if [[ -z $disk && $have == *external* ]]; then conflict "$name has disk-only snapshots: take this one disk-only too"; return 0; fi
  if [[ -n $disk ]]; then
    vm_quiesce "$name" "$q" || { conflict "the guest agent of $name does not answer, and this snapshot must freeze its filesystems first"; return 0; }
    args+=(--disk-only); [[ -n $QUIESCE ]] && args+=("$QUIESCE")
    how="disk-only, $(vm_how "$name")"
  else
    QUIESCE=; how="with its memory, internal"
  fi
  act "snapshot $name as $snap ($how)" || return 0
  try vq snapshot-create-as "$name" "$snap" "${args[@]}" || return 0
  # before libvirt 11.10 the overlays of a VM that is off were made readable by everyone (CVE-2025-13193): they hold its disk writes
  if [[ -n $disk && $(vm_state "$name") == "shut off" ]]; then
    vm_disks "$name" | cut -f2 | while read -r x; do [[ $x == *."$snap" && -f $x ]] && chmod go= -- "$x"; done
  fi
  ok "snapshot $snap of $name ($how)"
}

t_vm_revert() { local name=$1 snap=$2 start=$3 args=() out=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  vm_exists "$name" || { later "there is no VM $name here"; return 0; }
  vsh snapshot-info "$name" "$snap" >/dev/null 2>&1 || { conflict "$name has no snapshot $snap"; return 0; }
  [[ -n $start ]] && args+=(--running)
  act "revert $name to $snap: what its disks hold since then is lost${start:+, then start it}" || return 0
  if out=$(vsh snapshot-revert "$name" "$snap" ${args[@]+"${args[@]}"} 2>&1); then ok "$name is back at $snap, and $(vm_state "$name")"
  elif [[ $out == *disk-snapshot* || $out == *"external snapshot not supported"* ]]; then
    conflict "libvirt $(vm_libvirt) here cannot go back to a disk-only snapshot (libvirt 12.9 can): $name is as it was. On this host, revert snapshots taken with memory (disk-only off)"
  else conflict "the revert failed: $(tail -n 2 <<<"$out" | tr "\n" " ")"; fi
}

vm_kib() { vsh dumpxml --inactive "$1" | sed -n "s|.*<$2 unit=.KiB.>\([0-9]*\)</$2>.*|\1|p" | head -n 1; }
vm_cfg() { if [[ $(vm_state "$1") == running ]]; then echo "--config --live"; else echo "--config"; fi; }
t_vm_edit() { local name=$1 vcpus=$2 mem=$3 auto=$4 add=$5 label=${6:-extra} grow=$7 to=$8 rm=$9 restart=${10} changed=0 cur= max= kib= want= dir= t= f= have= cap= bytes=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  vm_exists "$name" || { later "there is no VM $name here"; return 0; }
  if [[ -n $vcpus ]]; then
    max=$(vsh vcpucount "$name" --config --maximum 2>/dev/null); cur=$(vsh vcpucount "$name" --config --current 2>/dev/null)
    if [[ $max == "$vcpus" && $cur == "$vcpus" ]]; then ok "$vcpus vCPUs"
    elif act "$vcpus vCPUs (now $cur)"; then
      if ((vcpus > max)); then try vq setvcpus "$name" "$vcpus" --config --maximum || return 0; fi
      try vq setvcpus "$name" "$vcpus" --config || return 0
      if ((vcpus < max)); then try vq setvcpus "$name" "$vcpus" --config --maximum || return 0; fi
      changed=1; ok "$vcpus vCPUs"
    fi
  fi
  if [[ -n $mem ]]; then
    want=$((mem * 1024)); kib=$(vm_kib "$name" memory); cur=$(vm_kib "$name" currentMemory)
    if [[ $kib == "$want" && ${cur:-$kib} == "$want" ]]; then ok "$mem MiB of memory"
    elif act "$mem MiB of memory (now $((${kib:-0} / 1024)) MiB)"; then
      if ((want > ${kib:-0})); then try vq setmaxmem "$name" "${mem}M" --config && try vq setmem "$name" "${mem}M" --config || return 0
      else try vq setmem "$name" "${mem}M" --config && try vq setmaxmem "$name" "${mem}M" --config || return 0; fi
      changed=1; ok "$mem MiB of memory"
    fi
  fi
  if [[ -n $auto ]]; then
    have=$(vsh dominfo "$name" | sed -n "s/^Autostart: *//p")
    if [[ ($auto == on && $have == enable) || ($auto == off && $have == disable) ]]; then ok "autostart $auto"
    elif act "autostart $auto"; then
      if [[ $auto == on ]]; then try vq autostart "$name"; else try vq autostart "$name" --disable; fi && ok "autostart $auto"
    fi
  fi
  if [[ -n $add ]]; then
    f=$(vm_disks "$name" | head -n 1 | cut -f2); dir=${f%/*}
    [[ -n $f && -d $dir ]] || { conflict "$name has no disk in a folder to put a new one beside"; return 0; }
    f=$dir/$name-$label.qcow2
    if vm_disks "$name" | cut -f2 | grep -Fxc -- "$f" >/dev/null; then ok "$f is attached"
    elif [[ -e $f ]]; then conflict "$f is there and is not a disk of $name: this step does not reuse a file"; return 0
    else
      for t in vd{b..z}; do vm_disks "$name" | cut -f1 | grep -xc "$t" >/dev/null || break; done
      if act "a new $add disk $f as $t"; then
        need qemu-img qemu-utils || return 0
        try qemu-img create -q -f qcow2 -- "$f" "$add" || return 0
        if ! vsh attach-disk "$name" "$f" "$t" --driver qemu --subdriver qcow2 --targetbus virtio $(vm_cfg "$name") >/dev/null; then
          rm -f -- "$f"; conflict "attaching $f failed, and the new file is removed"; return 0
        fi
        ok "a $add disk as $t: partition and format it in the guest"
      fi
    fi
  fi
  if [[ -n $grow ]]; then
    f=$(vm_disks "$name" | awk -v t="$grow" "\$1 == t { print \$2 }")
    [[ -n $f ]] || { conflict "$name has no disk $grow"; return 0; }
    bytes=$(numfmt --from=iec "$to" 2>/dev/null) || { conflict "$to is not a size"; return 0; }
    cap=$(vsh domblkinfo "$name" "$grow" 2>/dev/null | sed -n "s/^Capacity: *//p")
    if ((${cap:-0} >= bytes)); then ok "$grow is $((cap / 1073741824)) GiB already (a disk is never shrunk)"
    elif act "grow $grow of $name to $to"; then
      if [[ $(vm_state "$name") == running ]]; then try vq blockresize "$name" "$grow" "${bytes}B" || return 0
      else need qemu-img qemu-utils || return 0; try qemu-img resize -q -- "$f" "$bytes" || return 0; fi
      ok "$grow is $to: the guest grows its partition and filesystem itself (cloud images do it at boot)"
    fi
  fi
  if [[ -n $rm ]]; then
    f=$(vm_disks "$name" | awk -v t="$rm" "\$1 == t { print \$2 }")
    if [[ -z $f ]]; then ok "$name has no disk $rm"
    elif act "detach $rm ($f) from $name, keeping the file"; then
      try vq detach-disk "$name" "$rm" $(vm_cfg "$name") && ok "detached $rm: $f is still there"
    fi
  fi
  if ((changed)) && [[ $(vm_state "$name") == running ]]; then
    if [[ -z $restart ]]; then info "vCPUs and memory change when $name next starts"
    elif act "restart $name for its new vCPUs and memory: a clean shutdown, then start"; then
      vsh shutdown "$name" >/dev/null 2>&1
      if vm_wait_off "$name" 180; then try vq start "$name" && ok "$name restarted"
      else conflict "$name did not shut down in 3 minutes: the change applies when it next starts"; fi
    fi
  fi
}

mask_bits() { local m=$1 n=0 o=; [[ $m =~ ^[0-9]+$ ]] && { echo "$m"; return; }; IFS=. read -ra o <<<"$m"; for m in "${o[@]}"; do while ((m & 128)); do ((n++)); m=$(((m << 1) & 255)); done; done; echo "$n"; }
net_sig() { # a network XML on stdin -> mode, bridge it forwards to, address/prefix and DHCP range, the parts this step sets
  local x= mode= br= ip= pre= lo= hi=
  x=$(tr "\n" " " | sed "s/>[[:space:]]*</></g")
  mode=$(grep -o "<forward[^>]*>" <<<"$x" | head -n 1 | grep -o "mode=.[a-z]*" | cut -c7-)
  [[ -z $mode ]] && grep -q "<forward" <<<"$x" && mode=nat
  [[ -z $mode ]] && mode=isolated
  br=$(grep -o "<bridge [^>]*name=.[A-Za-z0-9_.@:-]*" <<<"$x" | head -n 1 | sed "s/.*name=.//")
  ip=$(grep -o "<ip [^>]*>" <<<"$x" | head -n 1)
  pre=$(grep -o "prefix=.[0-9]*" <<<"$ip" | cut -c9-); [[ -z $pre ]] && pre=$(mask_bits "$(grep -o "netmask=.[0-9.]*" <<<"$ip" | cut -c10-)")
  ip=$(grep -o "address=.[0-9.]*" <<<"$ip" | cut -c10-)
  lo=$(grep -o "<range [^>]*" <<<"$x" | head -n 1 | grep -o "start=.[0-9.]*" | cut -c8-); hi=$(grep -o "<range [^>]*" <<<"$x" | head -n 1 | grep -o "end=.[0-9.]*" | cut -c6-)
  [[ $mode == bridge ]] || br=-
  printf "%s|%s|%s|%s\n" "$mode" "$br" "${ip:+$ip/$pre}" "${lo:+$lo-$hi}"
}
net_users() { local d=; vsh list --all --name 2>/dev/null | while read -r d; do [[ -n $d ]] && vsh dumpxml --inactive "$d" 2>/dev/null | grep -c "<source network=.$1.[ /]" >/dev/null && printf "%s " "$d"; done; return 0; }
t_libvirt_network() { local name=$1 mode=${2:-nat} br=$3 addr=$4 dhcp=$5 auto=$6 restart=$7 state=${8:-present} xml= uuid= want= have= users= f= active=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  if [[ $state == absent ]]; then
    vsh net-info "$name" >/dev/null 2>&1 || { ok "there is no network $name"; return 0; }
    users=$(net_users "$name")
    [[ -z $users ]] || { conflict "VMs use network $name: $users"; return 0; }
    act "stop and remove network $name" || return 0
    vsh net-destroy "$name" >/dev/null 2>&1
    try vq net-undefine "$name" && ok "network $name removed"
    return 0
  fi
  want=$(printf "%s|%s|%s|%s" "$mode" "$([[ $mode == bridge ]] && echo "$br" || echo -)" "$addr" "$dhcp")
  if vsh net-info "$name" >/dev/null 2>&1; then
    have=$(vsh net-dumpxml --inactive "$name" | net_sig)
    uuid=$(vsh net-uuid "$name" 2>/dev/null)
  fi
  xml="<network><name>$name</name>${uuid:+<uuid>$uuid</uuid>}"
  case $mode in
    nat|route) xml+="<forward mode=\"$mode\"/>" ;;
    bridge) xml+="<forward mode=\"bridge\"/>" ;;
  esac
  [[ -n $br ]] && xml+="<bridge name=\"$br\"/>"
  if [[ $mode != bridge && -n $addr ]]; then
    xml+="<ip address=\"${addr%/*}\" prefix=\"${addr#*/}\">"
    [[ -n $dhcp ]] && xml+="<dhcp><range start=\"${dhcp%-*}\" end=\"${dhcp#*-}\"/></dhcp>"
    xml+="</ip>"
  fi
  xml+="</network>"
  f=$(mktemp) || { conflict "no temporary file"; return 0; }
  printf "%s\n" "$xml" >"$f"
  if [[ -z $have ]]; then
    if act "define network $name ($mode${addr:+ $addr}${dhcp:+, DHCP $dhcp}${br:+, bridge $br}) and start it"; then
      try vq net-define "$f" && try vq net-start "$name" && ok "network $name is up"
    fi
  elif [[ $have == "$want" ]]; then ok "network $name is $mode${addr:+ $addr}${dhcp:+, DHCP $dhcp}"
  elif act "change network $name to $mode${addr:+ $addr}${dhcp:+, DHCP $dhcp} (it is ${have//|/ })"; then
    if try vq net-define "$f"; then
      active=$(vsh net-info "$name" | sed -n "s/^Active: *//p")
      if [[ $active != yes ]]; then ok "redefined: it applies when $name starts"
      elif [[ -n $restart ]]; then
        users=$(vsh list --name 2>/dev/null | while read -r d; do [[ -n $d ]] && vsh dumpxml "$d" | grep -c "<source network=.$name.[ /]" >/dev/null && printf "%s " "$d"; done)
        vsh net-destroy "$name" >/dev/null && try vq net-start "$name" && ok "restarted with the new definition${users:+: $users lost the network until they are restarted}"
      else info "redefined: it applies when $name next starts (or with restart)"; fi
    fi
  fi
  rm -f -- "$f"
  if vsh net-info "$name" >/dev/null 2>&1 && [[ $(vsh net-info "$name" | sed -n "s/^Active: *//p") != yes ]]; then
    act "start network $name" && try vq net-start "$name" && ok "network $name is up"
  fi
  if vsh net-info "$name" >/dev/null 2>&1; then
    have=$(vsh net-info "$name" | sed -n "s/^Autostart: *//p")
    if [[ -n $auto && $have == yes ]] || [[ -z $auto && $have == no ]]; then ok "autostart $([[ -n $auto ]] && echo on || echo off)"
    elif act "autostart $([[ -n $auto ]] && echo on || echo off) for network $name"; then
      if [[ -n $auto ]]; then try vq net-autostart "$name"; else try vq net-autostart "$name" --disable; fi && ok "autostart $([[ -n $auto ]] && echo on || echo off)"
    fi
  fi
}

pool_users() { # pool path -> VMs with a disk in it
  local d=; [[ -n $1 ]] || return 0
  vsh list --all --name 2>/dev/null | while read -r d; do [[ -n $d ]] && vm_disks "$d" | cut -f2 | grep -c -- "^$1/" >/dev/null && printf "%s " "$d"; done; return 0
}
t_libvirt_pool() { local name=$1 type=${2:-dir} path=$3 src=$4 auto=$5 state=${6:-present} xml= uuid= have_t= have_p= have_s= f= users= d=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  if vsh pool-info "$name" >/dev/null 2>&1; then
    xml=$(vsh pool-dumpxml --inactive "$name" | tr "\n" " " | sed "s/>[[:space:]]*</></g")
    have_t=$(grep -o "<pool type=.[a-z]*" <<<"$xml" | cut -c13-)
    have_p=$(grep -o "<target><path>[^<]*" <<<"$xml" | cut -c15-)
    have_s=$(grep -o "<source>.*</source>" <<<"$xml" | grep -o "<name>[^<]*" | head -n 1 | cut -c7-)
    uuid=$(vsh pool-uuid "$name" 2>/dev/null)
  fi
  if [[ $state == absent ]]; then
    [[ -n $have_t ]] || { ok "there is no pool $name"; return 0; }
    users=$(pool_users "$have_p")
    [[ -z $users ]] || { conflict "VMs have disks in pool $name: $users"; return 0; }
    act "stop and undefine pool $name: its files${have_s:+ and volume group or dataset $have_s} stay" || return 0
    vsh pool-destroy "$name" >/dev/null 2>&1
    try vq pool-undefine "$name" && ok "pool $name undefined, and $have_p is as it was"
    return 0
  fi
  case $type in
    dir) xml="<pool type=\"dir\"><name>$name</name>${uuid:+<uuid>$uuid</uuid>}<target><path>$path</path></target></pool>" ;;
    logical) path=/dev/$src; xml="<pool type=\"logical\"><name>$name</name>${uuid:+<uuid>$uuid</uuid>}<source><name>$src</name><format type=\"lvm2\"/></source><target><path>$path</path></target></pool>" ;;
    zfs) xml="<pool type=\"zfs\"><name>$name</name>${uuid:+<uuid>$uuid</uuid>}<source><name>$src</name></source></pool>" ;;
  esac
  if [[ -n $have_t ]]; then
    if [[ $have_t != "$type" ]]; then conflict "pool $name is $have_t, not $type: remove it first"; return 0; fi
    if [[ $type == dir && $have_p != "$path" ]]; then
      # anything in the folder: libvirt lists only what it takes for a volume, and vol-list --name is not in every version
      [[ -z $(find "$have_p" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1) ]] || { conflict "pool $name holds volumes or files in $have_p: move them first, this step does not"; return 0; }
      if act "point pool $name at $path (it is $have_p)"; then
        f=$(mktemp) && printf "%s\n" "$xml" >"$f" && mkdir -p -- "$path" && try vq pool-define "$f" && rm -f -- "$f" || return 0
        if vsh pool-info "$name" | grep -c "^State: *running" >/dev/null; then vsh pool-destroy "$name" >/dev/null && try vq pool-start "$name"; fi
        ok "pool $name is $path"
      fi
    elif [[ $type != dir && $have_s != "$src" ]]; then conflict "pool $name is on $have_s, not $src: remove it first"; return 0
    else ok "pool $name is $type ${path:-$src}"; fi
  else
    case $type in
      dir) [[ -d $path ]] || { [[ -e $path ]] && { conflict "$path is there and is not a folder"; return 0; }; } ;;
      logical) need vgs lvm2 || return 0; vgs -- "$src" >/dev/null 2>&1 || { later "volume group $src must exist"; return 0; } ;;
      zfs) need zfs zfsutils-linux || return 0; zfs list -H -o name -- "$src" >/dev/null 2>&1 || { later "dataset $src must exist"; return 0; } ;;
    esac
    if act "define pool $name ($type ${path:-$src}) and start it"; then
      f=$(mktemp) || return 0; printf "%s\n" "$xml" >"$f"
      [[ $type == dir ]] && { try mkdir -p -- "$path" || return 0; }
      try vq pool-define "$f" && try vq pool-start "$name" && ok "pool $name is up"
      rm -f -- "$f"
    fi
  fi
  if vsh pool-info "$name" >/dev/null 2>&1 && [[ $(vsh pool-info "$name" | sed -n "s/^State: *//p") != running ]]; then
    act "start pool $name" && try vq pool-start "$name" && ok "pool $name is up"
  fi
  if vsh pool-info "$name" >/dev/null 2>&1; then
    d=$(vsh pool-info "$name" | sed -n "s/^Autostart: *//p")
    if [[ -n $auto && $d == yes ]] || [[ -z $auto && $d == no ]]; then ok "autostart $([[ -n $auto ]] && echo on || echo off)"
    elif act "autostart $([[ -n $auto ]] && echo on || echo off) for pool $name"; then
      if [[ -n $auto ]]; then try vq pool-autostart "$name"; else try vq pool-autostart "$name" --disable; fi && ok "autostart $([[ -n $auto ]] && echo on || echo off)"
    fi
  fi
}

# ── a copy of a VM to another libvirt host: the source side sends its disks ──
vm_commit() { # name: merge the overlays of a copy snapshot back, and remove them
  local t= f= bad=0
  while IFS=$TAB read -r t f; do
    [[ $f == *.sfcopy-* ]] || continue
    if vsh blockcommit "$1" "$t" --active --pivot --shallow --wait >/dev/null 2>&1; then rm -f -- "$f"
    else bad=1; conflict "$t of $1 still runs on $f: merge it with virsh blockcommit $1 $t --active --pivot --shallow"; fi
  done < <(vm_disks "$1")
  return $bad
}
t_vm_send() { local name=$1 dir=$3 live=$4 q=${5:-auto} as=${6:-$1} st= t= f= fmt= n= x= want= snap=sfcopy-$STAMP flat= sent=0 failed=0 todo=0 plan=() qi=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  need qemu-img qemu-utils || return 0
  send_to vm "$7" "$8" "$9" "$dir"
  send_reach || return 0
  vm_exists "$name" || { later "there is no VM $name here"; return 0; }
  st=$(vm_state "$name")
  if [[ $st != "shut off" && -z $live ]]; then conflict "$name is $st: shut it down first, or let the copy be taken live from a snapshot"; return 0; fi
  while IFS=$TAB read -r t f; do
    [[ $f == *.sfcopy-* ]] && { conflict "$name runs on $f, an overlay an earlier copy left: merge it first (virsh blockcommit $name $t --active --pivot --shallow)"; return 0; }
    qi=$(qemu-img info -U -- "$f" 2>/dev/null) || { conflict "qemu-img cannot read $f"; return 0; }
    fmt=$(sed -n "s/^file format: *//p" <<<"$qi" | head -n 1)
    grep -q "^backing file:" <<<"$qi" && fmt=flatten
    if [[ $st != "shut off" && ! -f $f ]]; then conflict "$t of $name is the block device $f: a live copy takes files only, so shut $name down first"; return 0; fi
    plan+=("$t|$f|$fmt")
  done < <(vm_disks "$name")
  ((${#plan[@]})) || { conflict "$name has no disk to copy"; return 0; }
  for x in "${plan[@]}"; do
    IFS="|" read -r t f fmt <<<"$x"
    n=$as-$t.$([[ $fmt == raw ]] && echo raw || echo qcow2)
    if ! st=$(there recv-state "$n"); then conflict "could not look at $dir/$n on $(there_name)"; return 0; fi
    case $st in
      done\ *) ok "$dir/$n is on $(there_name) already"; continue ;;
      partial) there recv-discard "$n" >/dev/null 2>&1 || { conflict "$dir/$n on $(there_name) is an unfinished copy that could not be removed"; return 0; } ;;
      other) conflict "$dir/$n is on $(there_name), and it is not a copy this step made"; return 0 ;;
    esac
    todo=$((todo + 1))
  done
  ((todo)) || return 0
  if [[ $(vm_state "$name") != "shut off" ]]; then
    vm_quiesce "$name" "$q" || { conflict "the guest agent of $name does not answer, and this copy must freeze its filesystems first"; return 0; }
    act "copy $name live to $dir on $(there_name): a disk-only snapshot ($(vm_how "$name")), each disk sent and checked, then the snapshot merged back" || return 0
    try vq snapshot-create-as "$name" "$snap" --disk-only --atomic --no-metadata ${QUIESCE:+"$QUIESCE"} || return 0
  else
    act "copy $name, shut off, to $dir on $(there_name): each disk sent and checked" || return 0
  fi
  there recv-mkdir || { conflict "cannot make $dir on $(there_name)"; vm_commit "$name"; return 0; }
  for x in "${plan[@]}"; do
    IFS="|" read -r t f fmt <<<"$x"
    n=$as-$t.$([[ $fmt == raw ]] && echo raw || echo qcow2)
    [[ $(there recv-state "$n" 2>/dev/null) == done\ * ]] && continue
    flat=
    if [[ $fmt == flatten ]]; then     # an overlay on a base image: sent whole, as one qcow2 file the target needs nothing else for
      flat=${f%/*}/.sfcopy-$STAMP-$t.qcow2
      if ! qemu-img convert -U -O qcow2 -- "$f" "$flat"; then rm -f -- "$flat"; conflict "could not make a whole copy of $f beside it (room?)"; failed=1; break; fi
      f=$flat
    fi
    want=$(sha256sum <"$f" | cut -c1-64)
    if send_stream "$n" "$want" cat -- "$f"; then ok "$t: $n, checked on both ends"; sent=$((sent + 1))
    else conflict "$t did not arrive whole, and what it left on $(there_name) is removed: see above"; failed=1; fi
    [[ -n $flat ]] && rm -f -- "$flat"
    ((failed)) && break
  done
  [[ $(vm_state "$name") != "shut off" ]] && { vm_commit "$name" && ok "the snapshot is merged back: $name runs on its own disks"; }
  if vm_disks "$name" | cut -f2 | grep -c "\.sfcopy-" >/dev/null; then vm_commit "$name"; fi
  ((failed)) || ok "$name: ${#plan[@]} disk(s) on $(there_name) in $dir, ready for the VM there"
}

# ── the target side: define the copy from what the plan says ──
t_vm_define() { local name=$1 dir=$2 disks=$3 vcpus=${4:-1} mem=${5:-1024} fw=$6 cpu=${7:-host-model} nics=$8 os=$9 machine=${10} gfx=${11:-none} tpm=${12} serial=${13} auto=${14} start=${15}
  local args=() d= t= bus= fmt= n= f= x= kind= src= model= mac= tmp=
  need virsh libvirt-clients || return 0
  vm_reach || return 0
  need virt-install virtinst || return 0
  if vm_exists "$name"; then
    IFS=, read -ra d <<<"$disks"; IFS=: read -r t bus fmt n <<<"${d[0]}"
    if vm_disks "$name" | cut -f2 | grep -Fxc -- "$dir/$n" >/dev/null; then ok "VM $name is defined, on $dir/$n"; else conflict "a VM named $name is here, and its disks are not the copy: give the copy another name"; fi
    return 0
  fi
  IFS=, read -ra d <<<"$disks"
  for x in "${d[@]}"; do
    IFS=: read -r t bus fmt n <<<"$x"
    f=$dir/$n
    if [[ ! -f $f ]]; then later "$f must be here: the step before sends it"; return 0; fi
    [[ -f $dir/.$n.sf-sha256 ]] || info "$f has no checksum from a send beside it: copied by hand?"
    args+=(--disk "path=$f,format=$fmt,bus=$bus,target.dev=$t")
  done
  IFS=, read -ra d <<<"$nics"
  for x in "${d[@]}"; do
    src=${x%%:*}; x=${x#*:}; model=${x%%:*}; mac=${x#*:}
    kind=${src%%=*}; src=${src#*=}
    if [[ $kind == network ]] && ! vsh net-info "$src" >/dev/null 2>&1; then later "network $src must be here"; return 0; fi
    if [[ $kind == network && -n $start && $(vsh net-info "$src" | sed -n "s/^Active: *//p") != yes ]]; then
      conflict "network $src is here but not running, and the copy is to start on it: start it first (Define or change a libvirt network)"; return 0
    fi
    args+=(--network "$kind=$src,model=$model${mac:+$([[ $mac == new ]] || echo ",mac=$mac")}")
  done
  ((${#d[@]})) || args+=(--network none)
  [[ $fw == uefi ]] && args+=(--boot uefi)
  [[ -n $machine ]] && args+=(--machine "$machine")
  [[ -n $tpm ]] && args+=(--tpm emulator)
  case $gfx in
    spice|vnc) args+=(--graphics "$gfx,listen=127.0.0.1") ;;
    *) args+=(--graphics none) ;;
  esac
  [[ -n $serial ]] && args+=(--console pty,target_type=serial)
  if [[ -n $os ]] && ! virt-install --osinfo list 2>/dev/null | grep -wFc -- "$os" >/dev/null; then info "this host does not know the OS $os (its osinfo database is older): generic defaults"; os=; fi
  act "define VM $name from $disks (${vcpus} vCPUs, $mem MiB${start:+, then start it})" || return 0
  tmp=$(mktemp) || { conflict "no temporary file"; return 0; }
  if ! virt-install --connect qemu:///system --import --name "$name" --vcpus "$vcpus" --memory "$mem" --cpu "$cpu" --osinfo "${os:-detect=on,require=off}" \
      --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 "${args[@]}" --noautoconsole --print-xml >"$tmp" 2>"$tmp.err"; then
    conflict "virt-install refused: $(tail -n 2 "$tmp.err" | tr "\n" " ")"; rm -f -- "$tmp" "$tmp.err"; return 0
  fi
  try vq define "$tmp" || { rm -f -- "$tmp" "$tmp.err"; return 0; }
  rm -f -- "$tmp" "$tmp.err"
  ok "VM $name defined"
  [[ -n $auto ]] && try vq autostart "$name"
  if [[ -n $start ]]; then try vq start "$name" && ok "$name started"; fi
}
"""

QUIESCE = F('quiesce', 'choice', 'Freeze filesystems first', options=['auto', 'require', 'off'], default='auto')


def _reading(conn, h):
    from . import inframeasure
    return inframeasure.reading(conn, h['name']) if h else None


def _libvirt_ready(conn, h, say) -> dict | None:
    r = _reading(conn, h)
    if not r:
        say('warn', f'{h["name"] if h else "this host"} has no infrastructure reading yet: the script looks when it runs')
        return None
    if 'virsh' not in (r.get('tools') or []):
        say('crit', f'{h["name"]} has no virsh: install libvirt there first')
        return None
    if r.get('stale'):
        say('warn', 'the last infrastructure reading is old: measure the host again before relying on what it says')
    return r


def _vm(r, name):
    return next((d for d in (r or {}).get('libvirt') or [] if d.get('name') == name), None)


def _check_name(p, say, *keys):
    for k in keys:
        if p.get(k) and not NAME.fullmatch(p[k]):
            say('crit', f'{p[k]} is not a name this step takes: letters, digits, _ . + and -, up to 64')


def _check_snapshot(conn, c, h, p, say):
    _check_name(p, say, 'name', 'snapshot')
    r = _libvirt_ready(conn, h, say)
    vm = _vm(r, p['name'])
    if r and not vm:
        say('warn', f'there is no VM {p["name"]} in the last reading of {h["name"]}')
    snaps = {s['name']: s for s in (vm or {}).get('snapshots') or []}
    if p['action'] == 'delete':
        if not p['snapshot']:
            say('crit', 'name the snapshot to delete')
        elif vm and p['snapshot'] not in snaps:
            say('ok', f'{p["name"]} has no snapshot {p["snapshot"]} in the last reading: nothing to delete')
        elif snaps.get(p['snapshot'], {}).get('location') == 'external':
            say('note', 'a disk-only snapshot is merged back into the disks: the restore point goes, the data stays')
        return
    if p['snapshot'] and p['snapshot'] in snaps:
        say('ok', f'{p["name"]} has a snapshot {p["snapshot"]} already')
    if not p['disk_only']:
        say('note', 'an internal snapshot with memory: it fails on a UEFI VM whose firmware variables are a raw file, and cannot freeze filesystems')
        if vm and vm.get('firmware') == 'uefi':
            say('warn', f'{p["name"]} boots by UEFI: take a disk-only snapshot instead')
    elif vm:
        agent = vm.get('agent')
        if p['quiesce'] == 'off':
            say('note', 'crash-consistent: what was in flight in the guest is as after a power cut')
        elif agent == 'connected':
            say('ok', 'its guest agent answers: filesystems are frozen for the moment of the snapshot')
        elif p['quiesce'] == 'require':
            say('warn' if vm.get('state') == 'running' else 'note', f'the guest agent of {p["name"]} is {agent or "not set up"}: the snapshot is refused unless it answers' if vm.get('state') == 'running'
                else f'{p["name"]} is off: nothing to freeze')
        else:
            say('note', f'the guest agent is {agent or "not set up"}: without it the snapshot is crash-consistent (install qemu-guest-agent in the guest)'
                if vm.get('state') == 'running' else f'{p["name"]} is off: its disks are as it left them')
        say('note', 'disk-only: each disk gets an overlay file beside it, which delete merges back')


def _check_revert(conn, c, h, p, say):
    _check_name(p, say, 'name', 'snapshot')
    r = _libvirt_ready(conn, h, say)
    vm = _vm(r, p['name'])
    snaps = {s['name']: s for s in (vm or {}).get('snapshots') or []}
    if vm and p['snapshot'] not in snaps:
        say('crit', f'{p["name"]} has no snapshot {p["snapshot"]} in the last reading' + (f' (it has {", ".join(sorted(snaps))})' if snaps else ''))
    say('note', 'everything the disks hold since the snapshot is lost: --apply --destructive only')
    if snaps.get(p['snapshot'], {}).get('location') == 'external':
        say('note', 'a disk-only snapshot: not every libvirt goes back to one (12.9 does, 10.0 and 9.0 refuse, and the step says so). The VM is off after unless it is started')


def _check_edit(conn, c, h, p, say):
    _check_name(p, say, 'name', 'add_label')
    r = _libvirt_ready(conn, h, say)
    vm = _vm(r, p['name'])
    if r and not vm:
        say('warn', f'there is no VM {p["name"]} in the last reading of {h["name"]}')
    if not any(p.get(k) for k in ('vcpus', 'memory_mib', 'autostart', 'add_disk', 'grow_disk', 'remove_disk')):
        say('crit', 'nothing to change: give vCPUs, memory, autostart or a disk')
    if p['grow_disk'] and not p['grow_to']:
        say('crit', 'give the size to grow the disk to')
    if p['memory_mib'] and int(p['memory_mib']) < 256:
        say('warn', 'under 256 MiB: few systems boot')
    if vm:
        disks = {d.get('target') for d in vm.get('disks') or [] if d.get('device') == 'disk'}
        for k in ('grow_disk', 'remove_disk'):
            if p[k] and p[k] not in disks:
                say('crit', f'{p["name"]} has no disk {p[k]}' + (f' (it has {", ".join(sorted(x for x in disks if x))})' if disks else ''))
        if (p['vcpus'] or p['memory_mib']) and vm.get('state') == 'running':
            say('note', 'vCPUs and memory change when it next starts' + (': restart is on, so it is shut down cleanly and started' if p['restart'] else ''))
        if p['remove_disk'] and vm.get('state') == 'running':
            say('warn', f'{p["remove_disk"]} goes from a running VM: unmount it in the guest first. The file stays')
        if (vm.get('snapshots') or []) and (p['add_disk'] or p['grow_disk'] or p['remove_disk']):
            say('warn', f'{p["name"]} has snapshots: a disk changed now is not in them, and libvirt may refuse to grow a disk with an overlay')
    if p['grow_disk']:
        say('note', 'a disk is never shrunk: the guest grows its partition and filesystem itself')


def _check_network(conn, c, h, p, say):
    import ipaddress
    _check_name(p, say, 'name')
    r = _libvirt_ready(conn, h, say)
    nets = {n['name']: n for n in (r or {}).get('libvirt_networks') or []}
    if p['state'] == 'absent':
        users = [d['name'] for d in (r or {}).get('libvirt') or [] if any(n.get('type') == 'network' and n.get('source') == p['name'] for n in d.get('nics') or [])]
        if users:
            say('crit', f'VMs use network {p["name"]}: {", ".join(users)}')
        elif r and p['name'] not in nets:
            say('ok', f'there is no network {p["name"]}')
        return
    if p['mode'] == 'bridge':
        if not p['bridge']:
            say('crit', 'a bridged network needs the host bridge it uses, such as br0')
        if p['address'] or p['dhcp']:
            say('crit', 'a bridged network has no address or DHCP of its own: the LAN gives them')
        say('note', 'bridged: guests are on the LAN, and the host firewall does not see their traffic')
        return
    if p['address']:
        try:
            iface = ipaddress.ip_interface(p['address'])
        except ValueError:
            say('crit', f'{p["address"]} is not an address with its prefix')
            return
        if iface.version != 4:
            say('crit', 'IPv4 only for now')
            return
        if p['dhcp']:
            lo, hi = (ipaddress.ip_address(x) for x in p['dhcp'].split('-'))
            if lo not in iface.network or hi not in iface.network or lo > hi or iface.ip in (lo, hi) or lo <= iface.ip <= hi:
                say('crit', f'DHCP {p["dhcp"]} must be in {iface.network}, in order, and leave out {iface.ip}')
        for n in nets.values():
            if n['name'] != p['name'] and n.get('address'):
                try:
                    other = ipaddress.ip_interface(f'{n["address"]}/{n.get("netmask") or 24}')
                except ValueError:
                    continue
                if other.network.overlaps(iface.network):
                    say('crit', f'{iface.network} overlaps network {n["name"]} ({other.network})')
    elif p['dhcp']:
        say('crit', 'DHCP needs the address of the network')
    elif p['mode'] in ('nat', 'route'):
        say('warn', f'{p["mode"]} with no address: guests get none unless the network is given one')
    have = nets.get(p['name'])
    if have and have.get('active'):
        say('note', 'a change to it applies when it next starts' + (': restart is on, so guests on it lose their network until they are restarted' if p['restart'] else ', or with restart'))
    if p['mode'] == 'isolated':
        say('note', 'isolated: only the libvirt host reaches the guests on it')


def _check_pool(conn, c, h, p, say):
    _check_name(p, say, 'name')
    r = _libvirt_ready(conn, h, say)
    pools = {x['name']: x for x in (r or {}).get('libvirt_pools') or []}
    have = pools.get(p['name'])
    if p['state'] == 'absent':
        if have and have.get('path'):
            users = [d['name'] for d in (r or {}).get('libvirt') or [] if any((x.get('source') or '').startswith(have['path'].rstrip('/') + '/') for x in d.get('disks') or [])]
            if users:
                say('crit', f'VMs have disks in pool {p["name"]}: {", ".join(users)}')
        say('note', 'undefined only: the files, volume group or dataset stay')
        return
    if p['type'] == 'dir':
        if not p['path']:
            say('crit', 'a folder pool needs its folder')
        else:
            m = changes.mount_of(h, p['path']) if h else None
            if m and m.get('total') and m.get('used') is not None:
                say('ok', f'{p["path"]} is on {m.get("target") or m.get("mount") or "a filesystem"} with {(m["total"] - m["used"]) // 2**30} GiB free')
    elif not p['source']:
        say('crit', f'a {p["type"]} pool needs its {"volume group" if p["type"] == "logical" else "dataset"}')
    if have and have.get('type') and have['type'] != p['type']:
        say('crit', f'pool {p["name"]} is {have["type"]}: remove it first to make it {p["type"]}')
    for n, x in pools.items():
        if n != p['name'] and p['type'] == 'dir' and x.get('path') == p['path']:
            say('warn', f'pool {n} is that folder too')


def _check_send(conn, c, h, p, say):
    from . import receiving
    _check_name(p, say, 'name', 'as_name')
    if not p['dest'].startswith('/') or '/../' in p['dest'] + '/':
        say('crit', f'{p["dest"]} is not a folder')
    r = _libvirt_ready(conn, h, say)
    vm = _vm(r, p['name'])
    if r and not vm:
        say('crit', f'there is no VM {p["name"]} in the last reading of {h["name"]}')
    if vm:
        if vm.get('state') == 'running' and not p['live']:
            say('crit', f'{p["name"]} is running: shut it down before the copy, or take the copy live')
        elif vm.get('state') == 'running':
            say('note', 'live: a disk-only snapshot is taken, each disk is sent from it, and it is merged back. ' +
                ('The guest agent answers, so filesystems are frozen for that moment' if vm.get('agent') == 'connected'
                 else 'No guest agent answers, so the copy is as after a power cut'))
        for d in vm.get('disks') or []:
            if d.get('device') == 'disk' and d.get('backing'):
                say('note', f'{d.get("target")} is an overlay on a base image: it is sent whole, made beside it first, which takes room there')
    hs = changes.hosts(conn)
    for level, text in receiving.check(conn, hs, h, p['dest_host'], 'vm', p['dest']):
        say(level, text)


def _check_define(conn, c, h, p, say):
    _check_name(p, say, 'name')
    r = _libvirt_ready(conn, h, say)
    if r and _vm(r, p['name']):
        say('warn', f'a VM named {p["name"]} is on {h["name"]}: the step checks it is this copy, and otherwise stops')
    if r:
        nets = {n['name'] for n in r.get('libvirt_networks') or []}
        active = {n['name']: n.get('active') for n in r.get('libvirt_networks') or []}
        for x in filter(None, (p['nics'] or '').split(',')):
            kind, src = x.split(':')[0].split('=')
            if kind == 'network' and src not in nets:
                say('crit', f'there is no libvirt network {src} on {h["name"]}' + (f' (it has {", ".join(sorted(nets))})' if nets else ''))
            elif kind == 'network' and p['start'] and active.get(src) is False:
                say('crit', f'network {src} on {h["name"]} is not running, and the copy is to start on it: start it first')
        if (p['cpu'] or 'host-model') in ('host-passthrough', 'host-model'):
            say('note', 'the CPU is the model of this host: a guest built for CPU features this host lacks will not run')
    if any(x.split(':')[-1] != 'new' for x in filter(None, (p['nics'] or '').split(','))):
        say('warn', 'the copy keeps the MAC addresses of the source: run only one of the two on a network')
    say('note', 'defined from what this step says, with the disks a send left in its folder: no XML comes from the source')


def _shell(fn, args):
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in args)
        head = ('APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
                'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; need() { command -v "$1" >/dev/null || conflict "$1 is not installed"; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\n{fn} {call}\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


def _ansible_send(t):
    return {'name': changes.title(t), 'ansible.builtin.fail': {'msg': (
        'A VM copy is a send: a signed run on both hosts, with a key of its own and no root login between them. A playbook has neither: deploy this plan from StorageForge.')}}


SNAP_ARGS = ('name', 'snapshot', 'action', 'disk_only', 'quiesce')
REVERT_ARGS = ('name', 'snapshot', 'start')
EDIT_ARGS = ('name', 'vcpus', 'memory_mib', 'autostart', 'add_disk', 'add_label', 'grow_disk', 'grow_to', 'remove_disk', 'restart')
NET_ARGS = ('name', 'mode', 'bridge', 'address', 'dhcp', 'autostart', 'restart', 'state')
POOL_ARGS = ('name', 'type', 'path', 'source', 'autostart', 'state')
SEND_ARGS = ('name', 'dest_host', 'dest', 'live', 'quiesce', 'as_name')
DEFINE_ARGS = ('name', 'folder', 'disks', 'vcpus', 'memory_mib', 'firmware', 'cpu', 'nics', 'osinfo', 'machine', 'graphics', 'tpm', 'serial', 'autostart', 'start')

VM = F('name', 'name', 'VM', required=True)

changes.register('vm-snapshot', {'group': 'VMs', 'label': 'Take or delete a VM snapshot', 'fields': [
    VM, F('snapshot', 'name', 'Snapshot', placeholder='empty: sf-<date and time>'), F('action', 'choice', 'Take or delete', options=['create', 'delete'], default='create'),
    F('disk_only', 'bool', 'Disk only (an overlay per disk; works on UEFI VMs and can freeze filesystems)', default=True), QUIESCE],
    'help': 'Disk-only by default: the guest agent freezes the filesystems first when it answers. Delete merges a disk-only snapshot back into the disks.'},
    SNAP_ARGS, lambda p: (f'Delete snapshot {p["snapshot"]} of {p["name"]}' if p['action'] == 'delete'
                          else f'Snapshot {p["name"]}' + (f' as {p["snapshot"]}' if p['snapshot'] else '') + ('' if p['disk_only'] else ' (with memory)')),
    _check_snapshot, _shell('t_vm_snapshot', SNAP_ARGS))

changes.register('vm-revert', {'group': 'VMs', 'label': 'Revert a VM to a snapshot', 'destructive': True, 'fields': [
    VM, F('snapshot', 'name', 'Snapshot', required=True), F('start', 'bool', 'Start it after')],
    'help': 'What the disks hold since the snapshot is lost. A disk-only snapshot takes a libvirt that does it (12.9 does, 10.0 does not), and the VM is off after unless started.'},
    REVERT_ARGS, lambda p: f'Revert {p["name"]} to {p["snapshot"]}', _check_revert, _shell('t_vm_revert', REVERT_ARGS))

changes.register('vm-edit', {'group': 'VMs', 'label': 'Change a VM', 'fields': [
    VM, F('vcpus', 'number', 'vCPUs'), F('memory_mib', 'number', 'Memory, MiB'), F('autostart', 'choice', 'Autostart', options=['', 'on', 'off'], default=''),
    F('add_disk', 'size', 'Add a disk of', placeholder='20G'), F('add_label', 'name', 'Its file name ends', placeholder='extra'),
    F('grow_disk', 'name', 'Grow disk', placeholder='vda'), F('grow_to', 'size', 'To', placeholder='40G'), F('remove_disk', 'name', 'Detach disk (the file stays)', placeholder='vdc'),
    F('restart', 'bool', 'Restart it so vCPUs and memory change now')],
    'help': 'Empty fields stay as they are. vCPUs and memory change at the next start, or now with restart. A disk is never shrunk, and a detached one keeps its file.'},
    EDIT_ARGS, lambda p: f'Change VM {p["name"]}: ' + ', '.join(x for x in (
        p['vcpus'] and f'{p["vcpus"]} vCPUs', p['memory_mib'] and f'{p["memory_mib"]} MiB', p['autostart'] and f'autostart {p["autostart"]}',
        p['add_disk'] and f'add {p["add_disk"]} disk', p['grow_disk'] and f'grow {p["grow_disk"]} to {p["grow_to"]}', p['remove_disk'] and f'detach {p["remove_disk"]}') if x),
    _check_edit, _shell('t_vm_edit', EDIT_ARGS))

changes.register('libvirt-network', {'group': 'VMs', 'label': 'Define or change a libvirt network', 'fields': [
    F('name', 'name', 'Network', required=True), F('mode', 'choice', 'Kind', options=['nat', 'route', 'isolated', 'bridge'], default='nat'),
    F('bridge', 'iface', 'Bridge', placeholder='virbr10, or the host bridge for bridged'), F('address', 'cidr', 'Address of the host on it', placeholder='10.88.0.1/24'),
    F('dhcp', 'dhcprange', 'DHCP range', placeholder='10.88.0.100-10.88.0.200'), F('autostart', 'bool', 'Start at boot', default=True),
    F('restart', 'bool', 'Restart it now if it changes (guests on it lose their network until restarted)'),
    F('state', 'choice', 'Define or remove', options=['present', 'absent'], default='present')],
    'help': 'Made, or changed to what the fields say. A change to a running network applies when it next starts, or now with restart. One that VMs use is never removed.'},
    NET_ARGS, lambda p: f'Remove network {p["name"]}' if p['state'] == 'absent' else f'Network {p["name"]} ({p["mode"]}' + (f' {p["address"]}' if p['address'] else '') + ')',
    _check_network, _shell('t_libvirt_network', NET_ARGS))

changes.register('libvirt-pool', {'group': 'VMs', 'label': 'Define or change a storage pool', 'fields': [
    F('name', 'name', 'Pool', required=True), F('type', 'choice', 'Kind', options=['dir', 'logical', 'zfs'], default='dir'),
    F('path', 'path', 'Folder, for a folder pool', placeholder='/srv/vms'), F('source', 'dataset', 'Volume group or dataset', placeholder='vg0, or tank/vms'),
    F('autostart', 'bool', 'Start at boot', default=True), F('state', 'choice', 'Define or remove', options=['present', 'absent'], default='present')],
    'help': 'A folder, an LVM volume group or a ZFS dataset that is there. Removing a pool undefines it: files, volumes and data stay. One that VMs use is never removed.'},
    POOL_ARGS, lambda p: f'Remove pool {p["name"]}' if p['state'] == 'absent' else f'Pool {p["name"]} ({p["type"]} {p["path"] or p["source"]})',
    _check_pool, _shell('t_libvirt_pool', POOL_ARGS))

changes.register('vm-send', {'group': 'VMs', 'label': 'Send a VM to another libvirt host', 'fields': [
    VM, F('dest_host', 'host', 'To host', required=True), F('dest', 'path', 'Into the folder there', required=True, placeholder='/var/lib/libvirt/images'),
    F('live', 'bool', 'While it runs, from a disk-only snapshot merged back after'), QUIESCE, F('as_name', 'name', 'Name of the copy', placeholder='the same')],
    'help': 'Each disk goes through a send of its own and is checked on both ends. The VM on the other side comes from a Define the copy step there.'},
    SEND_ARGS, lambda p: f'Send VM {p["name"]} to {p["dest_host"]}:{p["dest"]}' + (' (live)' if p['live'] else ''), _check_send, _ansible_send)

changes.register('vm-define', {'group': 'VMs', 'label': 'Define the copy of a VM', 'fields': [
    VM, F('folder', 'path', 'Its disks are in', required=True), F('disks', 'vmdisks', 'Disks', required=True, placeholder='vda:virtio:qcow2:web-vda.qcow2'),
    F('vcpus', 'number', 'vCPUs', required=True), F('memory_mib', 'number', 'Memory, MiB', required=True),
    F('firmware', 'choice', 'Firmware', options=['bios', 'uefi'], default='bios'), F('cpu', 'choice', 'CPU', options=['host-model', 'host-passthrough', 'qemu64'], default='host-model'),
    F('nics', 'vmnics', 'Network', placeholder='network=default:virtio:new'), F('osinfo', 'osinfo', 'OS', placeholder='debian12'),
    F('machine', 'choice', 'Machine', options=['', 'q35', 'pc'], default=''), F('graphics', 'choice', 'Graphical console', options=['none', 'spice', 'vnc'], default='none'),
    F('tpm', 'bool', 'TPM'), F('serial', 'bool', 'Serial console', default=True), F('autostart', 'bool', 'Start at boot'), F('start', 'bool', 'Start it')],
    'help': 'Defines a VM on the disks a send left here, from these fields alone. Made by Copy to another host…, from the reading of the source.'},
    DEFINE_ARGS, lambda p: f'Define VM {p["name"]} on {p["folder"]}', _check_define, _shell('t_vm_define', DEFINE_ARGS))

changes.EXTRA_BASH.append(BASH)
changes.SEND_TYPES.append('vm-send')


# ── a copy of a VM, as the two steps of a plan ──────────────────────
BUSES = {'virtio', 'sata', 'scsi', 'ide', 'usb'}
MODELS = {'virtio', 'e1000e', 'e1000', 'rtl8139'}


def _machine(m: str | None) -> str:
    m = m or ''
    return 'q35' if 'q35' in m else 'pc' if m.startswith('pc') else ''


def _osinfo(url: str | None) -> str:
    """http://debian.org/debian/12 -> debian12, as virt-install takes it, when it is that simple."""
    if not url:
        return ''
    parts = url.rstrip('/').split('/')
    guess = (parts[-2] + parts[-1]).lower() if len(parts) >= 2 else ''
    guess = guess.replace('ubuntu', 'ubuntu', 1)
    return guess if changes.CHECKS['osinfo'].fullmatch(guess) else ''


def copy_plan(conn, source: str, vm: str, target: str, *, name: str = '', pool: str = '', live: bool = False, start: bool = False,
              keep_macs: bool = False, network: str = '') -> dict:
    """The plan that copies VM vm of libvirt host source to target: a send of its disks on the source, then the VM defined on
    the target from the source's last reading. Raises ValueError with what is missing."""
    from . import inframeasure
    from .moves import find_host
    hs = changes.hosts(conn)
    src, dst = find_host(hs, source), find_host(hs, target)
    if not src or not dst:
        raise ValueError(f'{source if not src else target} is not a host StorageForge knows')
    r, t = inframeasure.reading(conn, src['name']), inframeasure.reading(conn, dst['name'])
    if not r or not t:
        raise ValueError(f'{src["name"] if not r else dst["name"]} has no infrastructure reading: measure it first')
    d = _vm(r, vm)
    if not d:
        raise ValueError(f'there is no VM {vm} in the last reading of {src["name"]}')
    as_name = name or vm
    if not NAME.fullmatch(as_name):
        raise ValueError(f'{as_name} is not a name a copy can have')
    pools = {p['name']: p for p in t.get('libvirt_pools') or []}
    want = pool or ('default' if 'default' in pools else next(iter(pools), ''))
    if want not in pools or pools[want].get('type') != 'dir' or not pools[want].get('path'):
        raise ValueError(f'{dst["name"]} has no folder pool {want or "at all"}' + (f' (it has {", ".join(sorted(pools))})' if pools else ''))
    folder = pools[want]['path'].rstrip('/')
    disks, skipped = [], []
    for x in d.get('disks') or []:
        if x.get('device') != 'disk':
            skipped.append(x.get('target') or '?')
            continue
        fmt = 'raw' if x.get('format') == 'raw' and not x.get('backing') else 'qcow2'
        bus = x.get('bus') if x.get('bus') in BUSES else 'virtio'
        disks.append(f'{x["target"]}:{bus}:{fmt}:{as_name}-{x["target"]}.{fmt}')
    if not disks:
        raise ValueError(f'{vm} has no disk to copy')
    nets = {n['name'] for n in t.get('libvirt_networks') or []}
    nics = []
    for n in d.get('nics') or []:
        kind = 'bridge' if n.get('type') == 'bridge' else 'network'
        srcname = n.get('source') or 'default'
        if kind == 'network' and srcname not in nets:
            srcname = network or ('default' if 'default' in nets else srcname)
        mac = (n.get('mac') or 'new').lower() if keep_macs else 'new'
        nics.append(f'{kind}={srcname}:{n.get("model") if n.get("model") in MODELS else "virtio"}:{mac}')
    gfx = next((g.get('type') for g in d.get('graphics') or [] if g.get('type') in ('spice', 'vnc')), 'none')
    send = {'type': 'vm-send', 'host': src['name'], 'params': {'name': vm, 'dest_host': dst['name'], 'dest': folder, 'live': bool(live), 'quiesce': 'auto', 'as_name': as_name if as_name != vm else ''}}
    define = {'type': 'vm-define', 'host': dst['name'], 'params': {
        'name': as_name, 'folder': folder, 'disks': ','.join(disks), 'vcpus': str(d.get('vcpus') or 1), 'memory_mib': str(d.get('memory_mib') or 1024),
        'firmware': 'uefi' if d.get('firmware') == 'uefi' else 'bios', 'cpu': d.get('cpu_mode') if d.get('cpu_mode') in ('host-model', 'host-passthrough') else 'host-model',
        'nics': ','.join(nics), 'osinfo': _osinfo(d.get('osinfo')), 'machine': _machine(d.get('machine')), 'graphics': gfx,
        'tpm': bool(d.get('tpm')), 'serial': bool(d.get('serial', True)), 'autostart': bool(d.get('autostart')), 'start': bool(start)}}
    return {'name': f'Copy VM {vm} from {src["name"]} to {dst["name"]}' + (f' as {as_name}' if as_name != vm else ''), 'tasks': [send, define],
            'skipped': skipped}
