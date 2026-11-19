"""A second operating system installed over SSH, beside the one that is running (roadmap section 7, phase 8).

Three plan steps, each reported first and run by a person like any other:

    os-install   put a distribution's cloud image on a disk of the host, in unpartitioned space or on a blank disk
    os-boot      start it at the next restart only, always, or never; and restart
    os-remove    take it off again: its partitions and its boot entry

What os-install holds to:

    * The running system is not written to. Not its bootloader, not its boot partition, not its filesystems. The new system gets
      partitions of its own, an EFI partition among them, copied one for one from the image; the only thing changed outside them
      is one new boot entry in the firmware, and that entry is not put in the boot order.
    * Only empty space is used: the largest unpartitioned stretch of a GPT disk, or a disk with nothing on it at all. A disk with
      anything that is not a GPT, and a stretch too small, are refused. Nothing is shrunk.
    * The image is fetched by the host and checked against the checksum its publisher lists before a byte of it is used.
    * A name the image is found by at boot (a filesystem's UUID or label, a partition's UUID) that this host already has is refused:
      two filesystems answering to one name is how the wrong one gets mounted as root.
    * First boot is told who may log in from a folder inside the new system's own root (cloud-init's NoCloud seed), where only
      that system reads it. Not from a partition labelled for cloud-init: the running system would read that at its next start
      and take the new system's host name and keys for its own, which is what the first trial of this did.
    * By default the new system has the machine's SSH host keys: they are read and written by this script on the host, and never
      leave it. It is the same machine at the same address, and an SSH client that warned each time it was restarted into the
      other system would teach its owner to ignore the warning.

os-boot's `once` sets the firmware's BootNext. If the new system does not come up, the restart after that is the old system
again, with nothing to repair. UEFI only: a BIOS machine has one boot sector per disk, and it is the running system's.
"""
from __future__ import annotations

import shlex

from . import changes, steps_vm
from .changes import F

# Alpine's image starts from a BIOS boot sector and has no EFI partition
IMAGES = {k: v for k, v in steps_vm.IMAGES.items() if not k.startswith('alpine')}
LABEL = 'sf-'                       # the boot entry and the partition names start with this, then the system's name
SCRATCH_GIB = 6                     # the image, and its raw form while it is copied

INSTALL_FIELDS = [
    F('name', 'vmname', 'Name of the new system: its host name and its boot entry', required=True, placeholder='nas-fedora'),
    F('image', 'choice', 'Image', options=list(IMAGES) + ['custom'], required=True),
    F('image_url', 'url', 'Custom image URL (https)', placeholder='https://example.com/disk.qcow2'),
    F('image_sha', 'sha', 'Its SHA-256 or SHA-512'),
    F('disk', 'device', 'Disk to put it on (free space on it, or a blank disk)', required=True, placeholder='/dev/nvme0n1'), changes.CONFIRM,
    F('size_gb', 'number', 'Size of its root, GiB (empty: all the free space)', placeholder='40'),
    F('user', 'user', 'Login account', required=True, placeholder='admin'),
    F('ssh_key', 'pubkey', 'Its SSH public key', required=True, placeholder='ssh-ed25519 AAAA… you@laptop'),
    F('sudo', 'choice', 'sudo for that account', options=['nopasswd', 'none'], default='nopasswd'),
    F('host_keys', 'choice', 'SSH host keys', options=['same', 'new'], default='same'),
    F('network', 'choice', 'Network', options=['same', 'fixed', 'dhcp'], default='same'),
    F('carry', 'choice', 'Data filesystems of this system', options=['mount', 'none'], default='mount'),
    F('scratch', 'path', 'Folder for the download', placeholder='/var/tmp'),
]
INSTALL_ARGS = ('name', 'image', 'image_url', 'image_sha', 'disk', 'size_gb', 'user', 'ssh_key', 'sudo', 'host_keys', 'network', 'carry', 'scratch')

BASH = r"""
sf_os_part() { [[ $1 =~ [0-9]$ ]] && printf '%sp%s\n' "$1" "$2" || printf '%s%s\n' "$1" "$2"; }      # /dev/nvme0n1 + 3 -> /dev/nvme0n1p3
sf_os_entry() { efibootmgr 2>/dev/null | sed -n "s/^Boot\([0-9A-Fa-f]\{4\}\)\*\{0,1\} @LABEL@$1\([[:space:]].*\)\{0,1\}$/\1/p" | head -n 1 || :; }
sf_os_parts() { lsblk -rno PATH,PARTLABEL 2>/dev/null | awk -v p="@LABEL@$1-" 'index($2, p) == 1 {print $1}' || :; }
sf_os_json() { awk 'BEGIN {printf "\""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); printf "%s\\n", $0} END {printf "\""}' "$@"; }
sf_os_rescan() { partx -u "$1" >/dev/null 2>&1 || partprobe "$1" >/dev/null 2>&1 || :; udevadm settle 2>/dev/null || sleep 1; }

sf_os_undo() { # the partitions and the boot entry this run made, and nothing else
  local disk=$1 name=$2 n e; shift 2
  e=$(sf_os_entry "$name"); [[ -z $e ]] || efibootmgr -q -b "$e" -B 2>/dev/null || :
  for n in "$@"; do wipefs -q -a "$(sf_os_part "$disk" "$n")" 2>/dev/null || :; sgdisk -d "$n" "$disk" >/dev/null 2>&1 || :; done
  sf_os_rescan "$disk"
  info "removed what this run had made on $disk"
}

sf_os_network() { # network-config for first boot, from what this system has now: the interface the default route leaves by.
  # $1 = fixed: the address it has now is written as a fixed one even where DHCP gave it
  local dev='' mac='' addr='' gw='' dns='' line='' how=${1:-same}
  dev=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  [[ -n $dev ]] || return 1
  # a bridge or a bond holds the address for a port of its: the new system has it on that port
  if [[ -d /sys/class/net/$dev/bridge || -d /sys/class/net/$dev/bonding ]]; then
    for line in /sys/class/net/"$dev"/lower_*; do [[ -e $line/device ]] && { mac=$(cat "$line/address"); break; }; done
  elif [[ -e /sys/class/net/$dev/device ]]; then mac=$(cat "/sys/class/net/$dev/address")
  fi
  [[ $mac =~ ^[0-9a-f:]{17}$ ]] || return 1
  line=$(ip -o -4 addr show dev "$dev" scope global 2>/dev/null | head -n 1)
  addr=$(awk '{for (i = 1; i < NF; i++) if ($i == "inet") {print $(i + 1); exit}}' <<<"$line")
  [[ $addr =~ ^[0-9.]+/[0-9]+$ ]] || return 1
  if [[ " $line " == *" dynamic "* && $how != fixed ]]; then
    printf '{"version": 2, "ethernets": {"lan": {"match": {"macaddress": "%s"}, "dhcp4": true}}}\n' "$mac"; return 0
  fi
  gw=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}')
  [[ $gw =~ ^[0-9.]+$ ]] || return 1
  dns=$(for line in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do [[ -r $line ]] && awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ {printf "%s\"%s\"", (n++ ? ", " : ""), $2}' "$line" && break; done)
  printf '{"version": 2, "ethernets": {"lan": {"match": {"macaddress": "%s"}, "addresses": ["%s"], "routes": [{"to": "0.0.0.0/0", "via": "%s"}], "nameservers": {"addresses": [%s]}}}}\n' "$mac" "$addr" "$gw" "$dns"
}

sf_os_mounts() { # the data filesystems of this system as cloud-init mounts: what fstab mounts by a name that holds on any system
  # one line: a test that looks for plan values running as code pairs single quotes line by line
  awk '$1 !~ /^#/ && NF >= 4 && $2 ~ /^\// && $2 != "/" && $2 !~ /^\/(boot|efi|proc|sys|dev|run|tmp|var\/tmp)(\/|$)/ && $1 ~ /^(UUID|LABEL|PARTUUID|PARTLABEL)=|^\/dev\/disk\/by-/ && $3 ~ /^(ext[234]|xfs|btrfs|vfat|exfat|ntfs|ntfs3|f2fs)$/ { o = $4; if (o !~ /(^|,)nofail(,|$)/) o = o ",nofail"; gsub(/["\\]/, "", $0); printf "%s[\"%s\", \"%s\", \"%s\", \"%s\", \"0\", \"2\"]", (n++ ? ", " : ""), $1, $2, $3, o }' "${SF_FSTAB:-/etc/fstab}" 2>/dev/null
}

t_os_install() { local name=$1 image=$2 url=$3 sum=$4 disk=$5 size=$6 user=$7 key=$8 sudo=${9:-nopasswd} hostkeys=${10:-same} network=${11:-same} carry=${12:-mount} scratch=${13:-/var/tmp}
  local c='' sums='' base='' raw='' have='' dump='' root='' big=0 p='' n='' s='' z='' t='' u='' esp='' num='' made=() m='' free=0 need=0 loader='' order='' new='' seed='' fs='' var='' line=''
  local BIOS=21686148-6449-6E6F-744E-656564454649 ESP=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
  [[ -d /sys/firmware/efi ]] || { conflict "this machine starts by BIOS, not UEFI: a second system beside the first needs the boot entries of UEFI"; return 0; }
  for c in qemu-img sgdisk sfdisk efibootmgr curl blkid wipefs sha256sum sha512sum; do
    command -v "$c" >/dev/null || { later "$c is not installed (packages qemu-utils or qemu-img, gdisk, efibootmgr, curl)"; return 0; }
  done
  [[ -b $disk && $(lsblk -dno TYPE "$disk" 2>/dev/null) == disk ]] || { conflict "$disk is not a disk here"; return 0; }
  if [[ -n $(sf_os_parts "$name") ]]; then
    if [[ -n $(sf_os_entry "$name") ]]; then ok "$name is installed: $(sf_os_parts "$name" | tr '\n' ' ')"; else conflict "partitions named for $name are here and its boot entry is not: remove it (os-remove) and install again"; fi
    return 0
  fi
  [[ -z $(sf_os_entry "$name") ]] || { conflict "a boot entry @LABEL@$name is here with no partitions of its own: remove it first (os-remove)"; return 0; }
  if [[ $image == custom ]]; then
    [[ -n $url && -n $sum ]] || { conflict "a custom image needs its URL and its checksum"; return 0; }
  else
    IFS=$'\t' read -r url sums c < <(sf_vm_image "$image") || { conflict "no image $image in the catalog"; return 0; }
  fi
  # what is on the disk now: a GPT with room, or nothing at all
  local table blank=0; table=$(blkid -p -o value -s PTTYPE "$disk" 2>/dev/null || :)
  if [[ -z $table ]]; then
    if [[ -n $(wipefs -n "$disk" 2>/dev/null) || -n $(lsblk -rno NAME "$disk" | sed 1d) ]]; then conflict "$disk has something on it that is not a partition table: it is not written over"; return 0; fi
    blank=1; free=$(($(blockdev --getsize64 "$disk") / 1048576 - 2))
  elif [[ $table == gpt ]]; then
    s=$(sgdisk -F "$disk" 2>/dev/null | tail -n 1 || :); z=$(sgdisk -E "$disk" 2>/dev/null | tail -n 1 || :)
    [[ $s =~ ^[0-9]+$ && $z =~ ^[0-9]+$ ]] || { conflict "the partition table of $disk could not be read"; return 0; }
    free=$(( (z - s) / 2048 ))
  else
    conflict "$disk has a $table partition table: this needs GPT"; return 0
  fi
  [[ -d $scratch ]] || { conflict "there is no folder $scratch for the download"; return 0; }
  have=$(df -P -B1G -- "$scratch" 2>/dev/null | awk 'NR == 2 {print $4}' || :)
  [[ -n $have ]] && ((have < @SCRATCH@)) && { conflict "$scratch has ${have} GiB free and the image needs @SCRATCH@ while it is copied: name another folder"; return 0; }
  ((free >= 3072)) || { conflict "$disk has $((free / 1024)) GiB of unpartitioned space in one stretch: too little for a system. Nothing is shrunk to make room"; return 0; }
  [[ -z $size ]] || ((size * 1024 <= free - 1100)) || { conflict "a ${size} GiB root does not fit in the $((free / 1024)) GiB that is free on $disk"; return 0; }
  info "$name from $(basename "$url"), checked against ${sum:+the checksum given}${sums:+$sums}"
  local where='unpartitioned space'; ((blank)) && where='a blank disk'
  info "on $disk, in $((free / 1024)) GiB of $where: its own EFI partition, and a root of ${size:-all that is left}${size:+ GiB}"
  info "login $user with the SSH key; SSH host keys: $hostkeys; network: $network; data filesystems of this system: $carry"
  info "the partitions and the bootloader of the running system are not written to, and the new boot entry is not put in the boot order"
  act "install $name on $disk" || return 0

  install -d -m 0700 "$scratch/.storageforge-images"; base="$scratch/.storageforge-images/$(basename "$url")"; raw="$base.raw"
  if [[ -z $sum ]]; then
    sum=$(curl -fsSL --retry 3 "$sums" | { case $sums in (*.sha512|*.sha256|*.SHA256) cat ;; (*) grep -F "$(basename "$url")" ;; esac; } \
          | grep -oE '\b[0-9a-f]{64}([0-9a-f]{64})?\b' | head -n 1) || true
    [[ -n $sum ]] || { conflict "no published checksum for $(basename "$url") at $sums"; return 0; }
  fi
  if [[ ! -f $base || $(cat "$base.ok" 2>/dev/null) != "$sum" ]]; then
    doing "download $(basename "$url")"
    curl -fsSL --retry 3 -o "$base.part" "$url" || { rm -f "$base.part"; conflict "could not download $url"; return 0; }
    case ${#sum} in 64) have=$(sha256sum "$base.part") ;; *) have=$(sha512sum "$base.part") ;; esac
    if [[ ${have%% *} != "$sum" ]]; then rm -f "$base.part"; conflict "$(basename "$url") does not match its checksum: not used"; return 0; fi
    mv -f "$base.part" "$base"; printf '%s\n' "$sum" >"$base.ok"
    ok "downloaded and checked $(basename "$url")"
  fi
  try qemu-img convert -O raw "$base" "$raw" || { rm -f "$raw"; return 0; }
  dump=$(sfdisk -d "$raw" 2>/dev/null || :)
  [[ $dump == *"label: gpt"* ]] || { rm -f "$raw"; conflict "the image has no GPT: it cannot be laid out beside another system"; return 0; }
  local parts=(); mapfile -t parts < <(sed -n 's/^[^:]*[^0-9]\([0-9]\{1,3\}\) : start= *\([0-9]\+\), size= *\([0-9]\+\), type=\([0-9A-Fa-f-]\{36\}\), uuid=\([0-9A-Fa-f-]\{36\}\).*/\1 \2 \3 \4 \5/p' <<<"$dump")
  for p in "${parts[@]}"; do read -r n s z t u <<<"$p"
    [[ ${t^^} == "$ESP" ]] && esp=$n
    [[ ${t^^} == "$BIOS" || ${t^^} == "$ESP" ]] && continue
    ((z > big)) && { big=$z; root=$n; }
  done
  [[ -n $esp && -n $root ]] || { rm -f "$raw"; conflict "the image has no EFI partition, or no root: it starts by BIOS only"; return 0; }
  # every name the image is found by at boot, against every name this host already has
  local mine theirs=''; mine=$(lsblk -rno UUID,LABEL,PARTUUID 2>/dev/null | tr ' ' '\n' | grep . | sort -u || :)
  need=0
  for p in "${parts[@]}"; do read -r n s z t u <<<"$p"; [[ ${t^^} == "$BIOS" ]] && continue
    need=$((need + z / 2048 + 2))
    theirs+="${u,,}"$'\n'"$(blkid -p -O $((s * 512)) -o value -s UUID "$raw" 2>/dev/null || :)"$'\n'"$(blkid -p -O $((s * 512)) -o value -s LABEL "$raw" 2>/dev/null || :)"$'\n'
  done
  c=$(grep -Fxf <(grep . <<<"$theirs" | sort -u) <<<"$mine" | head -n 3 | tr '\n' ' ' || :)
  [[ -z $c ]] || { rm -f "$raw"; conflict "this host already has a filesystem or partition called ${c% }, the name this image is started by: one of the two would be mounted for the other. A system from this image is here already"; return 0; }
  ((need <= free)) || { rm -f "$raw"; conflict "the image needs $((need / 1024 + 1)) GiB and $disk has $((free / 1024)) free"; return 0; }

  ((blank)) && { try sgdisk -o "$disk" >/dev/null || { rm -f "$raw"; return 0; }; }
  sf_os_copy() { local n='' s='' z='' t='' u='' end=''; read -r n s z t u <<<"$1"
    num=$(sgdisk -p "$disk" | awk '$1 ~ /^[0-9]+$/ {n = $1} END {print n + 1}')
    if [[ $n == "$root" ]]; then end=0; [[ -n $size ]] && end="+${size}G"; else end="+${z}s"; fi
    sgdisk -n "$num:0:$end" -t "$num:$t" -u "$num:$u" -c "$num:@LABEL@$name-$([[ $n == "$root" ]] && echo root || echo "$n")" "$disk" >/dev/null || return 1
    made+=("$num"); sf_os_rescan "$disk"
    [[ -b $(sf_os_part "$disk" "$num") ]] || return 1
    dd if="$raw" of="$(sf_os_part "$disk" "$num")" bs=1M iflag=skip_bytes,count_bytes skip=$((s * 512)) count=$((z * 512)) conv=fsync status=none || return 1
    [[ $n == "$esp" ]] && esp_num=$num; [[ $n == "$root" ]] && root_num=$num; return 0; }
  local esp_num='' root_num=''
  for p in "${parts[@]}"; do read -r n s z t u <<<"$p"; [[ ${t^^} == "$BIOS" || $n == "$root" ]] && continue
    sf_os_copy "$p" || { conflict "could not make or fill a partition on $disk"; sf_os_undo "$disk" "$name" "${made[@]}"; rm -f "$raw"; return 0; }
  done
  for p in "${parts[@]}"; do read -r n s z t u <<<"$p"; [[ $n == "$root" ]] || continue
    sf_os_copy "$p" || { conflict "could not make or fill the root partition on $disk"; sf_os_undo "$disk" "$name" "${made[@]}"; rm -f "$raw"; return 0; }
  done
  rm -f "$raw"

  # first boot: who logs in, the name, the network and the mounts, in a folder of the new root that only it reads
  m=$(mktemp -d); fs=$(blkid -p -o value -s TYPE "$(sf_os_part "$disk" "$root_num")" 2>/dev/null || :)
  if ! mount "$(sf_os_part "$disk" "$root_num")" "$m" 2>/dev/null; then
    rmdir "$m"; conflict "this system cannot mount the new root ($fs): its kernel is older than the filesystem of the image. Nothing could tell the new system who may log in"
    sf_os_undo "$disk" "$name" "${made[@]}"; return 0
  fi
  seed=$m; [[ -e $seed/etc/fstab || -e $seed/etc/os-release ]] || for c in "$m"/*; do [[ -e $c/etc/os-release || -e $c/etc/fstab ]] && { seed=$c; break; }; done
  # Only that folder: a disc or partition labelled for cloud-init (from a cloud, a hypervisor or another system) would otherwise
  # be read after it and win, and the new system would come up as somebody else
  if [[ -d $seed/etc/cloud ]]; then
    install -d -m 0755 "$seed/etc/cloud/cloud.cfg.d"
    printf 'datasource_list: [NoCloud, None]\ndatasource:\n  NoCloud:\n    fs_label: null\n' >"$seed/etc/cloud/cloud.cfg.d/90_storageforge.cfg"
  else
    umount "$m" || :; rmdir "$m" || :; conflict "the image has no cloud-init: nothing in it would set up the login at first boot"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0
  fi
  var=''
  if [[ $fs == btrfs && -r $seed/etc/fstab ]]; then   # /var may be a subvolume of its own, mounted over the one in the root
    var=$(awk '$2 == "/var" && $3 == "btrfs" {n = split($4, o, ","); for (i = 1; i <= n; i++) if (o[i] ~ /^subvol=/) {sub(/^subvol=/, "", o[i]); print o[i]}}' "$seed/etc/fstab" | head -n 1 || :)
  fi
  if [[ -n $var ]]; then
    umount "$m" || :; mount -o "subvol=$var" "$(sf_os_part "$disk" "$root_num")" "$m" 2>/dev/null || { rmdir "$m"; conflict "could not mount /var of the new system"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
    seed=$m/lib/cloud/seed/nocloud
  else
    seed=$seed/var/lib/cloud/seed/nocloud
  fi
  install -d -m 0700 "$seed"
  printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$name" "$(date +%s)" "$name" >"$seed/meta-data"
  { printf '#cloud-config\n{"hostname": "%s", "preserve_hostname": false, "growpart": {"mode": "off"}, "users": [{"name": "%s", "shell": "/bin/bash", "lock_passwd": true, "ssh_authorized_keys": ["%s"]' "$name" "$user" "$key"
    [[ $sudo == nopasswd ]] && printf ', "sudo": "ALL=(ALL) NOPASSWD:ALL"'
    printf '}]'
    if [[ $hostkeys == same ]]; then
      printf ', "ssh_deletekeys": false, "ssh_keys": {'; c=''
      for line in /etc/ssh/ssh_host_*_key; do [[ -r $line && -r $line.pub ]] || continue; t=${line##*/ssh_host_}; t=${t%_key}
        printf '%s"%s_private": %s, "%s_public": %s' "$c" "$t" "$(sf_os_json "$line")" "$t" "$(sf_os_json "$line.pub")"; c=', '; done
      printf '}'
    fi
    if [[ $carry == mount ]]; then line=$(sf_os_mounts); [[ -n $line ]] && printf ', "mounts": [%s]' "$line"; fi
    printf '}\n'; } >"$seed/user-data"
  chmod 0600 "$seed/user-data"
  if [[ $network != dhcp ]]; then
    if line=$(sf_os_network "$network"); then
      printf '%s\n' "$line" >"$seed/network-config"; info "network: $(sed 's/.*"lan": //; s/}}$//' <<<"$line")"
      # a DHCP server knows a machine by what its client says it is, and two systems say it differently
      [[ $line == *dhcp4* ]] && info "its address comes from DHCP, and the DHCP server may give the new system another one than this system has: 'fixed' keeps this one"
    else info "the network here is not one address on one card: the new system asks DHCP on its first card"; fi
  fi
  if [[ $carry == mount ]]; then line=$(sf_os_mounts | grep -o '"/[^"]*"' | tr -d '"' | tr '\n' ' ' || :); info "mounted in the new system as here: ${line:-nothing (fstab mounts no data filesystem by UUID or label)}"; fi
  sync; umount "$m" || :

  # the boot entry: the loader of the distribution itself where it has one. Started from \EFI\BOOT, shim runs its fallback, which
  # writes boot entries of its own and puts them first
  mount -o ro "$(sf_os_part "$disk" "$esp_num")" "$m" 2>/dev/null || { rmdir "$m"; conflict "could not read the new EFI partition"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  for c in "$m"/EFI/*/shimx64.efi "$m"/EFI/*/grubx64.efi "$m"/EFI/*/grub.efi "$m"/EFI/*/systemd-bootx64.efi "$m"/EFI/BOOT/BOOTX64.EFI; do
    [[ -e $c ]] || continue
    case ${c^^} in */EFI/BOOT/SHIMX64.EFI|*/EFI/BOOT/GRUBX64.EFI) continue ;; esac
    loader=${c#"$m"}; break
  done
  umount "$m" || :; rmdir "$m" || :
  [[ -n $loader ]] || { conflict "the EFI partition of the image has no loader this knows"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  order=$(efibootmgr | sed -n 's/^BootOrder: //p' || :)
  efibootmgr -q -c -d "$disk" -p "$esp_num" -L "@LABEL@$name" -l "${loader//\//\\}" || { conflict "the firmware did not take a new boot entry"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  new=$(sf_os_entry "$name")
  [[ -z $order ]] || efibootmgr -q -o "$order" || :       # efibootmgr puts a new entry first: the order goes back to what it was
  [[ -n $new ]] || { conflict "the boot entry was made and cannot be found again"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  ok "$name is installed on $(sf_os_part "$disk" "$root_num"), boot entry $new ($loader), and the boot order is as it was: $order"
  info "start it once with an os-boot step. If it does not come up, the restart after that is this system again"
}

t_os_boot() { local name=$1 when=${2:-once} restart=${3:-no} e='' order='' next='' rest=''
  command -v efibootmgr >/dev/null || { conflict "efibootmgr is not installed"; return 0; }
  e=$(sf_os_entry "$name"); [[ -n $e ]] || { later "there is no boot entry @LABEL@$name: os-install makes it"; return 0; }
  order=$(efibootmgr | sed -n 's/^BootOrder: //p' || :); next=$(efibootmgr | sed -n 's/^BootNext: //p' || :)
  rest=$(tr ',' '\n' <<<"$order" | grep -vix "$e" | paste -sd, - || :)
  case $when in
    once) if [[ ${next^^} == "${e^^}" ]]; then ok "$name starts at the next restart, once"
          else act "start $name at the next restart, once" || return 0; try efibootmgr -q -n "$e" || return 0; ok "$name starts at the next restart; the one after that follows the boot order ($order)"; fi ;;
    always) if [[ ${order%%,*} == "$e" ]]; then ok "$name is first in the boot order"
            else act "put $name first in the boot order" || return 0; try efibootmgr -q -o "$e${rest:+,$rest}" || return 0; ok "$name starts first from now on"; fi ;;
    never) if [[ ",$order," != *",$e,"* && ${next^^} != "${e^^}" ]]; then ok "$name is not in the boot order"
           else act "take $name out of the boot order" || return 0
             [[ ${next^^} != "${e^^}" ]] || efibootmgr -q -N || :
             [[ ",$order," == *",$e,"* ]] && { try efibootmgr -q -o "$rest" || return 0; }
             ok "$name is installed and does not start unless asked"; fi ;;
  esac
  if [[ $restart == yes ]]; then
    act "restart this machine in one minute" || return 0
    # in a minute, so this run ends and reports before the connection goes
    if command -v systemd-run >/dev/null && [[ -d /run/systemd/system ]]; then try systemd-run --quiet --on-active=60 systemctl reboot || return 0; else try shutdown -r +1 >/dev/null || return 0; fi
    ok "restarting in one minute"
  fi
}

t_os_remove() { local name=$1 e='' parts='' p='' disk='' n='' root=''
  parts=$(sf_os_parts "$name"); e=$(command -v efibootmgr >/dev/null && sf_os_entry "$name" || :)
  [[ -n $parts || -n $e ]] || { ok "there is no system named $name here"; return 0; }
  root=$(findmnt -no SOURCE / 2>/dev/null || :); root=${root%%[*}
  for p in $parts; do
    [[ $p == "$root" ]] && { conflict "$name is the system that is running: restart into the other one first"; return 0; }
    [[ -n $(lsblk -rno MOUNTPOINT "$p" 2>/dev/null | grep .) ]] && { conflict "$p of $name is mounted here: unmount it first"; return 0; }
  done
  act "remove $name: its partitions ${parts//$'\n'/ } and its boot entry" || return 0
  [[ -n $e ]] && { try efibootmgr -q -b "$e" -B || return 0; }
  for p in $parts; do
    disk=/dev/$(lsblk -rno PKNAME "$p" | head -n 1); n=$(cat "/sys/class/block/${p##*/}/partition")
    wipefs -q -a "$p" 2>/dev/null || :; try sgdisk -d "$n" "$disk" >/dev/null || return 0; sf_os_rescan "$disk"
  done
  ok "$name is gone; the space it had is unpartitioned again"
}
# (no apostrophes in this script comments or messages: a test that looks for values running as code pairs every single quote)
"""


def bash() -> str:
    return BASH.replace('@LABEL@', LABEL).replace('@SCRATCH@', str(SCRATCH_GIB))


def _check_install(conn, c, h, p, say):
    if p['image'] == 'custom' and not (p.get('image_url') and p.get('image_sha')):
        say('crit', 'a custom image needs its URL and its checksum')
    if p.get('size_gb') and not 3 <= int(p['size_gb']) <= 65536:
        say('crit', 'the root is between 3 GiB and 64 TiB')
    if p['user'] in ('root', '0'):
        say('crit', 'the login account is not root: cloud images do not let root in over SSH')
    if p.get('host_keys', 'same') == 'same':
        say('note', 'the new system gets this machine\'s SSH host keys, read and written on the host itself: an SSH client sees one machine')
    else:
        say('warn', 'the new system makes host keys of its own: SSH clients will warn that the host changed, each time the machine is restarted into the other system')
    say('note', 'only unpartitioned space or a blank disk is used, nothing is shrunk, and the running system\'s bootloader is not written to; the script looks when it runs')
    say('note', 'needs UEFI, and on the host: qemu-img, sgdisk, efibootmgr, curl')


def _check_boot(conn, c, h, p, say):
    if p.get('when') == 'always':
        say('warn', f'{p["name"]} becomes the system this machine starts by default. Do this after it has been reached once')
    if p.get('restart') == 'yes':
        say('warn', 'the machine restarts one minute after this step: everything running on it stops')


def _check_remove(conn, c, h, p, say):
    say('warn', f'the partitions of {p["name"]} are deleted with everything on them')


def _ansible(fn: str, args: tuple):
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(str(p.get(a) or '')) for a in args)
        head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
                'doing() { :; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + steps_vm.bash() + bash() + f'\n{fn} {call}\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


def _image(p):
    return IMAGES[p['image']][0] if p.get('image') in IMAGES else 'a custom image'


changes.register('os-install', {'group': 'Systems', 'label': 'Install a second system beside this one', 'destructive': True, 'fields': INSTALL_FIELDS,
    'help': 'A distribution\'s cloud image, checked against its checksum, on unpartitioned space or a blank disk, with an EFI partition of its own. '
            'The running system is not written to. UEFI only. Start it with an os-boot step.'},
    INSTALL_ARGS, lambda p: f'Install {p["name"]} ({_image(p)}) on {p["disk"]}', _check_install, _ansible('t_os_install', INSTALL_ARGS))

changes.register('os-boot', {'group': 'Systems', 'label': 'Choose which system starts', 'fields': [
    F('name', 'vmname', 'System', required=True), F('when', 'choice', 'Start it', options=['once', 'always', 'never'], default='once'),
    F('restart', 'choice', 'Restart the machine now', options=['no', 'yes'], default='no')],
    'help': 'Once: the next restart only, so a system that does not come up is followed by the old one. Always: first in the boot order. Never: installed, and started only when asked.'},
    ('name', 'when', 'restart'), lambda p: f'Start {p["name"]} {p.get("when") or "once"}' + (', and restart' if p.get('restart') == 'yes' else ''), _check_boot,
    _ansible('t_os_boot', ('name', 'when', 'restart')))

changes.register('os-remove', {'group': 'Systems', 'label': 'Remove a second system', 'destructive': True, 'fields': [F('name', 'vmname', 'System', required=True)],
    'help': 'Deletes the partitions os-install made for it and its boot entry. Not the system that is running.'},
    ('name',), lambda p: f'Remove the system {p["name"]}', _check_remove, _ansible('t_os_remove', ('name',)))

changes.EXTRA_BASH.append(bash())
