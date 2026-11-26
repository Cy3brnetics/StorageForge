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
again, with nothing to repair. UEFI only: a BIOS machine has one boot sector per disk, and it is the running system's. os-install
and os-boot say so on a BIOS machine and change nothing.

Secure Boot. The boot entry points at the image's own loader, which for the distributions in the catalog is their shim, signed
by Microsoft. The script reads whether Secure Boot is on (the firmware's variable, then mokutil). If it is, it reads the
loader's signature table and the firmware's list of trusted keys (db): a loader with no signature, or one signed only with a
Microsoft key the firmware does not list, is taken off again and refused. What it does not read: the revocation lists (dbx,
SBAT) and the kernel behind the shim. And what a firmware does with a loader it refuses is the firmware's business: most go
on to the boot order, some wait for a key at the machine. None of this has been run on a machine with Secure Boot on.

Network `same`: an address DHCP gave is asked for again; addresses set by hand are written as they are (every IPv4 address of
the interface, the IPv6 ones set by hand, the gateway, name servers and search domains).
"""
from __future__ import annotations

import shlex

from . import changes, steps_vm
from .changes import F

# Alpine's image starts from a BIOS boot sector and has no EFI partition
IMAGES = {k: v for k, v in steps_vm.IMAGES.items() if not k.startswith('alpine')}
LABEL = 'sf-'                       # the boot entry and the partition names start with this, then the system's name
# A GPT partition name holds 36 characters, and the longest is LABEL, the name and -root: a longer name is cut and never found again
NAME_MAX = 36 - len(LABEL) - len('-root')
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
sf_os_parts() { lsblk -rno PATH,PARTLABEL 2>/dev/null | awk -v p="@LABEL@$1-" 'index($2, p) == 1 && substr($2, length(p) + 1) ~ /^(root|[0-9]+)$/ {print $1}' || :; }   # nas is not nas-old
sf_os_json() { awk 'BEGIN {printf "\""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); printf "%s\\n", $0} END {printf "\""}' "$@"; }
# Tell the kernel about a changed table. On a disk with a mounted partition the whole table cannot be read again, and
# `partx -u` alone adds nothing new there (found in the lab on 2026-11-18): -a adds what is new and complains about the rest.
sf_os_rescan() { partx -a "$1" >/dev/null 2>&1 || :; partx -u "$1" >/dev/null 2>&1 || partprobe "$1" >/dev/null 2>&1 || :; udevadm settle 2>/dev/null || sleep 1; }
sf_os_forget() { partx -d --nr "$2" "$1" >/dev/null 2>&1 || :; }          # a partition taken out of the table, out of the kernel too

# ── how this machine starts ──
sf_os_uefi() { [[ -d ${SF_FIRMWARE:-/sys/firmware/efi} ]]; }
sf_os_bios() { # what a BIOS machine is told, by every step
  conflict "this machine was started by BIOS, not UEFI (there is no /sys/firmware/efi): $1. A BIOS disk has one boot sector, it belongs to the running system, and these steps do not write to it. A machine with UEFI firmware that was started in its legacy (CSM) mode is told the same, until the running system is started by UEFI. Nothing was changed"
}
sf_os_secureboot() { # on, off or unknown: the variable of the firmware itself, then mokutil where that cannot be read
  local f="${SF_FIRMWARE:-/sys/firmware/efi}/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" v=''
  if [[ -r $f ]]; then v=$(od -An -tu1 -j4 -N1 "$f" 2>/dev/null | tr -d ' \n' || :); fi      # four bytes of attributes, then the value
  case $v in 1) echo on; return 0 ;; 0) echo off; return 0 ;; esac
  if command -v mokutil >/dev/null; then
    case $(mokutil --sb-state 2>/dev/null | head -n 1 || :) in *enabled*) echo on; return 0 ;; *disabled*) echo off; return 0 ;; esac
  fi
  echo unknown
}
sf_os_sig() { # a loader (a PE file) -> where its signatures are and how many bytes (its certificate table), or 1 where it has none
  local f=$1 pe='' at='' off='' size=''
  [[ $(od -An -tx1 -N2 "$f" 2>/dev/null | tr -d ' \n') == 4d5a ]] || return 1
  pe=$(od -An -tu4 -j60 -N4 "$f" 2>/dev/null | tr -d ' \n'); [[ $pe =~ ^[0-9]{1,8}$ ]] || return 1
  [[ $(od -An -tx1 -j"$pe" -N4 "$f" 2>/dev/null | tr -d ' \n') == 50450000 ]] || return 1
  case $(od -An -tx1 -j$((pe + 24)) -N2 "$f" 2>/dev/null | tr -d ' \n') in      # the optional header: 64-bit or 32-bit, and where its fifth directory is
    0b02) at=$((pe + 24 + 112 + 32)) ;; 0b01) at=$((pe + 24 + 96 + 32)) ;; *) return 1 ;;
  esac
  off=$(od -An -tu4 -j"$at" -N4 "$f" 2>/dev/null | tr -d ' \n'); size=$(od -An -tu4 -j$((at + 4)) -N4 "$f" 2>/dev/null | tr -d ' \n')
  [[ $off =~ ^[0-9]+$ && $size =~ ^[0-9]+$ ]] && ((off > 0 && size > 0)) || return 1
  echo "$off $size"
}
sf_os_signed() { sf_os_sig "$1" >/dev/null; }      # it carries a signature. Whose, and whether it counts, the firmware decides
# The two keys Microsoft signs the shims of distributions with. A certificate holds its name as plain text, in the signature
# of a loader and in the list of the firmware (db) alike, so which of them each one names can be read without a tool.
sf_os_cas() { grep -a -o -F -e "Microsoft Corporation UEFI CA 2011" -e "Microsoft UEFI CA 2023" | sort -u || :; }      # reads what it is given
sf_os_trusted() { # LOADER -> yes NAME, no NAMES, or unknown: is a key that signed it in the list of this firmware
  local db="${SF_FIRMWARE:-/sys/firmware/efi}/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f" at='' signed='' have='' n=''
  at=$(sf_os_sig "$1") || { echo unknown; return 0; }
  signed=$(tail -c "+$((${at% *} + 1))" "$1" | head -c "${at#* }" | sf_os_cas)
  [[ -n $signed && -r $db ]] || { echo unknown; return 0; }
  have=$(sf_os_cas <"$db")
  while read -r n; do if grep -q -x -F "$n" <<<"$have"; then echo "yes $n"; return 0; fi; done <<<"$signed"
  echo "no $(paste -sd, - <<<"$signed" | sed 's/,/ or /g')"
}

# Secure Boot, for a loader that is here: one line, "no WHY" where it is known not to start, and then it is not installed, or
# "yes WHAT IS KNOWN". A firmware that refuses a loader may go on to the boot order, or may stop at a message until a key is
# pressed at the machine, which nobody on SSH can do: so what is known not to start is refused here, before it is tried
sf_os_boots() { local sb=$1 file=$2 loader=$3 trust='' after='If it is refused, the next restart is this system again on most firmware; some stop at a message until a key is pressed at the machine'
  [[ $sb == on ]] || return 0
  if ! sf_os_signed "$file"; then
    echo "no Secure Boot is on and the loader of this image ($loader) carries no signature: this firmware would refuse it. Not installed. Use an image of a distribution that ships a signed shim, or turn Secure Boot off in the firmware setup"; return 0
  fi
  trust=$(sf_os_trusted "$file")
  case $trust in
    no\ *) echo "no Secure Boot is on, the loader of this image ($loader) is signed with ${trust#no }, and the list of keys this firmware trusts (db) names none of them: it would be refused. Not installed. The firmware setup can turn that key on (often called the third-party CA), or Secure Boot off" ;;
    yes\ *) echo "yes Secure Boot is on: $loader is signed with ${trust#yes }, and this firmware lists that key. Not checked: the revocation list of the firmware (dbx) and of the shim (SBAT), which can still refuse an old shim, and the kernel the shim then starts. $after" ;;
    *) echo "yes Secure Boot is on: $loader carries a signature, and whether this firmware trusts it could not be read (its key is not one of the two Microsoft signs shims with, or the list of the firmware cannot be read). $after" ;;
  esac
}

sf_os_undo() { # the partitions and the boot entry this run made, and nothing else
  local disk=$1 name=$2 n e; shift 2
  e=$(sf_os_entry "$name"); [[ -z $e ]] || efibootmgr -q -b "$e" -B 2>/dev/null || :
  for n in "$@"; do wipefs -q -a "$(sf_os_part "$disk" "$n")" 2>/dev/null || :; sgdisk -d "$n" "$disk" >/dev/null 2>&1 || :; sf_os_forget "$disk" "$n"; done
  sf_os_rescan "$disk"
  info "removed what this run had made on $disk"
}

sf_os_ip4() { local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d )); }      # 10.0.0.5 -> a number
sf_os_in_net() { local bits=${2#*/}; ((bits <= 32)) || return 1; ((bits == 0)) || (( ($(sf_os_ip4 "$1") >> (32 - bits)) == ($(sf_os_ip4 "${2%/*}") >> (32 - bits)) )); }      # 10.0.0.1 10.0.0.5/24

sf_os_network() { # network-config for first boot, from what this system has now: the interface the default route leaves by.
  # An address DHCP gave is asked for again, and an address set by hand is written as it is, with its gateway, its name
  # servers and its search domains: every one the interface has, and the IPv6 ones that were set by hand beside them.
  # $1 = fixed: the IPv4 addresses it has now are written as fixed ones even where DHCP gave them
  local dev='' mac='' a='' gw='' gw6='' dns='' search='' line='' how=${1:-same} route='' fixed='' fixed6='' dyn=0 onlink=1 routes='' out='' V4='([0-9]{1,3}\.){3}[0-9]{1,3}'
  route=$(ip -4 route show default 2>/dev/null | head -n 1 || :)
  dev=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route")
  [[ -n $dev ]] || return 1
  # a bridge or a bond holds the address for a port of its: the new system has it on that port
  if [[ -d /sys/class/net/$dev/bridge || -d /sys/class/net/$dev/bonding ]]; then
    for line in /sys/class/net/"$dev"/lower_*; do [[ -e $line/device ]] && { mac=$(cat "$line/address"); break; }; done
  elif [[ -e /sys/class/net/$dev/device ]]; then mac=$(cat "/sys/class/net/$dev/address")
  fi
  [[ $mac =~ ^[0-9a-f:]{17}$ ]] || return 1
  while read -r line; do
    a=$(awk '{for (i = 1; i < NF; i++) if ($i == "inet") {print $(i + 1); exit}}' <<<"$line")
    [[ $a =~ ^$V4/[0-9]{1,2}$ ]] || continue
    if [[ " $line " == *" dynamic "* && $how != fixed ]]; then dyn=1; else fixed+="${fixed:+ }$a"; fi
  done < <(ip -o -4 addr show dev "$dev" scope global 2>/dev/null || :)
  [[ -n $fixed ]] || ((dyn)) || return 1
  out=$(printf '{"version": 2, "ethernets": {"lan": {"match": {"macaddress": "%s"}' "$mac")
  if [[ -z $fixed ]]; then printf '%s, "dhcp4": true}}}\n' "$out"; return 0; fi
  if ((dyn)); then   # one address from DHCP and one set by hand beside it: the route and the name servers are the ones DHCP gives
    printf '%s, "dhcp4": true, "addresses": ["%s"]}}}\n' "$out" "${fixed// /\", \"}"; return 0
  fi
  gw=$(awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}' <<<"$route")
  [[ $gw =~ ^$V4$ ]] || return 1
  # a gateway outside every network the interface is in (a /32 at a hoster) is reached on the link itself
  for a in $fixed; do if sf_os_in_net "$gw" "$a"; then onlink=0; fi; done
  routes=$(printf '{"to": "0.0.0.0/0", "via": "%s"' "$gw"); if ((onlink)); then routes+=', "on-link": true'; fi; routes+='}'
  while read -r line; do
    [[ " $line " == *" dynamic "* || " $line " == *" temporary "* ]] && continue
    a=$(awk '{for (i = 1; i < NF; i++) if ($i == "inet6") {print $(i + 1); exit}}' <<<"$line")
    if [[ $a =~ ^[0-9a-f:]{2,39}/[0-9]{1,3}$ ]]; then fixed6+=" $a"; fi
  done < <(ip -o -6 addr show dev "$dev" scope global 2>/dev/null || :)
  if [[ -n $fixed6 ]]; then
    gw6=$(ip -6 route show default dev "$dev" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}' || :)
    if [[ $gw6 =~ ^[0-9a-f:]{2,39}$ ]]; then routes+=$(printf ', {"to": "::/0", "via": "%s"}' "$gw6"); fi
  fi
  fixed+=$fixed6
  for line in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    line=${SF_RESOLV:-$line}; [[ -r $line ]] || continue
    dns=$(awk '$1 == "nameserver" && ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || $2 ~ /^[0-9a-f:]+$/) && $2 !~ /^127\./ && $2 != "::1" {printf "%s\"%s\"", (n++ ? ", " : ""), $2}' "$line")
    search=$(awk '$1 == "search" || $1 == "domain" {for (i = 2; i <= NF; i++) if ($i ~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ && !seen[$i]++) printf "%s\"%s\"", (n++ ? ", " : ""), $i}' "$line")
    break
  done
  printf '%s, "addresses": ["%s"], "routes": [%s]' "$out" "${fixed// /\", \"}" "$routes"
  if [[ -n $dns || -n $search ]]; then printf ', "nameservers": {"addresses": [%s]%s}' "$dns" "${search:+, \"search\": [$search]}"; fi
  printf '}}}\n'
}

sf_os_mounts() { # the data filesystems of this system as cloud-init mounts: what fstab mounts by a name that holds on any system
  # one line: a test that looks for plan values running as code pairs single quotes line by line
  awk '$1 !~ /^#/ && NF >= 4 && $2 ~ /^\// && $2 != "/" && $2 !~ /^\/(boot|efi|proc|sys|dev|run|tmp|var\/tmp)(\/|$)/ && $1 ~ /^(UUID|LABEL|PARTUUID|PARTLABEL)=|^\/dev\/disk\/by-/ && $3 ~ /^(ext[234]|xfs|btrfs|vfat|exfat|ntfs|ntfs3|f2fs)$/ { o = $4; if (o !~ /(^|,)nofail(,|$)/) o = o ",nofail"; gsub(/["\\]/, "", $0); printf "%s[\"%s\", \"%s\", \"%s\", \"%s\", \"0\", \"2\"]", (n++ ? ", " : ""), $1, $2, $3, o }' "${SF_FSTAB:-/etc/fstab}" 2>/dev/null
}

t_os_install() { local name=$1 image=$2 url=$3 sum=$4 disk=$5 size=$6 user=$7 key=$8 sudo=${9:-nopasswd} hostkeys=${10:-same} network=${11:-same} carry=${12:-mount} scratch=${13:-/var/tmp}
  local c='' sums='' base='' raw='' have='' dump='' root='' big=0 p='' n='' s='' z='' t='' u='' esp='' num='' made=() m='' free=0 need=0 loader='' order='' new='' seed='' fs='' var='' line=''
  local BIOS=21686148-6449-6E6F-744E-656564454649 ESP=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
  local sb='' trust=''
  ((${#name} <= @NAMEMAX@)) || { conflict "the name $name is longer than @NAMEMAX@ characters: a partition name holds 36, so the system could not be found again"; return 0; }
  sf_os_uefi || { sf_os_bios "a second system beside the first needs the boot entries of UEFI, and is not installed here"; return 0; }
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
    # a disk that was made larger still has its table ending where the disk used to end, and the new space is not in it
    c=$(sgdisk -p "$disk" 2>/dev/null | sed -n 's/.*last usable sector is \([0-9]*\).*/\1/p' | head -n 1 || :)
    if [[ $c =~ ^[0-9]+$ ]] && (( $(blockdev --getsz "$disk") - c > 1048576 )); then
      conflict "$disk is larger than its partition table knows: it was grown, and $(( ($(blockdev --getsz "$disk") - c) / 2097152 )) GiB at its end are not in the table. Move the end of the table there first (sgdisk -e $disk), then run this again"; return 0
    fi
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
  sb=$(sf_os_secureboot)
  case $sb in
    on) info "Secure Boot is on. The boot entry will point at the loader of the image itself: it must carry a signature, and one this firmware does not trust is not installed. That is looked at once the image is here" ;;
    off) info "Secure Boot is off: the firmware starts the loader of the image whoever signed it" ;;
    *) info "whether Secure Boot is on could not be read here: if it is, the new system starts only where the firmware trusts the key its loader is signed with" ;;
  esac
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
      [[ $line == *dhcp4* || $line == *nameservers* ]] || info "no name server could be read here (this system asks a resolver of its own): the new system has none until one is set in it"
      [[ $line == *on-link* ]] && info "the gateway is outside the network of the address and is reached on the link itself: not every image writes such a route the same way, so look at the address after the first start"
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
  if [[ -n $loader ]]; then trust=$(sf_os_boots "$sb" "$m$loader" "$loader"); fi
  umount "$m" || :; rmdir "$m" || :
  [[ -n $loader ]] || { conflict "the EFI partition of the image has no loader this knows"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  if [[ $trust == no\ * ]]; then conflict "${trust#no }"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; fi
  [[ -z $trust ]] || info "${trust#yes }"
  order=$(efibootmgr | sed -n 's/^BootOrder: //p' || :)
  efibootmgr -q -c -d "$disk" -p "$esp_num" -L "@LABEL@$name" -l "${loader//\//\\}" || { conflict "the firmware did not take a new boot entry"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  new=$(sf_os_entry "$name")
  [[ -z $order ]] || efibootmgr -q -o "$order" || :       # efibootmgr puts a new entry first: the order goes back to what it was
  [[ -n $new ]] || { conflict "the boot entry was made and cannot be found again"; sf_os_undo "$disk" "$name" "${made[@]}"; return 0; }
  ok "$name is installed on $(sf_os_part "$disk" "$root_num"), boot entry $new ($loader), and the boot order is as it was: $order"
  info "start it once with an os-boot step. If it does not come up, the restart after that is this system again"
}

t_os_boot() { local name=$1 when=${2:-once} restart=${3:-no} e='' order='' next='' rest=''
  sf_os_uefi || { sf_os_bios "it has no boot entries to choose between"; return 0; }
  command -v efibootmgr >/dev/null || { conflict "efibootmgr is not installed"; return 0; }
  e=$(sf_os_entry "$name"); [[ -n $e ]] || { later "there is no boot entry @LABEL@$name: os-install makes it"; return 0; }
  if [[ $when != never && $(sf_os_secureboot) == on ]]; then info "Secure Boot is on: os-install said whether the loader of $name is signed with a key this firmware lists. If the firmware refuses it, the next restart is this system again on most firmware; some stop at a message until a key is pressed at the machine"; fi
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

t_os_running() { local name=$1 root='' p='' # the steps after this one are for that system, and are not run in any other
  root=$(findmnt -no SOURCE / 2>/dev/null || :); root=${root%%[*}
  for p in $(sf_os_parts "$name"); do
    if [[ $p == "$root" ]]; then ok "$name is the system that is running"; return 0; fi
  done
  if [[ -z $(sf_os_parts "$name") ]]; then conflict "there is no system named $name on this machine: os-install makes it"; return 0; fi
  conflict "$name is installed and is not the system that is running: start it first (os-boot, then a restart), and run this plan then. Nothing was changed"
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
    wipefs -q -a "$p" 2>/dev/null || :; try sgdisk -d "$n" "$disk" >/dev/null || return 0; sf_os_forget "$disk" "$n"; sf_os_rescan "$disk"
  done
  ok "$name is gone; the space it had is unpartitioned again"
}
# (no apostrophes in this script comments or messages: a test that looks for values running as code pairs every single quote)
"""


def bash() -> str:
    return BASH.replace('@LABEL@', LABEL).replace('@NAMEMAX@', str(NAME_MAX)).replace('@SCRATCH@', str(SCRATCH_GIB))


def _check_install(conn, c, h, p, say):
    if p['image'] == 'custom' and not (p.get('image_url') and p.get('image_sha')):
        say('crit', 'a custom image needs its URL and its checksum')
    if p.get('size_gb') and not 3 <= int(p['size_gb']) <= 65536:
        say('crit', 'the root is between 3 GiB and 64 TiB')
    if len(p['name']) > NAME_MAX:
        say('crit', f'the name is at most {NAME_MAX} characters: the partitions are named for it, and a partition name holds 36')
    if p['user'] in ('root', '0'):
        say('crit', 'the login account is not root: cloud images do not let root in over SSH')
    if p.get('host_keys', 'same') == 'same':
        say('note', 'the new system gets this machine\'s SSH host keys, read and written on the host itself: an SSH client sees one machine')
    else:
        say('warn', 'the new system makes host keys of its own: SSH clients will warn that the host changed, each time the machine is restarted into the other system')
    say('note', 'only unpartitioned space or a blank disk is used, nothing is shrunk, and the running system\'s bootloader is not written to; the script looks when it runs')
    say('note', 'needs UEFI, and on the host: qemu-img, sgdisk, efibootmgr, curl. A machine started by BIOS is refused, and nothing on it is changed')
    say('note', 'Secure Boot: the script reads whether it is on. If it is, an image whose loader carries no signature, or one signed with a key '
                'the firmware does not list, is not installed. What it cannot read (a revoked shim) is found by starting the system once')


def _check_boot(conn, c, h, p, say):
    if p.get('when') == 'always':
        say('warn', f'{p["name"]} becomes the system this machine starts by default. Do this after it has been reached once')
    if p.get('restart') == 'yes':
        say('warn', 'the machine restarts one minute after this step: everything running on it stops')


def _check_remove(conn, c, h, p, say):
    say('warn', f'the partitions of {p["name"]} are deleted with everything on them')


def _check_running(conn, c, h, p, say):
    say('note', f'the steps after this one run only where {p["name"]} is the system that was started: in any other, the plan stops here and changes nothing')


def _ansible(fn: str, args: tuple):
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(w) for w in changes.words_of(p, args))
        head = changes.ansible_head('doing() { :; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
        return changes.shell_task(t, head + steps_vm.bash() + bash() + f'\n{fn} {call}\n')
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

changes.register('os-running', {'group': 'Systems', 'label': 'Go on only in a second system', 'fields': [F('name', 'vmname', 'System', required=True)],
    'help': 'Stops the plan unless the system that is running is the one named: its root is a partition os-install made for it. '
            'Put it before steps that are meant for the new system, such as a desktop, so that they are never run in the old one.'},
    ('name',), lambda p: f'Go on only if {p["name"]} is the system that is running', _check_running, _ansible('t_os_running', ('name',)))

changes.EXTRA_BASH.append(bash())
