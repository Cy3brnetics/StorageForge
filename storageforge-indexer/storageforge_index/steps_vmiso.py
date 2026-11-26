"""VMs from installer ISOs: the vm-iso plan step, for systems with no cloud image (Proxmox VE, or an installer you prefer).

Cloud images (vm-create in steps_vm.py) are the better way where there is one: they boot ready, with a login for your key. An ISO boots
its installer, and you answer it on the console, which listens on 127.0.0.1 only and is reached through an SSH tunnel or the console
page. On --apply the script reads the checksum list the publisher signs off on (or the checksum given for a custom ISO), picks the
newest file of the release from it, downloads it once into a folder of the libvirt pool, checks it, makes an empty disk and runs
virt-install with the ISO as its CD. It never writes over a disk or a VM that is already there.

The defaults a hand-written create-vm.sh tends to get wrong (infrastructure-platform-roadmap.md 7.3) are set here: the console on
loopback, the network checked before, the pool from the host and not a fixed folder, the ISO checked before it is attached, the OS
variant checked against the osinfo database of the host, UEFI for modern systems with secure boot and a TPM as choices, and the guest
agent channel there for snapshots that freeze the filesystems.

Unattended installs (kickstart, preseed, autoinstall) are not built: their answer files carry a password or a key, which would have to
come from the vault, and that part is not done.
"""
from __future__ import annotations

import shlex

from . import changes, pvenode, steps_vm
from .changes import F

# key -> (label, the checksum list the publisher puts beside its ISOs, the file names of this release in it (ERE), osinfo, firmware).
# The ISO is the newest name the pattern matches in that list, from the same folder: no version to keep up with by hand.
ISOS = {
    'debian13': ('Debian 13 (netinst)', 'https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA512SUMS', r'debian-13\.[0-9.]+-amd64-netinst\.iso', 'debian13', 'uefi'),
    'ubuntu2404': ('Ubuntu Server 24.04', 'https://releases.ubuntu.com/24.04/SHA256SUMS', r'ubuntu-24\.04(\.[0-9]+)?-live-server-amd64\.iso', 'ubuntu24.04', 'uefi'),
    'fedora44': ('Fedora Server 44 (netinst)', 'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Server/x86_64/iso/Fedora-Server-44-1.7-x86_64-CHECKSUM',
                 r'Fedora-Server-netinst-x86_64-44-[0-9.]+\.iso', 'fedora44', 'uefi'),
    'rocky10': ('Rocky Linux 10 (minimal)', 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/CHECKSUM', r'Rocky-10\.[0-9]+-x86_64-minimal\.iso', 'rocky10', 'uefi'),
    'alma10': ('AlmaLinux 10 (minimal)', 'https://repo.almalinux.org/almalinux/10/isos/x86_64/CHECKSUM', r'AlmaLinux-10\.[0-9]+-x86_64-minimal\.iso', 'almalinux10', 'uefi'),
    'arch': ('Arch Linux', 'https://geo.mirror.pkgbuild.com/iso/latest/sha256sums.txt', r'archlinux-x86_64\.iso', 'archlinux', 'uefi'),
    'alpine324': ('Alpine 3.24 (virt)', 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.1-x86_64.iso.sha256',
                  r'alpine-virt-3\.24\.[0-9]+-x86_64\.iso', 'alpinelinux3.24', 'bios'),
    'proxmox-ve9': ('Proxmox VE 9', 'https://enterprise.proxmox.com/iso/SHA256SUMS', r'proxmox-ve_9\.[0-9]+-[0-9]+\.iso', 'debian13', 'uefi'),
}
FIRMWARE = ['', 'bios', 'uefi', 'uefi-secure']
FIELDS = [
    F('name', 'vmname', 'VM name', required=True, placeholder='pve-lab'),
    F('iso', 'choice', 'ISO', options=[''] + list(ISOS) + ['custom'], required=True),
    F('iso_url', 'url', 'Custom ISO URL (https)', placeholder='https://example.com/installer.iso'),
    F('iso_sha', 'sha', 'Its SHA-256 or SHA-512'),
    F('osinfo', 'osinfo', 'OS variant (osinfo)', placeholder='debian13'),
    F('vcpus', 'number', 'vCPUs', placeholder='2'), F('ram_mb', 'number', 'Memory, MiB', placeholder='4096'), F('disk_gb', 'number', 'Disk, GiB', placeholder='32'),
    F('pool', 'name', 'libvirt storage pool', placeholder='default'),
    F('network', 'name', f'libvirt network ({steps_vm.ISOLATED} for an isolated one)', placeholder='default'), F('bridge', 'iface', 'Or a bridge'),
    F('firmware', 'choice', 'Firmware', options=FIRMWARE, default=''), F('tpm', 'bool', 'A TPM (swtpm)'),
    F('console', 'choice', 'Console', options=['', 'spice', 'vnc'], default=''), F('autostart', 'bool', 'Start with the libvirt host'),
]
ARGS = ('name', 'iso', 'iso_url', 'iso_sha', 'osinfo', 'vcpus', 'ram_mb', 'disk_gb', 'pool', 'network', 'bridge', 'firmware', 'tpm', 'console', 'autostart')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
viso_catalog() { # key -> the checksum list URL, the file pattern and the osinfo, by tabs
  case $1 in
@CATALOG@
    *) return 1 ;;
  esac
}
viso_pick() { # checksum-list pattern -> "file sum" of the newest file of the list the pattern matches
  # GNU form (sum, then the file, maybe after a star) and BSD form (SHA256 (file) = sum)
  sed -nE -e "s/^([0-9a-f]{64}|[0-9a-f]{128})[[:space:]]+[*]?([^[:space:]]+)[[:space:]]*$/\2 \1/p" \
          -e "s/^SHA(256|512) \(([^)]+)\) = ([0-9a-f]{64}|[0-9a-f]{128})[[:space:]]*$/\2 \3/p" "$1" \
    | grep -E "^($2) " | sort -V | tail -n 1 || true
}
viso_firmware_ok() { # is there UEFI firmware for QEMU here
  local root=${VISO_ROOT:-}
  compgen -G "$root/usr/share/qemu/firmware/*.json" >/dev/null || compgen -G "$root/usr/share/OVMF/OVMF_CODE*.fd" >/dev/null \
    || compgen -G "$root/usr/share/edk2/*/OVMF_CODE*" >/dev/null || compgen -G "$root/usr/share/edk2-ovmf/*/OVMF_CODE*" >/dev/null
}
t_vm_iso() { local name=$1 iso=$2 url=$3 sum=$4 osinfo=$5 vcpus=${6:-2} ram=${7:-4096} disk=${8:-32} pool=${9:-default} network=${10:-default} bridge=${11} firmware=${12} tpm=${13} console=${14:-spice} autostart=${15}
  not_on_pve || return 0
  local V="virsh -c qemu:///system" c dir net sums pattern cos list file got base root have tool extra=() made=()
  for c in virsh virt-install qemu-img curl sha256sum sha512sum; do
    command -v "$c" >/dev/null || { later "$c is not installed: the VM needs the libvirt client tools (virt-install, qemu-img) and curl"; return 0; }
  done
  if $V dominfo "$name" >/dev/null 2>&1; then
    if $V metadata "$name" "$SF_VM_NS" --config 2>/dev/null | grep -c "<sf" >/dev/null; then ok "$name exists, made by StorageForge"
    else conflict "a VM named $name exists, and StorageForge did not make it: choose another name"; fi
    return 0
  fi
  if [[ $iso == custom ]]; then
    [[ -n $url && -n $sum ]] || { conflict "a custom ISO needs its URL and its checksum"; return 0; }
    file=$(basename "$url")
  else
    IFS=$'\t' read -r sums pattern cos < <(viso_catalog "$iso") || { conflict "no ISO $iso in the catalog"; return 0; }
    osinfo=${osinfo:-$cos}
  fi
  firmware=${firmware:-bios}
  dir=$($V pool-dumpxml "$pool" 2>/dev/null | sed -n "s:.*<path>\(.*\)</path>.*:\1:p" | head -n 1)
  [[ -n $dir && -d $dir ]] || { conflict "the libvirt pool $pool is not here, or is not a folder"; return 0; }
  if [[ -n $bridge ]]; then
    [[ -d /sys/class/net/$bridge/bridge ]] || { conflict "there is no bridge $bridge here"; return 0; }
    net="bridge=$bridge"
  else
    $V net-info "$network" >/dev/null 2>&1 || { conflict "there is no libvirt network $network here: make it first (libvirt-network)"; return 0; }
    net="network=$network"
  fi
  if [[ $firmware == uefi* ]] && ! viso_firmware_ok; then conflict "no UEFI firmware for QEMU here: install OVMF (ovmf or edk2-ovmf), or choose bios"; return 0; fi
  if [[ -n $tpm ]] && ! command -v swtpm >/dev/null; then conflict "swtpm is not installed, and a TPM needs it"; return 0; fi
  root="$dir/$name-root.qcow2"
  [[ -e $root ]] && { conflict "$root is already there: this step never writes over a disk. Move it, or choose another name"; return 0; }
  have=$(df -P -B1G -- "$dir" 2>/dev/null | awk "NR == 2 {print \$4}")
  if [[ -n $have ]] && ((have < disk)); then info "its disk can grow to ${disk} GiB and $dir has ${have} GiB free: it is sparse, so that is fine until it fills"; fi
  info "$name: $vcpus vCPU, $ram MiB, a ${disk} GiB disk, on $net, $firmware${tpm:+ with a TPM}, a $console console on 127.0.0.1"
  info "from ${file:-the newest file named like $pattern in $sums}, checked against ${url:+the checksum given}${sums:+the list its publisher puts beside it}"
  act "create VM $name in $pool and boot its installer" || return 0
  install -d -m 0755 "$dir/.storageforge-images"
  if [[ -z $sum ]]; then
    list=$(mktemp)
    curl -fsSL --retry 3 -o "$list" "$sums" || { rm -f "$list"; conflict "could not read the checksum list $sums"; return 0; }
    got=$(viso_pick "$list" "$pattern"); rm -f "$list"
    [[ -n $got ]] || { conflict "no file named like $pattern in $sums"; return 0; }
    file=${got% *}; sum=${got##* }; url="$(dirname "$sums")/$file"
  fi
  base="$dir/.storageforge-images/$file"
  sf_vm_fetch "$url" "$sum" "" "$base" || return 0
  if [[ -n $osinfo ]] && ! virt-install --osinfo list 2>/dev/null | grep -wFc -- "$osinfo" >/dev/null; then
    info "this host does not know the OS $osinfo yet (its osinfo database is older): generic defaults"; osinfo=
  fi
  made=("$root")
  try qemu-img create -q -f qcow2 "$root" "${disk}G" || { rm -f "$root"; return 0; }
  case $firmware in
    uefi) extra+=(--boot uefi) ;;
    uefi-secure) extra+=(--boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes) ;;
  esac
  [[ -n $tpm ]] && extra+=(--tpm backend.type=emulator,backend.version=2.0,model=tpm-crb)
  case $console in vnc) extra+=(--graphics vnc,listen=127.0.0.1) ;; *) extra+=(--graphics spice,listen=127.0.0.1) ;; esac
  if ! try virt-install --connect qemu:///system --name "$name" --osinfo "${osinfo:-detect=on,require=off}" --vcpus "$vcpus" --memory "$ram" --cpu host-model \
       --disk "path=$root,format=qcow2,bus=virtio" --cdrom "$base" --network "$net,model=virtio" --video virtio --rng /dev/urandom \
       --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 "${extra[@]}" --noautoconsole >/dev/null; then
    rm -f "${made[@]}"; info "removed the disk this run had made"; return 0
  fi
  try $V metadata "$name" "$SF_VM_NS" --key storageforge --set "<sf iso=\"$iso\" made=\"$STAMP\"/>" --config >/dev/null
  [[ -n $autostart ]] && try $V autostart "$name" >/dev/null
  ok "$name boots its installer. Answer it on the console, on 127.0.0.1 of this host (virsh domdisplay $name)"
  info "when it is installed, take the ISO out: virsh change-media $name <the CD target, from virsh domblklist $name> --eject --config"
}
"""


def _catalog_case() -> str:
    q = shlex.quote
    return '\n'.join(f'    {k}) printf "%s\\t%s\\t%s\\n" {q(v[1])} {q(v[2])} {q(v[3])} ;;' for k, v in ISOS.items())


def bash() -> str:
    return BASH.replace('@CATALOG@', _catalog_case()).replace('"$SF_VM_NS"', shlex.quote(steps_vm.NS))


def _check(conn, c, h, p, say):
    from . import inframeasure
    if pvenode.refuse_on_node(conn, h, say):
        return
    r = inframeasure.reading(conn, h['name'])
    if not r:
        say('crit', f'{h["name"]} has no infrastructure reading yet, so nothing is known of its libvirt: measure it first')
        return
    if 'virsh' not in (r.get('tools') or []):
        say('crit', f'{h["name"]} has no virsh: install libvirt (a runtime-install step) first')
        return
    if r.get('stale'):
        say('warn', 'the last infrastructure reading is old: measure the host again before relying on what it says')
    if p['name'] in {d['name'] for d in r.get('libvirt') or []}:
        say('crit', f'a VM named {p["name"]} is already on {h["name"]}')
    pools = {x['name']: x for x in r.get('libvirt_pools') or []}
    pool = p['pool'] or 'default'
    if pool not in pools:
        say('crit', f'there is no libvirt pool {pool} on {h["name"]}' + (f' (it has {", ".join(sorted(pools))})' if pools else ''))
    else:
        path = pools[pool].get('path') or ''
        m = changes.mount_of(h, path) if path else None
        need = int(p['disk_gb'] or 32) + 2       # and the ISO beside it
        if m and m.get('total') is not None and m.get('used') is not None:
            free = (m['total'] - m['used']) // 2**30
            say('ok' if free >= need else 'warn', f'its disk can grow to {need - 2} GiB with the ISO beside it, and {path} has {free} GiB free')
        from . import placement
        placement.say_for_vm(conn, c, h, path, say)
    if p['bridge']:
        say('warn', 'bridged: the host firewall does not see this guest\'s traffic')
    else:
        nets = {x['name']: x for x in r.get('libvirt_networks') or []}
        net = p['network'] or 'default'
        if net not in nets:
            say('crit', f'there is no libvirt network {net} on {h["name"]}')
    if p['iso'] == 'custom':
        if not (p['iso_url'] and p['iso_sha']):
            say('crit', 'a custom ISO needs its URL and its checksum')
        elif not p['iso_url'].lower().endswith('.iso'):
            say('warn', 'the custom URL does not end in .iso: a compressed image (.iso.bz2, .img.xz) is not unpacked by this step')
    elif p['iso'] in ISOS:
        label, sums, _, _, fw = ISOS[p['iso']]
        say('ok', f'{label}: the newest file of the release in {sums.rsplit("/", 1)[-1]}, checked against it')
        if not p['firmware'] and fw == 'uefi':
            say('note', f'{label} installs best with UEFI firmware: choose uefi')
    if p['firmware'] == 'uefi-secure' and not p['tpm']:
        say('note', 'secure boot without a TPM: Windows 11 wants both')
    if p['tpm'] and not p['firmware'].startswith('uefi'):
        say('warn', 'a TPM with BIOS firmware: most systems use the TPM only with UEFI')
    if int(p['ram_mb'] or 4096) < 2048:
        say('warn', 'under 2 GiB: most installers need more')
    say('note', 'the installer runs on a console that listens on 127.0.0.1 only: reach it through an SSH tunnel, or the console page')
    say('note', 'nothing already there is written over: an existing disk or VM of that name is a conflict')


def _ansible(t):
    q = shlex.quote
    p = t['params']
    call = ' '.join(q(w) for w in changes.words_of(p, ARGS))
    head = (pvenode.NOT_ON_PVE_BASH + '\n' + 'APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'doing() { :; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
    return changes.shell_task(t, head + changes.bash_fn(steps_vm.bash(), 'sf_vm_fetch') + bash() + f'\nt_vm_iso {call}\n')


def _title(p):
    label = ISOS[p['iso']][0] if p.get('iso') in ISOS else 'a custom ISO'
    return f'VM {p["name"]} from {label}'


changes.register('vm-iso', {'group': 'Workloads', 'label': 'Create a VM from an installer ISO', 'fields': FIELDS,
    'help': 'For systems with no cloud image. The ISO is checked against the list its publisher puts beside it, and its installer is answered on a console on 127.0.0.1. '
            'Nothing already there is written over.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(bash())
