"""Creating VMs from cloud images: a catalog of images, VM specs to fill a VM in from, and the vm-create plan step.

vm-create is a change plan step like any other: checked against the index (the libvirt host's last infrastructure reading),
reported first, deployed and audited. On --apply it downloads the image once into a folder of the libvirt pool and checks
it against the checksum its publisher lists (or one given for a custom image), copies it to a new root disk, makes data
disks and a cloud-init seed holding one login account with the given SSH key, and runs virt-install --import. It never
writes over a disk or a VM that is already there, and never replaces a VM StorageForge did not make.

A spec is a set of field values with a name: "server" or "desktop", or one of your own. A step names a spec and its empty
fields are filled from it when the plan is saved, so a saved plan says everything it does, and changing a spec later
changes no plan that was saved with it.

Every value reaches the script through the field checks in changes.CHECKS and as a shlex-quoted word. The cloud-init file
is written by the script from those values, which the checks keep free of quotes, backslashes and line breaks.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

NS = 'https://storageforge.invalid/vm'      # the libvirt metadata namespace that marks a VM StorageForge made
ISOLATED = 'sf-isolated'                    # the libvirt network a test copy runs on: the libvirt host reaches it, nothing else

# key -> (label, image URL, URL of the published checksums, osinfo, os-release ID, VERSION_ID). The lab's images.conf
# holds the same images; these are the ones a lab build downloads and boots.
IMAGES = {
    'debian13': ('Debian 13', 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2',
                 'https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS', 'debian13', 'debian', '13'),
    'debian12': ('Debian 12', 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2',
                 'https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS', 'debian12', 'debian', '12'),
    'ubuntu2404': ('Ubuntu 24.04', 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
                   'https://cloud-images.ubuntu.com/noble/current/SHA256SUMS', 'ubuntu24.04', 'ubuntu', '24.04'),
    'ubuntu2204': ('Ubuntu 22.04', 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
                   'https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS', 'ubuntu22.04', 'ubuntu', '22.04'),
    'fedora44': ('Fedora 44', 'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2',
                 'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM', 'fedora44', 'fedora', '44'),
    'rocky9': ('Rocky Linux 9', 'https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2',
               'https://dl.rockylinux.org/pub/rocky/9/images/x86_64/CHECKSUM', 'rocky9', 'rocky', '9'),
    'rocky10': ('Rocky Linux 10', 'https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2',
                'https://dl.rockylinux.org/pub/rocky/10/images/x86_64/CHECKSUM', 'rocky10', 'rocky', '10'),
    'alma9': ('AlmaLinux 9', 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2',
              'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM', 'almalinux9', 'almalinux', '9'),
    'alma10': ('AlmaLinux 10', 'https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2',
               'https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/CHECKSUM', 'almalinux10', 'almalinux', '10'),
    'leap16': ('openSUSE Leap 16', 'https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2',
               'https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2.sha256', 'opensuse16.0', 'opensuse-leap', '16.0'),
    'leap15': ('openSUSE Leap 15.6', 'https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2',
               'https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2.sha256', 'opensuse15.6', 'opensuse-leap', '15.6'),
    'tumbleweed': ('openSUSE Tumbleweed', 'https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2',
                   'https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2.sha256', 'opensusetumbleweed', 'opensuse-tumbleweed', ''),
    'arch': ('Arch Linux', 'https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2',
             'https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256', 'archlinux', 'arch', ''),
    'alpine324': ('Alpine 3.24', 'https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2',
                  'https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2.sha512', 'alpinelinux3.24', 'alpine', '3.24'),
}
# Arch derivatives have no image of their own: their clones start from Arch (docs/host-migration.md)
LIKE_ARCH = {'cachyos', 'endeavouros', 'manjaro', 'garuda', 'artix'}

changes.CHECKS.update({
    'url': re.compile(r'https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?/[A-Za-z0-9._~/%+-]{1,1000}'),
    'sha': re.compile(r'[0-9a-f]{64}|[0-9a-f]{128}'),
    'sizes': re.compile(r'\d{1,5}(,\d{1,5}){0,15}'),
    'pubkey': re.compile(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'
                         r' [A-Za-z0-9+/]{16,4096}={0,3}( [A-Za-z0-9@._+-]{1,100})?'),
    'vmname': re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}'),
})

FIELDS = [
    F('name', 'vmname', 'VM name, and its host name', required=True, placeholder='web-01-copy'),
    F('spec', 'name', 'Fill the empty fields from this spec', placeholder='server'),
    F('image', 'choice', 'Image', options=[''] + list(IMAGES) + ['custom'], default=''),
    F('image_url', 'url', 'Custom image URL (https)', placeholder='https://example.com/disk.qcow2'),
    F('image_sha', 'sha', 'Its SHA-256 or SHA-512'),
    F('osinfo', 'name', 'OS variant (osinfo)', placeholder='debian13'),
    F('vcpus', 'number', 'vCPUs', placeholder='2'),
    F('ram_mb', 'number', 'Memory, MiB', placeholder='2048'),
    F('disk_gb', 'number', 'Root disk, GiB', placeholder='20'),
    F('data_disks', 'sizes', 'Data disks, GiB each', placeholder='50,50'),
    F('pool', 'name', 'libvirt storage pool', placeholder='default'),
    F('network', 'name', f'libvirt network ({ISOLATED} for an isolated one)', placeholder='default'),
    F('bridge', 'iface', 'Or a bridge'),
    F('firmware', 'choice', 'Firmware', options=['', 'bios', 'uefi'], default=''),
    F('cpu', 'choice', 'CPU model', options=['', 'host-model', 'host-passthrough'], default=''),
    F('console', 'choice', 'Console', options=['', 'serial', 'spice'], default=''),
    F('user', 'user', 'Login account', placeholder='admin'),
    F('ssh_key', 'pubkey', 'Its SSH public key', placeholder='ssh-ed25519 AAAA… you@laptop'),
    F('sudo', 'choice', 'sudo for that account', options=['', 'nopasswd', 'none'], default=''),
    F('autostart', 'bool', 'Start with the libvirt host'),
]
ARGS = ('name', 'image', 'image_url', 'image_sha', 'osinfo', 'vcpus', 'ram_mb', 'disk_gb', 'data_disks', 'pool', 'network', 'bridge',
        'firmware', 'cpu', 'console', 'user', 'ssh_key', 'sudo', 'autostart')
SPEC_FIELDS = tuple(f['name'] for f in FIELDS if f['name'] not in ('name', 'spec'))
DEFAULTS = {'vcpus': '2', 'ram_mb': '2048', 'disk_gb': '20', 'pool': 'default', 'network': 'default', 'firmware': 'bios',
            'cpu': 'host-model', 'console': 'serial', 'user': 'admin', 'sudo': 'nopasswd'}

# Built in and read-only. Your own specs sit beside them, in the settings table, and can't take these names.
BUILTIN = {
    'small': {'vcpus': '1', 'ram_mb': '1024', 'disk_gb': '10', 'note': 'A small server or a throwaway test'},
    'server': {'vcpus': '2', 'ram_mb': '4096', 'disk_gb': '40', 'note': 'A general server'},
    'desktop': {'vcpus': '4', 'ram_mb': '8192', 'disk_gb': '60', 'firmware': 'uefi', 'console': 'spice', 'cpu': 'host-passthrough',
                'note': 'A desktop copy: UEFI, a SPICE console on loopback, and the CPU passed through'},
    'test-copy': {'vcpus': '2', 'ram_mb': '4096', 'disk_gb': '40', 'network': ISOLATED, 'note': 'A test copy on the isolated network'},
}
SETTING = 'vm_specs'

BASH = r"""
sf_vm_image() { # catalog key -> image URL, checksums URL and osinfo, by tabs
  case $1 in
@CATALOG@
    *) return 1 ;;
  esac
}

t_vm_create() { local name=$1 image=$2 url=$3 sum=$4 osinfo=$5 vcpus=${6:-2} ram=${7:-2048} disk=${8:-20} data=$9 pool=${10:-default} network=${11:-default} bridge=${12} firmware=${13:-bios} cpu=${14:-host-model} console=${15:-serial} user=${16:-admin} key=${17} sudo=${18:-nopasswd} autostart=${19}
  local V="virsh -c qemu:///system" c sums='' dir net root f i=0 d files=() need base want have fmt seed tool
  for c in virsh virt-install qemu-img curl sha256sum sha512sum; do
    command -v "$c" >/dev/null || { later "$c is not installed: the VM needs libvirt's client tools (virt-install, qemu-img) and curl"; return 0; }
  done
  if $V dominfo "$name" >/dev/null 2>&1; then
    if $V metadata "$name" "$SF_VM_NS" --config 2>/dev/null | grep -q '<sf'; then ok "$name exists, made by StorageForge"
    else conflict "a VM named $name exists, and StorageForge did not make it: choose another name"; fi
    return 0
  fi
  [[ -n $key ]] || { conflict "no SSH key for $user: nothing could log in to $name"; return 0; }
  if [[ $image == custom ]]; then
    [[ -n $url && -n $sum ]] || { conflict "a custom image needs its URL and its checksum"; return 0; }
  else
    local cos; IFS=$'\t' read -r url sums cos < <(sf_vm_image "$image") || { conflict "no image $image in the catalog"; return 0; }
    osinfo=${osinfo:-$cos}
  fi
  dir=$($V pool-dumpxml "$pool" 2>/dev/null | sed -n 's:.*<path>\(.*\)</path>.*:\1:p' | head -n 1)
  [[ -n $dir && -d $dir ]] || { conflict "the libvirt pool $pool is not here, or is not a folder"; return 0; }
  if [[ -n $bridge ]]; then
    [[ -d /sys/class/net/$bridge/bridge ]] || { conflict "there is no bridge $bridge here"; return 0; }
    net="bridge=$bridge"
  elif [[ $network == @ISOLATED@ ]]; then
    net="network=$network"
    $V net-info "$network" >/dev/null 2>&1 || info "the isolated network $network is made first: this host reaches it, nothing else does (10.89.0.0/24)"
  else
    $V net-info "$network" >/dev/null 2>&1 || { conflict "there is no libvirt network $network here"; return 0; }
    net="network=$network"
  fi
  root="$dir/$name-root.qcow2"; files=("$root")
  for d in ${data//,/ }; do i=$((i + 1)); files+=("$dir/$name-data$i.qcow2"); done
  seed="$dir/$name-seed.iso"
  for f in "${files[@]}" "$seed"; do
    [[ -e $f ]] && { conflict "$f is already there: this step never writes over a disk. Move it, or choose another name"; return 0; }
  done
  need=$disk; for d in ${data//,/ }; do need=$((need + d)); done
  have=$(df -P -B1G -- "$dir" 2>/dev/null | awk 'NR == 2 {print $4}')
  if [[ -n $have ]] && ((have < need)); then info "its disks can grow to ${need} GiB and $dir has ${have} GiB free: they are sparse, so that is fine until they fill"; fi
  base="$dir/.storageforge-images/$(basename "$url")"
  info "$name: $vcpus vCPU, $ram MiB, a ${disk} GiB root disk${data:+ and data disks of $data GiB}, on $net, $firmware, $cpu, $console console"
  local how=' (no sudo)'; [[ $sudo == nopasswd ]] && how=' and sudo without a password'
  info "from $(basename "$url"), checked against ${sum:+the checksum given}${sums:+$sums}; login $user with the SSH key$how"
  act "create VM $name in $pool" || return 0
  install -d -m 0755 "$dir/.storageforge-images"
  if [[ -z $sum ]]; then
    sum=$(curl -fsSL --retry 3 "$sums" | { case $sums in *.sha512|*.sha256|*.SHA256) cat ;; *) grep -F "$(basename "$url")" ;; esac; } \
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
  fmt=$(qemu-img info "$base" 2>/dev/null | sed -n 's/^file format: //p' | head -n 1)
  # a copy, not an overlay: the VM keeps working if the downloaded image is replaced or removed
  try qemu-img convert -q -f "${fmt:-qcow2}" -O qcow2 "$base" "$root" || return 0
  try qemu-img resize -q "$root" "${disk}G" || return 0
  i=0; local diskargs=(--disk "path=$root,format=qcow2,bus=virtio")
  for d in ${data//,/ }; do
    i=$((i + 1)); try qemu-img create -q -f qcow2 "$dir/$name-data$i.qcow2" "${d}G" || return 0
    diskargs+=(--disk "path=$dir/$name-data$i.qcow2,format=qcow2,bus=virtio,serial=sf-data$i")
  done
  # cloud-init: JSON is YAML too, and every value here passed the plan's field checks, which allow no quote or backslash
  local cd; cd=$(mktemp -d); local sudoline=''
  [[ $sudo == nopasswd ]] && sudoline=', "sudo": "ALL=(ALL) NOPASSWD:ALL"'
  printf '#cloud-config\n{"hostname": "%s", "manage_etc_hosts": true, "ssh_pwauth": false, "disable_root": true, "users": [{"name": "%s", "lock_passwd": true, "ssh_authorized_keys": ["%s"]%s}]}\n' \
    "$name" "$user" "$key" "$sudoline" >"$cd/user-data"
  printf 'instance-id: sf-%s-%s\nlocal-hostname: %s\n' "$name" "$STAMP" "$name" >"$cd/meta-data"
  for tool in xorriso genisoimage mkisofs; do command -v $tool >/dev/null && break; tool=; done
  case $tool in
    xorriso) try xorriso -as mkisofs -quiet -volid cidata -joliet -rock -o "$seed" "$cd/user-data" "$cd/meta-data" 2>/dev/null || { rm -rf "$cd"; return 0; } ;;
    genisoimage|mkisofs) try $tool -quiet -volid cidata -joliet -rock -o "$seed" "$cd/user-data" "$cd/meta-data" || { rm -rf "$cd"; return 0; } ;;
    *) rm -rf "$cd"; conflict "no xorriso, genisoimage or mkisofs here, to write the cloud-init seed: install one (xorriso is in every distro)"; return 0 ;;
  esac
  rm -rf "$cd"
  diskargs+=(--disk "path=$seed,device=cdrom,bus=sata,readonly=on")
  if [[ $network == @ISOLATED@ ]] && ! $V net-info "$network" >/dev/null 2>&1; then
    local nx; nx=$(mktemp)
    printf '<network><name>%s</name><bridge name="sfiso0"/><ip address="10.89.0.1" netmask="255.255.255.0"><dhcp><range start="10.89.0.100" end="10.89.0.200"/></dhcp></ip></network>\n' "$network" >"$nx"
    try $V net-define "$nx" >/dev/null || { rm -f "$nx"; return 0; }
    rm -f "$nx"; try $V net-autostart "$network" >/dev/null; try $V net-start "$network" >/dev/null || return 0
    ok "made the isolated network $network"
  fi
  local extra=()
  [[ $firmware == uefi ]] && extra+=(--boot uefi)
  case $console in
    spice) extra+=(--graphics spice,listen=127.0.0.1 --video virtio) ;;
    *) extra+=(--graphics none --console pty,target_type=serial) ;;
  esac
  try virt-install --import --name "$name" --osinfo "${osinfo:-detect=on,require=off}" --vcpus "$vcpus" --memory "$ram" --cpu "$cpu" \
    --network "$net,model=virtio" "${diskargs[@]}" "${extra[@]}" --rng /dev/urandom --noautoconsole >/dev/null || return 0
  try $V metadata "$name" "$SF_VM_NS" --key storageforge --set "<sf image=\"$image\" made=\"$STAMP\"/>" --config >/dev/null
  [[ -n $autostart ]] && try $V autostart "$name" >/dev/null
  local where=''; [[ $console == spice ]] && where=', its console on 127.0.0.1 only'
  ok "$name is running$where. cloud-init sets it up on this first boot"
  local mac ip='' t
  mac=$($V domiflist "$name" 2>/dev/null | awk 'NR > 2 && $5 {print $5; exit}')
  for t in $(seq 1 30); do
    ip=$($V domifaddr "$name" 2>/dev/null | awk -v m="$mac" '$2 == m {sub(/\/.*/, "", $4); print $4; exit}')
    [[ -n $ip ]] && break; sleep 2
  done
  if [[ -n $ip ]]; then info "$name has $ip: when cloud-init is done, bind a vault key to $user@$ip and scan it"
  else info "$name has no address yet (MAC $mac): look with virsh domifaddr $name, then scan it"; fi
}
"""


def _catalog_case() -> str:
    q = shlex.quote
    return '\n'.join(f'    {k}) printf "%s\\t%s\\t%s\\n" {q(v[1])} {q(v[2])} {q(v[3])} ;;' for k, v in IMAGES.items())


def bash() -> str:
    return (BASH.replace('@CATALOG@', _catalog_case()).replace('@ISOLATED@', ISOLATED)
            .replace('"$SF_VM_NS"', shlex.quote(NS)))


# ── specs ───────────────────────────────────────────────────────────
def _clean(name: str, body: dict) -> dict:
    """A spec, through the same field checks as a step."""
    if not changes.CHECKS['name'].fullmatch(name or ''):
        raise ValueError(f'a spec name is letters, digits and ._:+- ({name!r} is not)')
    out = {}
    for f in FIELDS:
        k = f['name']
        if k not in SPEC_FIELDS or k not in body:
            continue
        v = body[k]
        if f['kind'] == 'bool':
            out[k] = bool(v)
            continue
        v = '' if v is None else str(v).strip()
        if not v:
            continue
        if f['kind'] == 'choice':
            if v not in f['options']:
                raise ValueError(f'{f["label"]} must be one of {", ".join(x for x in f["options"] if x)}')
        elif not changes.CHECKS[f['kind']].fullmatch(v):
            raise ValueError(f'{f["label"]} {v!r} is not valid')
        out[k] = v
    note = str(body.get('note') or '').strip()
    if note:
        out['note'] = changes.one_line(note)[:200]
    return out


def specs(conn) -> list[dict]:
    from .alerts import get_setting
    mine = get_setting(conn, SETTING) or {}
    rows = [{'name': k, 'builtin': True, **v} for k, v in BUILTIN.items()]
    rows += [{'name': k, 'builtin': False, **v} for k, v in sorted(mine.items())]
    return rows


def spec(conn, name: str) -> dict | None:
    return next(({k: v for k, v in s.items() if k not in ('name', 'builtin')} for s in specs(conn) if s['name'].lower() == (name or '').lower()), None)


def save_spec(conn, name: str, body: dict, actor: str) -> dict:
    from .alerts import get_setting, set_setting
    if name.lower() in BUILTIN:
        raise ValueError(f'{name} is built in: save yours under another name')
    clean = _clean(name, body)
    mine = get_setting(conn, SETTING) or {}
    mine = {k: v for k, v in mine.items() if k.lower() != name.lower()}
    mine[name] = clean
    if len(mine) > 200:
        raise ValueError('at most 200 specs')
    set_setting(conn, SETTING, mine, actor)
    return {'name': name, 'builtin': False, **clean}


def delete_spec(conn, name: str, actor: str) -> None:
    from .alerts import get_setting, set_setting
    if name.lower() in BUILTIN:
        raise ValueError(f'{name} is built in and stays')
    mine = get_setting(conn, SETTING) or {}
    kept = {k: v for k, v in mine.items() if k.lower() != name.lower()}
    if len(kept) == len(mine):
        raise LookupError(f'no spec {name}')
    set_setting(conn, SETTING, kept, actor)


def expand(conn, body: dict) -> dict:
    """A plan before it is checked or saved: each vm-create step's empty fields filled from its spec."""
    for i, t in enumerate(body.get('tasks') or [], 1):
        if t.get('type') != 'vm-create':
            continue
        p = t.setdefault('params', {})
        name = str(p.get('spec') or '').strip()
        if not name:
            continue
        s = spec(conn, name)
        if s is None:
            raise ValueError(f'task {i}: there is no VM spec {name}')
        for k in SPEC_FIELDS:
            if k in s and (p.get(k) in (None, '') or (k == 'autostart' and p.get(k) is None)):
                p[k] = s[k]
    return body


def image_for(distro: str | None, version: str | None) -> str | None:
    """The catalog image for a source host's os-release ID and VERSION_ID: what a copy of it starts from."""
    d, v = (distro or '').lower(), (version or '')
    if d in LIKE_ARCH:
        d = 'arch'
    for k, row in IMAGES.items():
        if row[4] == d and (row[5] == v or not row[5] or v.split('.')[0] == row[5]):
            return k
    return None


# ── the check against the index ─────────────────────────────────────
def _check(conn, c, h, p, say):
    from . import inframeasure
    r = inframeasure.reading(conn, h['name'])
    if not r:
        say('crit', f'{h["name"]} has no infrastructure reading yet, so nothing is known of its libvirt: measure it first')
        return
    if 'virsh' not in (r.get('tools') or []):
        say('crit', f'{h["name"]} has no virsh: install libvirt (and virt-install, qemu-img) there first')
        return
    if r.get('stale'):
        say('warn', 'the last infrastructure reading is old: measure the host again before relying on what it says')
    have = {d['name']: d for d in r.get('libvirt') or []}
    if p['name'] in have:
        say('crit', f'a VM named {p["name"]} is already on {h["name"]}')
    pools = {x['name']: x for x in r.get('libvirt_pools') or []}
    pool = p['pool'] or DEFAULTS['pool']
    if pool not in pools:
        say('crit', f'there is no libvirt pool {pool} on {h["name"]}' + (f' (it has {", ".join(sorted(pools))})' if pools else ''))
    else:
        path = pools[pool].get('path') or ''
        m = changes.mount_of(h, path) if path else None
        need = int(p['disk_gb'] or DEFAULTS['disk_gb']) + sum(int(x) for x in (p['data_disks'] or '').split(',') if x)
        if m and m.get('total') is not None and m.get('used') is not None:
            free = (m['total'] - m['used']) // 2**30
            say('ok' if free >= need else 'warn', f'its disks can grow to {need} GiB, and {path} has {free} GiB free')
    if p['bridge']:
        say('warn', 'bridged: the host firewall does not see this guest\'s traffic')
    else:
        nets = {x['name']: x for x in r.get('libvirt_networks') or []}
        net = p['network'] or DEFAULTS['network']
        if net == ISOLATED:
            say('note', 'on the isolated network: only the libvirt host reaches it. To scan it, StorageForge must run on that host')
        elif net not in nets:
            say('crit', f'there is no libvirt network {net} on {h["name"]}')
        elif nets[net].get('mode') == 'isolated':
            say('note', f'{net} is isolated: only the libvirt host reaches it')
    if not p['image']:
        say('crit', 'choose an image, or a spec that names one')
    elif p['image'] == 'custom' and not (p['image_url'] and p['image_sha']):
        say('crit', 'a custom image needs its URL and its checksum')
    elif p['image'] != 'custom':
        say('ok', f'{IMAGES[p["image"]][0]}, checked against the checksum its publisher lists')
    if not p['ssh_key']:
        say('crit', 'give an SSH public key for the login account: there is no password')
    else:
        name = conn.scalar('SELECT name FROM ssh_keys WHERE public_key = :k OR public_key LIKE :p', {'k': p['ssh_key'], 'p': ' '.join(p['ssh_key'].split()[:2]) + '%'})
        say('ok' if name else 'note', f'the key is vault key {name}: bind it to {p["user"] or DEFAULTS["user"]}@<address> to scan the VM' if name
            else 'the key is not in the vault: StorageForge can scan the VM only once you add one of its keys')
    if (p['sudo'] or DEFAULTS['sudo']) == 'nopasswd':
        say('note', 'the login account gets sudo without a password, as cloud images give it: its SSH key is root on the VM')
    if int(p['ram_mb'] or DEFAULTS['ram_mb']) < 1024:
        say('warn', 'under 1 GiB: package installs on Enterprise Linux and openSUSE are often killed for lack of memory')
    say('note', 'nothing already there is written over: an existing disk or VM of that name is a conflict')


def _ansible(t):
    q = shlex.quote
    p = t['params']
    call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in ARGS)
    head = ('APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'doing() { :; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + bash() + f'\nt_vm_create {call}\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


def _title(p):
    img = IMAGES[p['image']][0] if p.get('image') in IMAGES else (p.get('image') or 'an image')
    return f'VM {p["name"]} from {img}' + (f' ({p["spec"]})' if p.get('spec') else '')


changes.register('vm-create', {'group': 'Workloads', 'label': 'Create a VM from a cloud image', 'fields': FIELDS,
    'help': 'A cloud image checked against its checksum, copied to a new disk, with a cloud-init login for your SSH key. A spec fills the empty fields. '
            'Nothing already there is written over.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(bash())
changes.PREPARE.append(expand)
