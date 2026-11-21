"""What the infrastructure reading (inframeasure.py) adds for workloads (roadmap section 6): the MAC labels of the folders VM disks sit in,
and the lines of AppArmor's local libvirt-qemu abstraction. Printed in sections of the same signed, read-only run, and read back here.

Nothing printed here can hold a secret: paths, SELinux contexts and AppArmor path rules.
"""
from __future__ import annotations

import base64
import binascii

SECTIONS = ('vm_mac', 'quadlet')

BODY = r"""
# the MAC labels of where VM disks are: each pool folder and each folder a disk sits in, with SELinux's label for it and what it should be
sec vm_mac
if has virsh; then
  if has getenforce && [ "$(getenforce 2>/dev/null)" != Disabled ] && [ -n "$(getenforce 2>/dev/null)" ]; then mac=selinux
  elif [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then mac=apparmor; else mac=none; fi
  printf 'm\t%s\n' "$mac"
  { try virsh -c qemu:///system pool-list --all --name | head -n 50 | while read -r n; do [ -n "$n" ] && try virsh -c qemu:///system pool-dumpxml "$n" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p' | head -n 1; done
    try virsh -c qemu:///system list --all --name | head -n 200 | while read -r d; do [ -n "$d" ] && try virsh -c qemu:///system domblklist "$d" --details | awk '$1 == "file" && $2 == "disk" && $4 ~ /^\// {print $4}' | while read -r f; do dirname -- "$f"; done; done
  } | sort -u | head -n 200 | while read -r p; do
    [ -n "$p" ] || continue
    if [ "$mac" = selinux ]; then printf 's\t%s\t%s\t%s\n' "$(printf %s "$p" | base64 -w0)" "$(stat -c %C -- "$p" 2>/dev/null)" "$(has matchpathcon && matchpathcon -n -- "$p" 2>/dev/null)"
    else printf 'p\t%s\n' "$(printf %s "$p" | base64 -w0)"; fi
  done
  if [ "$mac" = apparmor ] && [ -r /etc/apparmor.d/local/abstractions/libvirt-qemu ]; then
    grep -av '^[[:space:]]*#' /etc/apparmor.d/local/abstractions/libvirt-qemu | head -n 200 | while IFS= read -r l; do [ -n "$l" ] && printf 'a\t%s\n' "$(printf %s "$l" | base64 -w0)"; done
  fi
fi
# Podman Quadlet units, of root and of each account that lingers: only the keys that say what runs. Never Environment, Secret or Exec,
# which can hold secrets
sec quadlet
qfiles() {
  [ -d "$2" ] || return 0
  find "$2" -maxdepth 3 -type f \( -name '*.container' -o -name '*.pod' -o -name '*.volume' -o -name '*.network' -o -name '*.kube' -o -name '*.image' -o -name '*.build' \) 2>/dev/null | head -n 200 | while read -r f; do
    printf 'f\t%s\t%s\n' "$1" "$(printf %s "$f" | base64 -w0)"
    awk '{ k = $0; sub(/=.*/, "", k); gsub(/[[:space:]]/, "", k) } /^\[/ { print "s\t" $0; next }
         k ~ /^(Image|ContainerName|PublishPort|Volume|Network|Label|Pod|PodName|AutoUpdate|HealthCmd|Pull|User|Yaml|VolumeName|NetworkName)$/ { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); print "k\t" k "\t" v }' "$f" 2>/dev/null | head -n 200
  done
}
for d in /etc/containers/systemd /usr/share/containers/systemd; do qfiles root "$d"; done
if [ -d /var/lib/systemd/linger ]; then
  for u in /var/lib/systemd/linger/*; do u=${u##*/}; h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6); [ -n "$h" ] && qfiles "$u" "$h/.config/containers/systemd"; done
fi
"""

QUADLET_KINDS = ('container', 'pod', 'volume', 'network', 'kube', 'image', 'build')


def quadlets(lines: list[str]) -> list[dict]:
    """The quadlet section: one record per unit file, with the unit systemd makes of it. Reads what it can."""
    import posixpath
    out: list[dict] = []
    cur = None
    for line in lines:
        tag, _, rest = line.partition('\t')
        if tag == 'f':
            user, _, b = rest.partition('\t')
            path = _b64(b)
            kind = posixpath.splitext(path or '')[1].lstrip('.')
            if not path or not path.startswith('/') or kind not in QUADLET_KINDS or not user:
                cur = None
                continue
            name = posixpath.splitext(posixpath.basename(path))[0]
            cur = {'path': path, 'user': user[:64], 'kind': kind, 'name': name, 'unit': name + ('' if kind in ('container', 'kube') else f'-{kind}') + '.service',
                   'image': None, 'container_name': None, 'publish': [], 'volumes': [], 'networks': [], 'labels': {}, 'auto_update': None, 'pod': None}
            out.append(cur)
        elif tag == 'k' and cur is not None:
            key, _, value = rest.partition('\t')
            value = value.strip()[:500]
            if key == 'Image':
                cur['image'] = value
            elif key == 'ContainerName':
                cur['container_name'] = value
            elif key == 'PublishPort':
                cur['publish'].append(value)
            elif key == 'Volume':
                cur['volumes'].append(value)
            elif key == 'Network':
                cur['networks'].append(value)
            elif key == 'Label':
                for part in value.split():
                    k, eq, v = part.strip('"').partition('=')
                    if eq and k:
                        cur['labels'][k[:100]] = v[:200]
            elif key == 'AutoUpdate':
                cur['auto_update'] = value
            elif key == 'Pod':
                cur['pod'] = value
    return out


def _b64(text: str) -> str | None:
    try:
        return base64.b64decode(text.strip(), validate=True).decode('utf-8')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _type(context: str) -> str | None:
    """'system_u:object_r:virt_image_t:s0' -> 'virt_image_t'."""
    f = (context or '').split(':')
    return f[2] if len(f) >= 3 and f[2] else None


def vm_mac(lines: list[str]) -> dict:
    """The vm_mac section: {'mac': selinux|apparmor|none|None, 'paths': [{'path', 'type', 'expected'}], 'apparmor_local': [rule lines]}.
    Reads what it can: a line it cannot read is left out."""
    out = {'mac': None, 'paths': [], 'apparmor_local': []}
    for line in lines:
        tag, _, rest = line.partition('\t')
        f = rest.split('\t')
        if tag == 'm' and f[0] in ('selinux', 'apparmor', 'none'):
            out['mac'] = f[0]
        elif tag in ('s', 'p'):
            path = _b64(f[0]) if f else None
            if path and path.startswith('/'):
                out['paths'].append({'path': path, 'type': _type(f[1]) if tag == 's' and len(f) > 1 else None,
                                     'expected': _type(f[2]) if tag == 's' and len(f) > 2 else None})
        elif tag == 'a':
            rule = _b64(f[0]) if f else None
            if rule:
                out['apparmor_local'].append(rule.strip()[:500])
    return out


def read(s: dict) -> dict:
    """What inframeasure.parse adds to a reading."""
    return {'vm_mac': vm_mac(s.get('vm_mac', [])), 'quadlets': quadlets(s.get('quadlet', []))}


# ── what the reading says about a VM's disks ────────────────────────
VM_TYPES = ('virt_image_t', 'svirt_image_t', 'virt_content_t', 'svirt_t')
LIBVIRT_DEFAULT = '/var/lib/libvirt/images'


def apparmor_covers(rules: list[str], path: str) -> bool:
    """Does a rule of the local abstraction reach files in this folder: a rule naming the folder or a parent with /** after it."""
    p = path.rstrip('/')
    for r in rules:
        r = r.strip().strip(',').strip()
        target = r.split()[0].strip('"') if r.split() else ''
        if target.endswith('/**'):
            base = target[:-3].rstrip('/')
            if p == base or p.startswith(base + '/'):
                return True
    return False


def disk_findings(reading: dict, disks: list[dict]) -> list[str]:
    """For one VM: the folders its disks sit in that SELinux or AppArmor would keep it from, each with the step that fixes it."""
    import posixpath
    vm = reading.get('vm_mac') or {}
    out = []
    labels = {x['path']: x for x in vm.get('paths') or []}
    for d in disks:
        src = d.get('source') or ''
        if not src.startswith('/') or d.get('device') == 'cdrom':
            continue
        folder = posixpath.dirname(src)
        if vm.get('mac') == 'selinux':
            x = labels.get(folder)
            if x and x['type'] and x['type'] not in VM_TYPES:
                out.append(f'{folder} is labelled {x["type"]}, not virt_image_t, so SELinux keeps QEMU from it: stage a vm-mac step for {folder}')
        elif vm.get('mac') == 'apparmor':
            if not (folder == LIBVIRT_DEFAULT or folder.startswith(LIBVIRT_DEFAULT + '/')) and not apparmor_covers(vm.get('apparmor_local') or [], folder):
                out.append(f'{folder} is not in AppArmor\'s libvirt-qemu abstraction: a backing file or a disk added later there can be refused. Stage a vm-mac step for {folder}')
    return sorted(set(out))


def with_quadlets(workloads: list[dict], host: str, units: list[dict]) -> None:
    """Ties each Podman container to the Quadlet unit that runs it (Podman labels it PODMAN_SYSTEMD_UNIT), and lists a Quadlet container
    with no container running as a workload of its own, in state 'defined'."""
    for q in units:
        if q['kind'] != 'container':
            continue
        found = False
        for w in workloads:
            if w.get('host') != host or w.get('runtime') != 'podman' or w.get('kind') != 'container':
                continue
            if (w.get('user') or 'root') == q['user'] and (w.get('labels') or {}).get('PODMAN_SYSTEMD_UNIT') == q['unit']:
                w['quadlet'], w['unit'] = q['path'], q['unit']
                found = True
        if not found:
            workloads.append({'host': host, 'runtime': 'podman', 'kind': 'container', 'name': q['container_name'] or f'systemd-{q["name"]}', 'state': 'defined',
                              'image': q['image'] or '', 'user': None if q['user'] == 'root' else q['user'], 'quadlet': q['path'], 'unit': q['unit'],
                              'mounts': [], 'ports': [], 'networks': [], 'labels': dict(q['labels']), 'detail': False, 'security': None,
                              'findings': [f'its Quadlet unit {q["unit"]} has no container running']})
