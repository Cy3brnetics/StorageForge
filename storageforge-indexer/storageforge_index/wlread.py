"""What the infrastructure reading (inframeasure.py) adds for workloads (roadmap section 6): the MAC labels of the folders VM disks sit in,
and the lines of AppArmor's local libvirt-qemu abstraction. Printed in sections of the same signed, read-only run, and read back here.

Nothing printed here can hold a secret: paths, SELinux contexts and AppArmor path rules.
"""
from __future__ import annotations

import base64
import binascii

SECTIONS = ('vm_mac',)

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
"""


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
    return {'vm_mac': vm_mac(s.get('vm_mac', []))}


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
