"""MAC at deploy for VMs (roadmap section 6, infrastructure-platform-roadmap.md 7.4): the vm-mac plan step, which lets QEMU use a folder of
VM disks under whichever MAC the host runs.

SELinux: QEMU may only open files labelled for VMs. Under /var/lib/libvirt/images the policy labels them virt_image_t; a pool anywhere
else has whatever its parent has, and a VM with a disk there fails to start with an AVC denial. The fix is the svirt_image_t fix the
roadmap names: register the folder as virt_image_t with semanage fcontext, so a relabel keeps it, and restorecon it. libvirt then gives
each running VM its disk as svirt_image_t with categories of its own.

AppArmor: libvirt writes a profile per VM with its disks in it, but a backing file, a disk added later or a pool path can still be
refused. The fix is two path rules in /etc/apparmor.d/local/abstractions/libvirt-qemu, which every VM profile includes. The file is
checked by apparmor_parser through a profile that includes the abstraction, as libvirt reads it, and put back when it is refused; the
profiles of running VMs are reloaded.

Container bind mounts get their SELinux label at deploy from the stack step (:Z or :z, steps_workloads.py).
"""
from __future__ import annotations

import shlex

from . import changes
from .changes import F

SYSTEM = ('/', '/etc', '/usr', '/var', '/var/lib', '/boot', '/root', '/home', '/proc', '/sys', '/dev', '/run', '/tmp', '/srv', '/opt', '/mnt', '/media')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
t_vm_mac() { local path=${1%/} want=$2 root=${WLM_ROOT:-} now file prof tmp err f
  file=$root/etc/apparmor.d/local/abstractions/libvirt-qemu
  if [[ -z $want ]]; then
    if command -v getenforce >/dev/null && [[ -n $(getenforce 2>/dev/null) && $(getenforce 2>/dev/null) != Disabled ]]; then want=selinux
    elif [[ $(cat "$root/sys/module/apparmor/parameters/enabled" 2>/dev/null) == Y ]]; then want=apparmor
    else ok "neither SELinux nor AppArmor is on here: nothing keeps QEMU from $path"; return 0; fi
  fi
  case ${path:-/} in /|/etc|/usr|/var|/var/lib|/boot|/root|/home|/proc|/sys|/dev|/run|/tmp|/srv|/opt|/mnt|/media) conflict "$path is a system folder: name the folder the VM disks are in"; return 0 ;; esac
  [[ -d $path ]] || { later "$path is not there yet"; return 0; }
  if [[ $want == selinux ]]; then
    command -v semanage >/dev/null || { conflict "semanage is not installed (policycoreutils-python-utils)"; return 0; }
    now=$(stat -c %C -- "$path" 2>/dev/null | cut -d: -f3)
    if [[ $now == virt_image_t ]] && semanage fcontext -l -C 2>/dev/null | grep -F -- "$path(/.*)?" | grep -q virt_image_t; then
      ok "$path is virt_image_t, and registered so a relabel keeps it"; return 0
    fi
    info "$path is ${now:-not labelled} now. libvirt gives each running VM its disks as svirt_image_t, with categories of its own, from virt_image_t"
    act "label $path virt_image_t with semanage fcontext, and restorecon it" || return 0
    semanage fcontext -a -t virt_image_t "$path(/.*)?" 2>/dev/null || try semanage fcontext -m -t virt_image_t "$path(/.*)?" || return 0
    try restorecon -R -- "$path" && ok "$path is virt_image_t"
    return 0
  fi
  [[ $want == apparmor ]] || { conflict "the MAC is selinux or apparmor"; return 0; }
  command -v apparmor_parser >/dev/null || { conflict "this host has no apparmor_parser"; return 0; }
  [[ -r $root/etc/apparmor.d/abstractions/libvirt-qemu ]] || { conflict "there is no libvirt-qemu abstraction here: is libvirt installed?"; return 0; }
  if [[ -r $file ]] && grep -qxF "  \"$path/**\" rwk," "$file"; then ok "AppArmor lets QEMU use $path"; return 0; fi
  act "let QEMU use $path, in $file" || return 0
  install -d -m 0755 "$(dirname "$file")"
  tmp=$(mktemp); [[ -r $file ]] && cp -a "$file" "$tmp"
  printf "# storageforge vm-mac %s\n  \"%s/\" r,\n  \"%s/**\" rwk,\n" "$path" "$path" "$path" >>"$file"
  # checked as libvirt reads it: through a profile that includes the abstraction, which includes this file
  prof=$(mktemp); err=$(mktemp)
  printf "profile sf-vm-mac-check {\n  #include <abstractions/libvirt-qemu>\n}\n" >"$prof"
  if ! apparmor_parser -Q -K -I "$root/etc/apparmor.d" "$prof" >"$err" 2>&1; then
    if [[ -s $tmp ]]; then cp -a "$tmp" "$file"; else rm -f "$file"; fi
    conflict "apparmor_parser refused it, so the file was put back: $(tail -n 3 "$err" | tr "\n" " ")"; rm -f "$tmp" "$prof" "$err"; return 0
  fi
  rm -f "$tmp" "$prof" "$err"
  # a running VM keeps the profile it started with: reload each, so it sees the folder too
  for f in "$root"/etc/apparmor.d/libvirt/libvirt-*; do [[ -f $f && $f != *.files ]] && apparmor_parser -r "$f" >/dev/null 2>&1; done
  ok "AppArmor lets QEMU use $path, for VMs started from now on and the running ones"
}
"""


def _check(conn, c, h, p, say):
    from . import inframeasure, security
    path = (p.get('path') or '').rstrip('/') or '/'
    if path in SYSTEM:
        say('crit', f'{path} is a system folder: name the folder the VM disks are in')
        return
    m = security.measurement(conn, h['name']) or {}
    have = 'selinux' if m.get('selinux') and m['selinux'] != 'Disabled' else 'apparmor' if (m.get('apparmor') or {}).get('enabled') else None
    want = p.get('system') or have
    if not m:
        say('note', f'no security reading of {h["name"]} yet: the script finds out which MAC it runs')
    elif not have:
        say('note', f'the last security reading of {h["name"]} saw neither SELinux nor AppArmor: nothing to label')
    elif p.get('system') and p['system'] != have:
        say('warn', f'{h["name"]} runs {have}, not {p["system"]}')
    if path == '/var/lib/libvirt/images' or path.startswith('/var/lib/libvirt/images/'):
        say('note', 'under /var/lib/libvirt/images the policy already lets QEMU in: this step is for pools anywhere else')
    r = inframeasure.reading(conn, h['name']) or {}
    users = sorted({d['name'] for d in r.get('libvirt') or [] for x in d.get('disks') or [] if (x.get('source') or '').startswith(path + '/')})
    if users:
        say('note', f'VMs with disks there: {", ".join(users[:8])}')
    if want == 'selinux':
        say('note', f'registers {path}(/.*)? as virt_image_t with semanage fcontext, so a relabel keeps it, and runs restorecon')
    elif want == 'apparmor':
        say('note', f'adds two path rules for {path} to /etc/apparmor.d/local/abstractions/libvirt-qemu, checked by apparmor_parser first and put back if refused')


def _ansible(t):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\nt_vm_mac {q(p["path"])} {q(p.get("system") or "")}\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.register('vm-mac', {'group': 'VMs', 'label': 'Let VMs use a folder of disks (SELinux or AppArmor)', 'fields': [
    F('path', 'path', 'Folder of VM disks', required=True, placeholder='/tank/vm'), F('system', 'choice', 'MAC', options=['', 'selinux', 'apparmor'], default='')],
    'help': 'SELinux: the folder registered as virt_image_t and relabelled. AppArmor: the folder added to the local libvirt-qemu abstraction, checked first. '
            'Left empty, the MAC is whichever the host runs.'},
    ('path', 'system'), lambda p: f'Let VMs use {p["path"]}' + (f' ({p["system"]})' if p.get('system') else ''), _check, _ansible)
changes.EXTRA_BASH.append(BASH)
