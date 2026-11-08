"""The md-array plan step: an mdadm array made from devices, with a filesystem on it (docs/host-migration.md).

It is a drive step like zfs-pool and lvm-vg: destructive, so the script runs it only with --apply --destructive and the
devices typed again, and each device must be free (nothing mounted, swapped on, or in another array, LUKS or LVM) and
hold no filesystem unless the plan allows overwriting it. The array is written to mdadm.conf, so udev puts it together
at boot; the boot image is left alone, as a data array does not need it.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import CONFIRM_ALL, DEVICES, MKFS, F

LEVELS = ['raid1', 'raid0', 'raid5', 'raid6', 'raid10', 'raid4', 'linear']
MIN = {'raid0': 2, 'raid1': 2, 'raid4': 3, 'raid5': 3, 'raid6': 4, 'raid10': 2, 'linear': 1}
NAME = re.compile(r'[A-Za-z0-9_-]{1,32}')
ARGS = ('name', 'level', 'devices', 'metadata', 'fstype', 'label', 'wipe')
FIELDS = [F('name', 'name', 'Array name (/dev/md/<name>)', required=True, placeholder='data'),
          F('level', 'choice', 'Level', options=LEVELS, required=True), DEVICES,
          F('metadata', 'choice', 'Metadata (1.2 if empty)', options=['', '1.2', '1.0']),
          F('fstype', 'choice', 'Then format as', options=[''] + MKFS), F('label', 'label', 'Label'),
          F('wipe', 'bool', 'They have a filesystem: overwrite it'), CONFIRM_ALL]

# mdadm takes no -- to end its options: the devices field allows only /dev/ paths, so none can be read as an option.
# Uses need, devs_guard, act, try, mkfs_dev and the report helpers of the change script. No apostrophes: the script
# text is checked for values that could end a quoted word.
BASH = r"""
md_conf() { if [[ -d /etc/mdadm ]]; then echo /etc/mdadm/mdadm.conf; else echo /etc/mdadm.conf; fi; }
t_md_array() { local name=$1 level=$2 devs=$3 meta=${4:-1.2} fs=$5 label=$6 wipe=$7 arr d dev conf line uuid have
  need mdadm mdadm || return 0
  dev=/dev/md/$name
  read -ra arr <<<"$devs"
  if [[ -e $dev ]] && mdadm --detail "$dev" >/dev/null 2>&1; then
    ok "array $name exists ($(mdadm --detail "$dev" | sed -n "s/^ *Raid Level : //p"), $(mdadm --detail "$dev" | sed -n "s/^ *State : //p"))"
  else
    # a cut-down kernel (openSUSE kernel-default-base, some cloud kernels) has no md driver: say so before any disk is touched
    if [[ ! -d /sys/module/md_mod ]] && ! modinfo md_mod >/dev/null 2>&1 && ! grep -qs "^Personalities" /proc/mdstat; then
      local hint="install the full kernel package and reboot, then run this again"
      rpm -q kernel-default-base >/dev/null 2>&1 && hint="this is kernel-default-base: zypper install kernel-default (it replaces it), reboot, then run this again"
      conflict "the running kernel $(uname -r) has no md driver (md_mod): $hint"; return 0
    fi
    devs_guard "$wipe" "${arr[@]}" || return 0
    act "mdadm --create $dev --level=$level --raid-devices=${#arr[@]} $devs${fs:+, then mkfs.$fs}" || return 0
    if [[ $wipe == 1 ]]; then for d in "${arr[@]}"; do try wipefs -aq -- "$d" || return 0; done; fi
    try mdadm --create "$dev" --run --level="$level" --raid-devices="${#arr[@]}" --metadata="$meta" --name="$name" "${arr[@]}" || return 0
    ok "created: it syncs in the background (cat /proc/mdstat), and is usable meanwhile"
  fi
  conf=$(md_conf)
  uuid=$(mdadm --detail --export "$dev" 2>/dev/null | sed -n "s/^MD_UUID=//p")
  if [[ -n $uuid ]] && ! grep -qs -- "$uuid" "$conf"; then
    if act "add the array to $conf, so it is put together at boot"; then
      line=$(mdadm --detail --brief "$dev")
      install -d -m 0755 "$(dirname "$conf")"; [[ -e $conf ]] && cp -a "$conf" "$conf.storageforge-$STAMP"
      printf "%s\n" "$line" >>"$conf" && ok "$conf: $line"
    fi
  elif [[ -n $uuid ]]; then ok "$conf names it"; fi
  [[ -n $fs ]] || return 0
  have=$(blkid -p -o value -s TYPE -- "$dev" 2>/dev/null || true)
  if [[ $have == "$fs" ]]; then ok "$dev is $fs"; return 0; fi
  [[ -z $have ]] || { conflict "$dev holds $have: the plan formats only an array it made empty"; return 0; }
  act "mkfs.$fs ${label:+-L $label }$dev" || return 0
  mkfs_dev "$dev" "$fs" "$label" "" && ok "formatted" || conflict "mkfs.$fs $dev failed"
}
"""


def _check(conn, c, h, p, say):
    if not NAME.fullmatch(p['name']):
        say('crit', f'{p["name"]} is not an array name: letters, digits, - and _, up to 32')
        return
    if any(x['type'] == 'mdadm' and x['name'] in (p['name'], f'md/{p["name"]}') for x in c.node['pools']):
        say('ok', f'array {p["name"]} already exists: nothing to do')
        return
    devs = p['devices'].split()
    if len(devs) < MIN.get(p['level'], 2):
        say('crit', f'{p["level"]} needs at least {MIN.get(p["level"], 2)} devices')
    changes._check_devices(c, h, devs, p['wipe'], say)
    if p['label']:
        lab = p['label'].lower()
        if lab in c.new_labels or any((x.get('label') or '').lower() == lab for d in c.node['disks'] for x in d['parts']):
            say('crit', f'the label {p["label"]} is already on {h["name"]}: a mount by label would find two')
        elif len(p['label']) > changes.LABEL_MAX.get(p['fstype'], 64):
            say('crit', f'{p["fstype"]} labels are at most {changes.LABEL_MAX[p["fstype"]]} characters')
        c.new_labels.add(lab)
    say('note', 'the array is written to mdadm.conf and put together at boot by udev; the boot image is left alone')


def _ansible(t):
    q = shlex.quote
    p = t['params']
    dev = f'/dev/md/{p["name"]}'
    devs = ' '.join(q(d) for d in p['devices'].split())
    guard = ('' if p.get('wipe') else
             f'for d in {devs}; do t=$(blkid -p -o value -s TYPE -- "$d" 2>/dev/null); [ -z "$t" ] || {{ echo "$d holds $t" >&2; exit 1; }}; done; ')
    wipe = f'for d in {devs}; do wipefs -aq -- "$d"; done; ' if p.get('wipe') else ''
    mk = (f'[ -n "$(blkid -p -o value -s TYPE -- {q(dev)})" ] || {{ mkfs.{p["fstype"]} {"-L " + q(p["label"]) + " " if p["label"] else ""}{q(dev)} && echo changed; }}; '
          if p.get('fstype') else '')
    cmd = (f'set -e; if ! mdadm --detail {q(dev)} >/dev/null 2>&1; then {guard}{wipe}'
           f'mdadm --create {q(dev)} --run --level={q(p["level"])} --raid-devices={len(p["devices"].split())} --metadata={q(p["metadata"] or "1.2")} '
           f'--name={q(p["name"])} -- {devs}; echo changed; fi; '
           'c=/etc/mdadm.conf; [ -d /etc/mdadm ] && c=/etc/mdadm/mdadm.conf; '
           f'u=$(mdadm --detail --export {q(dev)} | sed -n "s/^MD_UUID=//p"); grep -qs -- "$u" "$c" || {{ mdadm --detail --brief {q(dev)} >>"$c"; echo changed; }}; '
           + mk)
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': cmd, 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.register('md-array', {'group': 'mdadm', 'label': 'Create an mdadm array', 'destructive': True, 'fields': FIELDS,
    'help': 'An array at /dev/md/<name> from the devices, written to mdadm.conf so it is put together at boot, and formatted if asked. '
            'Prefer stable names from /dev/disk/by-id: sdX names can change at boot.'},
    ARGS, lambda p: f'Create mdadm array {p["name"]} ({p["level"]}) on {p["devices"]}', _check, _ansible)
changes.EXTRA_BASH.append(BASH)
