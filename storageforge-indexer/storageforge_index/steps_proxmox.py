"""Proxmox VE as plan steps: guests are started, stopped, snapshotted and removed with qm and pct on the node, so that whatever the script does
shows in the Proxmox web interface. The generic VM and LXC steps refuse a node (pvenode.py); these are the ones that belong there.

pve-action   start, shutdown, stop, reboot or snapshot a guest, named by kind (qemu or lxc), VMID and name.
pve-remove   destroy a stopped guest (destructive; the name is typed again to confirm).

A VMID alone is not enough to act on: the script reads the guest's name from qm or pct config and refuses when it is not the name in the step,
so a plan written for one node cannot touch another guest that happens to hold the same number on a different node.

The module holds one BASH block with a helper every Proxmox step shares (pve_guest); the Ansible export carries the whole block.
"""
from __future__ import annotations

import re
import shlex

from . import changes, pvenode
from .changes import F

KINDS = ['qemu', 'lxc']
ACTIONS = ['start', 'shutdown', 'stop', 'reboot', 'snapshot']
SNAPSHOT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,39}')
VMID_MIN, VMID_MAX = 100, 999999999

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
# pve_guest KIND VMID NAME: sets PVE_TOOL (qm or pct) and PVE_STATE (running, stopped...), and refuses a guest that is not there or whose
# name is not NAME. Every Proxmox step starts with it.
pve_guest() { local kind=$1 vmid=$2 name=$3 key cfg got
  case $kind in qemu) PVE_TOOL=qm key=name ;; lxc) PVE_TOOL=pct key=hostname ;; *) conflict "the kind of guest is qemu or lxc"; return 1 ;; esac
  command -v "$PVE_TOOL" >/dev/null || { conflict "this host is not a Proxmox VE node: $PVE_TOOL is not here"; return 1; }
  if ! PVE_STATE=$("$PVE_TOOL" status "$vmid" 2>/dev/null); then
    if ((APPLY)); then conflict "no $kind guest with VMID $vmid on this node"; else missing "no $kind guest with VMID $vmid was readable as $(id -un): --apply, as root, looks"; fi
    return 1
  fi
  PVE_STATE=${PVE_STATE#status:}; PVE_STATE=${PVE_STATE//[[:space:]]/}
  # read into a variable first: awk quitting early would make qm fail under pipefail
  cfg=$("$PVE_TOOL" config "$vmid" 2>/dev/null) || cfg=
  got=$(awk -v k="$key:" '$1 == k { print $2; exit }' <<<"$cfg")
  [[ $got == "$name" ]] || { conflict "VMID $vmid is named ${got:-nothing}, not $name: it is another guest, so it is left alone"; return 1; }
  return 0
}

t_pve_action() { local kind=$1 vmid=$2 name=$3 action=$4 snap=$5
  pve_guest "$kind" "$vmid" "$name" || return 0
  case $action in
    start) [[ $PVE_STATE == running ]] && { ok "$name ($vmid) is already running"; return 0; } ;;
    shutdown|stop) [[ $PVE_STATE != running ]] && { ok "$name ($vmid) is already stopped"; return 0; } ;;
    reboot) [[ $PVE_STATE == running ]] || { conflict "$name ($vmid) is $PVE_STATE: only a running guest reboots"; return 0; } ;;
    snapshot) [[ $snap =~ ^[A-Za-z][A-Za-z0-9_-]{0,39}$ ]] || { conflict "a snapshot name starts with a letter and holds letters, digits, - and _"; return 0; } ;;
    *) conflict "unknown action $action"; return 0 ;;
  esac
  if [[ $action == snapshot ]]; then
    act "snapshot $name ($vmid) as $snap through $PVE_TOOL" || return 0
    try "$PVE_TOOL" snapshot "$vmid" "$snap" >/dev/null && ok "snapshot $snap: $name ($vmid)"
  else
    act "$action $name ($vmid) through $PVE_TOOL" || return 0
    try "$PVE_TOOL" "$action" "$vmid" >/dev/null && ok "$action: $name ($vmid)"
  fi
  return 0
}

t_pve_remove() { local kind=$1 vmid=$2 name=$3 purge=$4
  pve_guest "$kind" "$vmid" "$name" || return 0
  [[ $PVE_STATE == stopped ]] || { conflict "$name ($vmid) is $PVE_STATE: stop it first"; return 0; }
  act "destroy $name ($vmid) through $PVE_TOOL${purge:+, and take it out of backup jobs and replication}" || return 0
  try "$PVE_TOOL" destroy "$vmid" ${purge:+--purge} >/dev/null && ok "destroyed: $name ($vmid)"
  return 0
}
"""

ANSIBLE_HEAD = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }; skip() { echo "skip: $*"; }\n'
                'doing() { echo "changed: $*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')


def ansible_of(fn: str, args: tuple, destructive=False):
    def render(t):
        q = shlex.quote
        p = t['params']
        words = [('1' if p.get(a) else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in args]
        task = {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': ANSIBLE_HEAD + BASH + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
        if destructive:
            task.update(tags=['destructive'], when='storageforge_destructive | default(false) | bool')
        return task
    return render


def guest_check(conn, h, p, say) -> dict | None:
    """The part of the check both steps share: a node, a sensible VMID, and what the last reading holds under that VMID. Returns the guest or None."""
    from . import workloads
    if not pvenode.is_proxmox_host(conn, h['name']):
        say('crit', f'{h["name"]} is not a Proxmox VE node: these steps run qm and pct there, so the guest shows in Proxmox. Use the generic steps on a plain host')
        return None
    vmid = int(p['vmid'])
    if not VMID_MIN <= vmid <= VMID_MAX:
        say('crit', f'a VMID is between {VMID_MIN} and {VMID_MAX}')
    w = next((x for x in workloads.listing(conn, h['name'])['workloads'] if x['runtime'] == 'proxmox' and str(x.get('vmid')) == str(vmid)), None)
    if not w:
        say('note', f'VMID {vmid} was not in the last reading of {h["name"]}: the script looks when it runs')
        return None
    if (w['kind'] == 'vm') != (p['kind'] == 'qemu'):
        say('crit', f'VMID {vmid} is {"a VM" if w["kind"] == "vm" else "a container"} on {h["name"]}: choose {"qemu" if w["kind"] == "vm" else "lxc"}')
    if w.get('name') != p['name']:
        say('crit', f'VMID {vmid} is named {w.get("name")} on {h["name"]}, not {p["name"]}: the script leaves another guest alone')
    return w


def check_action(conn, c, h, p, say):
    w = guest_check(conn, h, p, say)
    if p['action'] == 'snapshot':
        if not SNAPSHOT.fullmatch(p.get('snapshot') or ''):
            say('crit', 'name the snapshot: it starts with a letter and holds letters, digits, - and _ (up to 40)')
    elif p.get('snapshot'):
        say('note', 'the snapshot name is used by the snapshot action only')
    if not w or w.get('name') != p['name']:
        return
    state = w.get('state')
    if p['action'] == 'start' and state == 'running':
        say('ok', f'{p["name"]} ({p["vmid"]}) is already running')
    elif p['action'] in ('shutdown', 'stop') and state != 'running':
        say('ok', f'{p["name"]} ({p["vmid"]}) is already stopped')
    elif p['action'] == 'reboot' and state != 'running':
        say('warn', f'{p["name"]} ({p["vmid"]}) is {state}: only a running guest reboots')
    elif p['action'] == 'stop':
        say('warn', f'stop is as pulling the power on {p["name"]}: shutdown asks the guest to stop first')


def check_remove(conn, c, h, p, say):
    w = guest_check(conn, h, p, say)
    say('warn', 'destroying a guest deletes its disks' + (' and takes it out of backup jobs and replication' if p.get('purge') else ''))
    if w and w.get('name') == p['name'] and w.get('state') == 'running':
        say('crit', f'{p["name"]} ({p["vmid"]}) is running: stop it first (a Proxmox action step before this one)')


ACTION_ARGS = ('kind', 'vmid', 'name', 'action', 'snapshot')
REMOVE_ARGS = ('kind', 'vmid', 'name', 'purge')
KIND = F('kind', 'choice', 'Kind of guest', options=KINDS, required=True, default='qemu')
VMID = F('vmid', 'vmid', 'VMID', required=True, placeholder='101')
NAME = F('name', 'name', 'Name', required=True, placeholder='web-01')

changes.register('pve-action', {'group': 'Proxmox VE', 'label': 'Start, stop or snapshot a Proxmox guest', 'fields': [
    KIND, VMID, NAME, F('action', 'choice', 'Action', options=ACTIONS, required=True, default='start'),
    F('snapshot', 'name', 'Snapshot name (snapshot only)', placeholder='before-upgrade')],
    'help': 'Runs qm or pct on the node, so Proxmox shows it. The name must be the one the guest has: another guest with the same VMID is left alone. '
            'Shutdown asks the guest to stop, stop pulls the power.'},
    ACTION_ARGS, lambda p: f'Proxmox {p["kind"]} {p["name"]} ({p["vmid"]}): {p["action"]}' + (f' as {p["snapshot"]}' if p['action'] == 'snapshot' and p.get('snapshot') else ''),
    check_action, ansible_of('t_pve_action', ACTION_ARGS))

changes.register('pve-remove', {'group': 'Proxmox VE', 'label': 'Remove a Proxmox guest', 'destructive': True, 'confirm_of': 'name', 'fields': [
    KIND, VMID, NAME, F('purge', 'bool', 'Also take it out of backup jobs and replication', default=True),
    F('confirm', 'confirm', 'Type its name again to confirm', required=True)],
    'help': 'Destroys a stopped guest and its disks with qm or pct destroy. The name must be the one the guest has.'},
    REMOVE_ARGS, lambda p: f'Remove Proxmox {p["kind"]} {p["name"]} ({p["vmid"]})', check_remove, ansible_of('t_pve_remove', REMOVE_ARGS, destructive=True))
changes.EXTRA_BASH.append(BASH)
