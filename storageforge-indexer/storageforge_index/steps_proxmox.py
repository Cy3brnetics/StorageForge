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
# pve_free_vmid VMID TOOL: PVE_VMID is VMID, or the next free one Proxmox offers when it is empty; a VMID that is already a guest is a conflict.
pve_free_vmid() { local vmid=$1 tool=$2
  if [[ -z $vmid ]]; then
    vmid=$(pvesh get /cluster/nextid 2>/dev/null) || vmid=
    [[ $vmid =~ ^[0-9]+$ ]] || { conflict "Proxmox gave no free VMID: name one in the step"; return 1; }
  fi
  if "$tool" status "$vmid" >/dev/null 2>&1; then conflict "VMID $vmid is already a guest on this node: it is left alone"; return 1; fi
  PVE_VMID=$vmid
}

# The vault secret NAME as a file: where an apply from StorageForge wrote it, or where a test puts it.
pve_secret() { local d=/run/storageforge/secrets; ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}; echo "$d/$1"; }

# t_pve_ct VMID HOSTNAME TEMPLATE STORAGE DISK_GB CORES MEMORY_MB BRIDGE IP GATEWAY SSH_KEY PASSWORD_SECRET UNPRIVILEGED ONBOOT START
# An existing VMID is left alone. The root password is never an argument of any command: the vault secret is read from its file by a pipe into
# chpasswd inside the container, and the container is stopped again unless it was asked to start.
t_pve_ct() { local vmid=$1 host=$2 tmpl=$3 store=$4 disk=${5:-8} cores=${6:-1} mem=${7:-512} bridge=${8:-vmbr0} ip=${9:-dhcp} gw=${10} key=${11} sec=${12} unpriv=${13} onboot=${14} start=${15}
  local out tstore list net src= keyf= i ok_pw=0 name err=
  local -a args
  command -v pct >/dev/null || { conflict "this host is not a Proxmox VE node: pct is not here"; return 0; }
  pve_free_vmid "$vmid" pct || return 0
  vmid=$PVE_VMID
  if [[ -n $sec ]]; then
    src=$(pve_secret "$sec")
    if [[ ! -s $src ]]; then
      if ((APPLY)); then conflict "the vault secret $sec is not on this host: apply this from StorageForge, which brings it"; return 0; fi
      info "the vault secret $sec arrives with an apply from StorageForge"
    fi
  fi
  if [[ $tmpl != *:* ]]; then
    name=$tmpl
    out=$(pvesm status --content vztmpl 2>/dev/null) || out=
    tstore=$(awk 'NR > 1 && $3 == "active" { print $1; exit }' <<<"$out")
    [[ -n $tstore ]] || { conflict "no storage on this node holds container templates (content vztmpl)"; return 0; }
    tmpl=$tstore:vztmpl/$name
    list=$(pveam list "$tstore" 2>/dev/null) || list=
    if grep -qF -- "$tmpl" <<<"$list"; then ok "template $tmpl is on $tstore"
    elif act "download the template $name into $tstore with pveam"; then
      try pveam update >/dev/null && try pveam download "$tstore" "$name" >/dev/null || return 0
    fi
  else
    list=$(pveam list "${tmpl%%:*}" 2>/dev/null) || list=
    if ! grep -qF -- "$tmpl" <<<"$list"; then
      if ((APPLY)); then conflict "the template $tmpl is not on this node"; return 0; fi
      missing "the template $tmpl was not seen on this node: an apply checks again"
    fi
  fi
  net=name=eth0,bridge=$bridge,ip=$ip${gw:+,gw=$gw}
  act "create container $vmid ($host) from $tmpl on $store: ${disk} GiB, $cores cores, ${mem} MiB, $net${sec:+, root password from the vault}${key:+, with an SSH key}" || return 0
  args=("$vmid" "$tmpl" --hostname "$host" --storage "$store" --rootfs "$store:$disk" --cores "$cores" --memory "$mem" --net0 "$net" --unprivileged "${unpriv:-0}")
  [[ -n $onboot ]] && args+=(--onboot 1)
  if [[ -n $key ]]; then
    keyf=$(mktemp) && chmod 600 "$keyf" && printf "%s\n" "$key" >"$keyf" || { rm -f -- "$keyf"; conflict "could not write the SSH key to a temporary file"; return 0; }
    args+=(--ssh-public-keys "$keyf")
  fi
  if try pct create "${args[@]}" >/dev/null; then rm -f -- "$keyf"; else rm -f -- "$keyf"; return 0; fi
  ok "created container $vmid ($host)"
  if [[ -n $sec ]]; then
    try pct start "$vmid" >/dev/null || return 0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      if err=$({ printf "root:"; tr -d "\n" <"$src"; printf "\n"; } | pct exec "$vmid" -- chpasswd 2>&1); then ok_pw=1; break; fi
      sleep 2
    done
    # stopped before the conflict is said: an Ansible run exits on it, and would leave the container running
    [[ -n $start ]] || { try pct shutdown "$vmid" --forceStop 1 --timeout 30 >/dev/null && ok "stopped $vmid again: it was not asked to start"; }
    if ((ok_pw)); then ok "root password of $vmid set from the vault secret $sec"
    else err=${err//$'\n'/ }; conflict "could not set the root password of $vmid: ${err:0:200}"; return 0; fi
  elif [[ -n $start ]]; then
    try pct start "$vmid" >/dev/null && ok "started $vmid"
  fi
  return 0
}

# t_pve_vm VMID NAME SOURCE ISO IMAGE STORAGE DISK_GB CORES MEMORY_MB BRIDGE OSTYPE USER SSH_KEY ONBOOT START
# From an ISO already on the node, or from a catalog cloud image that is downloaded into a temporary folder, checked and imported. The folder is
# removed on every way out. pve_vm_make reads this function locals, as every function it calls does in bash.
t_pve_vm() { local vmid=$1 name=$2 source=$3 iso=$4 image=$5 store=$6 disk=${7:-32} cores=${8:-2} mem=${9:-2048} bridge=${10:-vmbr0} ostype=${11:-l26} user=${12:-admin} key=${13} onboot=${14} start=${15}
  local tmp= prev
  command -v qm >/dev/null || { conflict "this host is not a Proxmox VE node: qm is not here"; return 0; }
  pve_free_vmid "$vmid" qm || return 0
  vmid=$PVE_VMID
  if [[ $source == iso ]]; then
    [[ -n $iso ]] || { conflict "name the ISO image, as storage:iso/file"; return 0; }
    if ! pvesm path "$iso" >/dev/null 2>&1; then
      if ((APPLY)); then conflict "the ISO $iso is not on this node"; return 0; fi
      missing "the ISO $iso was not seen on this node: an apply checks again"
    fi
  else
    sf_vm_image "$image" >/dev/null || { conflict "no image $image in the catalog"; return 0; }
  fi
  act "create VM $vmid ($name) from ${iso:-$image} on $store: ${disk} GiB, $cores cores, ${mem} MiB, bridge $bridge" || return 0
  tmp=$(mktemp -d) || { conflict "could not make a temporary folder"; return 0; }
  # an Ansible export exits on a conflict: the trap removes the folder then too, and hands over to the trap that was there
  prev=$(trap -p EXIT)
  trap 'rm -rf -- "$tmp"; eval "$prev"' EXIT
  pve_vm_make || true
  rm -rf -- "$tmp"
  trap - EXIT; [[ -z $prev ]] || eval "$prev"
  return 0
}

pve_vm_make() { local url sums cos base keyf help unused
  local -a args=("$vmid" --name "$name" --memory "$mem" --cores "$cores" --net0 "virtio,bridge=$bridge" --scsihw virtio-scsi-single --ostype "$ostype" --agent 1)
  [[ -n $onboot ]] && args+=(--onboot 1)
  if [[ $source == iso ]]; then
    args+=(--scsi0 "$store:$disk" --ide2 "$iso,media=cdrom" --boot "order=scsi0;ide2")
    try qm create "${args[@]}" >/dev/null || return 1
  else
    IFS=$'\t' read -r url sums cos < <(sf_vm_image "$image") || { conflict "no image $image in the catalog"; return 1; }
    base=$tmp/$(basename "$url")
    sf_vm_fetch "$url" "" "$sums" "$base" || return 1
    args+=(--boot order=scsi0)
    help=$(qm help create 2>&1) || help=
    if grep -q import-from <<<"$help"; then
      try qm create "${args[@]}" --scsi0 "$store:0,import-from=$base" >/dev/null || return 1
    else
      try qm create "${args[@]}" >/dev/null || return 1
      try qm importdisk "$vmid" "$base" "$store" >/dev/null || return 1
      unused=$(qm config "$vmid" | awk '$1 == "unused0:" { print $2; exit }')
      [[ -n $unused ]] || { conflict "qm importdisk made no disk for $vmid"; return 1; }
      try qm set "$vmid" --scsi0 "$unused" >/dev/null || return 1
    fi
    try qm resize "$vmid" scsi0 "${disk}G" >/dev/null || return 1
    try qm set "$vmid" --ide2 "$store:cloudinit" --ciuser "$user" --ipconfig0 ip=dhcp --serial0 socket --vga serial0 >/dev/null || return 1
    if [[ -n $key ]]; then
      keyf=$tmp/key.pub; printf "%s\n" "$key" >"$keyf"
      try qm set "$vmid" --sshkeys "$keyf" >/dev/null || return 1
    fi
  fi
  ok "created VM $vmid ($name)"
  [[ -n $start ]] && { try qm start "$vmid" >/dev/null && ok "started $vmid"; }
  return 0
}
"""

ANSIBLE_HEAD = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }; skip() { echo "skip: $*"; }\n'
                'doing() { echo "changed: $*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')


def _vm_helpers() -> str:
    """The cloud image catalog and the download-and-check function of vm-create, which t_pve_vm calls: an export holds one step, so it carries them."""
    from . import steps_vm
    return ''.join(re.search(rf'^{fn}\(\) \{{.*?^\}}$', steps_vm.bash(), re.M | re.S)[0] + '\n' for fn in ('sf_vm_image', 'sf_vm_fetch'))


def ansible_of(fn: str, args: tuple, destructive=False):
    def render(t):
        q = shlex.quote
        p = t['params']
        words = [('1' if p.get(a) else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in args]
        task = {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': ANSIBLE_HEAD + (_vm_helpers() if fn == 't_pve_vm' else '') + BASH + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
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
# ── a container ─────────────────────────────────────────────────────
CT_ARGS = ('vmid', 'hostname', 'template', 'storage', 'disk_gb', 'cores', 'memory_mb', 'bridge', 'ip', 'gateway', 'ssh_key', 'password_secret', 'unprivileged', 'onboot', 'start')
HOSTNAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*')


def check_ct(conn, c, h, p, say):
    from . import inframeasure, workloads
    if not pvenode.is_proxmox_host(conn, h['name']):
        say('crit', f'{h["name"]} is not a Proxmox VE node: this step runs pct there, so the container shows in Proxmox. Use the generic LXC step on a plain host')
        return
    if not HOSTNAME.fullmatch(p['hostname']):
        say('crit', 'a container hostname is letters, digits and hyphens, with dots between labels')
    if p.get('vmid'):
        w = next((x for x in workloads.listing(conn, h['name'])['workloads'] if x['runtime'] == 'proxmox' and str(x.get('vmid')) == p['vmid']), None)
        if w:
            say('crit', f'VMID {p["vmid"]} is already {w.get("name")} on {h["name"]}: the script leaves it alone')
        elif not VMID_MIN <= int(p['vmid']) <= VMID_MAX:
            say('crit', f'a VMID is between {VMID_MIN} and {VMID_MAX}')
    else:
        say('note', 'no VMID given: the script asks Proxmox for the next free one')
    node = (inframeasure.reading(conn, h['name']) or {}).get('proxmox_node')
    if not node:
        say('note', f'the storages and templates of {h["name"]} are not read yet: the script checks when it runs')
    else:
        _storage_check(node, p, h['name'], say)
    if p['ip'] != 'dhcp':
        if not p.get('gateway'):
            say('warn', f'{p["ip"]} has no gateway: the container reaches only its own network')
    elif p.get('gateway'):
        say('note', 'the gateway is used with a fixed address only: with dhcp it is ignored')
    if not (p.get('ssh_key') or p.get('password_secret')):
        say('warn', 'no SSH key and no root password: the only way in is pct enter on the node')
    if p.get('password_secret'):
        say('note', f'the secret {p["password_secret"]} reaches {h["name"]} on the runner stdin in an apply; the container is started once to set the root password through chpasswd'
                    + ('' if p.get('start') else ', then stopped again'))
    if not p.get('unprivileged'):
        say('warn', 'a privileged container has root of the node inside it: prefer unprivileged unless it needs more')


def _storage_check(node: dict, p: dict, host: str, say):
    stores = {s['name']: s for s in node.get('storages') or []}
    have = ', '.join(sorted(stores)) or 'none'
    root = stores.get(p['storage'])
    if not root:
        say('crit', f'{host} has no storage {p["storage"]}: it has {have}')
    elif root.get('content') and 'rootdir' not in root['content']:
        say('crit', f'{p["storage"]} does not hold container disks (content {", ".join(root["content"])}): choose one with rootdir, such as {", ".join(n for n, s in sorted(stores.items()) if "rootdir" in (s.get("content") or [])) or "none here"}')
    elif not root.get('active'):
        say('warn', f'{p["storage"]} is not active on {host}')
    volids = {t['volid'] for t in node.get('templates') or []}
    tmpl = p['template']
    if ':' in tmpl:
        tstore = stores.get(tmpl.split(':', 1)[0])
        if not tstore or 'vztmpl' not in (tstore.get('content') or []):
            say('crit', f'{tmpl.split(":", 1)[0]} does not hold container templates on {host}: pick a storage with vztmpl ({", ".join(n for n, s in sorted(stores.items()) if "vztmpl" in (s.get("content") or [])) or "none here"})')
        elif tmpl not in volids:
            say('warn', f'{tmpl} was not in the last reading of {host}: the script checks again when it runs')
        else:
            say('ok', f'{tmpl} is on {host}')
    elif any(v.split('/', 1)[-1] == tmpl for v in volids):
        say('ok', f'{tmpl} is already on {host}')
    elif not any('vztmpl' in (s.get('content') or []) for s in stores.values()):
        say('crit', f'no storage on {host} holds container templates (content vztmpl): enable it on one in Proxmox first')
    else:
        say('warn', f'{tmpl} is not on {host}: it will be downloaded with pveam')


changes.CHECKS['pveip'] = re.compile(r'dhcp|((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)/(3[0-2]|[12]?\d)')
changes.CHECKS['pvetemplate'] = re.compile(r'([A-Za-z0-9][A-Za-z0-9_.-]{0,63}:vztmpl/)?[A-Za-z0-9][A-Za-z0-9_.+:-]{0,127}')
changes.register('pve-ct', {'group': 'Proxmox VE', 'label': 'Create a Proxmox container', 'fields': [
    F('vmid', 'vmid', 'VMID (empty: the next free one)', placeholder='105'),
    F('hostname', 'name', 'Hostname', required=True, placeholder='web-01'),
    F('template', 'pvetemplate', 'Template (storage:vztmpl/file, or a name to download)', required=True, placeholder='debian-13-standard_13.0-1_amd64.tar.zst'),
    F('storage', 'name', 'Storage for the root disk', required=True, placeholder='local-lvm'),
    F('disk_gb', 'number', 'Root disk, GiB', default='8'), F('cores', 'number', 'Cores', default='1'), F('memory_mb', 'number', 'Memory, MiB', default='512'),
    F('bridge', 'iface', 'Bridge', default='vmbr0'), F('ip', 'pveip', 'Address (dhcp, or address/prefix)', default='dhcp', placeholder='10.0.0.5/24'),
    F('gateway', 'ipv4', 'Gateway (fixed address only)', placeholder='10.0.0.1'),
    F('ssh_key', 'pubkey', 'SSH public key for root'),
    F('password_secret', 'secret', 'Vault secret holding the root password', placeholder='ct-root'),
    F('unprivileged', 'bool', 'Unprivileged', default=True), F('onboot', 'bool', 'Start with the node'), F('start', 'bool', 'Start it now')],
    'help': 'Created with pct on the node, so Proxmox shows it. A template name that is not on the node is downloaded with pveam first. The root password comes from the vault '
            'and never appears on a command line. An existing VMID is left alone.'},
    CT_ARGS, lambda p: f'Proxmox container {p["hostname"]} on {p["storage"]}', check_ct, ansible_of('t_pve_ct', CT_ARGS))


# ── a VM ────────────────────────────────────────────────────────────
VM_ARGS = ('vmid', 'name', 'source', 'iso', 'image', 'storage', 'disk_gb', 'cores', 'memory_mb', 'bridge', 'ostype', 'user', 'ssh_key', 'onboot', 'start')


def check_vm(conn, c, h, p, say):
    from . import inframeasure, steps_vm, workloads
    if not pvenode.is_proxmox_host(conn, h['name']):
        say('crit', f'{h["name"]} is not a Proxmox VE node: this step runs qm there, so the VM shows in Proxmox. Use the generic VM steps on a plain host')
        return
    if not HOSTNAME.fullmatch(p['name']):
        say('crit', 'a VM name is letters, digits and hyphens, with dots between labels')
    if p['source'] == 'iso' and (not p.get('iso') or p.get('image')):
        say('crit', 'from an ISO: name the ISO image and leave the cloud image empty')
    elif p['source'] == 'image' and (not p.get('image') or p.get('iso')):
        say('crit', 'from a cloud image: choose the image and leave the ISO empty')
    if p.get('vmid'):
        w = next((x for x in workloads.listing(conn, h['name'])['workloads'] if x['runtime'] == 'proxmox' and str(x.get('vmid')) == p['vmid']), None)
        if w:
            say('crit', f'VMID {p["vmid"]} is already {w.get("name")} on {h["name"]}: the script leaves it alone')
        elif not VMID_MIN <= int(p['vmid']) <= VMID_MAX:
            say('crit', f'a VMID is between {VMID_MIN} and {VMID_MAX}')
    else:
        say('note', 'no VMID given: the script asks Proxmox for the next free one')
    node = (inframeasure.reading(conn, h['name']) or {}).get('proxmox_node')
    if not node:
        say('note', f'the storages and ISO images of {h["name"]} are not read yet: the script checks when it runs')
    else:
        stores = {s['name']: s for s in node.get('storages') or []}
        disks = stores.get(p['storage'])
        if not disks:
            say('crit', f'{h["name"]} has no storage {p["storage"]}: it has {", ".join(sorted(stores)) or "none"}')
        elif disks.get('content') and 'images' not in disks['content']:
            say('crit', f'{p["storage"]} does not hold VM disks (content {", ".join(disks["content"])}): choose one with images, such as '
                        + (', '.join(n for n, s in sorted(stores.items()) if 'images' in (s.get('content') or [])) or 'none here'))
        if p['source'] == 'iso' and p.get('iso') and p['iso'] not in {i['volid'] for i in node.get('isos') or []}:
            say('crit', f'{p["iso"]} is not among the ISO images of {h["name"]}: upload it in Proxmox first')
    if p['source'] == 'image':
        if p.get('image') in steps_vm.IMAGES:
            say('ok', f'{steps_vm.IMAGES[p["image"]][0]}, downloaded to a temporary folder and checked against the checksum its publisher lists')
        if not p.get('ssh_key'):
            say('warn', f'no SSH key: there is no way to log in as {p["user"]} (a cloud image has no password)')
    elif p.get('ssh_key'):
        say('note', 'the SSH key and user are used with a cloud image only: an ISO installs by hand')
    if p['source'] == 'iso':
        say('note', 'it boots from the ISO: finish the install on its console in Proxmox')


def validate_vm(conn, body: dict) -> dict:
    """Before a plan is checked or saved: a source brings its own field and not the other's."""
    for i, t in enumerate(body.get('tasks') or [], 1):
        if t.get('type') != 'pve-vm':
            continue
        p = t.get('params') or {}
        src, iso, image = str(p.get('source') or ''), str(p.get('iso') or '').strip(), str(p.get('image') or '').strip()
        if src == 'iso' and not iso:
            raise ValueError(f'task {i}: a VM from an ISO needs the ISO image')
        if src == 'iso' and image:
            raise ValueError(f'task {i}: a VM from an ISO takes no cloud image')
        if src == 'image' and not image:
            raise ValueError(f'task {i}: a VM from a cloud image needs the image')
        if src == 'image' and iso:
            raise ValueError(f'task {i}: a VM from a cloud image takes no ISO')
    return body


def _vm_title(p):
    return f'Proxmox VM {p["name"]} from {p.get("iso") or p.get("image")}'


def _vm_fields():
    from . import steps_vm
    return [F('vmid', 'vmid', 'VMID (empty: the next free one)', placeholder='106'),
            F('name', 'name', 'Name', required=True, placeholder='app-01'),
            F('source', 'choice', 'Install from', options=['iso', 'image'], required=True, default='image'),
            F('iso', 'pveiso', 'ISO image on the node (iso only)', placeholder='local:iso/debian-13.iso'),
            F('image', 'choice', 'Cloud image (image only)', options=[''] + list(steps_vm.IMAGES), default=''),
            F('storage', 'name', 'Storage for the disk', required=True, placeholder='local-lvm'),
            F('disk_gb', 'number', 'Disk, GiB', default='32'), F('cores', 'number', 'Cores', default='2'), F('memory_mb', 'number', 'Memory, MiB', default='2048'),
            F('bridge', 'iface', 'Bridge', default='vmbr0'), F('ostype', 'choice', 'Guest type', options=['l26', 'win11', 'other'], default='l26'),
            F('user', 'name', 'Login user (cloud image only)', default='admin'), F('ssh_key', 'pubkey', 'SSH public key (cloud image only)'),
            F('onboot', 'bool', 'Start with the node'), F('start', 'bool', 'Start it now')]


changes.CHECKS['pveiso'] = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:iso/[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}')
changes.PREPARE.append(validate_vm)
changes.register('pve-vm', {'group': 'Proxmox VE', 'label': 'Create a Proxmox VM', 'fields': _vm_fields(),
    'help': 'Created with qm on the node, so Proxmox shows it. From an ISO on the node it boots the installer. From a cloud image it downloads the image to a temporary folder, '
            'checks it against the publisher checksum, imports it as the disk and sets a cloud-init login for your key. An existing VMID is left alone.'},
    VM_ARGS, _vm_title, check_vm, ansible_of('t_pve_vm', VM_ARGS))

changes.EXTRA_BASH.append(BASH)
