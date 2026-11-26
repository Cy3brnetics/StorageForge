"""Plan steps for full partition management, secure formatting, drive wiping and secure file deletion.

Every operation that modifies a partition table, overwrites storage blocks or permanently deletes files is marked
destructive: it requires typing the target path/device again to confirm, refuses mounted or active pool/RAID/LVM/LUKS
targets (and critical OS directories), and runs only under --apply --destructive (or -e storageforge_destructive=true).
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex

from . import changes, payloads
from .changes import CONFIRM, F
from .db import Conn
from .fsmap import SYSTEM_DIRS

PART_FLAGS = ['', 'esp', 'lvm', 'raid', 'swap', 'boot', 'msftdata']
FLAG_STATES = ['', 'on', 'off']
WIPE_METHODS = ['zero', 'random', 'random-zero', 'discard', 'nvme-sanitize']
PART_DEL_METHODS = ['quick', 'zero', 'random', 'random-zero', 'discard']
FILE_DEL_METHODS = ['random-zero', 'zero', 'random', 'unlink']
PASSES = ['1', '3', '7']
OS_SYSTEM_PATHS = set(SYSTEM_DIRS) | {'/boot/efi', '/boot/firmware', '/efi'}


def disks_of(conn: Conn, host: str | None = None) -> list[dict]:
    """Structured disk and partition inventory for the Partition Manager UI and /api/disks."""
    hs = changes.hosts(conn)
    out = []
    for name in sorted(hs):
        if host and name.lower() != host.lower() and name.split('.')[0].lower() != host.lower():
            continue
        h = hs[name]
        inv = conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']})
        inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
        node = payloads.node_from_lsblk(inv['lsblk'], name) if inv.get('lsblk') else {'disks': [], 'pools': []}
        if inv.get('zpool_status'):
            payloads.apply_zpool_status(node, payloads.parse_zpool_status(inv['zpool_status']))
        if inv.get('lvs'):
            payloads.apply_lvs(node, inv['lvs'])
        if inv.get('btrfs'):
            payloads.apply_btrfs(node, inv['btrfs'])
        c = changes.Host(conn, h)
        disks = []
        for d in node.get('disks') or []:
            ddev = '/dev/' + d['dev']
            size = d.get('size') or 0
            taken = sum(p.get('size') or 0 for p in d.get('parts') or [])
            parts = []
            for p in sorted(d.get('parts') or [], key=lambda x: (x.get('start') or 0, x.get('dev') or '')):
                m = re.search(r'(\d+)$', p.get('dev') or '')
                psize = p.get('size') or 0
                parts.append({
                    'dev': '/dev/' + p['dev'],
                    'name': p['dev'],
                    'num': int(m.group(1)) if m else None,
                    'start': p.get('start') or 0,
                    'size': psize,
                    'pct': round((psize * 100.0 / size), 2) if size else 0,
                    'fs': p.get('fs'),
                    'label': p.get('label'),
                    'uuid': p.get('uuid'),
                    'mount': p.get('mount'),
                    'member': p.get('member'),
                    'role': p.get('role'),
                })
            disks.append({
                'dev': ddev,
                'name': d['dev'],
                'model': d.get('model'),
                'serial': d.get('serial'),
                'bus': d.get('bus'),
                'media': d.get('media'),
                'tier': d.get('tier'),
                'table': d.get('table'),
                'size': size,
                'used_bytes': taken,
                'free_bytes': max(0, size - taken),
                'member': d.get('member'),
                'mounted': c.mounted_from(ddev),
                'parts': parts,
            })
        out.append({'host': name, 'disks': disks})
    return out


def _part_num(dev: str) -> str:
    m = re.search(r'(\d+)$', dev.rstrip())
    return m.group(1) if m else ''


def _part_num_bash() -> str:
    return (
        'part_num() { local p=$1 b=${1##*/}; '
        'if [[ -r /sys/class/block/$b/partition ]]; then cat "/sys/class/block/$b/partition"; '
        'else lsblk -nro PARTN -- "$p" 2>/dev/null | head -n 1; fi; }'
    )


# Uses need, dev_guard, act, try, later and report helpers of changes.py. No apostrophes in bash text.
BASH = r"""
# ── partition edit/delete, secure wipe and secure delete ──────────────
""" + _part_num_bash() + r"""
wipe_dev() { # device method passes
  local dev=$1 method=${2:-zero} passes=${3:-1} sz
  case $method in
    ''|quick) return 0 ;;
    zero)
      if command -v shred >/dev/null; then try shred -n 0 -z -- "$dev" || return 1
      else
        dd if=/dev/zero of="$dev" bs=4M conv=fdatasync status=none 2>/dev/null || dd if=/dev/zero of="$dev" bs=1M status=none 2>/dev/null || :
        sync || :
      fi ;;
    random)
      if command -v shred >/dev/null; then try shred -n "$passes" -- "$dev" || return 1
      else
        sz=$(blockdev --getsize64 -- "$dev" 2>/dev/null || echo 0)
        local n=0; while ((n < passes)); do
          if ((sz > 0)); then dd if=/dev/urandom of="$dev" bs=1M count="$(((sz + 1048575) / 1048576))" status=none 2>/dev/null || :
          else dd if=/dev/urandom of="$dev" bs=1M status=none 2>/dev/null || :; fi
          sync || :; n=$((n + 1))
        done
      fi ;;
    random-zero)
      if command -v shred >/dev/null; then try shred -n "$passes" -z -- "$dev" || return 1
      else
        wipe_dev "$dev" random "$passes" || return 1
        wipe_dev "$dev" zero 1 || return 1
      fi ;;
    discard)
      need blkdiscard util-linux || return 1
      try blkdiscard -f -- "$dev" || return 1 ;;
    nvme-sanitize)
      need nvme nvme-cli || return 1
      try nvme format -s 1 --force -- "$dev" || return 1 ;;
    *) conflict "unknown wipe method: $method"; return 1 ;;
  esac
  wipefs -aq -- "$dev" 2>/dev/null || true
  sync || :
}

t_partition_edit() { local disk=$1 part=$2 name=$3 size=$4 flag=$5 state=${6:-on} num table row cur_name start end want_bytes cur_bytes new_end fs mnt
  need parted parted || return 0
  [[ -b $disk ]] || { conflict "$disk is not a block device"; return 0; }
  [[ -b $part ]] || { later "$part must exist on $disk"; return 0; }
  num=$(part_num "$part")
  [[ -n $num ]] || { conflict "could not determine partition number for $part"; return 0; }
  table=$(parted -sm -- "$disk" print 2>/dev/null | awk -F: 'NR == 2 { print $6 }')
  if [[ -n $name && $table != gpt ]]; then conflict "$disk has a $table table: GPT partition names need GPT"; return 0; fi
  row=$(parted -sm -- "$disk" unit B print 2>/dev/null | awk -F: -v n="$num" '$1 == n { print; exit }')
  [[ -n $row ]] || { conflict "partition $num was not found in the table of $disk"; return 0; }
  IFS=: read -r _ start end cur_bytes _ cur_name _ <<<"$row"
  start=${start%B}; end=${end%B}; cur_bytes=${cur_bytes%B}
  local changed=0
  if [[ -n $name && $cur_name != "$name" ]]; then
    if act "rename partition $part ($num) to $name"; then
      try parted -s -- "$disk" name "$num" "$name" || return 0
      ok "named $part $name"; changed=1
    fi
  elif [[ -n $name ]]; then ok "$part is named $name"; fi
  if [[ -n $size ]]; then
    want_bytes=$(numfmt --from=iec "$size")
    if ((cur_bytes == want_bytes)); then
      ok "$part size is $(human "$cur_bytes")"
    else
      if ((want_bytes < cur_bytes)); then
        if findmnt -rn -S "$part" >/dev/null 2>&1; then
          conflict "$part is mounted: unmount and shrink its filesystem offline before shrinking the partition"; return 0
        fi
        if [[ -n $(blkid -p -o value -s TYPE -- "$part" 2>/dev/null || true) ]]; then
          info "shrinking $part offline: ensure the filesystem inside fits within $size first"
        fi
      fi
      new_end=$(( (start + want_bytes) / 1048576 ))MiB
      if act "resize partition $part ($num) to $size (end $new_end)"; then
        try parted -s -- "$disk" resizepart "$num" "$new_end" || return 0
        partprobe -- "$disk" 2>/dev/null || true; udevadm settle 2>/dev/null || true
        if ((want_bytes > cur_bytes)); then
          fs=$(blkid -p -o value -s TYPE -- "$part" 2>/dev/null || true)
          mnt=$(lsblk -nro MOUNTPOINT -- "$part" 2>/dev/null | head -n 1 || true)
          case $fs in
            ext2|ext3|ext4) command -v resize2fs >/dev/null && resize2fs -- "$part" >/dev/null 2>&1 || true ;;
            btrfs) [[ -n $mnt ]] && btrfs filesystem resize max -- "$mnt" >/dev/null 2>&1 || true ;;
            xfs) [[ -n $mnt ]] && xfs_growfs -- "$mnt" >/dev/null 2>&1 || true ;;
          esac
        fi
        ok "resized $part"; changed=1
      fi
    fi
  fi
  if [[ -n $flag ]]; then
    state=${state:-on}
    if act "set flag $flag=$state on partition $part ($num)"; then
      try parted -s -- "$disk" set "$num" "$flag" "$state" || return 0
      ok "flag $flag $state"; changed=1
    fi
  fi
  if ((changed)); then partprobe -- "$disk" 2>/dev/null || true; udevadm settle 2>/dev/null || true; fi
}

t_partition_delete() { local disk=$1 part=$2 method=${3:-quick} passes=${4:-1} num
  need parted parted || return 0
  if [[ ! -b $part ]]; then ok "$part does not exist"; return 0; fi
  dev_guard "$part" || return 0
  num=$(part_num "$part")
  [[ -n $num ]] || { conflict "could not determine partition number for $part"; return 0; }
  act "delete partition $part (number $num) on $disk${method:+, wipe=$method}" || return 0
  if [[ $method != quick && -n $method ]]; then
    wipe_dev "$part" "$method" "$passes" || return 0
  fi
  try wipefs -aq -- "$part" || return 0
  try parted -s -- "$disk" rm "$num" || return 0
  partprobe -- "$disk" 2>/dev/null || true; udevadm settle 2>/dev/null || true
  ok "deleted $part"
}

t_drive_wipe() { local dev=$1 method=${2:-zero} passes=${3:-1} zap=$4
  dev_guard "$dev" || return 0
  act "securely wipe $dev with $method${passes:+ ($passes pass(es))}${zap:+, zap partition table}" || return 0
  if [[ $zap == 1 ]]; then
    command -v sgdisk >/dev/null && sgdisk --zap-all -- "$dev" >/dev/null 2>&1 || true
    wipefs -aq -- "$dev" 2>/dev/null || true
  fi
  wipe_dev "$dev" "$method" "$passes" || return 0
  partprobe -- "$dev" 2>/dev/null || true; udevadm settle 2>/dev/null || true
  ok "wiped $dev"
}

sf_wipe_file() { local f=$1 method=$2 passes=${3:-1} sz
  [[ -f $f && ! -L $f ]] || return 0
  case $method in
    unlink) rm -f -- "$f" ;;
    zero)
      if command -v shred >/dev/null; then shred -u -n 0 -z -- "$f"
      else
        sz=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
        if ((sz > 0)); then dd if=/dev/zero of="$f" bs=65536 count="$(((sz + 65535) / 65536))" conv=notrunc status=none 2>/dev/null || :; fi
        sync || :; rm -f -- "$f"
      fi ;;
    random)
      if command -v shred >/dev/null; then shred -u -n "$passes" -- "$f"
      else
        sz=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
        local n=0; while ((n < passes)); do
          if ((sz > 0)); then dd if=/dev/urandom of="$f" bs=65536 count="$(((sz + 65535) / 65536))" conv=notrunc status=none 2>/dev/null || :; fi
          sync || :; n=$((n + 1))
        done
        rm -f -- "$f"
      fi ;;
    random-zero)
      if command -v shred >/dev/null; then shred -u -n "$passes" -z -- "$f"
      else
        sz=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
        local n=0; while ((n < passes)); do
          if ((sz > 0)); then dd if=/dev/urandom of="$f" bs=65536 count="$(((sz + 65535) / 65536))" conv=notrunc status=none 2>/dev/null || :; fi
          sync || :; n=$((n + 1))
        done
        if ((sz > 0)); then dd if=/dev/zero of="$f" bs=65536 count="$(((sz + 65535) / 65536))" conv=notrunc status=none 2>/dev/null || :; fi
        sync || :; rm -f -- "$f"
      fi ;;
    *) conflict "unknown delete method: $method"; return 1 ;;
  esac
}

t_secure_delete() { local p=$1 method=${2:-random-zero} passes=${3:-1}
  p=$(realpath -m -s -- "$p" 2>/dev/null) || { conflict "cannot work out the path $1"; return 0; }   # //etc, /etc/ and /./etc are /etc
  case $p in
    /|/bin|/boot|/boot/efi|/boot/firmware|/dev|/efi|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/usr|/var)
      conflict "refusing to delete system path $p"; return 0 ;;
  esac
  if [[ ! -e $p && ! -L $p ]]; then ok "$p is deleted"; return 0; fi
  [[ -L $p ]] && { conflict "$p is a symbolic link: remove the link or delete its target explicitly"; return 0; }
  mountpoint -q -- "$p" && { conflict "$p is a mount point: unmount it first"; return 0; }
  if [[ -d $p ]] && findmnt -rn -o TARGET | awk -v a="${p%/}/" 'index($0 "/", a) == 1 { f = 1 } END { exit !f }'; then
    conflict "a filesystem is mounted inside $p: unmount it first"; return 0
  fi
  act "securely delete $p ($method, $passes pass(es))" || return 0
  if [[ -f $p ]]; then
    try sf_wipe_file "$p" "$method" "$passes" && ok "securely deleted $p"
  elif [[ -d $p ]]; then
    if [[ $method != unlink ]]; then
      while IFS= read -r -d '' f; do
        sf_wipe_file "$f" "$method" "$passes" || { conflict "failed wiping $f"; return 0; }
      done < <(find "$p" -xdev -type f -print0)
    fi
    try rm -rf -- "$p" && ok "securely deleted $p"
  else
    try rm -f -- "$p" && ok "removed special file $p"
  fi
}
"""


def _check_part_edit(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    dinfo = c.device(p['disk'])
    pinfo = c.device(p['partition'])
    if not dinfo or dinfo['kind'] != 'disk':
        say('crit', f'{p["disk"]} is not a scanned disk on {h["name"]}')
        return
    if not pinfo or pinfo['kind'] != 'part':
        say('crit', f'{p["partition"]} is not a partition on {h["name"]}')
        return
    if pinfo['disk']['dev'] != dinfo['disk']['dev']:
        say('crit', f'{p["partition"]} belongs to /dev/{pinfo["disk"]["dev"]}, not {p["disk"]}')
        return
    if not any([p.get('name'), p.get('size'), p.get('flag')]):
        say('crit', 'pick at least one change: name, size or flag')
    table = (dinfo['disk'].get('table') or '').lower()
    if p.get('name') and table and table != 'gpt':
        say('crit', f'{p["disk"]} has a {table} table: GPT partition names need a GPT table')
    if p.get('size'):
        want = int(float(p['size'][:-1]) * 1024 ** ('KMGTP'.index(p['size'][-1]) + 1))
        cur = pinfo['part'].get('size') or 0
        if cur and want < cur:
            if pinfo['part'].get('mount') or p['partition'] in ('/dev/' + m for m in c.mounted_from(p['partition'])):
                say('crit', f'{p["partition"]} is mounted at {pinfo["part"].get("mount")}: cannot shrink a mounted partition')
            else:
                say('warn', f'shrinking {p["partition"]} below current {changes._fmt(cur)}: make sure its filesystem is shrunk first')
        if dinfo['disk'].get('size'):
            other = sum((x.get('size') or 0) for x in dinfo['parts'] if x['dev'] != pinfo['part']['dev'])
            if want > (dinfo['disk']['size'] - other):
                say('crit', f'{p["size"]} exceeds remaining capacity on {p["disk"]}')
        if pinfo['part'].get('fs') in ('ext4', 'xfs', 'btrfs') and cur and want > cur:
            say('note', f'also grows {pinfo["part"]["fs"]} filesystem when expanded')
    if pinfo['part'].get('member'):
        say('warn', f'{p["partition"]} is a member of {pinfo["part"]["member"]}')
    say('ok', f'edits {p["partition"]} on {p["disk"]}')


def _check_part_delete(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    dinfo = c.device(p['disk'])
    pinfo = c.device(p['partition'])
    if not dinfo or dinfo['kind'] != 'disk':
        say('crit', f'{p["disk"]} is not a scanned disk on {h["name"]}')
        return
    if not pinfo or pinfo['kind'] != 'part':
        say('crit', f'{p["partition"]} was not seen as a partition on {h["name"]}')
        return
    if pinfo['disk']['dev'] != dinfo['disk']['dev']:
        say('crit', f'{p["partition"]} is on /dev/{pinfo["disk"]["dev"]}, not {p["disk"]}')
        return
    used = c.mounted_from(p['partition'])
    if used:
        os_use = [u for u in used if u in changes.OS_MOUNTS or u == '/home']
        say('crit', f'{p["partition"]} is mounted at {", ".join(used[:5])}' + (' (operating system partition)' if os_use else ''))
    if pinfo.get('member'):
        say('crit', f'{p["partition"]} belongs to {pinfo["member"]}')
    if not used and not pinfo.get('member'):
        fs = pinfo.get('fs')
        say('warn', f'permanently deletes {p["partition"]}' + (f' ({fs})' if fs else '') + (f' using wipe method {p["method"]}' if p.get('method') != 'quick' else ''))
    dinfo['disk']['parts'] = [x for x in dinfo['disk']['parts'] if x['dev'] != pinfo['part']['dev']]


def _check_drive_wipe(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    info = c.device(p['device'])
    if not info:
        say('crit', f'{p["device"]} was not seen by the last scan of {h["name"]}')
        return
    used = c.mounted_from(p['device'])
    if used:
        os_use = [u for u in used if u in changes.OS_MOUNTS or u == '/home']
        say('crit', f'{p["device"]} is in use: mounted at {", ".join(used[:5])}' + (' (operating system disk)' if os_use else ''))
    if info.get('member') or (info['kind'] == 'disk' and any(x.get('member') for x in info['parts'])):
        say('crit', f'{p["device"]} belongs to {info.get("member") or "a pool"}')
    media = (info['disk'].get('media') or '').lower()
    bus = (info['disk'].get('bus') or '').lower()
    if p['method'] == 'discard' and media == 'hdd':
        say('warn', f'{p["device"]} appears to be a spinning HDD: blkdiscard may fail or be ignored')
    if p['method'] == 'nvme-sanitize' and 'nvme' not in bus and 'nvme' not in p['device'].lower():
        say('warn', f'{p["device"]} does not appear to be an NVMe device')
    if not used and not info.get('member'):
        say('warn', f'wipes {p["device"]} with method {p["method"]}')
    if info['kind'] == 'disk' and p.get('wipe_table'):
        info['disk']['parts'] = []


def _check_secure_delete(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    path = '/' + posixpath.normpath(p['path']).lstrip('/')         # normpath keeps a leading //, which is / to the kernel
    if path in OS_SYSTEM_PATHS:
        say('crit', f'refusing to delete protected system directory {path}')
        return
    if path in c.mounted and path not in c.unmounted:
        say('crit', f'{path} is a mount point: unmount it instead')
        return
    st = c.state(path)
    if st == 'missing':
        say('crit', f'{path} does not exist (or was removed in an earlier step)')
    elif st == 'link':
        say('crit', f'{path} is a symlink: pick its path explicitly rather than secure-deleting through a link')
    elif st == 'unknown':
        say('warn', f'{path} is not in the index; the script verifies it on the host')
    if st == 'dir':
        sz = c.size(path)
        if sz and sz['entries']:
            say('warn', f'permanently overwrites and deletes {sz["files"]:,} file(s) ({changes._fmt(sz["bytes"])}) in {path}')
    elif st == 'file':
        say('warn', f'permanently deletes {path} ({p["method"]})')
    _, fs = c.mount_at(path)
    if p['method'] != 'unlink' and fs in ('btrfs', 'zfs'):
        say('note', f'{fs} is copy-on-write: active data blocks are overwritten and unlinked, while prior snapshots or CoW extents require freeing snapshots / trimming')
    c.gone.add(path)


def _ansible_edit(t: dict) -> dict:
    p = t['params']
    q = shlex.quote
    disk, part = q(p['disk']), q(p['partition'])
    num_cmd = f'b=$(basename {part}); num=$(cat /sys/class/block/$b/partition 2>/dev/null || lsblk -nro PARTN -- {part} | head -n 1); '
    ops = []
    if p.get('name'):
        ops.append(f'parted -s -- {disk} name "$num" {q(p["name"])}')
    if p.get('size'):
        ops.append(
            f'row=$(parted -sm -- {disk} unit B print | awk -F: -v n="$num" \'$1==n {{print; exit}}\'); '
            f'start=$(printf "%s" "$row" | cut -d: -f2 | tr -d B); want=$(numfmt --from=iec {q(p["size"])}); '
            f'end=$(((start + want) / 1048576))MiB; parted -s -- {disk} resizepart "$num" "$end"'
        )
    if p.get('flag'):
        ops.append(f'parted -s -- {disk} set "$num" {q(p["flag"])} {q(p.get("flag_state") or "on")}')
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': f'set -euo pipefail\n{num_cmd}' + '\n'.join(ops) + f'\npartprobe -- {disk} || true\nudevadm settle || true'},
        'tags': ['destructive'],
        'when': 'storageforge_destructive | default(false) | bool',
    }


def _ansible_guards() -> str:
    """The host-side refusals of the script (device in use, holds RAID/LVM/LUKS), so a playbook run keeps them too."""
    guard = changes.bash_fn(changes.CHANGE_BODY_3, 'dev_guard')
    return ('APPLY=1; conflict() { echo "conflict: $*" >&2; exit 1; }; later() { conflict "$*"; }\n' + guard)


def _ansible_wipe_snippet(dev_expr: str, method: str, passes: str) -> str:
    if method == 'discard':
        return f'blkdiscard -f -- {dev_expr}\nwipefs -aq -- {dev_expr}'
    if method == 'nvme-sanitize':
        return f'nvme format -s 1 --force -- {dev_expr}\nwipefs -aq -- {dev_expr}'
    if method == 'zero':
        return f'shred -n 0 -z -- {dev_expr}\nwipefs -aq -- {dev_expr}'
    if method == 'random':
        return f'shred -n {passes} -- {dev_expr}\nwipefs -aq -- {dev_expr}'
    if method == 'random-zero':
        return f'shred -n {passes} -z -- {dev_expr}\nwipefs -aq -- {dev_expr}'
    return ''


def _ansible_part_delete(t: dict) -> dict:
    p = t['params']
    q = shlex.quote
    disk, part = q(p['disk']), q(p['partition'])
    wipe = _ansible_wipe_snippet(part, p.get('method') or 'quick', p.get('passes') or '1')
    wipe_line = (wipe + '\n') if wipe else f'wipefs -aq -- {part}\n'
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': (
            f'set -euo pipefail\n[ -b {part} ] || {{ echo unchanged; exit 0; }}\n{_ansible_guards()}dev_guard {part}\n'
            f'b=$(basename {part}); num=$(cat /sys/class/block/$b/partition 2>/dev/null || lsblk -nro PARTN -- {part} | head -n 1)\n'
            f'{wipe_line}parted -s -- {disk} rm "$num"\npartprobe -- {disk} || true\nudevadm settle || true')},
        'register': 'sf_out', 'changed_when': "'unchanged' not in sf_out.stdout",
        'tags': ['destructive'], 'when': 'storageforge_destructive | default(false) | bool',
    }


def _ansible_drive_wipe(t: dict) -> dict:
    p = t['params']
    q = shlex.quote
    dev = q(p['device'])
    zap = f'sgdisk --zap-all -- {dev} || true\nwipefs -aq -- {dev} || true\n' if p.get('wipe_table') else ''
    wipe = _ansible_wipe_snippet(dev, p.get('method') or 'zero', p.get('passes') or '1')
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': f'set -euo pipefail\n{_ansible_guards()}dev_guard {dev}\n{zap}{wipe}\npartprobe -- {dev} || true\nudevadm settle || true'},
        'tags': ['destructive'], 'when': 'storageforge_destructive | default(false) | bool',
    }


def _ansible_secure_delete(t: dict) -> dict:
    p = t['params']
    q = shlex.quote
    target, method, passes = '"$t"', p.get('method') or 'random-zero', p.get('passes') or '1'
    # the same refusals as t_secure_delete: a system path, a link, a mount point, a filesystem mounted inside
    guard = (f't=$(realpath -m -s -- {q(p["path"])}) || {{ echo "conflict: cannot work out the path" >&2; exit 1; }}\n'
             'case $t in\n  /|/bin|/boot|/boot/efi|/boot/firmware|/dev|/efi|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/usr|/var)\n'
             '    echo "conflict: refusing to delete system path $t" >&2; exit 1 ;;\nesac\n'
             'if [ -e "$t" ] || [ -L "$t" ]; then\n'
             '  [ ! -L "$t" ] || { echo "conflict: $t is a symbolic link" >&2; exit 1; }\n'
             '  ! mountpoint -q -- "$t" || { echo "conflict: $t is a mount point" >&2; exit 1; }\n'
             '  if [ -d "$t" ] && findmnt -rn -o TARGET | awk -v a="${t%/}/" \'index($0 "/", a) == 1 { f = 1 } END { exit !f }\'; then\n'
             '    echo "conflict: a filesystem is mounted inside $t" >&2; exit 1\n  fi\nfi\n')
    if method == 'unlink':
        cmd = f'rm -rf -- {target}'
    elif method == 'zero':
        cmd = f'if [ -f {target} ]; then shred -u -n 0 -z -- {target}; else find {target} -xdev -type f -exec shred -u -n 0 -z -- {{}} +; rm -rf -- {target}; fi'
    elif method == 'random':
        cmd = f'if [ -f {target} ]; then shred -u -n {passes} -- {target}; else find {target} -xdev -type f -exec shred -u -n {passes} -- {{}} +; rm -rf -- {target}; fi'
    else:
        cmd = f'if [ -f {target} ]; then shred -u -n {passes} -z -- {target}; else find {target} -xdev -type f -exec shred -u -n {passes} -z -- {{}} +; rm -rf -- {target}; fi'
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': f'set -euo pipefail\n{guard}[ ! -e {target} ] && [ ! -L {target} ] && {{ echo unchanged; exit 0; }}\n{cmd}'},
        'register': 'sf_out', 'changed_when': "'unchanged' not in sf_out.stdout",
        'tags': ['destructive'], 'when': 'storageforge_destructive | default(false) | bool',
    }


changes.register(
    'partition-edit',
    {'group': 'Drives', 'label': 'Edit a partition', 'destructive': True, 'confirm_of': 'partition', 'fields': [
        F('disk', 'device', 'Disk', required=True),
        F('partition', 'device', 'Partition', required=True),
        F('name', 'label', 'New GPT name (PARTLABEL)'),
        F('size', 'size', 'Resize to total size (e.g. 100G)'),
        F('flag', 'choice', 'Partition flag', options=PART_FLAGS),
        F('flag_state', 'choice', 'Flag action', options=FLAG_STATES, default='on'),
        CONFIRM],
        'help': 'Rename a GPT partition, grow or resize it, or change its partition flag.'},
    ('disk', 'partition', 'name', 'size', 'flag', 'flag_state'),
    lambda p: f'Edit partition {p["partition"]} on {p["disk"]}',
    _check_part_edit, _ansible_edit,
)

changes.register(
    'partition-delete',
    {'group': 'Drives', 'label': 'Delete a partition', 'destructive': True, 'confirm_of': 'partition', 'fields': [
        F('disk', 'device', 'Disk', required=True),
        F('partition', 'device', 'Partition', required=True),
        F('method', 'choice', 'Erase before deleting', options=PART_DEL_METHODS, default='quick'),
        F('passes', 'choice', 'Passes (for zero / random)', options=PASSES, default='1'),
        CONFIRM],
        'help': 'Optionally overwrites the partition before wiping signatures and removing it from the partition table.'},
    ('disk', 'partition', 'method', 'passes'),
    lambda p: f'Delete partition {p["partition"]} from {p["disk"]}' + (f' ({p["method"]})' if p.get('method') and p['method'] != 'quick' else ''),
    _check_part_delete, _ansible_part_delete,
)

changes.register(
    'drive-wipe',
    {'group': 'Drives', 'label': 'Securely wipe a drive or partition', 'destructive': True, 'fields': [
        F('device', 'device', 'Drive or partition', required=True),
        F('method', 'choice', 'Erase method', options=WIPE_METHODS, required=True, default='zero'),
        F('passes', 'choice', 'Overwrite passes (for random / random-zero)', options=PASSES, default='1'),
        F('wipe_table', 'bool', 'Remove partition table and filesystem signatures (zap GPT/MBR)', default=True),
        CONFIRM],
        'help': 'Securely overwrites or discards a full drive or single partition and clears filesystem/partition signatures.'},
    ('device', 'method', 'passes', 'wipe_table'),
    lambda p: f'Securely wipe {p["device"]} ({p["method"]})',
    _check_drive_wipe, _ansible_drive_wipe,
)

changes.register(
    'secure-delete',
    {'group': 'Files and folders', 'label': 'Securely delete file or folder', 'destructive': True, 'confirm_of': 'path', 'fields': [
        F('path', 'path', 'File or folder', required=True),
        F('method', 'choice', 'Method', options=FILE_DEL_METHODS, required=True, default='random-zero'),
        F('passes', 'choice', 'Overwrite passes', options=PASSES, default='1'),
        F('confirm', 'confirm', 'Type the path again to confirm', required=True)],
        'help': 'Permanently overwrites and unlinks a file or folder (bypasses .storageforge-trash). Refuses mount points, symlinks and system paths.'},
    ('path', 'method', 'passes'),
    lambda p: f'Securely delete {p["path"]} ({p["method"]})',
    _check_secure_delete, _ansible_secure_delete,
)

changes.EXTRA_BASH.append(BASH)
