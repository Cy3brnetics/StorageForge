"""The reinstall script of a host: from a freshly installed operating system back to every drive and subvolume mounted.

It reports by default, and changes things only with --apply. It never partitions, formats or destroys anything: it looks
for the filesystems a host had, by UUID, and brings back what uses them. Stages run in the order a rebuild needs:
tools, config files that describe storage, LUKS, md and LVM, ZFS pools, accounts (so files keep their owners), fstab
lines and mounts, shares, symlinks. The script holds everything itself, so it works with StorageForge itself gone.

Values come from the host's scan, so they reach the script only as shlex-quoted words, base64 or one_line() comments.
"""
from __future__ import annotations

import base64
import re
import shlex
import time

from . import __version__
from .hostconfig import CONFIG_PATH, REBUILT_MARK
from .moves import host_slug
from .scriptkit import CIFS_KERNEL, HELPERS, PACKAGES, REMOTE, comments, one_line

# filesystem or layer -> the program that shows its tools are there, then packages for apt, dnf, pacman, zypper
TOOLS = {'btrfs': ('btrfs', 'btrfs-progs', 'btrfs-progs', 'btrfs-progs', 'btrfsprogs'),
         'xfs': ('xfs_repair', 'xfsprogs', 'xfsprogs', 'xfsprogs', 'xfsprogs'),
         'f2fs': ('fsck.f2fs', 'f2fs-tools', 'f2fs-tools', 'f2fs-tools', 'f2fs-tools'),
         'exfat': ('fsck.exfat', 'exfatprogs', 'exfatprogs', 'exfatprogs', 'exfatprogs'),
         'ntfs': ('ntfs-3g', 'ntfs-3g', 'ntfs-3g', 'ntfs-3g', 'ntfs-3g'),
         'ntfs3': ('ntfs-3g', 'ntfs-3g', 'ntfs-3g', 'ntfs-3g', 'ntfs-3g'),
         'crypto_LUKS': ('cryptsetup', 'cryptsetup', 'cryptsetup', 'cryptsetup', 'cryptsetup'),
         'fuse.mergerfs': ('mergerfs', 'mergerfs', 'mergerfs', 'mergerfs', 'mergerfs'),
         'mergerfs': ('mergerfs', 'mergerfs', 'mergerfs', 'mergerfs', 'mergerfs'),
         'nfs': ('mount.nfs', 'nfs-common', 'nfs-utils', 'nfs-utils', 'nfs-client'),
         'nfs4': ('mount.nfs', 'nfs-common', 'nfs-utils', 'nfs-utils', 'nfs-client'),
         'cifs': ('mount.cifs', 'cifs-utils', 'cifs-utils', 'cifs-utils', 'cifs-utils'),
         'smb3': ('mount.cifs', 'cifs-utils', 'cifs-utils', 'cifs-utils', 'cifs-utils'),
         'fuse.sshfs': ('sshfs', 'sshfs', 'fuse-sshfs', 'sshfs', 'sshfs')}
LAYERS = {'md': ('mdadm', 'mdadm', 'mdadm', 'mdadm', 'mdadm'), 'lvm': ('vgchange', 'lvm2', 'lvm2', 'lvm2', 'lvm2'),
          'zfs': ('zpool', 'zfsutils-linux', 'zfs', 'zfs', 'zfs')}
SERVERS = {'nfs': ('NFS server', ('exportfs', 'nfs-kernel-server', 'nfs-utils', 'nfs-utils', 'nfs-kernel-server')),
           'smb': ('Samba', ('smbd', 'samba', 'samba', 'samba', 'samba'))}

BODY = r"""
HOST= APPLY=0 REPLACE=0 FORCE_ZFS=0 ANY_HOST=0 ONLY= ARGS=("$@")
usage() { sed -n '/^# Usage/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }
while (($#)); do case $1 in
  --apply) APPLY=1 ;;
  --replace-configs) REPLACE=1 ;;
  --force-zfs-import) FORCE_ZFS=1 ;;
  --any-host) ANY_HOST=1 ;;
  --only) ONLY=${2:?--only needs a list}; shift ;;
  --host) HOST=${2:?--host needs a name}; shift ;;
  -h|--help) usage; exit 0 ;;
  *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
esac; shift; done
@@REMOTE@@
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
if ((APPLY)) && [[ $EUID -ne 0 ]]; then echo "--apply needs root: sudo $0 ${ARGS[*]}" >&2; exit 1; fi
STAMP=$(date +%Y%m%d-%H%M%S)
stage() { [[ -z $ONLY || ",$ONLY," == *",$1,"* ]]; }
@@HELPERS@@
@@PACKAGES@@
backup() { [[ -e $1 ]] && cp -a -- "$1" "$1.storageforge-$STAMP"; }

this=$(uname -n)
section "Rebuilding @@NAME@@ from its configuration of @@WHEN@@"
@@NOTE@@
if [[ $(host_slug "$this") != $(host_slug @@QNAME@@) ]]; then
  if ((APPLY && !ANY_HOST)); then echo "This is $this, and this script is for "@@QNAME@@". If that is right, add --any-host." >&2; exit 1; fi
  info "this is $this, and the script is for "@@QNAME@@" (--apply will want --any-host)"
fi
((APPLY)) || info "report only: nothing changes without --apply"

device_of() { # spec -> device path, or nothing when this machine does not have it
  case $1 in
    UUID=*) blkid -U "${1#UUID=}" 2>/dev/null || { [[ -e /dev/disk/by-uuid/${1#UUID=} ]] && echo "/dev/disk/by-uuid/${1#UUID=}"; } ;;
    LABEL=*) blkid -L "${1#LABEL=}" 2>/dev/null || { [[ -e /dev/disk/by-label/${1#LABEL=} ]] && echo "/dev/disk/by-label/${1#LABEL=}"; } ;;
    PARTUUID=*) [[ -e /dev/disk/by-partuuid/${1#PARTUUID=} ]] && echo "/dev/disk/by-partuuid/${1#PARTUUID=}" ;;
    PARTLABEL=*) [[ -e /dev/disk/by-partlabel/${1#PARTLABEL=} ]] && echo "/dev/disk/by-partlabel/${1#PARTLABEL=}" ;;
    *) [[ -e $1 ]] && echo "$1" ;;
  esac
}

restore_file() { # path base64 replaceable(1: a package wrote it this run, so it holds nothing of yours)
  local path=$1 tmp replaceable=${3:-0}; tmp=$(mktemp)
  base64 -d <<<"$2" >"$tmp"
  if [[ -e $path ]] && cmp -s "$tmp" "$path"; then ok "$path"; rm -f "$tmp"; return 1; fi
  # a saved copy rebuilt from what was live cannot be compared with the file it stands in for, so it never replaces one
  if [[ -e $path ]] && head -n 1 "$tmp" | grep -q '^@@MARK@@' && grep -Eqv '^[[:space:]]*(#|;|$)' "$path"; then ok "$path (kept: the scan could not read the original)"; rm -f "$tmp"; return 1; fi
  # a file holding only comments and blank lines says nothing either
  if [[ -e $path ]] && grep -Eqv '^[[:space:]]*(#|;|$)' "$path" && ((!REPLACE && !replaceable)); then
    conflict "$path differs from the saved one and was left alone (--replace-configs replaces it, keeping a backup)"; rm -f "$tmp"; return 1
  fi
  if ((APPLY)); then
    mkdir -p "$(dirname "$path")"; backup "$path"; install -m 0644 "$tmp" "$path"; rm -f "$tmp"; doing "restored $path"; return 0
  fi
  missing "$path"; rm -f "$tmp"; return 1
}

service_on() { # unit... (the first this host has)
  if ! command -v systemctl >/dev/null; then info "no systemd: start ${1} yourself and enable it at boot"; return; fi
  local u found=; for u; do systemctl cat "$u.service" >/dev/null 2>&1 && { found=$u; break; }; done
  if [[ -z $found ]]; then ((APPLY)) && conflict "no service found among: $*" || missing "service $1"; return; fi
  if systemctl is-active -q "$found" && systemctl is-enabled -q "$found" 2>/dev/null; then ok "$found running and enabled"; return; fi
  if ((APPLY)); then doing "systemctl enable --now $found"; systemctl enable --now "$found" 2>&1 | tail -n 2 || conflict "$found did not start"; else missing "$found not running and enabled"; fi
}

open_luks() { # name spec keyfile
  local name=$1 spec=$2 key=$3 dev
  if [[ -e /dev/mapper/$name ]]; then ok "LUKS $name is open"; return; fi
  dev=$(device_of "$spec")
  if [[ -z $dev ]]; then conflict "LUKS $name: $spec is not on this machine"; return; fi
  if [[ -n $key && ! -r $key ]]; then conflict "LUKS $name: its key file $key is gone; put it back, then run this again"; return; fi
  if ((!APPLY)); then missing "LUKS $name on $dev is closed"; return; fi
  if [[ -n $key ]]; then cryptsetup open --key-file "$key" "$dev" "$name" && doing "opened LUKS $name" || conflict "LUKS $name did not open with $key"
  elif [[ -t 0 ]]; then doing "open LUKS $name: type its passphrase"; cryptsetup open "$dev" "$name" || conflict "LUKS $name did not open"
  else conflict "LUKS $name needs its passphrase: run this script in a terminal, or: cryptsetup open $dev $name"; fi
}

crypttab_line() { # name line spec
  if [[ -e /etc/crypttab ]] && awk -v n="$1" '!/^[[:space:]]*#/ && $1 == n { found = 1 } END { exit !found }' /etc/crypttab; then ok "crypttab has $1"; return; fi
  if [[ -z $(device_of "$3") ]]; then conflict "crypttab: $1 not added, $3 is not on this machine"; return; fi
  if ((APPLY)); then backup /etc/crypttab; printf '%s\n' "$2" >>/etc/crypttab; doing "crypttab: added $1"; else missing "crypttab: $2"; fi
}

fs_tool() { # as need_cmd. These filesystems mount without their tools, so a host we cannot install on is not a failure
  if [[ $(pm) == none ]] && ! command -v "$1" >/dev/null; then info "$2 tools are not installed and I know no package manager here: install them if you need them"; return; fi
  need_cmd "$@"
}

md_assemble() {
  local out; out=$(mdadm --assemble --scan 2>&1)
  if grep -q '^md' /proc/mdstat 2>/dev/null; then doing "md arrays are running"; return; fi
  conflict "no md array started. Does this kernel have the md modules? $(tail -n 2 <<<"$out" | tr '\n' ' ')"
}

zfs_pool() { # name
  if ! command -v zpool >/dev/null; then ((APPLY)) && conflict "ZFS pool $1: ZFS tools are not installed" || missing "ZFS pool $1 (looks for its drives once ZFS is installed)"; return; fi
  if zpool list -H -o name "$1" >/dev/null 2>&1; then ok "ZFS pool $1 is imported"; return; fi
  if ! zpool import 2>/dev/null | grep -Eq "^[[:space:]]*pool: $1\$"; then conflict "ZFS pool $1: its drives are not on this machine"; return; fi
  if ((!APPLY)); then missing "ZFS pool $1 is not imported"; return; fi
  local out flag=(); ((FORCE_ZFS)) && flag=(-f)
  if out=$(zpool import ${flag[@]+"${flag[@]}"} "$1" 2>&1); then doing "imported ZFS pool $1"
  elif grep -q 'another system' <<<"$out"; then conflict "ZFS pool $1 was last used by the old install. Make sure no other machine has it, then add --force-zfs-import"
  else conflict "ZFS pool $1: $(tail -n 2 <<<"$out" | tr '\n' ' ')"; fi
}

zfs_dataset() { # name target
  if findmnt -rn --mountpoint "$2" >/dev/null 2>&1; then ok "$2 ($1)"
  elif ((APPLY)) && zfs list -H -o name "$1" >/dev/null 2>&1; then zfs mount "$1" 2>/dev/null; findmnt -rn --mountpoint "$2" >/dev/null 2>&1 && doing "mounted $2 ($1)" || conflict "$2: ZFS dataset $1 did not mount there"
  else missing "$2 ($1)"; fi
}

group_on() { # name gid
  local have; have=$(getent group "$1" | cut -d: -f3)
  if [[ $have == "$2" ]]; then ok "group $1 ($2)"; return; fi
  if [[ -n $have ]]; then conflict "group $1 has gid $have here and had $2: files on your drives still say $2"; return; fi
  local taken; taken=$(getent group "$2" | cut -d: -f1)
  if [[ -n $taken ]]; then conflict "group $1 had gid $2, which is $taken here"; return; fi
  if ((APPLY)); then groupadd -g "$2" "$1" && doing "group $1 ($2)" || conflict "could not add group $1"; else missing "group $1 ($2)"; fi
}

user_on() { # name uid gid home shell
  local have; have=$(id -u "$1" 2>/dev/null)
  if [[ $have == "$2" ]]; then ok "user $1 ($2)"; return; fi
  if [[ -n $have ]]; then conflict "user $1 has uid $have here and had $2: files on your drives still say $2"; return; fi
  local taken; taken=$(getent passwd "$2" | cut -d: -f1)
  if [[ -n $taken ]]; then conflict "user $1 had uid $2, which is $taken here"; return; fi
  if ((!APPLY)); then missing "user $1 ($2), home $4"; return; fi
  local shell=$5; [[ -x $shell ]] || shell=/bin/bash
  if useradd -u "$2" -g "$3" -d "$4" -s "$shell" -M "$1"; then doing "user $1 ($2), with no password yet: passwd $1"; else conflict "could not add user $1"; fi
}

member_on() { # user group
  id -u "$1" >/dev/null 2>&1 && getent group "$2" >/dev/null || { info "$1 in $2: skipped, one of them is not here"; return; }
  if id -nG "$1" | tr ' ' '\n' | grep -Fxq -- "$2"; then return; fi
  if ((APPLY)); then usermod -aG "$2" "$1" && doing "$1 joined $2" || conflict "could not add $1 to $2"; else missing "$1 in group $2"; fi
}

home_on() { # user home uid gid
  id -u "$1" >/dev/null 2>&1 || return
  [[ -d $2 ]] && return
  if ((APPLY)); then install -d -m 0750 -o "$3" -g "$4" -- "$2" && doing "created $2" || conflict "could not create $2"; else missing "home folder $2"; fi
}

fstab_line() { # target line: 0 when the line is there or was added
  local t=$1 line=$2 esc have before=0
  esc=$(awk -v s="$t" 'BEGIN { gsub(/\\/, "\\134", s); gsub(/ /, "\\040", s); gsub(/\t/, "\\011", s); gsub(/#/, "\\043", s); gsub(/\\/, "\\\\", s); print s }')
  have=$(awk -v t="$esc" '!/^[[:space:]]*#/ && $2 == t' /etc/fstab 2>/dev/null)
  if [[ $have == "$line" ]]; then ok "fstab line for $t"; return 0; fi
  if [[ -n $have && $(awk '{print $1, $3}' <<<"$have") == "$(awk '{print $1, $3}' <<<"$line")" ]]; then ok "fstab line for $t (with its own options)"; return 0; fi
  if [[ -n $have ]]; then conflict "fstab already has another line for $t, left alone: $have (saved: $line)"; return 1; fi
  if ((!APPLY)); then missing "fstab: $line"; return 1; fi
  command -v findmnt >/dev/null && findmnt --verify >/dev/null 2>&1 && before=1
  [[ -n ${FSTAB_SAVED:-} ]] || { backup /etc/fstab; FSTAB_SAVED=1; }
  local prev; prev=$(mktemp); cp -a /etc/fstab "$prev"
  printf '# restored by StorageForge\n%s\n' "$line" >>/etc/fstab
  mkdir -p -- "$t"
  if ((before)) && ! findmnt --verify >/dev/null 2>&1; then
    cat "$prev" >/etc/fstab; rm -f "$prev"; conflict "findmnt --verify rejects this line, so it was taken out: $line"; return 1
  fi
  rm -f "$prev"; doing "fstab: $line"; RELOAD=1; return 0
}

mount_it() { # target
  [[ -z ${RELOAD:-} ]] || { command -v systemctl >/dev/null && reload_systemd; RELOAD=; }
  mkdir -p -- "$1"
  local out; if out=$(mount -- "$1" 2>&1); then doing "mounted $1"; return 0; fi
  conflict "$1 did not mount: $(tail -n 2 <<<"$out" | tr '\n' ' ')"; return 1
}

is_mounted() { findmnt -rn --mountpoint "$1" >/dev/null 2>&1; }

mount_device() { # target spec fstype line origin
  local t=$1 spec=$2 fs=$3 line=$4 dev got
  dev=$(device_of "$spec")
  if [[ -z $dev && $spec == /dev/* && $spec != /dev/[sv]d* && $spec != /dev/nvme* ]]; then   # LVM or LUKS: it appears once opened
    ((APPLY)) && conflict "$t: $spec did not appear. Check that its LUKS volume is open or its volume group active, then run this again" || missing "$t: $spec appears once its LUKS or LVM layer is up"
    return
  fi
  # a report assembles nothing, so a filesystem on an md array or in LVM may just not be visible yet
  if [[ -z $dev ]] && ((!APPLY && LAYERED)); then missing "$t: $spec is not visible yet, and may appear once storage is assembled"; return; fi
  if [[ -z $dev ]]; then conflict "$t: $spec is not on this machine (expected $fs). Attach that drive, or leave it out"; return; fi
  got=$(blkid -o value -s TYPE "$dev" 2>/dev/null)
  if [[ -n $got && $got != "$fs" && $fs != auto ]]; then conflict "$t: $spec holds $got and was $fs, so it is not the same filesystem"; return; fi
  fstab_line "$t" "$line" || return
  if is_mounted "$t"; then ok "mounted $t"; elif ((APPLY)); then mount_it "$t"; else missing "mount $t"; fi
}

mount_other() { # target line needs(a path that must exist first)
  local t=$1 line=$2 needs=${3:-}
  if [[ -n $needs && ! -e $needs ]]; then ((APPLY)) && conflict "$t: its source $needs is not there" || missing "$t waits for $needs"; return; fi
  fstab_line "$t" "$line" || return
  local cred=; [[ $line =~ (^|[ ,])(credentials|cred)=([^ ,]+) ]] && cred=${BASH_REMATCH[3]}
  if [[ -n $cred && ! -e $cred ]] && ! is_mounted "$t"; then
    ((APPLY)) && conflict "$t: its credentials file $cred is not kept. Create it, then: mount $t" || missing "$t: needs its credentials file $cred back"
    return
  fi
  if is_mounted "$t"; then ok "mounted $t"; elif ((APPLY)); then mount_it "$t"; else missing "mount $t"; fi
}

share_folder() { [[ -d $1 ]] && ok "$1 exists" || { ((APPLY)) && conflict "$1, shared by $2, is not there" || missing "$1, shared by $2, is not there yet"; }; }

link_on() { # path target needs(the mount the link lives on)
  local p=$1 t=$2 needs=${3:-}
  if [[ -L $p && $(readlink -- "$p") == "$t" ]]; then ok "$p -> $t"; return; fi
  if [[ -e $p || -L $p ]]; then conflict "$p exists and is not a link to $t"; return; fi
  if [[ -n $needs ]] && ! is_mounted "$needs"; then ((APPLY)) && conflict "$p -> $t: $needs is not mounted" || missing "$p -> $t (once $needs is mounted)"; return; fi
  if ((APPLY)); then mkdir -p -- "$(dirname -- "$p")" && ln -s -- "$t" "$p" && doing "$p -> $t" || conflict "could not create $p"; else missing "$p -> $t"; fi
}
"""

USAGE = """# Usage: @@FILE@@ [options]
#   (no options)         report what is there and what is missing; changes nothing
#   --apply              do it, as root: install tools, open and import storage, add accounts, add fstab lines, mount,
#                        restore shares and symlinks. Never partitions or formats. fstab gets a backup first
#   --replace-configs    with --apply: also replace config files that differ from the saved ones, keeping backups
#   --force-zfs-import   with --apply: import ZFS pools the old install last used. Reinstalling needs it; check no other
#                        machine has those drives
#   --any-host           with --apply: run on a machine with another name
#   --only LIST          only these stages: tools,storage,accounts,mounts,shares,links (comma separated)
#   --host H             copy this script to H and run it there with sudo
# Needs bash: on Alpine, apk add bash util-linux shadow first.
"""

def _q(v) -> str:
    return shlex.quote(str(v))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8', 'surrogateescape')).decode()


def _tool(what: str, t: tuple) -> str:
    return f'need_cmd {t[0]} {_q(what)} {t[1]} {t[2]} {t[3]} {t[4]}\n'


def _smb_has_shares(files: dict) -> bool:
    for path, text in files.items():
        if path.startswith('/etc/samba/'):
            for m in re.finditer(r'^\s*\[([^\]]+)\]', text, re.M):
                if m.group(1).lower() not in ('global', 'printers', 'print$', 'homes'):
                    return True
    return False


def _nfs_has_shares(files: dict) -> bool:
    return any((p == '/etc/exports' or p.startswith('/etc/exports.d/')) and re.search(r'^\s*[^#\s]', t, re.M) for p, t in files.items())


def script(version: dict) -> str:
    """The Bash script for a stored version: {'host', 'config_id', 'captured_at', 'body'}."""
    b = version['body']
    name, at = version['host'], version.get('captured_at') or int(time.time())
    when = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(at))
    files = {p: t for p, t in (b.get('files') or {}).items() if CONFIG_PATH.fullmatch(p)}
    mounts = b.get('mounts') or []
    active = [m for m in mounts if m['kind'] not in ('system', 'rootfs')]
    nfs, smb = _nfs_has_shares(files), _smb_has_shares(files)
    file_name = f'reinstall-{host_slug(name)}.sh'
    newer = version.get('instead_of')
    note = (f'info "from before the reinstall: version {newer["config_id"]} is a scan of the new install, with less on it"' if newer else '')

    head = ['#!/usr/bin/env bash', f'# Reinstall script for {name}, from its configuration of {when} (version {version.get("config_id", "live")}).',
            f'# Written by StorageForge {__version__}. Run after reinstalling the operating system. It holds everything it needs.', '#',
            '# Mounts every drive and subvolume this host had, and restores its accounts, shares and symlinks.',
            '# Nothing here partitions or formats: a filesystem that is not on this machine is reported, not recreated.',
            '# Passwords and keys are not in this script: account and Samba passwords, LUKS passphrases, keys and credentials= files.']
    if b.get('os'):
        head.append(f'# It ran {b["os"]}.')
    drives = b.get('drives') or []
    if drives:
        head += ['#', '# Filesystems it had:']
        for d in drives:
            head.append(f'#   {d["uuid"]}  {d["fstype"]}  {d.get("label") or "-"}  {d.get("dev") or ""}  {d.get("model") or ""}  {d.get("serial") or ""}')
    out = [comments(head, ''), '', USAGE.replace('@@FILE@@', file_name), 'set -u']
    body = (BODY.replace('@@REMOTE@@', REMOTE).replace('@@HELPERS@@', HELPERS).replace('@@PACKAGES@@', PACKAGES + CIFS_KERNEL)
            .replace('@@MARK@@', REBUILT_MARK).replace('@@WHEN@@', when).replace('@@NOTE@@', note).replace('@@NAME@@', re.sub(r'[^A-Za-z0-9._-]', '_', name)).replace('@@QNAME@@', _q(name)))
    out.append(body)
    out.append(f'LAYERED={int(bool(b.get("has_md") or b.get("has_lvm") or b.get("crypt")))}\n')

    # tools
    s = 'if stage tools; then\n  section "Tools"\n'
    fstypes = set(b.get('fstypes') or [])
    for key, t in TOOLS.items():
        if key in ('xfs', 'f2fs', 'exfat', 'btrfs') and key in fstypes:
            s += '  ' + _tool(key, t).replace('need_cmd', 'fs_tool', 1)
        elif key in fstypes or (key == 'crypto_LUKS' and b.get('crypt')):
            s += '  ' + _tool(key, t)
    if fstypes & {'cifs', 'smb3'}:
        s += '  cifs_kernel\n'
    if b.get('has_md'):
        s += '  ' + _tool('mdadm', LAYERS['md'])
    if b.get('has_lvm'):
        s += '  ' + _tool('LVM', LAYERS['lvm'])
    if b.get('zpools'):
        s += '  ' + _tool('ZFS', LAYERS['zfs'])
    if s.endswith('"Tools"\n'):
        s += '  info "nothing beyond the base system"\n'
    out.append(s + 'fi\n')

    # storage
    s = 'if stage storage; then\n  section "Storage layers"\n'
    for p in ('/etc/mdadm.conf', '/etc/mdadm/mdadm.conf'):
        if p in files and b.get('has_md'):
            s += f'  restore_file {_q(p)} {_q(_b64(files[p]))}\n'
    if b.get('has_md'):
        s += ('  if command -v mdadm >/dev/null; then ((APPLY)) && md_assemble\n'
              '    [[ -r /proc/mdstat ]] && grep -E "^md" /proc/mdstat | while read -r l; do info "$l"; done; fi\n')
    for c in b.get('crypt') or []:
        s += f'  open_luks {_q(c["name"])} {_q(c["spec"])} {_q(c.get("key") or "")}\n'
        if c.get('in_crypttab'):
            s += f'  crypttab_line {_q(c["name"])} {_q(c["line"])} {_q(c["spec"])}\n'
        else:
            s += f'  info {_q("LUKS " + c["name"] + " is not in a crypttab the scan could read: add it to /etc/crypttab so it opens at boot")}\n'
    if b.get('has_lvm'):
        s += '  if command -v vgchange >/dev/null; then vgscan >/dev/null 2>&1; ((APPLY)) && { vgchange -ay >/dev/null 2>&1; doing "activated LVM volume groups"; }; fi\n'
    if any(f == 'btrfs' for f in fstypes):
        s += '  command -v btrfs >/dev/null && ((APPLY)) && btrfs device scan >/dev/null 2>&1\n'
    s += '  command -v udevadm >/dev/null && udevadm settle 2>/dev/null\n'
    for pool in b.get('zpools') or []:
        s += f'  zfs_pool {_q(pool)}\n'
    if b.get('zpools'):
        s += ('  if ((APPLY)) && command -v zfs >/dev/null; then zfs mount -a 2>/dev/null\n'
              '    if command -v systemctl >/dev/null; then systemctl enable zfs-import-cache zfs-mount zfs.target >/dev/null 2>&1; fi\n')
        s += ''.join(f'    zpool set cachefile=/etc/zfs/zpool.cache {_q(p)} 2>/dev/null\n' for p in b['zpools'])
        s += '  fi\n'
    for d in b.get('datasets') or []:
        s += f'  zfs_dataset {_q(d["name"])} {_q(d["target"])}\n'
    out.append(s + 'fi\n')

    # accounts
    acc = b.get('accounts') or {}
    users, groups = acc.get('users') or [], acc.get('groups') or []
    s = 'if stage accounts; then\n  section "Accounts"\n'
    if not users and not groups:
        s += '  info "the scan saw no accounts to restore (rescan with this version of StorageForge)"\n'
    gids = {u['gid'] for u in users}
    for g in groups:
        if g['gid'] >= 1000 or g['gid'] in gids:
            s += f'  group_on {_q(g["name"])} {int(g["gid"])}\n'
    for u in users:
        s += f'  user_on {_q(u["name"])} {int(u["uid"])} {int(u["gid"])} {_q(u["home"])} {_q(u["shell"])}\n'
    for g in groups:
        for m in g['members']:
            s += f'  member_on {_q(m)} {_q(g["name"])}\n'
    out.append(s + 'fi\n')

    # mounts
    s = 'if stage mounts; then\n  section "Mounts"\n'
    if not active:
        s += '  info "no drives, subvolumes or network mounts beyond the system disk"\n'
    if not b.get('captured_files'):
        s += '  info "built from the mount table only: rescan so the fstab itself is captured"\n'
    if '/etc/fstab' in (b.get('unreadable') or []):
        s += '  conflict "the scan could not read /etc/fstab: these lines come from the mount table"\n'
    for m in active:
        t, line = _q(m['target']), _q(m['line'])
        s += f'  # {one_line(m["line"])}\n'
        if m.get('blocked'):
            s += f'  conflict {_q(m["target"] + ": " + m["blocked"] + " (" + m["spec"] + ")")}\n'
        elif m['kind'] == 'device':
            s += f'  mount_device {t} {_q(m["spec"])} {_q(m["fstype"])} {line}\n'
        elif m['kind'] == 'derived' and m['fstype'] not in ('fuse.mergerfs', 'mergerfs') and m['spec'].startswith('/'):
            s += f'  mount_other {t} {line} {_q(m["spec"])}\n'
        else:
            s += f'  mount_other {t} {line}\n'
    for m in mounts:
        if m['kind'] == 'rootfs':
            s += f'  skip {_q(m["target"] + ": on the old system disk, so the new install lays it out")}\n'
    for u in users:
        s += f'  home_on {_q(u["name"])} {_q(u["home"])} {int(u["uid"])} {int(u["gid"])}\n'
    if b.get('unreadable'):
        s += f'  info {_q("the scan could not read " + ", ".join(b["unreadable"]) + ": give the scan user access, or restore them by hand")}\n'
    out.append(s + 'fi\n')

    # shares
    s = 'if stage shares; then\n  section "Shares"\n'
    if nfs or smb:
        for what, used in (('nfs', nfs), ('smb', smb)):
            if used:
                label, t = SERVERS[what]
                s += f'  had_{what}=0; command -v {t[0]} >/dev/null || had_{what}=1\n  ' + _tool(label, t)
    else:
        s += '  info "no NFS or SMB shares"\n'
    if nfs:
        s += '  nfs_changed=0\n'
        for p in sorted(files):
            if p == '/etc/exports' or p.startswith('/etc/exports.d/'):
                s += f'  restore_file {_q(p)} {_q(_b64(files[p]))} && nfs_changed=1\n'
        for e in b.get('exports') or []:
            if e.get('protocol') == 'NFS' or e.get('proto') == 'NFS':
                s += f'  share_folder {_q(e.get("path") or "")} NFS\n'
        s += '  if command -v exportfs >/dev/null; then service_on nfs-server nfs-kernel-server; ((APPLY && nfs_changed)) && { exportfs -ra && doing "exportfs -ra"; }; fi\n'
    if smb:
        s += '  smb_changed=0\n'
        for p in sorted(p for p in files if p.startswith('/etc/samba/')):
            s += f'  restore_file {_q(p)} {_q(_b64(files[p]))} "$had_smb" && smb_changed=1\n'
        for e in b.get('exports') or []:
            if e.get('protocol') == 'SMB' or e.get('proto') == 'SMB':
                s += f'  share_folder {_q(e.get("path") or "")} SMB\n'
        s += ('  if command -v testparm >/dev/null; then testparm -s >/dev/null 2>&1 && ok "testparm: config is valid" || { ((APPLY)) && conflict "testparm rejects the Samba config: testparm -s"; }\n'
              '    service_on smb smbd\n    ((APPLY && smb_changed)) && command -v systemctl >/dev/null && systemctl reload smb smbd 2>/dev/null\n'
              '    info "Samba passwords are not kept: set each with smbpasswd -a USER"; fi\n')
    if nfs or smb:
        ports = ' '.join((['2049/tcp (NFS)', '111/tcp'] if nfs else []) + (['445/tcp (SMB)'] if smb else []))
        s += f'  info {_q("firewall rules are not restored: open " + ports + " for your clients if this host has a firewall")}\n'
    out.append(s + 'fi\n')

    # links
    s = 'if stage links; then\n  section "Symlinks"\n'
    links = b.get('links') or []
    if not links:
        s += '  info "none that cross a mount"\n'
    for l in links:
        s += f'  link_on {_q(l["path"])} {_q(l["target"])} {_q(l.get("needs") or "")}\n'
    if b.get('links_left_out'):
        s += f'  info "{int(b["links_left_out"])} more symlinks are left out (the first 500 are here)"\n'
    out.append(s + 'fi\n')

    out.append(r"""section "Result"
if ((PROBLEMS)); then printf '  %s need attention, listed above as conflict\n' "$PROBLEMS"; else ok "no conflicts"; fi
if ((APPLY)); then info "next: set passwords for restored accounts, and scan this host again in StorageForge"
else info "run again with --apply to do this"; fi
((PROBLEMS == 0))
""")
    return '\n'.join(out)
