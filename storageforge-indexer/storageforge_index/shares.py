"""Deploy NFS and SMB servers from a host's design, and mount the shares on client hosts.

Exports added in the topology view (or the planner) live in the host's saved design. The scan reports the shares a
host already serves; the ones you add are what this deploys. script() writes one Bash script per server, in the
style of storage-setup.sh: a read-only report by default, --apply to make it so, --host to run it elsewhere.

Server side: installs the NFS server or Samba if missing, writes StorageForge's own files
(/etc/exports.d/storageforge.exports, /etc/samba/storageforge.conf, included once from smb.conf), labels SMB paths
for SELinux, opens the firewall (firewalld or ufw) for the clients, and starts the services.
Client side, for each "mount on" entry: installs the mount helper, appends an fstab line (automount, nofail,
_netdev) after a backup, keeps SMB credentials in a 0600 file, and mounts it. Nothing existing is edited: a
different fstab line for the same mount point is a conflict to fix by hand.
"""
from __future__ import annotations

import datetime as dt
import re
import shlex

from .db import Conn
from .moves import find_host, host_slug, hosts, mount_of
from .payloads import is_designed
from .scriptkit import HELPERS, REMOTE

SMB_NAME = re.compile(r'[A-Za-z0-9_.$-]{1,80}')
NFS_DEFAULT = 'rw,sync,no_subtree_check'


def proto(e: dict) -> str:
    p = str(e.get('protocol') or e.get('proto') or '').upper()
    return 'SMB' if p.startswith(('SMB', 'CIFS')) else 'NFS' if p.startswith('NFS') else p


def design_exports(conn: Conn, host: str) -> list[dict]:
    from .graph import stored_blueprint
    bp = stored_blueprint(conn, host)
    if not bp:
        raise LookupError(f'{host} has no saved design: add exports in the topology view and save it')
    out = []
    for e in bp.get('exports') or []:
        if not is_designed(e) or proto(e) not in ('NFS', 'SMB'):
            continue
        out.append({'deployed': bool(e.get('fromScan')), 'proto': proto(e), 'name': str(e.get('name') or '').strip(), 'path': str(e.get('path') or '').rstrip('/') or '/',
                    'clients': str(e.get('clients') or '').strip(), 'options': str(e.get('options') or '').strip(),
                    'mounts': [{'host': str(m.get('host') or '').strip(), 'path': str(m.get('path') or '').strip()}
                               for m in e.get('mounts') or [] if m.get('host') and m.get('path')]})
    return out


def check(conn: Conn, host: str) -> dict:
    hs = hosts(conn)
    srv = find_host(hs, host)
    if not srv:
        raise LookupError(f'{host} has not been scanned')
    exports, items = design_exports(conn, srv['name']), []
    say = lambda i, level, text: items.append({'export': i, 'level': level, 'text': text})   # noqa: E731
    for i, e in enumerate(exports):
        if not e['path'].startswith('/') or '\n' in e['path'] or '"' in e['path']:
            say(i, 'crit', f'{e["path"]!r} is not a usable absolute path')
            continue
        m = mount_of(srv, e['path'])
        say(i, 'ok' if m and m['target'] != '/' else 'warn',
            f'{e["path"]} is on {m["target"]} ({m["fstype"]})' if m else f'{e["path"]} is not on a scanned mount')
        if e['proto'] == 'NFS':
            if not e['clients']:
                say(i, 'crit', 'NFS needs clients: a subnet like 10.42.0.0/24, or host names. "*" would export to everyone')
            elif '*' in e['clients'].split():
                say(i, 'warn', 'exported to every host that can reach it ("*")')
        else:
            if not SMB_NAME.fullmatch(e['name'] or ''):
                say(i, 'crit', 'an SMB share needs a name of letters, digits, . _ - (e.g. media)')
            users = [u for u in e['clients'].split() if not re.match(r'^[\d.:/]+$', u)]
            say(i, 'note', f'Samba accounts needed: {", ".join(users)} (smbpasswd -a <user> on {srv["name"]})' if users
                else 'no valid users set: any Samba account can connect; set clients to user names or @groups to restrict')
        for mt in e['mounts']:
            ch = find_host(hs, mt['host'])
            if not ch:
                say(i, 'crit', f'client {mt["host"]} has not been scanned')
            elif ch['id'] == srv['id']:
                say(i, 'warn', f'{mt["host"]} is the server itself')
            elif not mt['path'].startswith('/'):
                say(i, 'crit', f'mount point {mt["path"]!r} on {ch["name"]} must be absolute')
            else:
                used = next((m for m in ch['mounts'] if m['target'] == mt['path'] and m['state'] != 'gone'), None)
                say(i, 'warn' if used else 'ok', f'{ch["name"]}:{mt["path"]} already has {used["fstype"]} mounted'
                    if used else f'mounts on {ch["name"]} at {mt["path"]}')
    return {'host': srv['name'], 'address': srv['ssh_host'], 'exports': exports, 'items': items,
            'crit': sum(1 for x in items if x['level'] == 'crit'), 'warn': sum(1 for x in items if x['level'] == 'warn')}


def script(conn: Conn, host: str) -> str:
    c = check(conn, host)
    hs = hosts(conn)
    q = shlex.quote
    e_arrays = {k: [] for k in ('E_PROTO', 'E_NAME', 'E_PATH', 'E_CLIENTS', 'E_OPTS')}
    c_arrays = {k: [] for k in ('C_HOST', 'C_TARGET', 'C_PROTO', 'C_SOURCE', 'C_NAME')}
    lines = []
    for e in c['exports']:
        for k, v in (('E_PROTO', e['proto']), ('E_NAME', e['name'] or e['path']), ('E_PATH', e['path']),
                     ('E_CLIENTS', e['clients']), ('E_OPTS', e['options'] or (NFS_DEFAULT if e['proto'] == 'NFS' else 'rw'))):
            e_arrays[k].append(v)
        lines.append(f'#   {e["proto"]} {e["name"] if e["proto"] == "SMB" else e["path"]}  ({e["path"]} → {e["clients"] or "anyone"})')
        for mt in e['mounts']:
            ch = find_host(hs, mt['host'])
            src = f'{c["address"]}:{e["path"]}' if e['proto'] == 'NFS' else f'//{c["address"]}/{e["name"]}'
            for k, v in (('C_HOST', host_slug(ch['name'] if ch else mt['host'])), ('C_TARGET', mt['path']),
                         ('C_PROTO', e['proto']), ('C_SOURCE', src), ('C_NAME', e['name'] or 'share')):
                c_arrays[k].append(v)
            lines.append(f'#       mounted on {mt["host"]}:{mt["path"]}')
    problems = [f'#   {x["level"].upper()}: {x["text"]}' for x in c['items'] if x['level'] in ('crit', 'warn')]
    decl = '\n'.join(f'{k}=({" ".join(q(v) for v in vs)})' for k, vs in {**e_arrays, **c_arrays}.items())
    return (SHARES_HEAD.format(host=c['host'], slug=host_slug(c['host']), date=dt.datetime.now().strftime('%Y-%m-%d %H:%M'),
                               shares='\n'.join(lines) or '#   (no exports in the design)', problems='\n'.join(problems) or '#   none')
            + f'SERVER={q(host_slug(c["host"]))}\nSERVER_ADDR={q(c["address"])}\n{decl}\n'
            + SHARES_BODY_1 + HELPERS + SHARES_BODY_2 + REMOTE + SHARES_BODY_3)


SHARES_HEAD = r"""#!/usr/bin/env bash
# shares-{slug}.sh — StorageForge share deployment for {host}, generated {date}.
#
# Shares from the saved design:
{shares}
#
# What StorageForge flagged when this was generated:
{problems}
#
#   ./shares-{slug}.sh            report: packages, config files, services, firewall, client mounts (read-only)
#   sudo ./shares-{slug}.sh --apply   install what is missing, write StorageForge's config files, start services,
#                                     open the firewall, add client fstab lines and mount
#   --only server|clients        one side only        --host [user@]host   run on that machine instead
#
# Run it on the server and on each client (or from here with --host). It writes only its own files
# (/etc/exports.d/storageforge.exports, /etc/samba/storageforge.conf, /etc/samba/credentials/*) and appends to
# smb.conf (one include line) and fstab (after a backup). It never edits or removes existing lines.
set -euo pipefail

"""

SHARES_BODY_1 = r"""
MODE=report; ONLY=; HOST=; ARGS=("$@")
while (($#)); do
  case $1 in
    --report) MODE=report ;; --apply) MODE=apply ;;
    --only) ONLY=${2:?--only server or clients}; shift ;;
    --host) HOST=${2:?--host needs [user@]host}; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
"""

SHARES_BODY_2 = r"""
"""

SHARES_BODY_3 = r"""
set -f          # client lists hold "*" and @groups: split them on spaces, never glob them
ME=$(host_slug "$(uname -n)")
APPLY=0; [[ $MODE == apply ]] && APPLY=1
if ((APPLY)) && [[ $EUID -ne 0 ]]; then echo "--apply needs root: sudo $0 ${ARGS[*]}" >&2; exit 1; fi
STAMP=$(date +%Y%m%d-%H%M%S)

pm() { for m in apt-get dnf zypper pacman; do command -v $m >/dev/null && { echo $m; return; }; done; echo none; }
install_pkg() { # apt-name rpm-name arch-name
  local m; m=$(pm)
  case $m in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1" >/dev/null ;;
    dnf) dnf install -y -q "$2" >/dev/null ;; zypper) zypper -nq install "$2" >/dev/null ;; pacman) pacman -S --needed --noconfirm "$3" >/dev/null ;;
    *) conflict "no package manager I know: install $2 yourself"; return 1 ;;
  esac
}
need_cmd() { # command what apt rpm arch
  if command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  if ((APPLY)); then doing "install $2"; install_pkg "$3" "$4" "$5" && ok "$2 installed"; else missing "$2 (package $3 / $4)"; fi
}
backup() { [[ -e $1 ]] && cp -a -- "$1" "$1.storageforge-$STAMP"; }
own_file() { # path content -> StorageForge's own file: written whole (after a backup) when it differs
  if [[ -e $1 && $(cat "$1") == "$2" ]]; then ok "$1"; return 1; fi
  if ((APPLY)); then mkdir -p "$(dirname "$1")"; backup "$1"; printf '%s\n' "$2" >"$1"; doing "wrote $1"; return 0
  else missing "$1 $([[ -e $1 ]] && echo '(differs)')"; return 1; fi
}
service_on() { # unit...
  local u
  for u; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && break; done
  if systemctl is-active -q "$u" && systemctl is-enabled -q "$u" 2>/dev/null; then ok "$u running and enabled"; return; fi
  if ((APPLY)); then doing "systemctl enable --now $u"; systemctl enable --now "$u"; else missing "$u not running/enabled"; fi
}
cidrs() { tr ' ' '\n' <<<"$1" | grep -E '^[0-9.:]+(/[0-9]+)?$' || true; }
open_fw() { # label tcp-ports clients firewalld-services...
  local label=$1 ports=$2 clients=$3; shift 3
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    local s; for s; do
      if firewall-cmd --query-service="$s" >/dev/null 2>&1; then ok "firewalld allows $s"
      elif ((APPLY)); then doing "firewalld: allow $s"; firewall-cmd -q --permanent --add-service="$s"; firewall-cmd -q --reload
      else missing "firewalld does not allow $s"; fi
    done
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    local from p c; from=$(cidrs "$clients"); [[ -n $from ]] || from=any
    for c in $from; do for p in $ports; do
      if ufw status | grep -qE "^$p/tcp +ALLOW +(IN +)?$([[ $c == any ]] && echo Anywhere || echo "${c//./\\.}")"; then ok "ufw allows $p/tcp from $c"
      elif ((APPLY)); then doing "ufw allow from $c to any port $p proto tcp"; ufw allow from "$c" to any port "$p" proto tcp >/dev/null
      else missing "ufw does not allow $p/tcp from $c ($label)"; fi
    done; done
  else info "no active firewalld or ufw: nothing to open for $label"; fi
}

server_nfs() {
  local i body="# StorageForge NFS exports for $(uname -n). Written by shares-$SERVER.sh; edit the design, not this file."
  [[ " ${E_PROTO[*]} " == *" NFS "* ]] || return 0
  section "NFS server"
  for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == NFS ]] || continue
    local line c; line=$(printf '"%s"' "${E_PATH[$i]}")
    local cl=${E_CLIENTS[$i]}; [[ -n $cl ]] || cl='*'
    for c in $cl; do line+=" $c(${E_OPTS[$i]})"; done
    body+=$'\n'"$line"
    if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi
  done
  need_cmd exportfs "NFS server" nfs-kernel-server nfs-utils nfs-utils || return 0
  own_file /etc/exports.d/storageforge.exports "$body" && ((APPLY)) && { doing "exportfs -ra"; exportfs -ra; }
  service_on nfs-server nfs-kernel-server
  open_fw NFS "2049 111" "$(printf '%s ' "${E_CLIENTS[@]}")" nfs mountd rpc-bind
  if command -v exportfs >/dev/null; then
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == NFS ]] || continue
      if exportfs -s 2>/dev/null | grep -qF "${E_PATH[$i]}"; then ok "exported: ${E_PATH[$i]}"; elif ((!APPLY)); then missing "not exported yet: ${E_PATH[$i]}"; else conflict "${E_PATH[$i]} is not exported after exportfs -ra"; fi
    done
  fi
}
server_smb() {
  local i body="# StorageForge Samba shares for $(uname -n). Written by shares-$SERVER.sh; edit the design, not this file."
  [[ " ${E_PROTO[*]} " == *" SMB "* ]] || return 0
  section "SMB server (Samba)"
  for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
    local users=() hostsallow=() c
    for c in ${E_CLIENTS[$i]}; do if [[ $c =~ ^[0-9.:]+(/[0-9]+)?$ ]]; then hostsallow+=("$c"); else users+=("$c"); fi; done
    body+=$'\n'"[${E_NAME[$i]}]"$'\n'"   path = ${E_PATH[$i]}"$'\n'"   browseable = yes"
    body+=$'\n'"   read only = $([[ ${E_OPTS[$i]} == *ro* ]] && echo yes || echo no)"
    ((${#users[@]})) && body+=$'\n'"   valid users = ${users[*]}"
    ((${#hostsallow[@]})) && body+=$'\n'"   hosts allow = ${hostsallow[*]} 127.0.0.1"
    if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi
  done
  need_cmd smbd "Samba" samba samba samba || return 0
  local changed=0; own_file /etc/samba/storageforge.conf "$body" && changed=1
  local inc='include = /etc/samba/storageforge.conf'
  if [[ ! -e /etc/samba/smb.conf ]]; then
    if ((APPLY)); then printf '[global]\n   workgroup = WORKGROUP\n   server role = standalone server\n   map to guest = never\n\n%s\n' "$inc" >/etc/samba/smb.conf; doing "wrote a minimal /etc/samba/smb.conf"; changed=1
    else missing "/etc/samba/smb.conf"; fi
  elif grep -qF "$inc" /etc/samba/smb.conf; then ok "smb.conf includes storageforge.conf"
  elif ((APPLY)); then backup /etc/samba/smb.conf; printf '\n# added by StorageForge\n%s\n' "$inc" >>/etc/samba/smb.conf; doing "appended the include to smb.conf"; changed=1
  else missing "smb.conf does not include storageforge.conf yet"; fi
  if command -v testparm >/dev/null && [[ -e /etc/samba/smb.conf ]]; then
    if testparm -s >/dev/null 2>&1; then ok "testparm: config is valid"; else conflict "testparm rejects the config: testparm -s"; fi
  fi
  if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
      if ls -Zd "${E_PATH[$i]}" 2>/dev/null | grep -q samba_share_t; then ok "SELinux: ${E_PATH[$i]} is samba_share_t"
      elif ((APPLY)); then doing "SELinux: label ${E_PATH[$i]} samba_share_t"
        if command -v semanage >/dev/null; then semanage fcontext -a -t samba_share_t "${E_PATH[$i]}(/.*)?" 2>/dev/null || true; restorecon -R "${E_PATH[$i]}"
        else chcon -R -t samba_share_t "${E_PATH[$i]}"; fi
      else missing "SELinux would block Samba from ${E_PATH[$i]} (needs samba_share_t)"; fi
    done
  fi
  service_on smb smbd
  ((APPLY && changed)) && systemctl reload smb smbd 2>/dev/null || true
  open_fw SMB "445 139" "$(printf '%s ' "${E_CLIENTS[@]}")" samba
  if command -v pdbedit >/dev/null; then
    local known u; known=$(pdbedit -L 2>/dev/null | cut -d: -f1)
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
      for u in ${E_CLIENTS[$i]}; do [[ $u == @* || $u =~ ^[0-9.:/]+$ ]] && continue
        if grep -qx "$u" <<<"$known"; then ok "Samba account $u"; else missing "Samba account $u: sudo smbpasswd -a $u (sets its SMB password)"; fi
      done
    done
  fi
}

client_mount() { # index into C_*
  local i=$1 t=${C_TARGET[$1]} line opts
  section "mount ${C_SOURCE[$i]} at $t"
  if [[ ${C_PROTO[$i]} == NFS ]]; then
    need_cmd mount.nfs "NFS client" nfs-common nfs-utils nfs-utils || return 0
    line="${C_SOURCE[$i]// /\\040} ${t// /\\040} nfs4 _netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=30 0 0"
  else
    need_cmd mount.cifs "SMB client" cifs-utils cifs-utils cifs-utils || return 0
    local cred=/etc/samba/credentials/$SERVER-${C_NAME[$i]} who=${SUDO_USER:-root}
    if [[ -s $cred ]]; then ok "credentials $cred"
    elif ((APPLY)) && [[ -t 0 ]]; then
      local u p; read -r -p "  Samba user for ${C_SOURCE[$i]}: " u; read -r -s -p "  password: " p; echo
      mkdir -p /etc/samba/credentials; chmod 700 /etc/samba/credentials
      ( umask 077; printf 'username=%s\npassword=%s\n' "$u" "$p" >"$cred" ); unset p; doing "wrote $cred (0600)"
    else missing "credentials $cred (--apply asks for them; or write username=/password= lines, chmod 600)"; return 0; fi
    line="${C_SOURCE[$i]// /\\040} ${t// /\\040} cifs credentials=$cred,uid=$(id -u "$who"),gid=$(id -g "$who"),iocharset=utf8,_netdev,nofail,x-systemd.automount 0 0"
  fi
  local have; have=$(awk -v t="${t// /\\040}" '!/^[[:space:]]*#/ && $2 == t' /etc/fstab)
  if [[ $have == "$line" ]]; then ok "fstab line"
  elif [[ -n $have && $(awk '{print $1, $3}' <<<"$have") == "$(awk '{print $1, $3}' <<<"$line")" ]]; then ok "fstab line (its own options kept)"
  elif [[ -n $have ]]; then conflict "fstab already has a different line for $t: $have"
  elif ((APPLY)); then
    backup /etc/fstab; mkdir -p "$t"; printf '%s\n' "$line" >>/etc/fstab; doing "appended to /etc/fstab"
    if ! findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1; then conflict "findmnt --verify complains about /etc/fstab; the backup is /etc/fstab.storageforge-$STAMP"; return 1; fi
    systemctl daemon-reload
  else missing "fstab: $line"; fi
  if mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then doing "mount $t"; mount "$t" && ok "mounted" || conflict "mount $t failed"
  else missing "not mounted"; fi
}

echo "${H}shares for $SERVER${N0} · $MODE on $(uname -n)"
if [[ $ONLY != clients ]]; then
  if [[ $ME == "$SERVER" ]]; then server_nfs; server_smb
  else section "server"; skip "the shares are served by $SERVER: ./$(basename "$0") --host <user>@$SERVER_ADDR ${ARGS[*]}"; fi
fi
if [[ $ONLY != server ]]; then
  for i in "${!C_HOST[@]}"; do
    if [[ ${C_HOST[$i]} == "$ME" ]]; then client_mount "$i" || true
    else section "mount ${C_SOURCE[$i]} at ${C_TARGET[$i]}"; skip "client ${C_HOST[$i]}: run this script there (or --host)"; fi
  done
fi
echo
if ((PROBLEMS)); then echo "${R}$PROBLEMS problem(s)${N0}"; exit 1; fi
echo "${G}done${N0}"
"""
