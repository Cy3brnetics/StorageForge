"""What takes root to read about a host's infrastructure: firewall rules, which process owns each listener, VMs, instances,
rootless containers and clients on storage ports. A signed run through storageforge-run, like the security measurement, and
only reads. Stored in security_measurements as kind 'infra'. Hosts with deploy access are read every 6 hours unless turned
off per host, and those without one, or where deploys are refused, stay at what a scan can see and say so.

Everything printed here lands in deploy_runs.output, so what could hold a secret never gets printed: no command lines, no
environment, no `incus list --format json` (its config can hold cloud-init data), only known Proxmox config keys.
"""
from __future__ import annotations

import re
import shlex
import time

from . import alerts, deploy, firewall, netfacts, security
from .db import Conn
from .runtimes import docker, guests

MEASURE_EVERY = 6 * 3600
OFF_KEY = 'infra.read.off'
SECTIONS = ('tools', 'fw_state', 'nft', 'iptables', 'ip6tables', 'ufw', 'firewalld', 'listeners', 'storage_clients', 'libvirt', 'libvirt_snap', 'libvirt_net', 'libvirt_pool',
            'incus', 'lxc', 'proxmox', 'podman', 'wireguard', 'tailscale', 'netbird', 'headscale', 'caddy', 'nginx', 'units', 'end')
PVE_KEYS = '^(cores|memory|onboot|unprivileged|net[0-9]+|(scsi|virtio|sata|ide|efidisk|tpmstate|mp)[0-9]+|rootfs): '
BODY = r"""
sec() { printf '\n@@%s\n' "$1"; }
try() { timeout 30 "$@" 2>/dev/null || :; }
has() { command -v "$1" >/dev/null; }
capped() { head -c "$1"; }                 # a section cut short fails to parse and reads as unreadable, not as smaller
one() { base64 | tr -d '\n'; }
sec tools; for c in nft iptables iptables-save ip6tables-save ufw firewall-cmd ss virsh incus lxc-ls qm pct podman wg tailscale netbird headscale caddy nginx; do has "$c" && echo "$c"; done
sec fw_state; has firewall-cmd && try firewall-cmd --state
sec nft
# table by table, and without iptables-nft's tables when iptables-save reads them better: with Docker and ufw those run to hundreds of KB as JSON
if has nft; then
  try nft -j list tables; echo
  ipt=; has iptables-save && [ -n "$(try iptables-save | grep -m1 '^-A')" ] && ipt=1
  try nft list tables | while read -r _ fam name; do
    case $ipt:$fam:$name in 1:ip:filter|1:ip:nat|1:ip:mangle|1:ip:raw|1:ip:security|1:ip6:filter|1:ip6:nat|1:ip6:mangle|1:ip6:raw|1:ip6:security) continue ;; esac
    try nft -j list table "$fam" "$name" | capped 60000; echo
  done
fi
sec iptables; has iptables-save && try iptables-save | capped 40000
sec ip6tables; has ip6tables-save && try ip6tables-save | capped 20000
sec ufw; has ufw && try ufw status verbose | capped 20000
sec firewalld; has firewall-cmd && try firewall-cmd --list-all-zones | capped 20000
sec listeners; has ss && try ss -H -tulnp | capped 40000
sec storage_clients; has ss && try ss -H -tn state established '( sport = :445 or sport = :139 or sport = :2049 )' | capped 20000
sec libvirt
if has virsh && try virsh -c qemu:///system version >/dev/null; then
  try virsh -c qemu:///system list --all --name | head -n 200 | while read -r d; do
    [ -n "$d" ] || continue
    st=$(try virsh -c qemu:///system domstate "$d" | head -n1)
    au=$(try virsh -c qemu:///system dominfo "$d" | sed -n 's/^Autostart: *//p')
    printf '%s\t%s\t%s\t%s\n' "$d" "$st" "$au" "$(try virsh -c qemu:///system dumpxml "$d" | one)"
  done
fi
# each VM's snapshots: what a snapshot's XML says before the copy of the domain it carries, and which is current
sec libvirt_snap
if has virsh && try virsh -c qemu:///system version >/dev/null; then
  try virsh -c qemu:///system list --all --name | head -n 200 | while read -r d; do
    [ -n "$d" ] || continue
    cur=$(try virsh -c qemu:///system snapshot-current --name "$d" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    try virsh -c qemu:///system snapshot-list "$d" --name | head -n 100 | while read -r n; do
      [ -n "$n" ] || continue
      printf '%s\t%s\t%s\t%s\n' "$d" "$n" "$([ "$n" = "$cur" ] && echo 1 || echo 0)" "$(try virsh -c qemu:///system snapshot-dumpxml "$d" "$n" | sed '/<domain[ >]/,$d' | capped 20000 | one)"
    done
  done
fi
sec libvirt_net
if has virsh; then try virsh -c qemu:///system net-list --all --name | head -n 50 | while read -r n; do [ -n "$n" ] && printf '%s\t%s\t%s\n' "$n" "$(try virsh -c qemu:///system net-dumpxml --inactive "$n" | one)" "$(try virsh -c qemu:///system net-info "$n" | one)"; done; fi
sec libvirt_pool
if has virsh; then try virsh -c qemu:///system pool-list --all --name | head -n 50 | while read -r n; do [ -n "$n" ] && printf '%s\t%s\t%s\n' "$n" "$(try virsh -c qemu:///system pool-dumpxml --inactive "$n" | one)" "$(try virsh -c qemu:///system pool-info --bytes "$n" | one)"; done; fi
sec incus
if has incus; then
  try incus list -f csv -c nstP4S | head -n 200 | while IFS= read -r l; do
    printf 'i\t%s\n' "$l"; n=${l%%,*}
    printf 'd\t%s\t%s\n' "$n" "$(try incus config device show "$n" | one)"
    for k in security.privileged security.nesting; do printf 's\t%s\t%s\t%s\n' "$n" "$k" "$(try incus config get "$n" "$k")"; done
  done
fi
sec lxc; has lxc-ls && try lxc-ls -f -F NAME,STATE,IPV4 | head -n 200
sec proxmox
if has qm; then
  try qm list | awk 'NR>1 {print $1, $2, $3}' | head -n 200 | while read -r id name st; do
    printf 'g\tqemu\t%s\t%s\t%s\n' "$id" "$name" "$st"; try qm config "$id" | grep -E "$PVE_KEYS" | sed 's/^/c\t/'
  done
fi
if has pct; then
  try pct list | awk 'NR>1 {print $1, $2, $NF}' | head -n 200 | while read -r id st name; do
    printf 'g\tlxc\t%s\t%s\t%s\n' "$id" "$name" "$st"; try pct config "$id" | grep -E "$PVE_KEYS" | sed 's/^/c\t/'
  done
fi
sec podman
if has podman && [ -d /var/lib/systemd/linger ]; then
  for u in /var/lib/systemd/linger/*; do
    u=${u##*/}; id -u "$u" >/dev/null 2>&1 || continue
    uid=$(id -u "$u"); ids=$(try runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$uid" podman ps -aq)
    [ -n "$ids" ] || continue
    printf 'u\t%s\n' "$u"
    # shellcheck disable=SC2086
    try runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$uid" podman container inspect --format "$FMT" $ids | capped 40000
  done
fi
sec wireguard
# public keys, endpoints and routes only. `wg show dump` and `wg showconf` print private keys, so neither is ever called
if has wg; then
  for i in $(try wg show interfaces); do
    printf 'i\t%s\t%s\t%s\n' "$i" "$(try wg show "$i" public-key)" "$(try wg show "$i" listen-port)"
    try wg show "$i" endpoints | sed "s/^/e\t$i\t/"
    try wg show "$i" allowed-ips | tr ' ' ',' | sed "s/\t/ /; s/ /\t/" | sed "s/^/a\t$i\t/"
    try wg show "$i" latest-handshakes | sed "s/^/h\t$i\t/"
  done
fi
sec tailscale; has tailscale && try tailscale status | head -n 200 | capped 12000
sec netbird; has netbird && try netbird status | head -n 40 | capped 4000
sec headscale; has headscale && try headscale nodes list | head -n 200 | capped 12000
# site names and upstreams, no other line: these files can hold passwords and keys
sec caddy; for f in /etc/caddy/Caddyfile /etc/caddy/conf.d/*; do [ -r "$f" ] && grep -aE '^[^#[:space:]][^{]*\{[[:space:]]*$|^[[:space:]]*reverse_proxy[[:space:]]' "$f" | capped 12000; done
sec nginx; for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do [ -r "$f" ] && grep -aE '^[[:space:]]*(server_name|proxy_pass)[[:space:]]' "$f" | capped 12000; done
sec units; has systemctl && try systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}' | grep -aE '^(authelia|authentik|keycloak|lldap|slapd|pomerium|traefik|caddy|nginx|wg-quick@|headscale|tailscaled|netbird)' | head -n 40
sec end
"""


def script() -> str:
    fmt = docker.FMT_C[:-1] + ',' + docker.FMT_D_PODMAN[docker.FMT_D_PODMAN.index('"image_id"'):]
    return ('#!/usr/bin/env bash\n# Written by StorageForge. Only reads.\nset -u\nexport LC_ALL=C\nPATH=$PATH:/usr/sbin:/sbin\n'
            f'PVE_KEYS={shlex.quote(PVE_KEYS)}\nFMT={shlex.quote(fmt)}\n' + BODY)


def _sections(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith('@@') and line[2:] in SECTIONS:
            cur = line[2:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out


def parse_listeners(lines: list[str]) -> list[dict]:
    """ss -p: process names only. `users:(("sshd",pid=1,fd=3))` has no arguments in it."""
    out = []
    for line in lines:
        got = netfacts.parse_listeners(line)
        if got:
            names = sorted(set(re.findall(r'\("([^"]+)",pid=', line)))
            out.append({**got[0], 'process': names})
    return out


def parse_storage_clients(lines: list[str]) -> list[dict]:
    """`ss state established` drops its state column: recv send local peer. Counted per client and port, nothing more."""
    seen: dict = {}
    for line in lines:
        f = line.split()
        if len(f) < 4:
            continue
        local, peer = netfacts._split_addr(f[2]), netfacts._split_addr(f[3])
        if local and peer:
            key = (peer[0], local[1])
            seen[key] = seen.get(key, 0) + 1
    return [{'client': c, 'port': p, 'connections': n} for (c, p), n in sorted(seen.items())]


def _podman(lines: list[str]) -> list[dict]:
    out, user, buf = [], None, []

    def flush():
        if user is None or not buf:
            return
        text = '@@engine\tpodman\trootless\n@@containers\n' + '\n'.join(buf) + '\n@@details\n' + '\n'.join(buf)
        out.append({'user': user, 'containers': docker.parse_engine(text)['containers']})

    for line in lines:
        if line.startswith('u\t'):
            flush()
            user, buf = line[2:], []
        else:
            buf.append(line)
    flush()
    return out


WGKEY = re.compile(r'[A-Za-z0-9+/]{42,43}=')


def parse_wireguard(lines: list[str]) -> list[dict]:
    """One record per interface, keyed on public keys. A line that holds anything else is dropped: nothing here may hold a secret."""
    ifaces: dict = {}
    for line in lines:
        f = line.split('\t')
        if f[0] == 'i' and len(f) >= 4 and WGKEY.fullmatch(f[2]):
            ifaces[f[1]] = {'name': f[1], 'public_key': f[2], 'listen_port': int(f[3]) if f[3].isdigit() else None, 'peers': {}}
        elif f[0] in ('e', 'a', 'h') and len(f) >= 4 and f[1] in ifaces and WGKEY.fullmatch(f[2]):
            peer = ifaces[f[1]]['peers'].setdefault(f[2], {'public_key': f[2], 'endpoint': None, 'allowed_ips': [], 'handshake': None})
            if f[0] == 'e':
                peer['endpoint'] = None if f[3] == '(none)' else f[3]
            elif f[0] == 'a':
                peer['allowed_ips'] = [x for x in f[3].replace(' ', ',').split(',') if x and x != '(none)']
            else:
                peer['handshake'] = int(f[3]) if f[3].isdigit() and f[3] != '0' else None
    return [{**i, 'peers': list(i['peers'].values())} for i in ifaces.values()]


def parse_tailscale(lines: list[str]) -> list[dict]:
    """`tailscale status`: address, name, user, OS, state. The user is left out."""
    out = []
    for line in lines:
        f = line.split()
        if len(f) >= 4 and re.fullmatch(r'[0-9.:a-f]+', f[0]) and '.' in f[0] or (len(f) >= 4 and ':' in f[0]):
            out.append({'ip': f[0], 'name': f[1], 'os': f[3], 'active': 'active' in line})
    return out


def parse_proxy_routes(caddy: list[str], nginx: list[str]) -> list[dict]:
    routes, site = [], None
    for line in caddy:
        text = line.strip()
        if text.endswith('{') and not line[:1].isspace():
            site = text[:-1].strip()
        elif text.startswith('reverse_proxy') and site:
            for up in text.split()[1:]:
                if not up.startswith(('{', '@')):
                    routes.append({'proxy': 'caddy', 'site': site, 'upstream': up})
    names = None
    for line in nginx:
        text = line.strip().rstrip(';')
        if text.startswith('server_name'):
            names = ' '.join(text.split()[1:]) or None
        elif text.startswith('proxy_pass') and names:
            routes.append({'proxy': 'nginx', 'site': names, 'upstream': text.split()[1] if len(text.split()) > 1 else ''})
    return routes[:200]


def parse_access(s: dict, tools: list[str]) -> dict:
    return {'wireguard': parse_wireguard(s.get('wireguard', [])) if 'wg' in tools else None, 'tailscale': parse_tailscale(s.get('tailscale', [])) if 'tailscale' in tools else None,
            'netbird': 'netbird' in tools, 'headscale': 'headscale' in tools, 'proxy_routes': parse_proxy_routes(s.get('caddy', []), s.get('nginx', [])),
            'units': [u.strip() for u in s.get('units', []) if u.strip()]}


def parse(text: str) -> dict | None:
    """None unless the script ran to its end."""
    s = _sections(text)
    if 'end' not in s:
        return None
    tools = [t.strip() for t in s.get('tools', []) if t.strip()]
    joined = {k: '\n'.join(v).strip() for k, v in s.items()}
    fw = firewall.model({'tools': tools, 'nft': joined.get('nft'), 'iptables': joined.get('iptables'), 'ip6tables': joined.get('ip6tables'),
                         'ufw': joined.get('ufw'), 'firewalld': joined.get('firewalld'), 'firewalld_state': joined.get('fw_state')})
    return {'tools': tools, 'firewall': fw, 'listeners': parse_listeners(s.get('listeners', [])), 'storage_clients': parse_storage_clients(s.get('storage_clients', [])),
            'libvirt': guests.with_snapshots(guests.parse_libvirt(s.get('libvirt', [])), guests.parse_libvirt_snapshots(s.get('libvirt_snap', []))), 'libvirt_networks': guests.parse_libvirt_networks(s.get('libvirt_net', [])),
            'libvirt_pools': guests.parse_libvirt_pools(s.get('libvirt_pool', [])), 'incus': guests.parse_incus(s.get('incus', [])), 'lxc': guests.parse_lxc(s.get('lxc', [])),
            'proxmox': guests.parse_proxmox(s.get('proxmox', [])), 'podman_rootless': _podman(s.get('podman', [])), 'access': parse_access(s, tools)}


def measure(db, conn: Conn, host, actor: str) -> dict:
    name = security.known_host(conn, host)
    res = deploy.run(db, name, script(), [], kind='security', ref='infra-measure', mode='report', actor=actor, timeout=300)
    if res['status'] != 'ok':
        return {'ok': False, 'host': name, 'error': (res.get('output') or res['status'])[-500:], 'run_id': res.get('run_id')}
    data = parse(res.get('output') or '')
    if data is None:
        return {'ok': False, 'host': name, 'error': 'the reading was cut short: nothing was recorded', 'run_id': res.get('run_id')}
    now = int(time.time())
    security._save_measurement(conn, name, 'infra', now, 'measure', data)
    from .infragraph import rebuild
    rebuild(conn, name)
    return {'ok': True, 'host': name, 'measured_at': now, 'run_id': res.get('run_id')}


def reading(conn: Conn, host: str) -> dict | None:
    return security.measurement(conn, host, 'infra')


def off_hosts(conn: Conn) -> list[str]:
    return list(alerts.get_setting(conn, OFF_KEY) or [])


def set_off(conn: Conn, host, off: bool, actor: str) -> dict:
    name = security.known_host(conn, host)
    hosts = set(off_hosts(conn))
    (hosts.add if off else hosts.discard)(name)
    alerts.set_setting(conn, OFF_KEY, sorted(hosts), actor[:60])
    return {'ok': True, 'host': name, 'off': off}


def tick(db) -> int:
    """Hosts with deploy access that are due. One bad host must not hold up the rest."""
    from . import errlog
    conn = db.connect()
    done = 0
    try:
        off, now = set(off_hosts(conn)), int(time.time())
        for row in deploy.access(conn):
            host = row['host']
            if host in off or row.get('state') != 'ready' or not deploy.ready(conn, host):
                continue
            at = conn.scalar("SELECT measured_at FROM security_measurements WHERE host = :h AND kind = 'infra'", {'h': host})
            if at is None or now - at >= MEASURE_EVERY:
                try:
                    done += bool(measure(db, conn, host, 'system')['ok'])
                except Exception:
                    errlog.trace()
    finally:
        conn.close()
    return done
