"""The one place StorageForge sends packets to find out what exists: an nmap scan someone turned on, of ranges someone named. Everything else reads what enrolled machines report, and with
this off (as it starts), that's still all there is: no scan runs, by schedule or by hand.

Connect scans only (-sT): the container has no NET_RAW and needs none, and nothing here asks for root. Only a CIDR that passed the check reaches nmap's command line, after `--`. Each address found is
matched against what StorageForge already manages, by address, so a result can link back to that host's or device's own pages. What matches nothing is what's new on the network.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import threading
import time
from xml.etree import ElementTree

from .alerts import get_setting, set_setting
from .db import Conn, loads
from .remote import child_env

KEY = 'netscan.settings'
DEFAULTS = {'enabled': False, 'ranges': [], 'top_ports': 100, 'every_hours': 0}
MIN_PREFIX = 20            # 4094 addresses: past that this is not one network
MAX_TOP_PORTS = 1000
RUN_LIMIT = 1800
KEEP_RUNS = 50
MAX_XML = 64 << 20
_running = threading.Lock()


class ScanRefused(ValueError):
    pass


def settings(conn: Conn) -> dict:
    return {**DEFAULTS, **(get_setting(conn, KEY) or {}), 'nmap': bool(shutil.which('nmap'))}


def check_range(text) -> str:
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise ScanRefused(f'{str(text)[:60]!r} is not an address or network') from None
    if net.version != 4:
        raise ScanRefused('IPv4 only: an IPv6 network can\'t be swept')
    if net.prefixlen < MIN_PREFIX:
        raise ScanRefused(f'{net} is too wide: /{MIN_PREFIX} at most')
    if not net.is_private:
        raise ScanRefused(f'{net} is not a private network: StorageForge won\'t scan the internet')
    return str(net)


def save_settings(conn: Conn, body: dict, actor: str) -> dict:
    cur = {**DEFAULTS, **(get_setting(conn, KEY) or {})}
    if 'enabled' in body:
        cur['enabled'] = body['enabled'] is True
    if 'ranges' in body:
        if not isinstance(body['ranges'], list) or len(body['ranges']) > 32:
            raise ScanRefused('ranges is a list of at most 32 networks')
        cur['ranges'] = [check_range(r) for r in body['ranges']]
    if 'top_ports' in body:
        top = body['top_ports']
        if not isinstance(top, int) or not 1 <= top <= MAX_TOP_PORTS:
            raise ScanRefused(f'top_ports is 1 to {MAX_TOP_PORTS}')
        cur['top_ports'] = top
    if 'every_hours' in body:
        every = body['every_hours']
        if not isinstance(every, int) or not 0 <= every <= 24 * 30:
            raise ScanRefused('every_hours is 0 (never) to 720')
        cur['every_hours'] = every
    set_setting(conn, KEY, cur, actor[:60])
    return settings(conn)


def command(target: str, top_ports: int) -> list[str]:
    return ['nmap', '-sT', '-n', '--open', '--top-ports', str(int(top_ports)), '-T3', '--host-timeout', '120s', '--max-retries', '1', '-oX', '-', '--', target]


def parse_xml(text: str) -> list[dict]:
    if len(text or '') > MAX_XML:
        raise ValueError('more than a scan should ever say')
    if '<!ENTITY' in (text or ''):
        raise ValueError('it declares an entity: refused')
    root = ElementTree.fromstring(text)
    out = []
    for h in root.findall('host'):
        if (h.find('status') is not None and h.find('status').get('state') != 'up'):
            continue
        ip = next((a.get('addr') for a in h.findall('address') if a.get('addrtype') == 'ipv4'), None)
        if not ip:
            continue
        mac = next((a for a in h.findall('address') if a.get('addrtype') == 'mac'), None)
        name = next((n.get('name') for n in h.findall('hostnames/hostname')), None)
        ports = []
        for p in h.findall('ports/port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = p.find('service')
            ports.append({'proto': p.get('protocol'), 'port': int(p.get('portid')), 'service': svc.get('name') if svc is not None else None})
        out.append({'ip': ip, 'mac': mac.get('addr').lower() if mac is not None else None, 'vendor': mac.get('vendor') if mac is not None else None, 'name': name, 'ports': ports})
    return out


def known_addresses(conn: Conn) -> dict:
    """{address: (kind, name)} for everything StorageForge manages."""
    from .netdevice import names as device_names
    from .netfacts import reading
    devices = {k.lower() for k in device_names(conn)}
    out = {}
    for name, ip, ssh_host in conn.all('SELECT hostname, ip_address, ssh_host FROM hosts'):
        kind = 'device' if name.lower() in devices else 'host'
        for a in (ip, ssh_host):
            if a:
                out[a] = (kind, name)
        for i in (reading(conn, name) or {}).get('interfaces') or []:
            for a in i.get('addresses') or []:
                if a.get('ip'):
                    out.setdefault(a['ip'], (kind, name))
    return out


def link_of(row: dict, known: dict) -> dict:
    """Where this result goes in StorageForge. A host reached over SSH links to its config pages; something with SSH open that nothing manages links to where it could be added."""
    got = known.get(row['ip'])
    ssh = any(p['port'] == 22 for p in row['ports'])
    if got:
        kind, name = got
        if kind == 'device':
            return {'kind': 'device', 'name': name, 'managed': True, 'links': [{'label': 'Device', 'url': f'/manage#device={name}'}, {'label': 'On the map', 'url': f'/#view=map&host={name}'}]}
        return {'kind': 'host', 'name': name, 'managed': True, 'links': [{'label': 'Config', 'url': f'/#host={name}&tab=rebuild'}, {'label': 'Network', 'url': f'/#host={name}&tab=infra'}, {'label': 'On the map', 'url': f'/#view=map&host={name}'}]}
    return {'kind': 'unknown', 'name': None, 'managed': False, 'ssh': ssh, 'links': ([{'label': 'Add it', 'url': f'/#tab=keys&address={row["ip"]}'}, {'label': 'Add as a device', 'url': f'/manage#add={row["ip"]}'}] if ssh else [{'label': 'Add as a device', 'url': f'/manage#add={row["ip"]}'}])}


def run(db, conn: Conn, target: str | None, actor: str, wait: bool = False, runner=None) -> dict:
    cfg = settings(conn)
    if not cfg['enabled']:
        raise ScanRefused('the scanner is off: turn it on first')
    targets = [check_range(target)] if target else cfg['ranges']
    if not targets:
        raise ScanRefused('no network named to scan')
    if target and check_range(target) not in cfg['ranges']:
        raise ScanRefused(f'{target} is not one of the ranges this site allows: add it first')
    if not _running.acquire(blocking=False):
        raise ScanRefused('a scan is already running')
    now = int(time.time())
    try:
        sid = conn.scalar("INSERT INTO network_scans (target, started_at, status, actor) VALUES (:t, :a, 'running', :u) RETURNING scan_id", {'t': ' '.join(targets), 'a': now, 'u': actor[:60]})
    except Exception:
        _running.release()
        raise

    def work():
        from . import errlog
        c = db.connect()
        try:
            hosts, error = [], None
            for t in targets:
                argv = command(t, cfg['top_ports'])
                try:
                    if runner:
                        text = runner(argv)
                    else:
                        p = subprocess.run(argv, capture_output=True, text=True, timeout=RUN_LIMIT, env=child_env())
                        if p.returncode != 0:
                            raise RuntimeError(p.stderr.strip()[-400:] or f'nmap exited {p.returncode}')
                        text = p.stdout
                    hosts += parse_xml(text)
                except Exception as exc:
                    error = str(exc)[:500]
            with c.tx():
                for h in hosts:
                    c.execute("""INSERT INTO network_scan_hosts (scan_id, ip, mac, vendor, name, ports_json) VALUES (:s, :i, :m, :v, :n, :p)
                                 ON CONFLICT (scan_id, ip) DO NOTHING""", {'s': sid, 'i': h['ip'], 'm': h['mac'], 'v': h['vendor'], 'n': h['name'], 'p': json.dumps(h['ports'])})
                c.execute('UPDATE network_scans SET finished_at = :t, status = :st, error = :e, host_count = :n WHERE scan_id = :s', {'t': int(time.time()), 'st': 'failed' if error else 'done', 'e': error, 'n': len(hosts), 's': sid})
                for (old,) in c.all('SELECT scan_id FROM network_scans ORDER BY scan_id DESC LIMIT 1000 OFFSET :k', {'k': KEEP_RUNS}):
                    c.execute('DELETE FROM network_scan_hosts WHERE scan_id = :s', {'s': old})
                    c.execute('DELETE FROM network_scans WHERE scan_id = :s', {'s': old})
        except Exception:
            errlog.trace()
        finally:
            c.close()
            _running.release()

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    if wait:
        worker.join(RUN_LIMIT + 60)
    return {'ok': True, 'scan_id': sid, 'targets': targets}


def scans(conn: Conn, limit: int = 20) -> list[dict]:
    keys = ('id', 'target', 'started_at', 'finished_at', 'status', 'actor', 'error', 'hosts')
    return [dict(zip(keys, r)) for r in conn.all('SELECT scan_id, target, started_at, finished_at, status, actor, error, host_count FROM network_scans ORDER BY scan_id DESC LIMIT :l', {'l': limit})]


def results(conn: Conn, scan_id: int | None = None) -> dict:
    """A scan's results, each linked to what it is, with what's changed from the scan before."""
    sid = scan_id or conn.scalar("SELECT max(scan_id) FROM network_scans WHERE status <> 'running'")
    if not sid:
        return {'scan': None, 'hosts': []}
    rows = conn.all('SELECT ip, mac, vendor, name, ports_json FROM network_scan_hosts WHERE scan_id = :s ORDER BY ip', {'s': sid})
    before = conn.scalar("SELECT max(scan_id) FROM network_scans WHERE scan_id < :s AND status = 'done'", {'s': sid})
    previous = {r[0]: loads(r[1]) if isinstance(r[1], str) else r[1] for r in conn.all('SELECT ip, ports_json FROM network_scan_hosts WHERE scan_id = :s', {'s': before})} if before else None
    known = known_addresses(conn)
    out = []
    for ip, mac, vendor, name, ports in rows:
        row = {'ip': ip, 'mac': mac, 'vendor': vendor, 'name': name, 'ports': loads(ports) if isinstance(ports, str) else ports}
        row['link'] = link_of(row, known)
        if previous is not None:
            old = previous.get(ip)
            row['new'] = old is None
            row['new_ports'] = [] if old is None else sorted({p['port'] for p in row['ports']} - {p['port'] for p in old})
        out.append(row)
    out.sort(key=lambda r: tuple(int(x) for x in r['ip'].split('.')))
    gone = sorted(set(previous or {}) - {r['ip'] for r in out}) if previous is not None else []
    scan = next((s for s in scans(conn, 100) if s['id'] == sid), None)
    return {'scan': scan, 'hosts': out, 'gone': gone, 'previous': before}


def graph(conn: Conn, scan_id: int | None = None) -> dict:
    """The same results as a drawing: what was found grouped by network."""
    res = results(conn, scan_id)
    nets: dict = {}
    for h in res['hosts']:
        net = str(ipaddress.ip_network(f'{h["ip"]}/24', strict=False))
        nets.setdefault(net, []).append(h)
    return {'scan': res['scan'], 'networks': [{'network': n, 'hosts': rows} for n, rows in sorted(nets.items())], 'gone': res.get('gone') or []}


def tick(db) -> int:
    conn = db.connect()
    try:
        cfg = settings(conn)
        if not cfg['enabled'] or not cfg['every_hours'] or not cfg['ranges'] or not cfg['nmap']:
            return 0
        last = conn.scalar('SELECT max(started_at) FROM network_scans') or 0
        if time.time() - last < cfg['every_hours'] * 3600:
            return 0
        run(db, conn, None, 'system')
        return 1
    finally:
        conn.close()

