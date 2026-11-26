"""Read-only SNMP (v2c / v3) adapter for switches, APs, printers and PDUs that have no SSH or API.

Walks standard MIB-II and LLDP tables (`system`, `ifTable`, `ipAddrTable`, `ipNetToMediaTable`, `lldpRemTable`) using
`snmpwalk` when installed on the controller host, never spawning a shell and never modifying anything on the target.
Community strings or v3 credentials are kept only in memory for the single invocation.
"""
from __future__ import annotations

import re
import shutil
import subprocess

from . import netfacts
from .firewall import _rule

COMMANDS = {
    'system': '1.3.6.1.2.1.1',
    'if': '1.3.6.1.2.1.2.2.1',
    'ip': '1.3.6.1.2.1.4.20.1',
    'arp': '1.3.6.1.2.1.4.22.1',
    'lldp': '1.0.8802.1.1.2.1.4.1.1',
}


def _strip_val(raw: str) -> str:
    raw = raw.strip()
    if ':' in raw:
        tag, _, rest = raw.partition(':')
        if tag.strip().upper() in ('STRING', 'INTEGER', 'COUNTER32', 'COUNTER64', 'GAUGE32', 'TIMETICKS', 'IPADDRESS', 'HEX-STRING', 'OID'):
            raw = rest.strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1]
    return raw.strip()


def _parse_lines(text: str) -> list[tuple[str, str]]:
    rows = []
    for line in (text or '').splitlines():
        oid, sep, val = line.partition(' = ')
        if sep and oid.strip():
            rows.append((oid.strip(), _strip_val(val)))
    return rows


def _int(v: str, default: int = 0) -> int:
    m = re.search(r'-?\d+', str(v or ''))
    return int(m[0]) if m else default


def _mac(v: str) -> str | None:
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(v or ''))
    if len(cleaned) != 12 or cleaned == '0' * 12:
        return None
    return ':'.join(cleaned[i:i + 2].lower() for i in range(0, 12, 2))


def parse(sections: dict[str, str]) -> dict:
    """Turn `{system, if, ip, arp, lldp}` walk text into the standard device reading dict."""
    sys_name, sys_descr = None, None
    for oid, val in _parse_lines(sections.get('system') or ''):
        if oid.endswith('.1.0') or oid.endswith('.sysDescr.0'):
            sys_descr = val
        elif oid.endswith('.5.0') or oid.endswith('.sysName.0'):
            sys_name = val

    ifaces: dict[str, dict] = {}
    counters_map: dict[str, dict] = {}
    for oid, val in _parse_lines(sections.get('if') or ''):
        parts = oid.split('.')
        if len(parts) < 2 or not parts[-1].isdigit():
            continue
        col, idx = parts[-2], parts[-1]
        cur = ifaces.setdefault(idx, {'name': f'if{idx}', 'kind': 'ethernet', 'state': 'unknown', 'mtu': None,
                                      'mac': None, 'master': None, 'parent': None, 'vlan_id': None, 'bridge_vlans': [], 'addresses': []})
        c = counters_map.setdefault(idx, {'iface': cur['name'], 'rx_bytes': 0, 'tx_bytes': 0, 'rx_drop': 0, 'tx_drop': 0, 'rx_error': 0, 'tx_error': 0})
        if col == '2':
            cur['name'] = val or cur['name']
            c['iface'] = cur['name']
        elif col == '3':
            cur['kind'] = 'loopback' if '24' in val or 'loopback' in val.lower() else 'ethernet'
        elif col == '4':
            cur['mtu'] = _int(val) or None
        elif col == '6':
            cur['mac'] = _mac(val)
        elif col == '8':
            cur['state'] = 'up' if _int(val) == 1 or 'up(' in val.lower() else 'down'
        elif col == '10':
            c['rx_bytes'] = _int(val)
        elif col == '13':
            c['rx_drop'] = _int(val)
        elif col == '14':
            c['rx_error'] = _int(val)
        elif col == '16':
            c['tx_bytes'] = _int(val)
        elif col == '19':
            c['tx_drop'] = _int(val)
        elif col == '20':
            c['tx_error'] = _int(val)

    ip_rows: dict[str, dict] = {}
    for oid, val in _parse_lines(sections.get('ip') or ''):
        m = re.search(r'\.(\d+)\.(\d+\.\d+\.\d+\.\d+)$', oid)
        if not m:
            continue
        col, ip = m[1], m[2]
        entry = ip_rows.setdefault(ip, {})
        entry[col] = val
    for ip, info in ip_rows.items():
        idx = info.get('2')
        prefix = netfacts.prefix_of_mask(info['3']) if info.get('3') else None
        if idx and str(idx) in ifaces:
            scope = 'loopback' if ip.startswith('127.') else 'global'
            ifaces[str(idx)]['addresses'].append({'ip': ip, 'prefix': prefix, 'scope': scope})

    arp = []
    arp_rows: dict[tuple[str, str], dict] = {}
    for oid, val in _parse_lines(sections.get('arp') or ''):
        m = re.search(r'\.(\d+)\.(\d+)\.(\d+\.\d+\.\d+\.\d+)$', oid)
        if not m:
            continue
        col, idx, ip = m[1], m[2], m[3]
        arp_rows.setdefault((idx, ip), {})[col] = val
    for (idx, ip), row in list(arp_rows.items())[:500]:
        mac = _mac(row.get('2') or '')
        if mac:
            arp.append({'ip': ip, 'mac': mac, 'dev': (ifaces.get(idx) or {}).get('name')})

    lldp_entries: dict[str, dict] = {}
    for oid, val in _parse_lines(sections.get('lldp') or ''):
        parts = oid.split('.')
        if len(parts) < 4:
            continue
        col, rem_key = parts[-4], '.'.join(parts[-3:])
        entry = lldp_entries.setdefault(rem_key, {'protocol': 'lldp'})
        if col == '7':
            entry['remote_port'] = val
        elif col == '9':
            entry['name'] = val
        elif col == '10':
            entry['platform'] = val[:120]
    discovered = [v for v in lldp_entries.values() if v.get('name')]

    iface_list = [ifaces[k] for k in sorted(ifaces, key=lambda x: int(x))]
    counters = [counters_map[k] for k in sorted(counters_map, key=lambda x: int(x))]
    net = {
        'interfaces': iface_list,
        'routes': [],
        'gateways': [],
        'neighbours': arp,
        'listeners': [],
        'dns': {'nameservers': [], 'search': []},
        'unreadable': ['routes', 'listeners'],
        'complete': bool(iface_list or sys_name),
    }
    fw = {'readable': False, 'backends': [], 'policies': {}, 'chains': [], 'rules': [], 'nat': [], 'zones': [],
          'notes': ['SNMP is read-only: firewall rules are not read over SNMP'], '_rule_sample': bool(_rule)}
    fw.pop('_rule_sample', None)
    return {
        'net': net,
        'firewall': fw,
        'os': (sys_descr or 'SNMP device')[:160],
        'identity': sys_name,
        'facts': {
            'platform': 'snmp',
            'version': sys_descr[:80] if sys_descr else None,
            'identity': sys_name,
            'discovered': discovered,
            'leases': [],
            'counters': counters,
        },
        'config': None,
    }


def collect(host: str, port: int = 161, secret: dict | None = None, runner=None) -> dict:
    """Walk the target over SNMPv2c/v3 (read-only) using `snmpwalk` or a test `runner(oid)`."""
    if runner is not None:
        return parse({k: runner(oid) for k, oid in COMMANDS.items()})
    exe = shutil.which('snmpwalk')
    if not exe:
        raise ValueError('snmpwalk is not installed on this server')
    s = secret or {}
    community = str(s.get('community') or s.get('password') or 'public')
    target = f'{host}:{int(port)}' if port and int(port) != 161 else host
    base = [exe, '-v2c', '-c', community, '-On', '-t', '3', '-r', '1', target]
    if s.get('username') and s.get('auth_pass'):
        base = [exe, '-v3', '-u', str(s['username']), '-l', 'authPriv' if s.get('priv_pass') else 'authNoPriv',
                '-a', str(s.get('auth_proto') or 'SHA'), '-A', str(s['auth_pass']),
                *(['-x', str(s.get('priv_proto') or 'AES'), '-X', str(s['priv_pass'])] if s.get('priv_pass') else []),
                '-On', '-t', '3', '-r', '1', target]
    sections = {}
    for key, oid in COMMANDS.items():
        res = subprocess.run([*base, oid], capture_output=True, text=True, timeout=15, check=False)
        if res.returncode != 0 and key == 'system':
            raise ValueError((res.stderr or res.stdout or 'SNMP request failed').strip()[:300])
        sections[key] = res.stdout or ''
    return parse(sections)
