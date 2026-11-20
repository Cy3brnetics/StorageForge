"""Private networks between hosts (roadmap section 2): which one an interface belongs to, and what each tool says about its peers.

Two things live here and nothing else: the naming, so that an address in 100.64.0.0/10 is no longer called Tailscale whoever handed
it out, and one reader per tool that turns the tool's own status into one shape:

    {'network': 'netbird', 'state': 'connected', 'self': {'name': …, 'addresses': […], 'key': …},
     'peers': [{'name': …, 'addresses': […], 'key': …, 'online': True, 'direct': True, 'os': …, 'routes': […], 'last_seen': …}],
     'routes': […], 'control': 'https://…'}

A reader is given text a host sent. It never raises: what it cannot read is `{'network': …, 'error': …}`, and every list and string
is cut to a size, because a host that has been taken over chooses what its tools print. No user or account name is kept: who owns a
peer is not what the map draws.
"""
from __future__ import annotations

import ipaddress
import json
import re

import yaml

from . import confread

CGNAT = ipaddress.ip_network('100.64.0.0/10')       # Tailscale, Headscale and NetBird all hand addresses out of it
MAX_PEERS, MAX_TEXT, MAX_LIST, MAX_INPUT = 2000, 255, 64, 4 * 1024 * 1024

# what a network is called, in the console, on the map and in a plan
LABELS = {'storageforge': 'the StorageForge network', 'tailscale': 'Tailscale', 'netbird': 'NetBird', 'zerotier': 'ZeroTier', 'nebula': 'Nebula',
          'netmaker': 'Netmaker', 'wireguard': 'WireGuard', 'openvpn': 'OpenVPN', 'ipsec': 'IPsec', 'openziti': 'OpenZiti', 'overlay': 'a private network'}

# an interface's name says whose it is. In order: the first that matches. `sf0` is StorageForge's own (section 2.1)
INTERFACES = (('storageforge', re.compile(r'sf\d+')), ('tailscale', re.compile(r'tailscale\d*|ts\d+')), ('netbird', re.compile(r'wt\d+|netbird\d*')),
              ('zerotier', re.compile(r'zt[0-9a-z]{6,13}')), ('nebula', re.compile(r'nebula\d*')), ('netmaker', re.compile(r'nm-[\w-]+|netmaker\d*')),
              ('openziti', re.compile(r'ziti\d*')), ('wireguard', re.compile(r'wg[\w-]*')), ('openvpn', re.compile(r'(tun|tap)\d+|ovpn[\w-]*')),
              ('ipsec', re.compile(r'(ipsec|vti|xfrm)\d*')))


def network_of(interface: str | None, address: str | None = None, known: dict | None = None) -> str | None:
    """Which private network this interface is on, or None for an ordinary one. What a tool said of its own interface comes first
    (`known`, from `interfaces_of`): Nebula's can be given any name in its configuration. Then the interface's name decides. An
    address in 100.64.0.0/10 on an interface that says nothing is 'overlay': a private network, without a guess at whose."""
    name = (interface or '').lower()
    if known and known.get(name) in LABELS:
        return known[name]
    for network, pattern in INTERFACES:
        if pattern.fullmatch(name):
            return network
    if address:
        try:
            if ipaddress.ip_address(address.split('/')[0]) in CGNAT:
                return 'overlay'
        except ValueError:
            pass
    return None


def label(network: str | None) -> str:
    return LABELS.get(network or '', LABELS['overlay'])


def interfaces_of(readings) -> dict:
    """{interface: network} from what each tool said its own interface is called, for `network_of`."""
    out = {}
    for r in readings if isinstance(readings, list) else []:
        if not isinstance(r, dict) or r.get('error') or r.get('network') not in LABELS:
            continue
        for name in [r.get('interface')] + [n.get('interface') for n in r.get('networks') or [] if isinstance(n, dict)]:
            if isinstance(name, str) and name:
                out[name.lower()] = r['network']
    return out


# ── what the readers share ──
def _text(v, limit: int = MAX_TEXT) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _addresses(values) -> list[str]:
    """Addresses without their prefix length, and only what parses as one."""
    out = []
    for v in values if isinstance(values, list) else [values]:
        if not isinstance(v, str):
            continue
        try:
            out.append(str(ipaddress.ip_interface(v.strip()).ip))
        except ValueError:
            continue
        if len(out) >= MAX_LIST:
            break
    return out


def _routes(values) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else []:
        v = v.get('target') or v.get('range') or v.get('network') if isinstance(v, dict) else v
        if not isinstance(v, str):
            continue
        try:
            out.append(str(ipaddress.ip_network(v.strip(), strict=False)))
        except ValueError:
            continue
        if len(out) >= MAX_LIST:
            break
    return out


def _loaded(network: str, text, want: type):
    """The tool's JSON, or the error to return. Tools print warnings before their JSON: it starts at the first bracket."""
    if not isinstance(text, str) or not text.strip():
        return None, {'network': network, 'error': 'nothing read'}
    if len(text) > MAX_INPUT:
        return None, {'network': network, 'error': 'more than it should ever print'}
    opener = '{' if want is dict else '['
    at = text.find(opener)
    try:
        doc = json.loads(text[at:]) if at >= 0 else None
    except (ValueError, RecursionError):
        doc = None
    if not isinstance(doc, want):
        return None, {'network': network, 'error': 'not the JSON this tool prints'}
    return doc, None


def _peer(name, addresses, key=None, online=None, direct=None, os=None, routes=(), last_seen=None) -> dict:
    return {'name': _text(name), 'addresses': addresses, 'key': _text(key, 128), 'online': online if isinstance(online, bool) else None,
            'direct': direct if isinstance(direct, bool) else None, 'os': _text(os, 64), 'routes': list(routes), 'last_seen': _text(last_seen, 40)}


# ── Tailscale, and Headscale's clients, which are Tailscale's ──
def tailscale(text: str) -> dict:
    """`tailscale status --json`."""
    doc, error = _loaded('tailscale', text, dict)
    if error:
        return error
    me = doc.get('Self') if isinstance(doc.get('Self'), dict) else {}
    peers = []
    for p in list((doc.get('Peer') if isinstance(doc.get('Peer'), dict) else {}).values())[:MAX_PEERS]:
        if not isinstance(p, dict):
            continue
        # a peer reached at an address of its own is direct; through a relay (DERP) it has none
        direct = bool(p.get('CurAddr')) if p.get('Online') else None
        peers.append(_peer(p.get('HostName') or p.get('DNSName'), _addresses(p.get('TailscaleIPs') or []), p.get('PublicKey'), p.get('Online'), direct,
                           p.get('OS'), _routes(p.get('PrimaryRoutes') or []), p.get('LastSeen')) | {'exit_node': bool(p.get('ExitNode')), 'offers_exit': bool(p.get('ExitNodeOption'))})
    tailnet = doc.get('CurrentTailnet') if isinstance(doc.get('CurrentTailnet'), dict) else {}
    return {'network': 'tailscale', 'state': {'Running': 'connected', 'NeedsLogin': 'needs login', 'Stopped': 'stopped'}.get(doc.get('BackendState'), _text(doc.get('BackendState'), 32)),
            'self': {'name': _text(me.get('HostName')), 'addresses': _addresses(me.get('TailscaleIPs') or []), 'key': _text(me.get('PublicKey'), 128)},
            'peers': peers, 'routes': _routes(me.get('PrimaryRoutes') or []), 'control': _text(tailnet.get('MagicDNSSuffix') or doc.get('MagicDNSSuffix'))}


def headscale(text: str) -> dict:
    """`headscale nodes list -o json`, on the host that runs the control server: every node it knows, online or not."""
    doc, error = _loaded('tailscale', text, list)
    if error:
        return error
    peers = []
    for n in doc[:MAX_PEERS]:
        if isinstance(n, dict):
            peers.append(_peer(n.get('given_name') or n.get('name'), _addresses(n.get('ip_addresses') or []), n.get('node_key'), n.get('online'), None, None,
                               _routes(n.get('approved_routes') or [])))
    return {'network': 'tailscale', 'state': 'control server', 'self': None, 'peers': peers, 'routes': [], 'control': 'headscale'}


# ── NetBird ──
def netbird(text: str) -> dict:
    """`netbird status --json`."""
    doc, error = _loaded('netbird', text, dict)
    if error:
        return error
    listed = doc.get('peers') if isinstance(doc.get('peers'), dict) else {}
    peers = []
    for p in (listed.get('details') if isinstance(listed.get('details'), list) else [])[:MAX_PEERS]:
        if not isinstance(p, dict):
            continue
        online = p.get('status') == 'Connected' if isinstance(p.get('status'), str) else None
        kind = p.get('connectionType')
        peers.append(_peer(p.get('fqdn'), _addresses(p.get('netbirdIp') or []), p.get('publicKey'), online, (kind == 'P2P') if online and isinstance(kind, str) and kind else None,
                           None, _routes(p.get('networks') or p.get('routes') or []), p.get('lastWireguardHandshake')))
    management = doc.get('management') if isinstance(doc.get('management'), dict) else {}
    return {'network': 'netbird', 'state': 'connected' if management.get('connected') is True else 'not connected',
            'self': {'name': _text(doc.get('fqdn')), 'addresses': _addresses(doc.get('netbirdIp') or []), 'key': _text(doc.get('publicKey'), 128)},
            'peers': peers, 'routes': _routes(doc.get('networks') or doc.get('routes') or []), 'control': _text(management.get('url'))}


# ── ZeroTier ──
def zerotier(info: str, networks: str, peers: str = '') -> dict:
    """`zerotier-cli -j info`, `-j listnetworks` and `-j peers`. A ZeroTier peer is known by its ten-digit address, not by an IP:
    the addresses here are this host's own, one per network it has joined."""
    me, error = _loaded('zerotier', info, dict)
    if error:
        return error
    nets, error = _loaded('zerotier', networks, list)
    if error:
        nets = []
    joined, addresses, routes = [], [], []
    for n in nets[:MAX_LIST]:
        if not isinstance(n, dict):
            continue
        own = _addresses(n.get('assignedAddresses') or [])
        addresses += own
        routes += _routes(n.get('routes') or [])
        joined.append({'id': _text(n.get('nwid') or n.get('id'), 16), 'name': _text(n.get('name')), 'status': _text(n.get('status'), 32), 'private': n.get('type') == 'PRIVATE',
                       'interface': _text(n.get('portDeviceName'), 15), 'addresses': own})
    seen = []
    listed, error = _loaded('zerotier', peers, list)
    for p in (listed or [])[:MAX_PEERS]:
        if not isinstance(p, dict) or p.get('role') != 'LEAF':          # PLANET and MOON are ZeroTier's root servers, not this site's hosts
            continue
        paths = [x for x in p.get('paths') or [] if isinstance(x, dict) and x.get('active')]
        seen.append(_peer(p.get('address'), [], p.get('address'), bool(paths), bool(paths)) | {'latency_ms': p.get('latency') if isinstance(p.get('latency'), int) and p['latency'] >= 0 else None})
    return {'network': 'zerotier', 'state': 'connected' if me.get('online') is True else 'not connected', 'self': {'name': _text(me.get('address'), 16), 'addresses': addresses[:MAX_LIST], 'key': _text(me.get('address'), 16)},
            'peers': seen, 'routes': routes[:MAX_LIST], 'control': None, 'networks': joined}


# ── OpenVPN, on the server ──
def openvpn(text: str) -> dict:
    """An OpenVPN server's status file (version 1, the default): the clients connected now, with the address each was given."""
    if not isinstance(text, str) or 'CLIENT LIST' not in text[:MAX_INPUT]:
        return {'network': 'openvpn', 'error': 'not an OpenVPN status file'}
    given, section, peers = {}, None, {}
    for line in text[:MAX_INPUT].splitlines():
        line = line.strip()
        if line in ('OpenVPN CLIENT LIST', 'ROUTING TABLE', 'GLOBAL STATS'):
            section = line
            continue
        parts = line.split(',')
        if section == 'OpenVPN CLIENT LIST' and len(parts) >= 5 and parts[0] not in ('Common Name', 'Updated') and len(peers) < MAX_PEERS:
            peers[parts[0]] = _peer(parts[0], [], None, True, True, None, (), parts[4])
        elif section == 'ROUTING TABLE' and len(parts) >= 3 and parts[0] != 'Virtual Address':
            given.setdefault(parts[1], []).append(parts[0])
    for name, peer in peers.items():
        mine = given.get(name, [])
        peer['addresses'] = _addresses([a for a in mine if '/' not in a])
        peer['routes'] = _routes([a for a in mine if '/' in a])          # an iroute: a network behind that client
    return {'network': 'openvpn', 'state': 'server', 'self': None, 'peers': list(peers.values()), 'routes': [], 'control': None}


# ── Nebula ──
def _nebula_certificate(text) -> dict | None:
    """`nebula-cert print -json -path host.crt`: a list of certificates since 1.10 (`networks`, `unsafeNetworks`), one object before
    (`ips`, `subnets`). The first that is not a CA is the host's."""
    if not isinstance(text, str) or not text.strip():
        return None
    doc, error = _loaded('nebula', text, list if text.lstrip()[:1] == '[' else dict)
    if error:
        return None
    for c in (doc if isinstance(doc, list) else [doc])[:8]:
        d = c.get('details') if isinstance(c, dict) and isinstance(c.get('details'), dict) else None
        if d and d.get('isCa') is not True:
            groups = [g[:64] for g in d.get('groups') or [] if isinstance(g, str)][:MAX_LIST] if isinstance(d.get('groups'), list) else []
            return {'name': _text(d.get('name')), 'addresses': _addresses(d.get('networks') or d.get('ips') or []), 'routes': _routes(d.get('unsafeNetworks') or d.get('subnets') or []),
                    'groups': groups, 'expires': _text(d.get('notAfter'), 40), 'fingerprint': _text(c.get('fingerprint'), 128)}
    return None


def nebula(config: str, certificate: str = '') -> dict:
    """`/etc/nebula/config.yml`, which arrives without its key, and the host certificate as `nebula-cert print -json` shows it.
    Nebula has no status command: what is read is what the host is configured to be (a lighthouse, a relay or neither), the
    lighthouses and other hosts its configuration names, and who its certificate says it is. Whether a peer is up is not known."""
    if not isinstance(config, str) or not config.strip():
        return {'network': 'nebula', 'error': 'nothing read'}
    if len(config) > MAX_INPUT:
        return {'network': 'nebula', 'error': 'more than it should ever print'}
    try:
        doc = yaml.safe_load(confread.scrub(config))
    except (yaml.YAMLError, RecursionError, ValueError):
        doc = None
    if not isinstance(doc, dict) or not any(isinstance(doc.get(k), dict) for k in ('pki', 'lighthouse', 'static_host_map', 'tun')):
        return {'network': 'nebula', 'error': 'not a Nebula configuration'}

    def part(name):
        return doc.get(name) if isinstance(doc.get(name), dict) else {}
    lighthouses, relays = _addresses(part('lighthouse').get('hosts') or []), _addresses(part('relay').get('relays') or [])
    endpoints = {}
    for ip, real in list(part('static_host_map').items())[:MAX_PEERS]:
        for a in _addresses(ip):
            endpoints[a] = [e[:MAX_TEXT] for e in (real if isinstance(real, list) else [real]) if isinstance(e, str)][:8]
    peers = []
    for ip in list(dict.fromkeys(lighthouses + list(endpoints) + relays))[:MAX_PEERS]:
        peers.append(_peer(None, [ip]) | {'lighthouse': ip in lighthouses, 'relay': ip in relays, 'endpoints': endpoints.get(ip, [])})
    cert = _nebula_certificate(certificate)
    am_lighthouse, am_relay = part('lighthouse').get('am_lighthouse') is True, part('relay').get('am_relay') is True
    uses = part('tun').get('unsafe_routes')
    port = part('listen').get('port')
    return {'network': 'nebula', 'state': 'configured', 'role': 'lighthouse' if am_lighthouse else 'relay' if am_relay else 'host', 'relay': am_relay,
            'self': {'name': cert['name'] if cert else None, 'addresses': cert['addresses'] if cert else [], 'key': cert['fingerprint'] if cert else None},
            'peers': peers, 'routes': cert['routes'] if cert else [], 'uses_routes': _routes([r.get('route') for r in uses if isinstance(r, dict)] if isinstance(uses, list) else []),
            'control': None, 'interface': _text(part('tun').get('dev'), 15), 'port': port if isinstance(port, int) and not isinstance(port, bool) and 0 <= port < 65536 else None,
            'certificate': {'name': cert['name'], 'groups': cert['groups'], 'expires': cert['expires']} if cert else None}


# ── Netmaker ──
def netmaker(text: str) -> dict:
    """`netclient list -l`: each Netmaker network this host is a node of, and its peers there. A peer is a WireGuard peer: the
    addresses it is allowed that are one host wide are its own, and anything wider is a network it is the gateway to."""
    doc, error = _loaded('netmaker', text, list)
    if error:
        return error
    joined, addresses, peers = [], [], {}
    for n in doc[:MAX_LIST]:
        if not isinstance(n, dict):
            continue
        own = _addresses([n.get('ipv4_addr') or '', n.get('ipv6_addr') or ''])
        addresses += own
        joined.append({'id': _text(n.get('node_id'), 64), 'name': _text(n.get('network'), 64), 'connected': n.get('connected') is True, 'addresses': own})
        for p in (n.get('peers') if isinstance(n.get('peers'), list) else [])[:MAX_PEERS]:
            if not isinstance(p, dict) or not _text(p.get('public_key')) or len(peers) >= MAX_PEERS:
                continue
            hosts, behind = [], []
            for a in p.get('allowed_ips') if isinstance(p.get('allowed_ips'), list) else []:
                try:
                    net = ipaddress.ip_network(a.strip(), strict=False) if isinstance(a, str) else None
                except ValueError:
                    net = None
                if net is not None and net.prefixlen == net.max_prefixlen:
                    hosts.append(str(net.network_address))
                elif net is not None:
                    behind.append(str(net))
            seen = peers.setdefault(p['public_key'][:128], _peer(None, [], p['public_key']) | {'gateway': False})
            seen['addresses'] = list(dict.fromkeys(seen['addresses'] + hosts))[:MAX_LIST]
            seen['routes'] = list(dict.fromkeys(seen['routes'] + behind))[:MAX_LIST]
            seen['gateway'] = bool(seen['routes'])
    return {'network': 'netmaker', 'state': 'connected' if any(n['connected'] for n in joined) else 'not connected', 'self': {'name': None, 'addresses': addresses[:MAX_LIST], 'key': None},
            'peers': list(peers.values()), 'routes': [], 'control': None, 'networks': joined}


# ── strongSwan (IPsec) ──
_SWAN_IKE = re.compile(r'(\S[^:]*): #\d+, (\w+), IKEv(\d)')
_SWAN_END = re.compile(r"\s+(local|remote)\s+'.*' @ ([^\[\s]+)\[\d+\](.*)")
_SWAN_CHILD = re.compile(r'  (\S[^:]*): #\d+, reqid \d+, (\w+), (\w+)')
_SWAN_CONN = re.compile(r'(\S[^:]*): IKEv([12/]+),')
_SWAN_CONN_CHILD = re.compile(r'  (\S[^:]*): (TUNNEL|TRANSPORT|BEET|PASS|DROP)\b')
_SWAN_VIRTUAL = re.compile(r'\[([^\]]*)\]\s*$')


def _selectors(text: str) -> list[str]:
    """Traffic selectors as networks: `10.1.0.0/16 10.3.0.0/24[tcp/80]` without the protocol and port. `dynamic` is not one."""
    return _routes([t.split('[')[0] for t in text.split()])


def _swan_tunnel(name: str, version: str, up: bool) -> dict:
    return {'name': name[:MAX_TEXT], 'up': up, 'ike': f'IKEv{version}', 'remote': None, 'client': False, 'local_routes': [], 'remote_routes': [], 'children': 0}


def strongswan(sas: str, conns: str = '') -> dict:
    """`swanctl --list-sas` and `swanctl --list-conns`: each tunnel that is up, with the networks at each end, and each
    connection that is configured and down. A remote end that was handed a virtual address is a client: it is known by that
    address, and where it connects from is not kept. No identity is kept either: an EAP or XAuth identity is a person."""
    sas, conns = (t if isinstance(t, str) else '' for t in (sas, conns))
    if not sas.strip() and not conns.strip():
        return {'network': 'ipsec', 'error': 'nothing read'}
    if len(sas) > MAX_INPUT or len(conns) > MAX_INPUT:
        return {'network': 'ipsec', 'error': 'more than it should ever print'}
    tunnels, local, cur, child = [], [], None, None
    for line in sas.splitlines():
        if (m := _SWAN_IKE.match(line)):
            if len(tunnels) >= MAX_PEERS:
                break
            cur, child = _swan_tunnel(m[1], m[3], m[2] == 'ESTABLISHED'), None
            tunnels.append(cur)
        elif cur is None:
            continue
        elif (m := _SWAN_CHILD.match(line)):
            child = True
            cur['children'] += 1
        elif child is None and (m := _SWAN_END.match(line)):
            virtual = _addresses(v[1].split()) if (v := _SWAN_VIRTUAL.search(m[3])) else []
            if m[1] == 'local':
                local += _addresses(m[2])
            elif virtual:
                cur['remote'], cur['client'] = virtual[0], True
            else:
                cur['remote'] = (_addresses(m[2]) or [None])[0]
        elif child and (m := re.match(r'    (local|remote)\s+(\S.*)', line)):
            cur[f'{m[1]}_routes'] = list(dict.fromkeys(cur[f'{m[1]}_routes'] + _selectors(m[2])))[:MAX_LIST]
    configured, cur, child = {}, None, False
    for line in conns.splitlines():
        if (m := _SWAN_CONN.match(line)):
            if len(configured) >= MAX_PEERS:
                break
            cur, child = configured.setdefault(m[1][:MAX_TEXT], _swan_tunnel(m[1], m[2], False)), False
        elif cur is None:
            continue
        elif _SWAN_CONN_CHILD.match(line):
            child = True
            cur['children'] += 1
        elif not child and (m := re.match(r'  remote:\s+(\S+)', line)):
            where = m[1].split('[')[0]
            cur['client'] = cur['client'] or where.startswith('%any') or '/' in where or '-' in where
            cur['remote'] = cur['remote'] or (_addresses(where) or [None])[0]
        elif child and (m := re.match(r'    (local|remote):\s+(\S.*)', line)):
            cur[f'{m[1]}_routes'] = list(dict.fromkeys(cur[f'{m[1]}_routes'] + _selectors(m[2])))[:MAX_LIST]
    if not tunnels and not configured and any(line.strip() and not line.lstrip().startswith(('loaded plugins', 'no ')) for line in (sas + '\n' + conns).splitlines()):
        return {'network': 'ipsec', 'error': 'not what swanctl prints'}
    up = {t['name'] for t in tunnels}
    tunnels += [c for name, c in configured.items() if name not in up]
    peers = [_peer(t['name'], [t['remote']] if t['remote'] else [], None, t['up'], True if t['up'] else None, None, t['remote_routes'])
             | {'local_routes': t['local_routes'], 'client': t['client'], 'ike': t['ike']} for t in tunnels[:MAX_PEERS]]
    return {'network': 'ipsec', 'state': 'connected' if any(t['up'] for t in tunnels) else 'not connected', 'self': {'name': None, 'addresses': list(dict.fromkeys(local))[:MAX_LIST], 'key': None},
            'peers': peers, 'routes': list(dict.fromkeys(r for t in tunnels for r in t['local_routes']))[:MAX_LIST], 'control': None, 'configured': len(configured)}


READERS = {'tailscale': tailscale, 'headscale': headscale, 'netbird': netbird, 'openvpn': openvpn, 'nebula': nebula, 'netmaker': netmaker, 'strongswan': strongswan}
