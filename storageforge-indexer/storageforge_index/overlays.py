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


def network_of(interface: str | None, address: str | None = None) -> str | None:
    """Which private network this interface is on, or None for an ordinary one. The interface's name decides. An address in
    100.64.0.0/10 on an interface that says nothing is 'overlay': a private network, without a guess at whose."""
    name = (interface or '').lower()
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


READERS = {'tailscale': tailscale, 'headscale': headscale, 'netbird': netbird, 'openvpn': openvpn}
