"""StorageForge's own encrypted network (roadmap section 2.1): the arithmetic, with no database and no host in it.

A WireGuard network between the controller and the hosts it is turned on for. Each host makes its key pair itself and the private
half never leaves it; the controller holds public keys and addresses, and writes peers as plan steps (`wg-peer`). This module decides
four things and does nothing else:

    pick_range(in_use)            a range that meets nothing the site already uses, and never 100.64.0.0/10
    join(network, host, …)        a member with the lowest free address; an address once given is not given to another host
    desired_peers(network, host)  who that host should have as peers, by public key
    steps(network, host, seen)    the plan steps that take the host from what a scan saw to that
    confirm(network, seen)        per host: which peers a scan confirmed by key, which are missing, which nobody asked for

A network is a plain dict, as it will be stored:

    {'range': '10.203.0.0/20', 'port': 51903, 'topology': 'mesh' | 'hub',
     'members': [{'host', 'address', 'public_key', 'next_public_key', 'endpoint', 'hub', 'state': 'pending' | 'active' | 'revoked'}]}

A peer is trusted for its own address and nothing more (`/32`), so one host that is taken over cannot answer for another's address.
In the hub topology a hub is trusted for the whole range, because traffic between two spokes goes through it.
"""
from __future__ import annotations

import ipaddress
import re

INTERFACE = 'sf0'
PORT = 51903
KEEPALIVE = 25                       # seconds, towards a peer that has to be reached through its own NAT
WGKEY = re.compile(r'[A-Za-z0-9+/]{43}=')
SHARED = ipaddress.ip_network('100.64.0.0/10')          # Tailscale's and NetBird's: never ours
# Tried in order. Ranges nobody's router hands out by default, sixteen /24s each: room for about four thousand hosts.
CANDIDATES = ('10.203.0.0/20', '10.87.64.0/20', '10.151.112.0/20', '172.29.160.0/20', '172.22.208.0/20', '192.168.203.0/24')


class NetworkError(ValueError):
    pass


def pick_range(in_use) -> str:
    """The first candidate that overlaps nothing in in_use (networks or addresses the site's hosts have, as scans saw them). What
    does not parse is skipped: a scan's odd line must not decide the network."""
    taken = [SHARED]
    for value in in_use:
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen > 0:          # a default route is not a network in use
            taken.append(net)
    for candidate in CANDIDATES:
        net = ipaddress.ip_network(candidate)
        if not any(net.overlaps(t) for t in taken):
            return candidate
    raise NetworkError('every range StorageForge would pick is in use at this site: give it one')


def new(in_use=(), range_: str | None = None, topology: str = 'mesh') -> dict:
    if topology not in ('mesh', 'hub'):
        raise NetworkError('topology is mesh or hub')
    if range_ is not None:
        try:
            net = ipaddress.ip_network(range_)
        except ValueError:
            raise NetworkError(f'{range_!r} is not a network') from None
        if net.version != 4 or not net.is_private or net.overlaps(SHARED) or not 16 <= net.prefixlen <= 28:
            raise NetworkError('the range is a private IPv4 network between /16 and /28, outside 100.64.0.0/10')
    return {'range': range_ or pick_range(in_use), 'port': PORT, 'topology': topology, 'members': []}


def member(network: dict, host: str) -> dict | None:
    return next((m for m in network['members'] if m['host'] == host), None)


def join(network: dict, host: str, endpoint: str | None = None, hub: bool = False) -> dict:
    """The host as a member, pending until it has made its key. Joining again changes nothing but the endpoint and hub mark; a
    revoked host that joins again gets a new address, since its old one may still be written on a peer that was unreachable."""
    m = member(network, host)
    if m and m['state'] != 'revoked':
        m['endpoint'], m['hub'] = endpoint, bool(hub)
        return m
    given = {x['address'] for x in network['members']}          # revoked members' addresses stay taken
    address = next((str(a) for a in ipaddress.ip_network(network['range']).hosts() if str(a) not in given), None)
    if address is None:
        raise NetworkError(f'{network["range"]} has no address left')
    if m:
        network['members'].remove(m)
        network['members'].append({**m, 'host': f'{host} (revoked {m["address"]})', 'endpoint': None})          # kept, so its key and address stay refused
    m = {'host': host, 'address': address, 'public_key': None, 'next_public_key': None, 'endpoint': endpoint, 'hub': bool(hub), 'state': 'pending'}
    network['members'].append(m)
    return m


def _key(value: str) -> str:
    if not isinstance(value, str) or not WGKEY.fullmatch(value):
        raise NetworkError('not a WireGuard public key')
    return value


def set_key(network: dict, host: str, public_key: str) -> dict:
    """The key the host made, as a scan read it. A pending member becomes active. An active member's key does not change this way:
    a different key on its interface is a finding (confirm), and a wanted change is rotate()."""
    m = member(network, host)
    if m is None or m['state'] == 'revoked':
        raise NetworkError(f'{host} is not on the network')
    key = _key(public_key)
    if any(key in (x['public_key'], x['next_public_key']) for x in network['members'] if x is not m):
        raise NetworkError('another member has that key: a key pair belongs to one host')
    if m['state'] == 'pending':
        m['public_key'], m['state'] = key, 'active'
    elif m['public_key'] != key:
        raise NetworkError(f'{host} already has a key: rotate it through a plan')
    return m


def rotate(network: dict, host: str, new_public_key: str) -> dict:
    """First half of a rotation: the host has made a new pair, and every peer is to accept both keys until it switches."""
    m = member(network, host)
    if m is None or m['state'] != 'active':
        raise NetworkError(f'{host} is not an active member')
    key = _key(new_public_key)
    if any(key in (x['public_key'], x['next_public_key']) for x in network['members']):
        raise NetworkError('that key is already known here')
    m['next_public_key'] = key
    return m


def rotated(network: dict, host: str) -> dict:
    """Second half: the host uses the new key now, and the old one is to be taken off every peer."""
    m = member(network, host)
    if m is None or not m.get('next_public_key'):
        raise NetworkError(f'{host} has no rotation under way')
    m['public_key'], m['next_public_key'] = m['next_public_key'], None
    return m


def revoke(network: dict, host: str) -> dict:
    """The host is off the network: steps() takes its key off every other member. Its address is not given out again."""
    m = member(network, host)
    if m is None:
        raise NetworkError(f'{host} is not on the network')
    m['state'], m['next_public_key'] = 'revoked', None
    return m


def desired_peers(network: dict, host: str) -> list[dict]:
    """Who this host should have as peers: [{'host', 'public_key', 'allowed': [...], 'endpoint', 'keepalive'}]. One entry per key, so
    a member in the middle of a rotation appears twice, with its address on the key it uses now."""
    me = member(network, host)
    if me is None or me['state'] != 'active':
        return []
    out = []
    for m in network['members']:
        if m is me or m['state'] != 'active':
            continue
        if network['topology'] == 'hub' and not (m['hub'] or me['hub']):
            continue                                      # two spokes are not peers: they meet at a hub
        whole = network['topology'] == 'hub' and m['hub'] and not me['hub']
        allowed = [network['range']] if whole else [f'{m["address"]}/32']
        endpoint = f'{m["endpoint"]}:{network["port"]}' if m['endpoint'] else None
        # without an address to call, the other side has to call here and keep the path open
        keepalive = KEEPALIVE if (endpoint and not me['endpoint']) else None
        out.append({'host': m['host'], 'public_key': m['public_key'], 'allowed': allowed, 'endpoint': endpoint, 'keepalive': keepalive})
        if m.get('next_public_key'):
            # WireGuard gives an address to one key at a time: the new key is known but carries nothing until the host switches
            out.append({'host': m['host'], 'public_key': m['next_public_key'], 'allowed': [], 'endpoint': endpoint, 'keepalive': keepalive})
    return out


def _seen(interfaces) -> dict | None:
    """The sf0 record of a scan's WireGuard read (inframeasure.parse_wireguard), or None where the host has none."""
    return next((i for i in interfaces or [] if isinstance(i, dict) and i.get('name') == INTERFACE), None)


def steps(network: dict, host: str, interfaces) -> list[dict]:
    """Plan steps that take this host's sf0 from what the scan saw to what it should be: peers to add or change, then peers to
    revoke. Anything on sf0 that is not wanted is revoked, whoever put it there: the interface is StorageForge's."""
    want = {p['public_key']: p for p in desired_peers(network, host)}
    iface = _seen(interfaces)
    have = {p['public_key']: p for p in (iface or {}).get('peers', []) if isinstance(p, dict) and p.get('public_key')}
    out = []
    for key, p in want.items():
        seen = have.get(key)
        if seen is None or sorted(seen.get('allowed_ips') or []) != sorted(p['allowed']):
            out.append({'kind': 'wg-peer', 'params': {'iface': INTERFACE, 'pubkey': key, 'allowed': ','.join(p['allowed']), 'endpoint': p['endpoint'] or '',
                                                      'keepalive': str(p['keepalive'] or ''), 'state': 'present'}, 'why': f'{p["host"]} is on the StorageForge network'})
    names = {k: m['host'] for m in network['members'] for k in (m['public_key'], m.get('next_public_key')) if k}
    for key in have:
        if key not in want:
            out.append({'kind': 'wg-peer', 'params': {'iface': INTERFACE, 'pubkey': key, 'allowed': '', 'endpoint': '', 'keepalive': '', 'state': 'absent'},
                        'why': f'{names[key]} is no longer on the network' if key in names else 'a peer nobody asked for'})
    return out


def confirm(network: dict, seen: dict) -> dict:
    """What the scans confirm, per active or pending member: seen is {host: that host's WireGuard interfaces}. A peer is confirmed
    when its key is on the interface with the address it should carry. A member's own key that differs from the one on record is
    `key_changed`: either a rotation nobody planned or a different machine."""
    out = {}
    for m in network['members']:
        if m['state'] == 'revoked':
            continue
        host = m['host']
        iface = _seen(seen.get(host))
        if iface is None:
            out[host] = {'state': 'no interface' if host in seen else 'not scanned', 'confirmed': [], 'missing': [p['host'] for p in desired_peers(network, host)], 'unknown': [], 'key_changed': False}
            continue
        have = {p['public_key']: p for p in iface.get('peers', []) if isinstance(p, dict) and p.get('public_key')}
        want = desired_peers(network, host)
        confirmed = [p['host'] for p in want if p['public_key'] in have and sorted(have[p['public_key']].get('allowed_ips') or []) == sorted(p['allowed'])]
        wanted_keys = {p['public_key'] for p in want}
        own = iface.get('public_key')
        out[host] = {'state': 'pending' if m['state'] == 'pending' else 'ok', 'confirmed': confirmed, 'missing': sorted({p['host'] for p in want} - set(confirmed)),
                     'unknown': sorted(k for k in have if k not in wanted_keys),
                     'key_changed': m['state'] == 'active' and own not in (m['public_key'], m.get('next_public_key'))}
        if out[host]['state'] == 'ok' and (out[host]['missing'] or out[host]['unknown'] or out[host]['key_changed']):
            out[host]['state'] = 'differs'
    return out
