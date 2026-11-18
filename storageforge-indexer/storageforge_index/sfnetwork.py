"""StorageForge's own encrypted network, kept (roadmap section 2.1): sfnet.py's arithmetic against the index.

The network is one setting, the dict sfnet.py describes. It holds ranges, addresses and public keys, and no secret: each host's
private key is made on that host by the `wg-interface` step and stays there. What this module does:

    create(conn, actor)            a network with a range no scanned host uses
    join(conn, host, actor)        the host as a member, pending until a reading shows the key it made
    leave(conn, host, actor)       the host revoked: its key comes off every other member at the next plan
    observe(conn)                  pending members whose interface a reading has seen become active, with that key
    status(conn)                   the network, and per member what the readings confirm
    plan(conn, actor)              a change plan that takes every member from what was read to what should be

Nothing here reaches a host. A plan is a change plan like any other: a person reads it, confirms their password and runs it.
A member's key is taken from a reading once, when it joins. A different key on an active member afterwards is never accepted
here: it is a finding (`key_changed`), because it is either a rotation nobody planned or another machine.
"""
from __future__ import annotations

import ipaddress
import re
import time

from . import alerts, changes, security, sfnet
from .db import Conn

KEY = 'sfnet'
NAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?){0,8}')


def load(conn: Conn) -> dict | None:
    return alerts.get_setting(conn, KEY) or None


def _save(conn: Conn, network: dict, actor: str):
    alerts.set_setting(conn, KEY, network, actor[:60])


def _network(conn: Conn) -> dict:
    network = load(conn)
    if network is None:
        raise sfnet.NetworkError('there is no StorageForge network yet')
    return network


def in_use(conn: Conn) -> list[str]:
    """Every address and route the scanned hosts have, as their last network reading saw them."""
    from . import netfacts
    out = []
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        facts = netfacts.reading(conn, name) or {}
        for i in facts.get('interfaces') or []:
            if i.get('name') == sfnet.INTERFACE:
                continue
            out += [f'{a.get("ip")}/{a.get("prefix")}' for a in i.get('addresses') or [] if a.get('ip') and a.get('prefix') is not None]
        out += [str(r.get('dst')) for r in facts.get('routes') or [] if isinstance(r, dict) and r.get('dst') and r.get('dst') != 'default']
    return out


def create(conn: Conn, actor: str, range_: str | None = None, topology: str = 'mesh') -> dict:
    with conn.tx():
        if load(conn) is not None:
            raise sfnet.NetworkError('the StorageForge network already exists')
        network = sfnet.new(in_use(conn), range_ or None, topology)
        _save(conn, network, actor)
    return network


def _callable(where: str) -> bool:
    """A host name or an IPv4 address, and nothing after it: the port is the network's."""
    try:
        return ipaddress.ip_address(where).version == 4
    except ValueError:
        return bool(NAME.fullmatch(where)) and not where.replace('.', '').isdigit()


def _called_at(conn: Conn, host: str) -> str | None:
    row = conn.all('SELECT ssh_host, ip_address FROM hosts WHERE hostname = :h', {'h': host})
    return (row[0][0] or row[0][1] or None) if row else None


def join(conn: Conn, host, actor: str, endpoint: str | None = None, hub: bool = False, reachable: bool = True) -> dict:
    """endpoint: where the other members call this host; by default the address scans reach it at. reachable=False: nobody can
    call it (it is behind a NAT of its own), so it calls the others and keeps the path open."""
    name = security.known_host(conn, host)
    with conn.tx():
        network = _network(conn)
        where = (str(endpoint).strip() or None) if endpoint else (_called_at(conn, name) if reachable else None)
        if where and not _callable(where):
            raise sfnet.NetworkError('where to call it is a host name or an address, without a port')
        member = dict(sfnet.join(network, name, where if reachable else None, hub))
        _save(conn, network, actor)
    return member


def leave(conn: Conn, host, actor: str) -> dict:
    with conn.tx():
        network = _network(conn)
        name = next((m['host'] for m in network['members'] if m['host'].lower() == str(host or '').strip().lower()), str(host or ''))
        member = dict(sfnet.revoke(network, name))
        _save(conn, network, actor)
    return member


def seen(conn: Conn, network: dict) -> dict:
    """{host: its WireGuard interfaces} for each member a reading exists for. A host whose reading had no `wg` is {host: []}."""
    out = {}
    for m in network['members']:
        reading = security.measurement(conn, m['host'], 'infra') if '(revoked' not in m['host'] else None
        if reading is not None:
            out[m['host']] = (reading.get('access') or {}).get('wireguard') or []
    return out


def observe(conn: Conn, actor: str = 'reading') -> list[str]:
    """Pending members whose interface a reading has seen become active with the key it read. Returns the hosts that did."""
    network = load(conn)
    if network is None or not any(m['state'] == 'pending' for m in network['members']):
        return []
    took, readings = [], seen(conn, network)
    for m in network['members']:
        iface = sfnet._seen(readings.get(m['host'])) if m['state'] == 'pending' else None
        if iface and iface.get('public_key'):
            try:
                sfnet.set_key(network, m['host'], iface['public_key'])
                took.append(m['host'])
            except sfnet.NetworkError:
                pass                      # a key another member already has: it stays pending, and status() says why
    if took:
        with conn.tx():
            _save(conn, network, actor)
    return took


def status(conn: Conn) -> dict:
    observe(conn)
    network = load(conn)
    if network is None:
        return {'network': None, 'members': []}
    readings = seen(conn, network)
    confirmed = sfnet.confirm(network, readings)
    members = []
    for m in network['members']:
        iface = sfnet._seen(readings.get(m['host']))
        row = {**m, **(confirmed.get(m['host']) or {'state': m['state'], 'confirmed': [], 'missing': [], 'unknown': [], 'key_changed': False})}
        if m['state'] == 'pending' and iface and iface.get('public_key'):
            row['state'] = 'key refused'           # observe() would have taken it: another member holds the same key
        if m['state'] == 'revoked':
            row['still_up'] = iface is not None
        members.append(row)
    return {'network': {k: network[k] for k in ('range', 'port', 'topology')}, 'interface': sfnet.INTERFACE, 'members': members}


def tasks(conn: Conn) -> list[dict]:
    """The steps of the plan, host by host: the interface where a host has none yet, then its peers."""
    observe(conn)
    network = _network(conn)
    readings = seen(conn, network)
    prefix = network['range'].split('/')[1]
    out = []
    for m in network['members']:
        host = m['host']
        if '(revoked' in host:
            continue
        iface = sfnet._seen(readings.get(host))
        if m['state'] == 'revoked':
            if iface is not None:
                out.append({'type': 'wg-interface', 'host': host, 'params': {'iface': sfnet.INTERFACE, 'address': f'{m["address"]}/{prefix}', 'port': str(network['port']), 'state': 'absent'}})
            continue
        if iface is None:
            out.append({'type': 'wg-interface', 'host': host, 'params': {'iface': sfnet.INTERFACE, 'address': f'{m["address"]}/{prefix}', 'port': str(network['port']), 'state': 'present'}})
        # a member with no key yet has no peers and is nobody's peer: its peers are written by the plan after the reading that takes its key
        out += [{'type': s['kind'], 'host': host, 'params': {k: v for k, v in s['params'].items() if v != ''}} for s in sfnet.steps(network, host, readings.get(host))]
    return out


def plan(conn: Conn, actor: str) -> dict:
    """Save the plan and return {'plan_id', 'tasks'}; plan_id is None when every member is already as it should be."""
    todo = tasks(conn)
    if not todo:
        return {'plan_id': None, 'tasks': 0}
    name = f'StorageForge network {time.strftime("%Y-%m-%d %H:%M:%S")}'
    return {'plan_id': changes.save_plan(conn, {'name': name, 'tasks': todo}, actor), 'tasks': len(todo), 'name': name}


def problems(conn: Conn) -> dict:
    """What cannot wait for someone to open the page: a member whose key changed under it, and a peer nobody asked for."""
    out = {}
    try:
        members = status(conn)['members']
    except Exception:
        return out
    for m in members:
        if m.get('key_changed'):
            out[f'sfnet-key:{m["host"]}'] = ('sfnet-key', m['host'], f'{m["host"]} has a different key on the StorageForge network',
                                           'Nobody planned a rotation: either the interface was made again by hand, or this is another machine. Its peers still hold the key on record', 'crit')
        elif m.get('unknown'):
            out[f'sfnet-peer:{m["host"]}'] = ('sfnet-peer', m['host'], f'{m["host"]} has a peer on {sfnet.INTERFACE} that nobody asked for',
                                            f'{len(m["unknown"])} key(s) not on record. The next plan revokes them', 'warn')
    return out
