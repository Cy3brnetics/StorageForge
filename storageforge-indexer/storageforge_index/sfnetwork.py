"""StorageForge's own encrypted network, kept (roadmap section 2.1): sfnet.py's arithmetic against the index.

The network is one setting, the dict sfnet.py describes. It holds ranges, addresses and public keys, and no secret: each host's
private key is made on that host by the `wg-interface` step and stays there. What this module does:

    create(conn, actor)            a network with a range no scanned host uses
    join(conn, host, actor)        the host as a member, pending until a reading shows the key it made
    leave(conn, host, actor)       the host revoked: its key comes off every other member at the next plan
    observe(conn)                  pending members whose interface a reading has seen become active, with that key
    rotate(conn, host, actor)      a person asks for the member's key to change: the plans that follow do it in two halves
    join_controller, apply_controller   the controller itself as a member, through its link (sfcontroller.py)
    status(conn)                   the network, and per member what the readings confirm
    plan(conn, actor)              a change plan that takes every member from what was read to what should be
    via(conn, host, port)          the host's address on the network, for a connection from here that can go over it

Nothing here reaches a host. A plan is a change plan like any other: a person reads it, confirms their password and runs it.
A member's key is taken from a reading once, when it joins. A different key on an active member afterwards is never accepted
here: it is a finding (`key_changed`), because it is either a rotation nobody planned or another machine. The one way a key
changes is a rotation a person asked for: then, and only then, the next key the host made is taken from a reading, once.
"""
from __future__ import annotations

import ipaddress
import re
import time

from . import alerts, changes, overlays, security, sfcontroller, sfnet
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
    """{host: its WireGuard interfaces} for each member a reading exists for. A host whose reading had no `wg` is {host: []}. The
    controller's own comes from its link (sfcontroller.py), which reports the same lines a scan reads."""
    out = {}
    for m in network['members']:
        if '(revoked' in m['host']:
            continue
        if m['host'] == network.get('controller'):
            mine = sfcontroller.reading()
            if mine is not None:
                out[m['host']] = mine
            continue
        reading = security.measurement(conn, m['host'], 'infra')
        if reading is not None:
            out[m['host']] = (reading.get('access') or {}).get('wireguard') or []
    return out


def observe(conn: Conn, actor: str = 'reading') -> list[str]:
    """What the readings may change, and nothing else may: a pending member whose interface was read becomes active with that key;
    a member a person asked to rotate gets the next key its host made; a member whose interface now uses its next key has switched.
    Returns the hosts something was taken for. A key that fits none of the three is left to status() to report."""
    network = load(conn)
    if network is None or not any(m['state'] == 'pending' or m.get('rotation') or m.get('next_public_key') for m in network['members']):
        return []
    took, readings = [], seen(conn, network)
    for m in network['members']:
        iface = sfnet._seen(readings.get(m['host'])) if m['state'] != 'revoked' else None
        if not iface or not iface.get('public_key'):
            continue
        try:
            if m['state'] == 'pending':
                sfnet.set_key(network, m['host'], iface['public_key'])
            elif m.get('next_public_key') and iface['public_key'] == m['next_public_key']:
                sfnet.rotated(network, m['host'])
            elif m.get('rotation') == 'asked' and not m.get('next_public_key') and iface.get('next_public_key') and iface['public_key'] == m['public_key']:
                sfnet.rotate(network, m['host'], iface['next_public_key'])
            else:
                continue
            took.append(m['host'])
        except sfnet.NetworkError:
            pass                      # a key another member already has: nothing is taken, and status() says why
    if took:
        with conn.tx():
            _save(conn, network, actor)
    return took


def _stage(network: dict, m: dict, readings: dict) -> dict | None:
    """Where a member's rotation stands, for the page: what the next plan does about it, and who it waits for."""
    if m['state'] != 'active' or not (m.get('rotation') or m.get('next_public_key')):
        return None
    if not m.get('next_public_key'):
        iface = sfnet._seen(readings.get(m['host']))
        refused = bool(iface and iface.get('next_public_key'))             # observe() would have taken it
        return {'step': 'key refused' if refused else 'make the key', 'waiting': []}
    waiting = sfnet.waiting_for(network, m['host'], readings)
    return {'step': 'tell the peers', 'waiting': waiting} if waiting else {'step': 'switch', 'waiting': []}


def _controller_want(network: dict, readings: dict) -> str | None:
    """What the controller's link should be asked for now, or None when the controller is not a member."""
    name = network.get('controller')
    me = sfnet.member(network, name) if name else None
    if me is None:
        return None
    then, ready = sfnet.after_switch(network, readings)
    iface = sfnet._seen(readings.get(name))
    rotation = None
    if me['state'] == 'active':
        if me.get('next_public_key'):
            rotation = ('switch', me['next_public_key']) if name in ready else ('prepare', None)
        elif me.get('rotation') == 'asked':
            rotation = ('prepare', None)
        elif iface and iface.get('next_public_key'):
            rotation = ('cancel', None)
    # its peers are worked out as a host's are: against the network as it is once those ready to switch have
    return sfcontroller.want(network, me, sfnet.desired_peers(then, name) if me['state'] == 'active' else [], rotation)


def controller(conn: Conn) -> dict:
    """The controller's own end: whether a link is there and running, and whether what it was asked for is what it should be."""
    network = load(conn)
    said = sfcontroller.report()
    out = {'configured': said['configured'], 'running': said['running'], 'error': said['error'], 'member': None, 'pending': False}
    if network is None or not network.get('controller'):
        return out
    out['member'] = network['controller']
    out['pending'] = out['configured'] and _controller_want(network, seen(conn, network)) != sfcontroller.wanted()
    return out


def join_controller(conn: Conn, actor: str, endpoint: str | None = None, hub: bool = False) -> dict:
    """The controller as a member. endpoint: where hosts call it (in Docker, the Docker host's address, with the UDP port
    published); without one the controller calls the hosts and keeps the paths open."""
    if not sfcontroller.configured():
        raise sfnet.NetworkError('this controller was not started with a link for the StorageForge network: see docs/infrastructure-map.md')
    where = str(endpoint or '').strip() or None
    if where and not _callable(where):
        raise sfnet.NetworkError('where to call it is a host name or an address, without a port')
    with conn.tx():
        network = _network(conn)
        member = dict(sfnet.join(network, sfcontroller.NAME, where, hub))
        network['controller'] = sfcontroller.NAME
        _save(conn, network, actor)
    return member


def apply_controller(conn: Conn, actor: str) -> dict:
    """Hand the link what the controller's interface should be. This is the controller's half of a plan: the link makes the
    interface and the key, and sets the peers. Returns {'changed': whether anything was asked that had not been before}."""
    observe(conn)
    network = _network(conn)
    text = _controller_want(network, seen(conn, network))
    if text is None:
        raise sfnet.NetworkError('the controller is not on the network')
    changed = text != sfcontroller.wanted()
    if changed:
        sfcontroller.write(text)
    return {'changed': changed, 'peers': sum(1 for line in text.splitlines() if line.startswith('p\t'))}


def rotate(conn: Conn, host, actor: str, cancel: bool = False) -> dict:
    """A person asks for a member's key to change, or takes that back before the host has switched. This alone lets a new key be
    taken from a reading, once."""
    with conn.tx():
        network = _network(conn)
        name = next((m['host'] for m in network['members'] if m['host'].lower() == str(host or '').strip().lower()), str(host or ''))
        member = dict(sfnet.cancel_rotation(network, name) if cancel else sfnet.ask_rotation(network, name))
        _save(conn, network, actor)
    return member


def status(conn: Conn) -> dict:
    observe(conn)
    network = load(conn)
    if network is None:
        return {'network': None, 'members': [], 'controller': controller(conn)}
    readings = seen(conn, network)
    confirmed = sfnet.confirm(network, readings)
    members = []
    for m in network['members']:
        iface = sfnet._seen(readings.get(m['host']))
        row = {**m, **(confirmed.get(m['host']) or {'state': m['state'], 'confirmed': [], 'missing': [], 'unknown': [], 'key_changed': False})}
        row['rotation'], row['is_controller'] = _stage(network, m, readings), m['host'] == network.get('controller')
        if m['state'] == 'pending' and iface and iface.get('public_key'):
            row['state'] = 'key refused'           # observe() would have taken it: another member holds the same key
        if m['state'] == 'revoked':
            row['still_up'] = iface is not None
        # a next key waiting on a host nobody asked to rotate: not taken, and said
        row['key_unasked'] = bool(m['state'] == 'active' and not m.get('rotation') and not m.get('next_public_key') and iface and iface.get('next_public_key'))
        members.append(row)
    return {'network': {k: network[k] for k in ('range', 'port', 'topology')}, 'interface': sfnet.INTERFACE, 'members': members, 'controller': controller(conn),
            'label': overlays.label('storageforge')}


def tasks(conn: Conn) -> list[dict]:
    """The steps of the plan, host by host: the interface where a host has none yet, the half of a rotation that is due, then its
    peers. A host that is ready to switch to its next key does so first, and its peers move its address to that key in the same
    plan. The controller is not in a plan: its link is asked instead (apply_controller)."""
    observe(conn)
    network = _network(conn)
    readings = seen(conn, network)
    then, ready = sfnet.after_switch(network, readings)
    prefix = network['range'].split('/')[1]
    first, out = [], []
    for m in network['members']:
        host = m['host']
        if '(revoked' in host or host == network.get('controller'):
            continue
        iface = sfnet._seen(readings.get(host))
        interface = {'iface': sfnet.INTERFACE, 'address': f'{m["address"]}/{prefix}', 'port': str(network['port'])}
        if m['state'] == 'revoked':
            if iface is not None:
                out.append({'type': 'wg-interface', 'host': host, 'params': {**interface, 'state': 'absent'}})
            continue
        if iface is None:
            out.append({'type': 'wg-interface', 'host': host, 'params': {**interface, 'state': 'present'}})
        elif m['state'] == 'active':
            waits = iface.get('next_public_key')
            if host in ready and iface.get('public_key') != m['next_public_key']:
                first.append({'type': 'wg-rotate', 'host': host, 'params': {'iface': sfnet.INTERFACE, 'phase': 'switch', 'pubkey': m['next_public_key']}})
            elif m.get('rotation') == 'asked' and not m.get('next_public_key') and not waits:
                out.append({'type': 'wg-rotate', 'host': host, 'params': {'iface': sfnet.INTERFACE, 'phase': 'prepare'}})
            elif waits and not m.get('rotation') and not m.get('next_public_key'):
                out.append({'type': 'wg-rotate', 'host': host, 'params': {'iface': sfnet.INTERFACE, 'phase': 'cancel'}})
        # a member with no key yet has no peers and is nobody's peer: its peers are written by the plan after the reading that takes its key
        out += [{'type': s['kind'], 'host': host, 'params': {k: v for k, v in s['params'].items() if v != ''}} for s in sfnet.steps(then, host, readings.get(host))]
    return first + out


def plan(conn: Conn, actor: str) -> dict:
    """Save the plan and return {'plan_id', 'tasks'}; plan_id is None when every member is already as it should be."""
    todo = tasks(conn)
    if not todo:
        return {'plan_id': None, 'tasks': 0}
    name = f'StorageForge network {time.strftime("%Y-%m-%d %H:%M:%S")}'
    return {'plan_id': changes.save_plan(conn, {'name': name, 'tasks': todo}, actor), 'tasks': len(todo), 'name': name}


def route(conn: Conn, host: str) -> str | None:
    """The host's address on the StorageForge network, when a connection from this controller can go over it: the controller is an
    active member with its interface up, the host is an active member, and the readings confirm each as the other's peer by key.
    host is a name or the address scans reach it at. None in every other case: the caller uses the normal address. In the hub
    topology two spokes are not peers, so a controller that is a spoke reaches only the hubs this way."""
    network = load(conn)
    name = (network or {}).get('controller')
    me = sfnet.member(network, name) if name else None
    if me is None or me['state'] != 'active':
        return None
    names = {r[0] for r in conn.all('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h', {'h': str(host)})}
    m = next((x for x in network['members'] if x['host'] in names and x['state'] == 'active' and x is not me), None)
    if m is None:
        return None
    confirmed = sfnet.confirm(network, seen(conn, network))
    mine, theirs = confirmed.get(name) or {}, confirmed.get(m['host']) or {}
    if mine.get('key_changed') or theirs.get('key_changed') or m['host'] not in mine.get('confirmed', ()) or name not in theirs.get('confirmed', ()):
        return None
    return m['address']


_UNREACHED: dict = {}              # (address, port) -> when a connection over the network last failed
RETRY = 60


def via(conn: Conn, host: str, port: int | None = 22, probe=None) -> str | None:
    """route(), and the address answers on the SSH port. A connection that fails is not tried again for a minute, so a network that
    is down costs one wait and not one per connection. The SSH host key is checked as it always is: the address is only the path."""
    try:
        address = route(conn, host)
    except Exception:
        return None                # the network is an extra path: nothing about it may stop a scan
    if address is None:
        return None
    at = (address, int(port or 22))
    if time.time() - _UNREACHED.get(at, 0) < RETRY:
        return None
    try:
        (probe or _answers)(*at)
    except OSError:
        _UNREACHED[at] = time.time()
        return None
    _UNREACHED.pop(at, None)
    return address


def _answers(address: str, port: int):
    import socket
    socket.create_connection((address, port), timeout=2).close()


def problems(conn: Conn) -> dict:
    """What cannot wait for someone to open the page: a member whose key changed under it, a next key nobody asked for, and a peer
    nobody asked for."""
    out = {}
    try:
        members = status(conn)['members']
    except Exception:
        return out
    for m in members:
        if m.get('key_changed'):
            out[f'sfnet-key:{m["host"]}'] = ('sfnet-key', m['host'], f'{m["host"]} has a different key on the StorageForge network',
                                           'Nobody planned a rotation: either the interface was made again by hand, or this is another machine. Its peers still hold the key on record', 'crit')
        elif m.get('key_unasked'):
            out[f'sfnet-key:{m["host"]}'] = ('sfnet-key', m['host'], f'{m["host"]} has a second key waiting on the StorageForge network that nobody asked for',
                                           'A rotation was started on the host and not from here. The key is not taken, and the next plan removes it', 'warn')
        elif m.get('unknown'):
            out[f'sfnet-peer:{m["host"]}'] = ('sfnet-peer', m['host'], f'{m["host"]} has a peer on {sfnet.INTERFACE} that nobody asked for',
                                            f'{len(m["unknown"])} key(s) not on record. The next plan revokes them', 'warn')
    return out
