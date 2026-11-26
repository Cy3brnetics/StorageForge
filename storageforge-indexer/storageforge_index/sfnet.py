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

    {'range': '10.203.0.0/20', 'port': 51903, 'topology': 'mesh' | 'hub', 'controller': None | the member that is the controller,
     'members': [{'host', 'address', 'public_key', 'next_public_key', 'endpoint', 'hub', 'state': 'pending' | 'active' | 'revoked',
                  'rotation': None | 'asked'}]}

A key changes in one way only: a person asks for a rotation (ask_rotation), the host makes a second pair, a reading shows its public
half (rotate), every peer is told to know both, the host switches (rotated), and the old key comes off every peer. A new key that
nobody asked for is never taken: confirm() reports it.

A peer is trusted for its own address and nothing more (`/32`), so one host that is taken over cannot answer for another's address.
In the hub topology a hub is trusted for the whole range, because traffic between two spokes goes through it.
"""
from __future__ import annotations

import ipaddress
import re

INTERFACE = 'sf0'
PORT = 51903
KEEPALIVE = 25                       # seconds, towards a peer that has to be reached through its own NAT
DIRECTORY_NS = 'storageforge-sfnet-directory'
WGKEY = re.compile(r'[A-Za-z0-9+/]{43}=')
SHARED = ipaddress.ip_network('100.64.0.0/10')          # Tailscale's and NetBird's: never ours
# Tried in order. Ranges nobody's router hands out by default, sixteen /24s each: room for about four thousand hosts.
CANDIDATES = ('10.203.0.0/20', '10.87.64.0/20', '10.151.112.0/20', '172.29.160.0/20', '172.22.208.0/20', '192.168.203.0/24')
ULA_CANDIDATES = ('fd53:466e:7400::/64', 'fd53:466e:7401::/64', 'fd53:466e:7402::/64')


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


def pick_v6_range(in_use=()) -> str:
    """Pick the first candidate IPv6 ULA /64 that does not overlap any IPv6 network in in_use."""
    taken = []
    for value in in_use:
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 6 and net.prefixlen > 0:
            taken.append(net)
    for candidate in ULA_CANDIDATES:
        net = ipaddress.ip_network(candidate)
        if not any(net.overlaps(t) for t in taken):
            return candidate
    raise NetworkError('every IPv6 ULA range StorageForge would pick is in use at this site: give it one')


def new(in_use=(), range_: str | None = None, topology: str = 'mesh', range6: str | bool | None = None) -> dict:
    if topology not in ('mesh', 'hub'):
        raise NetworkError('topology is mesh or hub')
    if range_ is not None:
        try:
            net = ipaddress.ip_network(range_)
        except ValueError:
            raise NetworkError(f'{range_!r} is not a network') from None
        if net.version != 4 or not net.is_private or net.overlaps(SHARED) or not 16 <= net.prefixlen <= 28:
            raise NetworkError('the range is a private IPv4 network between /16 and /28, outside 100.64.0.0/10')
    out = {'range': range_ or pick_range(in_use), 'port': PORT, 'topology': topology, 'controller': None, 'members': []}
    if range6 is True:
        out['range6'] = pick_v6_range(in_use)
    elif isinstance(range6, str) and range6:
        try:
            net6 = ipaddress.ip_network(range6)
        except ValueError:
            raise NetworkError(f'{range6!r} is not an IPv6 network') from None
        if net6.version != 6 or not net6.is_private or not 48 <= net6.prefixlen <= 64:
            raise NetworkError('the IPv6 range is a private ULA network between /48 and /64')
        out['range6'] = str(net6)
    return out


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
    m = {'host': host, 'address': address, 'public_key': None, 'next_public_key': None, 'endpoint': endpoint, 'hub': bool(hub), 'state': 'pending', 'rotation': None}
    if network.get('range6'):
        given6 = {x.get('address6') for x in network['members'] if x.get('address6')}
        net6 = ipaddress.ip_network(network['range6'])
        idx = int(ipaddress.ip_address(address)) - int(ipaddress.ip_network(network['range']).network_address)
        cand6 = str(net6.network_address + max(1, idx))
        if cand6 in given6:
            cand6 = next(str(net6.network_address + i) for i in range(1, 65536) if str(net6.network_address + i) not in given6)
        m['address6'] = cand6
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


def ask_rotation(network: dict, host: str) -> dict:
    """A person wants this member's key changed. Nothing is trusted yet: the host is to make a second pair, and rotate() takes its
    public half from a reading. Without this mark a new key is a finding, never a rotation."""
    m = member(network, host)
    if m is None or m['state'] != 'active':
        raise NetworkError(f'{host} is not an active member')
    if m.get('rotation') or m.get('next_public_key'):
        raise NetworkError(f'{host} has a rotation under way')
    m['rotation'] = 'asked'
    return m


def cancel_rotation(network: dict, host: str) -> dict:
    """Before the host has switched: the next key is forgotten, and steps() takes it off every peer."""
    m = member(network, host)
    if m is None or not (m.get('rotation') or m.get('next_public_key')):
        raise NetworkError(f'{host} has no rotation under way')
    m['rotation'], m['next_public_key'] = None, None
    return m


def rotate(network: dict, host: str, new_public_key: str) -> dict:
    """First half of a rotation: the host has made a new pair, and every peer is to accept both keys until it switches."""
    m = member(network, host)
    if m is None or m['state'] != 'active':
        raise NetworkError(f'{host} is not an active member')
    if m.get('next_public_key'):
        raise NetworkError(f'{host} has a rotation under way')
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
    m['public_key'], m['next_public_key'], m['rotation'] = m['next_public_key'], None, None
    return m


def waiting_for(network: dict, host: str, seen: dict) -> list[str]:
    """The members that do not hold this host's next key yet, as the readings show. While there is one, the host must not switch:
    that member would lose it. seen is {host: that host's WireGuard interfaces}."""
    m = member(network, host)
    key = (m or {}).get('next_public_key')
    if not key:
        return []
    out = []
    for other in network['members']:
        if other is m or other['state'] != 'active' or not any(p['public_key'] == key for p in desired_peers(network, other['host'])):
            continue
        iface = _seen(seen.get(other['host']))
        if iface is None or not any(isinstance(p, dict) and p.get('public_key') == key for p in iface.get('peers', [])):
            out.append(other['host'])
    return out


def after_switch(network: dict, seen: dict) -> tuple[dict, list[str]]:
    """The network as it will be once every member whose peers all hold its next key has switched, and who those members are.
    The peers of a plan are worked out against this, so the address moves to the new key in the same plan as the switch."""
    import copy
    then, ready = copy.deepcopy(network), []
    for m in network['members']:
        if m['state'] == 'active' and m.get('next_public_key') and not waiting_for(network, m['host'], seen):
            rotated(then, m['host'])
            ready.append(m['host'])
    return then, ready


def revoke(network: dict, host: str) -> dict:
    """The host is off the network: steps() takes its key off every other member. Its address is not given out again."""
    m = member(network, host)
    if m is None:
        raise NetworkError(f'{host} is not on the network')
    m['state'], m['next_public_key'], m['rotation'] = 'revoked', None, None
    return m


def format_endpoint(where: str | None, port: int) -> str | None:
    """Format host/IPv4/IPv6 endpoint as wg expects (`host:port` or `[ipv6]:port`)."""
    if not where:
        return None
    clean = where.strip()
    if clean.startswith('[') and clean.endswith(']'):
        clean = clean[1:-1]
    try:
        if ipaddress.ip_address(clean).version == 6:
            return f'[{clean}]:{int(port)}'
    except ValueError:
        pass
    return f'{clean}:{int(port)}'


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
        if network.get('range6') and m.get('address6'):
            allowed.append(network['range6'] if whole else f'{m["address6"]}/128')
        endpoint = format_endpoint(m['endpoint'], network['port'])
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


def directory_payload(network: dict, *, seq: int = 1, issued: int | None = None, ttl: int = 86400) -> dict:
    """Signed-head directory payload so roaming peers can verify current controller/hub/peer endpoints from any mirror."""
    import time
    now = int(issued if issued is not None else time.time())
    port = int(network['port'])
    peers = []
    for m in network.get('members') or []:
        if m.get('state') != 'active' or not m.get('public_key'):
            continue
        peers.append({
            'host': m['host'],
            'address': m['address'],
            'public_key': m['public_key'],
            'hub': bool(m.get('hub')),
            'endpoint': format_endpoint(m.get('endpoint'), port),
        })
    ctrl = network.get('controller')
    head = next((p for p in peers if p['host'] == ctrl and p.get('endpoint')), None)
    if head is None:
        head = next((p for p in peers if p['hub'] and p.get('endpoint')), None)
    if head is None:
        head = next((p for p in peers if p['host'] == ctrl or p['hub']), None)
    return {
        'format': 1,
        'network': INTERFACE,
        'range': network['range'],
        'port': port,
        'topology': network['topology'],
        'seq': int(seq),
        'issued': now,
        'expires': now + max(60, int(ttl)),
        'head': head,
        'peers': peers,
    }


def verify_directory(text: str, signature: str, signers: list[str], *, min_seq: int = 0, now: float | None = None) -> dict:
    """Verify an sshsig-signed management directory against pinned signer public keys, rejecting expired or stale seqs."""
    import json
    import subprocess
    import tempfile
    import time
    from pathlib import Path
    if not signers:
        raise NetworkError('no trusted directory signer keys supplied')
    try:
        doc = json.loads(text)
    except ValueError:
        raise NetworkError('directory payload is not valid JSON') from None
    if not isinstance(doc, dict) or doc.get('format') != 1 or doc.get('network') != INTERFACE:
        raise NetworkError('not a StorageForge management directory')
    if not isinstance(doc.get('seq'), int) or doc['seq'] < min_seq:
        raise NetworkError('stale directory sequence number')
    at = float(now if now is not None else time.time())
    if not isinstance(doc.get('expires'), (int, float)) or doc['expires'] <= at:
        raise NetworkError('directory signature has expired')
    for entry in ([doc['head']] if doc.get('head') else []) + list(doc.get('peers') or []):
        if not isinstance(entry, dict) or not WGKEY.fullmatch(str(entry.get('public_key') or '')):
            raise NetworkError('directory entry carries an invalid WireGuard public key')
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        allowed = tmp / 'allowed'
        sig_path = tmp / 'dir.sig'
        allowed.write_text(''.join(f'sfnet {k.strip()}\n' for k in signers if str(k).strip()))
        sig_path.write_text(signature or '')
        p = subprocess.run(
            ['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'sfnet', '-n', DIRECTORY_NS, '-s', str(sig_path)],
            input=text.encode(), capture_output=True, timeout=10,
        )
        if p.returncode != 0:
            raise NetworkError('directory signature verification failed')
    return doc


def mirror_pull_script(mirrors: list[str], signers: list[str], iface: str = INTERFACE) -> str:
    """Render an outbound roaming peer shell script that fetches /api/sfnet/directory from mirrors,
    verifies the sshsig signature and monotonic seq, and updates WireGuard peer endpoints."""
    import shlex
    clean_mirrors = [str(m).strip() for m in mirrors if str(m).strip()]
    clean_signers = [str(k).strip() for k in signers if str(k).strip()]
    if not clean_mirrors or not clean_signers:
        raise NetworkError('at least one mirror URL and one directory signer key are required')
    signer_lines = ''.join(f'sfnet {k}\n' for k in clean_signers)
    mirror_args = ' '.join(shlex.quote(u) for u in clean_mirrors)
    return (
        '#!/usr/bin/env bash\n'
        'set -euo pipefail\n'
        f'IFACE={shlex.quote(iface)}\n'
        'STATE=/var/lib/storageforge-sfnet\n'
        'mkdir -p "$STATE"\n'
        'TMP=$(mktemp -d)\n'
        'trap "rm -rf $TMP" EXIT\n'
        'cat > "$TMP/allowed" <<\\ALLOWED\n'
        f'{signer_lines}'
        'ALLOWED\n'
        f'for url in {mirror_args}; do\n'
        '  if curl -fsSL --max-time 10 "$url" > "$TMP/resp.json" 2>/dev/null; then\n'
        '    if python3 - "$TMP" "$STATE" "$IFACE" <<\\PY\n'
        'import json, pathlib, subprocess, sys, time\n'
        'tmp, state, iface = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]\n'
        'resp = json.loads((tmp / "resp.json").read_text())\n'
        '# the exact text that was signed: re-serialising the parsed directory would give other bytes\n'
        'payload = resp.get("directory_json") or ""\n'
        'sig = resp.get("signature") or ""\n'
        '(tmp / "dir.sig").write_text(sig)\n'
        'doc = json.loads(payload)\n'
        'seq_file = state / "seq"\n'
        'min_seq = int(seq_file.read_text().strip()) if seq_file.exists() else 0\n'
        'if doc.get("seq", 0) < min_seq or doc.get("expires", 0) <= time.time():\n'
        '    sys.exit(1)\n'
        f'subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(tmp / "allowed"), "-I", "sfnet", "-n", {DIRECTORY_NS!r}, "-s", str(tmp / "dir.sig")], input=payload.encode(), check=True)\n'
        'for p in doc.get("peers") or []:\n'
        '    if p.get("public_key") and p.get("endpoint"):\n'
        '        subprocess.run(["wg", "set", iface, "peer", p["public_key"], "endpoint", p["endpoint"]], check=False)\n'
        'seq_file.write_text(str(doc["seq"]))\n'
        'PY\n'
        '    then exit 0; fi\n'
        '  fi\n'
        'done\n'
        'exit 1\n'
    )
