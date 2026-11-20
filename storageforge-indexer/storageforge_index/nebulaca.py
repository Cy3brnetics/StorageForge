"""A Nebula certificate authority (roadmap section 2, "Nebula"): the CA's own certificate and the hosts', built here and signed
wherever the CA key is.

Like sshca.py, this module builds the certificate and never holds the CA's private key. It is given a `sign(data) -> signature`
callable that returns the bare 64-byte Ed25519 signature: with the key enclave that is one `sign` request for the CA's row, so the
CA key signs inside the enclave like any other vault key. A host's own key pair is made on the host (`nebula-cert keygen`) and
only its public half comes here.

The format is Nebula's version 1 certificate, the one `nebula-cert -version 1` writes: a protobuf message of the details and the
signature over the details' bytes, in a PEM block. Nebula verifies by encoding the details again, so the bytes here are the
canonical encoding its own library writes. Version 1 carries one IPv4 address per host. Version 2 (ASN.1, IPv6 too, the default of
nebula-cert since 1.10) is not written here; every Nebula still reads version 1.

What a host certificate from here always has:

    one address     with its network's prefix, inside the CA's networks when the CA names any
    an end          no later than the CA's own. There is no "forever"
    the issuer      the CA certificate's fingerprint, so a host tells which CA signed it

Also here: the configuration file of a host (`config`), as text, with every value checked before it is written.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import time

BANNER = 'NEBULA CERTIFICATE'
PUBLIC_BANNER = 'NEBULA X25519 PUBLIC KEY'
NAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?')
GROUP = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}')
MAX_CA_SECONDS = 10 * 366 * 24 * 3600
MAX_GROUPS, MAX_NETWORKS = 32, 16
BACKDATE = 60                       # seconds: a host whose clock is a little behind still accepts a certificate just made
DIR = '/etc/nebula'
PORT = 4242
ENDPOINT = re.compile(r'(?:[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?){0,8}|\[[0-9A-Fa-f:]{2,39}\]):([0-9]{1,5})')
RULE = re.compile(r'(icmp|tcp|udp|any)(?:/([0-9]{1,5})(?:-([0-9]{1,5}))?)?(?:@([A-Za-z0-9][A-Za-z0-9_.:-]{0,63}))?')
FINGERPRINT = re.compile(r'[0-9a-f]{64}')


class CertificateError(ValueError):
    pass


# ── protobuf, as far as a certificate needs it ──
def _varint(n: int) -> bytes:
    if n < 0:
        n += 1 << 64                 # an int64 below zero is ten bytes, as protobuf writes it
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number: int, wire: int, payload: bytes) -> bytes:
    return _varint(number << 3 | wire) + (_varint(len(payload)) + payload if wire == 2 else payload)


def _read_varint(data: bytes, at: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        if at >= len(data) or shift > 63:
            raise CertificateError('not a Nebula certificate')
        b = data[at]
        at += 1
        n |= (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            return n, at


def _fields(data: bytes) -> list[tuple[int, int, object]]:
    """[(number, wire type, value)]: a varint as an int, a length-delimited field as bytes. Nothing else is in a certificate."""
    out, at = [], 0
    while at < len(data):
        key, at = _read_varint(data, at)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, at = _read_varint(data, at)
        elif wire == 2:
            size, at = _read_varint(data, at)
            if size > len(data) - at:
                raise CertificateError('not a Nebula certificate')
            value, at = data[at:at + size], at + size
        else:
            raise CertificateError('not a Nebula certificate')
        out.append((number, wire, value))
    return out


def _pairs(networks: list) -> bytes:
    """Addresses as Nebula packs them: address then mask, each a 32-bit number, one after another."""
    out = b''
    for n in networks:
        out += _varint(int(n.ip)) + _varint(int(n.netmask))
    return out


def _details(name: str, networks: list, unsafe: list, groups: list[str], not_before: int, not_after: int, public: bytes, is_ca: bool, issuer: bytes) -> bytes:
    """RawNebulaCertificateDetails in field order, a field left out when it is empty, as proto3 writes it."""
    out = _field(1, 2, name.encode()) if name else b''
    if networks:
        out += _field(2, 2, _pairs(networks))
    if unsafe:
        out += _field(3, 2, _pairs(unsafe))
    for g in groups:
        out += _field(4, 2, g.encode())
    if not_before:
        out += _field(5, 0, _varint(not_before))
    if not_after:
        out += _field(6, 0, _varint(not_after))
    if public:
        out += _field(7, 2, public)
    if is_ca:
        out += _field(8, 0, _varint(1))
    if issuer:
        out += _field(9, 2, issuer)
    return out


def _pem(banner: str, body: bytes) -> str:
    b64 = base64.b64encode(body).decode()
    return f'-----BEGIN {banner}-----\n' + '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64)) + f'\n-----END {banner}-----\n'


def _unpem(text: str, banner: str, what: str) -> bytes:
    m = re.search(rf'-----BEGIN {banner}-----\s+([A-Za-z0-9+/=\s]+?)-----END {banner}-----', text if isinstance(text, str) else '')
    if not m:
        raise CertificateError(f'{what} is not a PEM block named {banner}')
    try:
        return base64.b64decode(''.join(m.group(1).split()), validate=True)
    except ValueError:
        raise CertificateError(f'{what} is not a PEM block named {banner}') from None


# ── reading ──
def _unpairs(data: bytes) -> list[str]:
    numbers, at = [], 0
    while at < len(data):
        n, at = _read_varint(data, at)
        numbers.append(n)
    if len(numbers) % 2 or any(n >= 1 << 32 for n in numbers):
        raise CertificateError('not a Nebula certificate')
    out = []
    for ip, mask in zip(numbers[::2], numbers[1::2]):
        try:
            out.append(str(ipaddress.ip_interface((ip, bin(mask).count('1')))))
        except ValueError:
            raise CertificateError('not a Nebula certificate') from None
    return out


def read(pem: str) -> dict:
    """What a version 1 certificate says: {'name', 'networks', 'unsafe_networks', 'groups', 'not_before', 'not_after', 'public_key',
    'is_ca', 'issuer', 'fingerprint'}, with the bytes that were signed and the signature under 'signed' and 'signature'."""
    raw = _unpem(pem, BANNER, 'the certificate')
    details = signature = b''
    for number, wire, value in _fields(raw):
        if (number, wire) == (1, 2):
            details = value
        elif (number, wire) == (2, 2):
            signature = value
    if not details or len(signature) != 64:
        raise CertificateError('not a Nebula version 1 certificate signed with Ed25519')
    out = {'name': '', 'networks': [], 'unsafe_networks': [], 'groups': [], 'not_before': 0, 'not_after': 0, 'public_key': b'', 'is_ca': False, 'issuer': ''}
    for number, wire, value in _fields(details):
        if number == 1 and wire == 2:
            out['name'] = value.decode('utf-8', 'replace')
        elif number == 2 and wire == 2:
            out['networks'] += _unpairs(value)
        elif number == 3 and wire == 2:
            out['unsafe_networks'] += _unpairs(value)
        elif number == 4 and wire == 2:
            out['groups'].append(value.decode('utf-8', 'replace'))
        elif number == 5 and wire == 0:
            out['not_before'] = value
        elif number == 6 and wire == 0:
            out['not_after'] = value
        elif number == 7 and wire == 2:
            out['public_key'] = value
        elif number == 8 and wire == 0:
            out['is_ca'] = bool(value)
        elif number == 9 and wire == 2:
            out['issuer'] = value.hex()
        elif number == 100 and wire == 0 and value:
            raise CertificateError('a certificate on the P256 curve: only Curve25519 is read here')
    return out | {'fingerprint': hashlib.sha256(raw).hexdigest(), 'signed': details, 'signature': signature}


def fingerprint(pem: str) -> str:
    return read(pem)['fingerprint']


def verify(certificate: str, ca: str, now: float | None = None) -> dict:
    """The certificate's details when ca signed it and both are in their time. Raises CertificateError with the reason otherwise."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    cert, authority = read(certificate), read(ca)
    now = int(now if now is not None else time.time())
    if not authority['is_ca'] or len(authority['public_key']) != 32:
        raise CertificateError('the CA certificate is not a CA')
    if cert['issuer'] != authority['fingerprint']:
        raise CertificateError('this CA did not issue the certificate')
    try:
        Ed25519PublicKey.from_public_bytes(authority['public_key']).verify(cert['signature'], cert['signed'])
    except InvalidSignature:
        raise CertificateError('the signature is not the CA\'s') from None
    for what, c in (('the CA certificate', authority), ('the certificate', cert)):
        if now < c['not_before']:
            raise CertificateError(f'{what} is not valid yet')
        if now > c['not_after']:
            raise CertificateError(f'{what} has ended')
    return cert


# ── writing ──
def _networks(values, what: str, hosts: bool = False) -> list:
    out = []
    for v in values or []:
        try:
            n = ipaddress.ip_interface(v)
        except (ValueError, TypeError):
            raise CertificateError(f'{what}: {v!r} is not an address with its prefix, such as 10.9.0.5/24') from None
        if n.version != 4:
            raise CertificateError(f'{what}: a version 1 certificate carries IPv4 only')
        if hosts and (n.ip == n.network.network_address or n.ip == n.network.broadcast_address or n.network.prefixlen > 30):
            raise CertificateError(f'{what}: {v} is not a host address inside a network')
        out.append(n if hosts else ipaddress.ip_interface(str(n.network)))
    if len(out) > MAX_NETWORKS:
        raise CertificateError(f'{what}: at most {MAX_NETWORKS}')
    return out


def _groups(values) -> list[str]:
    groups = list(values or [])
    if len(groups) > MAX_GROUPS or not all(isinstance(g, str) and GROUP.fullmatch(g) for g in groups) or len(set(groups)) != len(groups):
        raise CertificateError(f'groups are names of letters, digits, . _ : and -, each once, at most {MAX_GROUPS}')
    return groups


def _signed(details: bytes, sign) -> str:
    signature = sign(details)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise CertificateError('the CA key returned no Ed25519 signature')
    return _pem(BANNER, _field(1, 2, details) + _field(2, 2, bytes(signature)))


def ed25519_public(line: str) -> bytes:
    """The 32 bytes of an OpenSSH `ssh-ed25519` public key line, which is how the vault names the CA's key."""
    parts = line.split() if isinstance(line, str) else []
    try:
        blob = base64.b64decode(parts[1], validate=True) if len(parts) >= 2 and parts[0] == 'ssh-ed25519' else b''
    except ValueError:
        blob = b''
    if len(blob) != 51 or blob[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise CertificateError('the CA key must be an ed25519 key')
    return blob[19:]


def ca_certificate(name: str, public: bytes, sign, *, seconds: int, networks: list[str] | None = None, groups: list[str] | None = None, now: float | None = None) -> str:
    """The CA's own certificate, signed by itself through sign(data). public is the CA key's 32 bytes. networks, when given, are
    the only ranges a host certificate of this CA may take its address from."""
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise CertificateError('a CA needs a name of letters, digits, . _ and -')
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise CertificateError('the CA key must be an ed25519 key')
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 3600 <= seconds <= MAX_CA_SECONDS:
        raise CertificateError('a CA lasts between an hour and ten years')
    start = int(now if now is not None else time.time())
    return _signed(_details(name, _networks(networks, 'the CA networks'), [], _groups(groups), start - BACKDATE, start + seconds, bytes(public), True, b''), sign)


def public_key(pem: str) -> bytes:
    """The 32 bytes of a host public key as `nebula-cert keygen` writes it."""
    raw = _unpem(pem, PUBLIC_BANNER, 'the host public key')
    if len(raw) != 32:
        raise CertificateError('the host public key is not an X25519 key')
    return raw


def host_certificate(ca: str, sign, *, name: str, address: str, public: bytes, seconds: int | None = None, groups: list[str] | None = None,
                     unsafe_networks: list[str] | None = None, now: float | None = None) -> str:
    """A host certificate under the CA certificate ca, signed through sign(data). address is the host's address with the network's
    prefix (10.9.0.5/24). seconds None: until a second before the CA ends, as nebula-cert does."""
    authority = read(ca)
    if not authority['is_ca']:
        raise CertificateError('the CA certificate is not a CA')
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise CertificateError('a host certificate needs a name of letters, digits, . _ and -')
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise CertificateError('the host public key is not an X25519 key')
    own = _networks([address], 'the address', hosts=True)
    unsafe = _networks(unsafe_networks, 'the networks behind the host')
    groups = _groups(groups)
    allowed = [ipaddress.ip_network(n, strict=False) for n in authority['networks']]
    if allowed and not any(own[0].network.subnet_of(a) for a in allowed):
        raise CertificateError(f'{address} is outside the networks this CA may issue for ({", ".join(map(str, allowed))})')
    behind = [ipaddress.ip_network(n, strict=False) for n in authority['unsafe_networks']]
    if behind and not all(any(u.network.subnet_of(a) for a in behind) for u in unsafe):
        raise CertificateError('a network behind the host is outside those this CA may issue for')
    if authority['groups'] and not set(groups) <= set(authority['groups']):
        raise CertificateError(f'this CA issues only for the groups {", ".join(authority["groups"])}')
    start = int(now if now is not None else time.time())
    if start >= authority['not_after']:
        raise CertificateError('the CA certificate has ended')
    end = authority['not_after'] - 1 if seconds is None else start + seconds
    if seconds is not None and (not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 60):
        raise CertificateError('a host certificate lasts at least a minute')
    if end > authority['not_after']:
        raise CertificateError('a host certificate cannot outlast its CA')
    return _signed(_details(name, own, unsafe, groups, start - BACKDATE, end, bytes(public), False, bytes.fromhex(authority['fingerprint'])), sign)


# ── a host's configuration ──
def lighthouses(text: str) -> dict[str, str]:
    """'10.9.0.1=lh.example.org:4242, 10.9.0.2=198.51.100.7:4242' as {address on the Nebula network: where it is reached}."""
    out = {}
    for item in [x.strip() for x in (text or '').split(',') if x.strip()]:
        inner, sep, outer = item.partition('=')
        try:
            inner = str(ipaddress.IPv4Address(inner.strip()))
        except ValueError:
            raise CertificateError(f'{item!r}: a lighthouse is its Nebula address, =, and where it is reached, such as 10.9.0.1=lh.example.org:4242') from None
        m = ENDPOINT.fullmatch(outer.strip())
        if not sep or not m or not 1 <= int(m.group(m.lastindex)) <= 65535:
            raise CertificateError(f'{item!r}: a lighthouse is reached at a name or address and a port, such as lh.example.org:4242')
        out[inner] = outer.strip()
    if len(out) > 8:
        raise CertificateError('at most 8 lighthouses')
    return out


def inbound(text: str) -> list[dict]:
    """'icmp, tcp/22, tcp/8000-8100@admins' as Nebula firewall rules: protocol, port or range, and the group it is open to."""
    out = []
    for item in [x.strip() for x in (text or '').split(',') if x.strip()]:
        m = RULE.fullmatch(item)
        if not m:
            raise CertificateError(f'{item!r}: an inbound rule is icmp, any, tcp/PORT or udp/PORT, with @group to open it to one group only')
        proto, low, high, group = m.groups()
        if proto in ('tcp', 'udp') and not low:
            raise CertificateError(f'{item!r}: name the port, such as {proto}/22')
        if proto == 'icmp' and low:
            raise CertificateError(f'{item!r}: icmp has no port')
        if low and not (1 <= int(low) <= 65535 and (high is None or int(low) < int(high) <= 65535)):
            raise CertificateError(f'{item!r}: ports are 1 to 65535')
        out.append({'proto': proto, 'port': 'any' if not low else f'{low}-{high}' if high else int(low), **({'group': group} if group else {'host': 'any'})})
    if len(out) > 32:
        raise CertificateError('at most 32 inbound rules')
    return out


def config(*, lighthouse: bool, lighthouses_text: str, port: int | None = None, inbound_text: str = 'icmp', blocklist: list[str] | None = None, directory: str = DIR) -> str:
    """config.yml for one host. A lighthouse listens on a port others are told (4242 unless given) and names no lighthouse of its
    own; any other host needs at least one. blocklist: fingerprints of certificates this CA issued and no longer accepts."""
    known = lighthouses(lighthouses_text)
    rules = inbound(inbound_text)
    if not lighthouse and not known:
        raise CertificateError('a host that is not a lighthouse needs at least one lighthouse to find the others')
    port = (PORT if lighthouse else 0) if port in (None, '') else int(port)
    if not 0 <= port <= 65535 or (lighthouse and port == 0):
        raise CertificateError('a lighthouse listens on a port others are told, 1 to 65535')
    blocked = list(blocklist or [])
    if not all(isinstance(f, str) and FINGERPRINT.fullmatch(f) for f in blocked):
        raise CertificateError('a blocklist is certificate fingerprints')
    lines = ['# Written by StorageForge (the nebula plan step). A change made here is overwritten by the next run of that step.',
             'pki:', f'  ca: {directory}/ca.crt', f'  cert: {directory}/host.crt', f'  key: {directory}/host.key']
    if blocked:
        lines += ['  blocklist:'] + [f'    - {f}' for f in sorted(set(blocked))]
    lines += ['static_host_map:' if known else 'static_host_map: {}'] + [f'  "{inner}": ["{outer}"]' for inner, outer in known.items()]
    lines += ['lighthouse:', f'  am_lighthouse: {"true" if lighthouse else "false"}', '  interval: 60']
    # a lighthouse names none: it is one. The others it may know of stay in the map above, so two lighthouses reach each other
    lines += ['  hosts: []'] if lighthouse or not known else ['  hosts:'] + [f'    - "{inner}"' for inner in known]
    lines += ['listen:', '  host: 0.0.0.0', f'  port: {port}', 'punchy:', '  punch: true', 'relay:', '  am_relay: false', '  use_relays: true',
              'tun:', '  dev: nebula1', '  mtu: 1300', 'logging:', '  level: info', '  format: text',
              'firewall:', '  outbound:', '    - port: any', '      proto: any', '      host: any']
    lines += ['  inbound:' if rules else '  inbound: []']
    for r in rules:
        lines += [f'    - port: {r["port"]}', f'      proto: {r["proto"]}', f'      group: "{r["group"]}"' if 'group' in r else '      host: any']
    return '\n'.join(lines) + '\n'
