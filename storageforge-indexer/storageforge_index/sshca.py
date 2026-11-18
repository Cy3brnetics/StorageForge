"""An SSH certificate authority (roadmap section 2, "SSH CA"): short-lived certificates, built here and signed wherever the CA key is.

This module builds the certificate and never holds the CA's private key. `issue()` is given a `sign(data) -> signature` callable:
with the key enclave that is one `sign` request for the CA's row, so the CA key signs inside the enclave like any other vault key
(the signature it returns is already in the form a certificate carries). The format is OpenSSH's PROTOCOL.certkeys.

What a certificate from here always has, because each is a way a certificate goes wrong when it is missing:

    principals      at least one. A certificate with none is valid for every user on every host that trusts the CA.
    an end          at most MAX_USER_SECONDS or MAX_HOST_SECONDS from now. There is no "forever".
    a serial        so one certificate can be named in a revocation list.
    a key id        who it was issued to and why; sshd writes it to its log at every login.

A user certificate gets no extensions unless asked: no port forwarding, no agent forwarding, no X11. `permit-pty` is the only one
a console needs.
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re
import struct
import time

USER, HOST = 1, 2
MAX_USER_SECONDS = 24 * 3600
MAX_HOST_SECONDS = 400 * 24 * 3600
BACKDATE = 60                       # seconds: a host whose clock is a little behind still accepts a certificate just made
EXTENSIONS = ('permit-pty', 'permit-user-rc', 'permit-port-forwarding', 'permit-agent-forwarding', 'permit-X11-forwarding', 'no-touch-required')
KEY_TYPES = ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521')
PRINCIPAL = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}')
KEY_ID = re.compile(r'[\x20-\x7e]{1,200}')


class CertificateError(ValueError):
    pass


def _s(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def _first_string(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) < 4:
        raise CertificateError('not a public key')
    n = struct.unpack('>I', blob[:4])[0]
    if n > len(blob) - 4:
        raise CertificateError('not a public key')
    return blob[4:4 + n], blob[4 + n:]


def _public(line: str, what: str) -> tuple[str, bytes]:
    """(type, wire blob) of an OpenSSH public key line."""
    parts = line.split() if isinstance(line, str) else []
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise CertificateError(f'{what} is not an ed25519, RSA or ECDSA public key')
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise CertificateError(f'{what} is not a public key') from None
    kind, _ = _first_string(blob)
    if kind.decode('ascii', 'replace') != parts[0]:
        raise CertificateError(f'{what} says one key type and holds another')
    return parts[0], blob


def issue(subject: str, ca: str, sign, *, key_id: str, principals: list[str], serial: int, seconds: int, kind: int = USER,
          extensions: tuple[str, ...] = (), force_command: str | None = None, source_addresses: list[str] | None = None, now: float | None = None) -> str:
    """The certificate line (`<type>-cert-v01@openssh.com <base64> <key id>`) for subject, signed by ca through sign(data).
    subject and ca are OpenSSH public key lines. Raises CertificateError for anything that would make a certificate wider than asked."""
    if kind not in (USER, HOST):
        raise CertificateError('a certificate is for a user or for a host')
    subject_type, subject_blob = _public(subject, 'the key to certify')
    _, ca_blob = _public(ca, 'the CA')
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise CertificateError('a certificate needs a key id: who it is for, in plain characters')
    if not principals or not all(isinstance(p, str) and PRINCIPAL.fullmatch(p) for p in principals) or len(principals) > 64:
        raise CertificateError('a certificate names its principals: without any it would be valid for every user')
    limit = MAX_USER_SECONDS if kind == USER else MAX_HOST_SECONDS
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 60 <= seconds <= limit:
        raise CertificateError(f'a {"user" if kind == USER else "host"} certificate lasts between a minute and {limit // 3600} hours')
    if not isinstance(serial, int) or isinstance(serial, bool) or not 1 <= serial < 1 << 63:
        raise CertificateError('a certificate needs a serial number of its own')
    if kind == HOST and (extensions or force_command or source_addresses):
        raise CertificateError('a host certificate takes no options')
    if any(e not in EXTENSIONS for e in extensions):
        raise CertificateError(f'extensions are among: {", ".join(EXTENSIONS)}')
    critical = {}
    if force_command is not None:
        if not force_command or '\n' in force_command or '\0' in force_command or len(force_command) > 1024:
            raise CertificateError('the forced command is one line')
        critical['force-command'] = force_command
    if source_addresses:
        try:
            critical['source-address'] = ','.join(str(ipaddress.ip_network(a, strict=False)) for a in source_addresses)
        except (ValueError, TypeError):
            raise CertificateError('source addresses are addresses or networks') from None
    start = int(now if now is not None else time.time())
    _, key_fields = _first_string(subject_blob)
    cert_type = f'{subject_type}-cert-v01@openssh.com'
    body = (_s(cert_type.encode()) + _s(os.urandom(32)) + key_fields + struct.pack('>QI', serial, kind) + _s(key_id.encode())
            + _s(b''.join(_s(p.encode()) for p in principals)) + struct.pack('>QQ', start - BACKDATE, start + seconds)
            + _s(b''.join(_s(k.encode()) + _s(_s(v.encode())) for k, v in sorted(critical.items())))          # options, in order of name, as the format demands
            + _s(b''.join(_s(e.encode()) + _s(b'') for e in sorted(set(extensions))))
            + _s(b'') + _s(ca_blob))
    signature = sign(body)
    algorithm, _ = _first_string(signature) if isinstance(signature, (bytes, bytearray)) else (b'', b'')
    if algorithm == b'ssh-rsa':
        raise CertificateError('the CA signed with SHA-1, which no current sshd accepts')          # an RSA CA signs rsa-sha2-512
    if not algorithm:
        raise CertificateError('the CA returned no signature')
    return f'{cert_type} {base64.b64encode(body + _s(bytes(signature))).decode()} {key_id.replace(" ", "_")}'


def trusted_user_ca_line(ca: str) -> str:
    """What goes in the file sshd's TrustedUserCAKeys names: the CA's public key and nothing after it."""
    kind, blob = _public(ca, 'the CA')
    return f'{kind} {base64.b64encode(blob).decode()}'


def known_hosts_line(ca: str, pattern: str) -> str:
    """A known_hosts line that trusts host certificates from this CA for the hosts the pattern names."""
    if not isinstance(pattern, str) or not re.fullmatch(r'[A-Za-z0-9*?.,_\[\]:-]{1,255}', pattern):
        raise CertificateError('the host pattern is names, addresses and wildcards')
    return f'@cert-authority {pattern} {trusted_user_ca_line(ca)}'
