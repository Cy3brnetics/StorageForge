"""Signed scan payloads: every byte a host sends a scan is signed on the host, and checked here before any of it is used.

    host                                               this machine
    ────                                               ────────────
    the scan's command | tee ──► stdout ──ssh──►       hashes what arrives (sha256)
          └─► sha256 of exactly those bytes
    "storageforge-scan-v1\\n<nonce>\\n<sha256>\\n"
    signed with ssh-keygen -Y sign -n storageforge-scan  ──stderr, last line──►  SFSIG1 <sha256> <signature>
                                                       the digests agree, and the signature verifies with a key pinned
                                                       for this host: the data is used. Anything else: it is not.

The nonce is new for every command, so an old signed payload cannot be played again, and one stream's payload cannot stand
in for another's. The key that signs is, in order: the scan signing key the read-only scan access setup made
(/usr/local/lib/storageforge/scan-sign, readable only by the storageforge-scan group, its public half pinned when StorageForge
ran that setup over a connection that accepted only the confirmed host key), or the host's own SSH host key when the scan logs
in as root (already pinned in known_hosts, since the scan's connection proved it). The namespace keeps these signatures from
meaning anything to SSH, git or anything else that verifies SSHSIG.

What it does not do: a host whose scan account is taken over can sign whatever that account sends, because the account is what
reads the host. It proves the payload came from the host the key belongs to, unchanged, and for this request. docs/security.md.

A host that cannot sign (no key it can read, OpenSSH older than 8.0) says why, and its payloads count as unsigned:
used, and shown as unsigned, unless the site requires signed scans (setting scans.require_signed), when they are refused like a bad one.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import secrets
import struct
import subprocess
import tempfile
import time

from .remote import RemoteError

NAMESPACE = 'storageforge-scan'
VERSION = 'storageforge-scan-v1'
SIGNING_KEY = '/usr/local/lib/storageforge/scan-sign'          # made by access.SETUP, beside the capability tools
KEY_PATHS = (SIGNING_KEY, '/etc/ssh/ssh_host_ed25519_key', '/etc/ssh/ssh_host_ecdsa_key', '/etc/ssh/ssh_host_rsa_key')      # tried in order
REQUIRE = 'scans.require_signed'
MARK_SIGNED, MARK_UNSIGNED = 'SFSIG1 ', 'SFSIG0 '

# Run on the host around a scan command. %(cmd)s is the command, %(nonce)s a hex nonce. POSIX sh: the scan may land in dash,
# busybox or bash. The command keeps its own stdin (the checksum pass and the git survey read theirs) and its exit status.
WRAP = r"""sf_n=%(nonce)s
sf_d=$(mktemp -d /tmp/sfsig.XXXXXX 2>/dev/null) && mkfifo "$sf_d/p" 2>/dev/null || { [ -n "$sf_d" ] && rm -rf "$sf_d"; sf_d=; }
if [ -z "$sf_d" ]; then
  ( %(cmd)s
  )
  sf_rc=$?
  echo "SFSIG0 there is no temporary folder to sign in" >&2
  exit $sf_rc
fi
sf_sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
sf_sum < "$sf_d/p" > "$sf_d/h" &
{ ( %(cmd)s
  ); echo $? > "$sf_d/rc"; } | tee "$sf_d/p"
wait
sf_rc=$(cat "$sf_d/rc" 2>/dev/null || echo 1)
sf_h=$(cut -d' ' -f1 "$sf_d/h")
printf '%(version)s\n%%s\n%%s\n' "$sf_n" "$sf_h" > "$sf_d/m"
sf_k=
for f in %(keys)s; do
  if [ -r "$f" ]; then sf_k=$f; break; fi
done
if [ -z "$sf_k" ]; then
  echo "SFSIG0 this account can read no signing key: run the read-only scan access setup again" >&2
elif ssh-keygen -Y sign -n %(namespace)s -f "$sf_k" "$sf_d/m" >/dev/null 2>&1 && [ -s "$sf_d/m.sig" ]; then
  printf 'SFSIG1 %%s %%s\n' "$sf_h" "$(base64 < "$sf_d/m.sig" | tr -d '\n')" >&2
else
  echo "SFSIG0 ssh-keygen could not sign here: it needs OpenSSH 8.0 or later" >&2
fi
rm -rf "$sf_d"
exit "$sf_rc"
"""


class BadSignature(RemoteError):
    """A payload that must not be used: its signature is missing where it is required, does not verify, or covers other bytes."""


def wrap(script: str, nonce: str, keys=KEY_PATHS) -> str:
    import shlex
    return WRAP % {'cmd': script, 'nonce': nonce, 'version': VERSION, 'keys': ' '.join(shlex.quote(k) for k in keys), 'namespace': NAMESPACE}


def message(nonce: str, digest: str) -> bytes:
    return f'{VERSION}\n{nonce}\n{digest}\n'.encode()


def _ssh_string(buf: bytes, at: int) -> tuple[bytes, int]:
    """A length-prefixed string. ValueError, never struct.error, when the buffer is too short for it: a host chooses these bytes."""
    try:
        (n,) = struct.unpack('>I', buf[at:at + 4])
    except struct.error:
        raise ValueError('the signature is cut short') from None
    if len(buf) < at + 4 + n:
        raise ValueError('the signature is cut short')
    return buf[at + 4:at + 4 + n], at + 4 + n


def signer_key(armored: str) -> str:
    """The public key inside an SSHSIG signature, as an authorized_keys-style 'type base64' line. ValueError if it is not one."""
    body = ''.join(line for line in armored.splitlines() if line and not line.startswith('-----'))
    blob = base64.b64decode(body, validate=True)
    if not blob.startswith(b'SSHSIG'):
        raise ValueError('not an SSH signature')
    key, _ = _ssh_string(blob, 10)               # magic (6) and version (4), then the public key
    kind, _ = _ssh_string(key, 0)
    return f'{kind.decode()} {base64.b64encode(key).decode()}'


def fingerprint(key_line: str) -> str:
    blob = base64.b64decode(key_line.split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def known_host_lines(host: str, port: int, known_hosts: str | None) -> list[str]:
    """The public keys pinned for host:port in a known_hosts file, as 'type base64'."""
    known_hosts = known_hosts or os.path.expanduser('~/.ssh/known_hosts')
    if not os.path.exists(known_hosts):
        return []
    name = host if port == 22 else f'[{host}]:{port}'
    p = subprocess.run(['ssh-keygen', '-F', name, '-f', known_hosts], capture_output=True, text=True, timeout=15)
    out = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith('#'):
            out.append(f'{parts[1]} {parts[2]}')
    return out


def _verify(msg: bytes, armored: str, keys: list[str]) -> bool:
    with tempfile.TemporaryDirectory(prefix='sfsig-') as d:
        signers, sig = os.path.join(d, 'signers'), os.path.join(d, 'm.sig')
        with open(signers, 'w') as f:
            f.write(''.join(f'storageforge namespaces="{NAMESPACE}" {k}\n' for k in keys))
        with open(sig, 'w') as f:
            f.write(armored)
        p = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', signers, '-I', 'storageforge', '-n', NAMESPACE, '-s', sig],
                           input=msg, capture_output=True, timeout=15)
        return p.returncode == 0


def _valid_alone(msg: bytes, armored: str) -> bool:
    """The signature is sound for this message, whoever made it (before a key is pinned for the first time)."""
    with tempfile.TemporaryDirectory(prefix='sfsig-') as d:
        sig = os.path.join(d, 'm.sig')
        with open(sig, 'w') as f:
            f.write(armored)
        p = subprocess.run(['ssh-keygen', '-Y', 'check-novalidate', '-n', NAMESPACE, '-s', sig], input=msg, capture_output=True, timeout=15)
        return p.returncode == 0


class Signing:
    """What one scan of one host needs to check its payloads, and what it found. Created by whoever opens the Transport.

    pinned: the scan signing key already pinned for this host ('type base64'), or None. host_keys: the SSH host keys pinned in
    known_hosts. require: refuse unsigned payloads. pin(key_line): called once, when a host with no pinned key signs for the first
    time with a key that is not one of its host keys (trust on first use, as for the host key itself)."""

    def __init__(self, host_keys, pinned: str | None = None, require: bool = False, pin=None, key_paths=KEY_PATHS):
        # host_keys may be a function: on a host's first scan, known_hosts learns its key only once the connection is made
        self._host_keys, self.pinned, self.require, self._pin, self.key_paths = host_keys, pinned, require, pin, tuple(key_paths)
        self.signed, self.unsigned, self.keys, self.reasons = 0, 0, set(), []

    def nonce(self) -> str:
        return secrets.token_hex(16)

    def wrap(self, script: str, nonce: str) -> str:
        return wrap(script, nonce, self.key_paths)

    def check(self, nonce: str, digest: str, stderr_tail, what: str = 'a scan command') -> str:
        """Raises BadSignature when the payload must not be used; otherwise returns 'signed' or 'unsigned'."""
        mark = next((line for line in reversed(list(stderr_tail)) if line.startswith((MARK_SIGNED, MARK_UNSIGNED))), None)
        if mark is None or mark.startswith(MARK_UNSIGNED):
            reason = mark[len(MARK_UNSIGNED):] if mark else 'no signature came back with it'
            if self.require:
                raise BadSignature(f'{what}: not signed ({reason}), and this site requires signed scans. Nothing it sent was used')
            self.unsigned += 1
            if reason not in self.reasons:
                self.reasons.append(reason)
            return 'unsigned'
        try:
            claimed, b64 = mark[len(MARK_SIGNED):].split(' ', 1)
            armored = base64.b64decode(b64, validate=True).decode()
            key = signer_key(armored)
        except (ValueError, UnicodeDecodeError) as exc:
            raise BadSignature(f'{what}: the signature that came back cannot be read ({exc}). Nothing it sent was used') from None
        if not re.fullmatch(r'[0-9a-f]{64}', claimed) or claimed != digest:
            raise BadSignature(f'{what}: the host signed other bytes than arrived, so they were changed on the way. Nothing it sent was used')
        msg = message(nonce, digest)
        host_keys = list(self._host_keys() if callable(self._host_keys) else self._host_keys)
        allowed = host_keys + ([self.pinned] if self.pinned else [])
        if key in allowed and _verify(msg, armored, [key]):
            pass
        elif not self.pinned and key not in host_keys and _valid_alone(msg, armored):
            self.pinned = key                      # the first signature from this host's scan key: pinned, and said so
            if self._pin:
                self._pin(key)
        else:
            raise BadSignature(f'{what}: signed with a key that is not pinned for this host ({fingerprint(key)}), or the signature does not '
                               'verify. If the host was rebuilt, forget its scan signing key and scan again. Nothing it sent was used')
        self.signed += 1
        self.keys.add(fingerprint(key))
        return 'signed'

    def summary(self) -> dict:
        state = 'signed' if self.signed and not self.unsigned else 'partly signed' if self.signed else 'unsigned'
        return {'state': state, 'signed': self.signed, 'unsigned': self.unsigned, 'keys': sorted(self.keys), 'reasons': self.reasons[:3]}


class HashingReader(io.RawIOBase):
    """Passes a raw stream through unchanged and hashes every byte, so a stream's payload can be checked once it ends."""

    def __init__(self, raw):
        super().__init__()
        self.raw, self.h = raw, hashlib.sha256()

    def readable(self):
        return True

    def fileno(self):
        return self.raw.fileno()

    def readinto(self, buf):
        n = self.raw.readinto(buf)
        if n:
            self.h.update(memoryview(buf)[:n])
        return n

    def digest(self) -> str:
        return self.h.hexdigest()


# ── what is pinned, and what the last scan found (migration 041) ──────────────────────────────────────────────

def address(host: str, port: int) -> str:
    return host if int(port or 22) == 22 else f'{host}:{int(port)}'


def pinned_key(conn, host: str, port: int) -> str | None:
    return conn.scalar('SELECT public_key FROM scan_signers WHERE address = :a', {'a': address(host, port)})


def pin(conn, host: str, port: int, key_line: str, how: str):
    conn.execute('DELETE FROM scan_signers WHERE address = :a', {'a': address(host, port)})
    conn.execute('INSERT INTO scan_signers (address, public_key, fingerprint, pinned_at, how) VALUES (:a, :k, :f, :t, :h)',
                 {'a': address(host, port), 'k': key_line, 'f': fingerprint(key_line), 't': int(time.time()), 'h': how[:80]})


def forget(conn, host: str, port: int = 22) -> bool:
    return bool(conn.execute('DELETE FROM scan_signers WHERE address = :a', {'a': address(host, port)}).rowcount)


def parse_switch(value) -> bool:
    """The signing switch from a request: a JSON boolean, or text that plainly says on or off. Anything else is ValueError (a 400), never 'on'."""
    if isinstance(value, bool):
        return value
    text = value.strip().lower() if isinstance(value, str) else None
    if text in ('true', 'on', 'yes', '1'):
        return True
    if text in ('false', 'off', 'no', '0'):
        return False
    raise ValueError('require must be true or false')


def required(conn) -> bool:
    from .alerts import get_setting
    return bool(get_setting(conn, REQUIRE))


def for_scan(conn, host: str, port: int, known_hosts: str | None) -> Signing:
    """The Signing a scan of host:port opens its Transport with."""
    return Signing(lambda: known_host_lines(host, port, known_hosts), pinned_key(conn, host, port), required(conn),
                   pin=lambda key: pin(conn, host, port, key, 'first signed scan'))


def record(conn, host_name: str, s: Signing):
    sm = s.summary()
    conn.execute('DELETE FROM scan_signatures WHERE host = :h', {'h': host_name})
    conn.execute('INSERT INTO scan_signatures (host, state, signed, unsigned, keys, reason, checked_at) VALUES (:h, :s, :n, :u, :k, :r, :t)',
                 {'h': host_name, 's': sm['state'], 'n': sm['signed'], 'u': sm['unsigned'], 'k': ' '.join(sm['keys']),
                  'r': '; '.join(sm['reasons'])[:500], 't': int(time.time())})


def status(conn, host_name: str | None = None) -> list[dict]:
    keys = ('host', 'state', 'signed', 'unsigned', 'keys', 'reason', 'checked_at')
    sql = 'SELECT host, state, signed, unsigned, keys, reason, checked_at FROM scan_signatures'
    rows = conn.all(sql + (' WHERE host = :h' if host_name else '') + ' ORDER BY host', {'h': host_name} if host_name else {})
    return [dict(zip(keys, r)) for r in rows]
