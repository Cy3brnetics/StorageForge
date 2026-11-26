"""netconsole: kernel messages over UDP, straight from a host's kernel to the controller (roadmap section 3, phase 5). The kernel sends
them itself, from the network driver, so they still come when user space is dead: a panic, an oops or a hard hang reaches the
controller when journald, sshd and the agent cannot.

    receiver          a UDP socket of its own on a thread of its own (STORAGEFORGE_NETCONSOLE_LISTEN, say 0.0.0.0:6666; off when unset).
                      A packet is taken only when its source address and port are exactly those of one host in netconsole_sources;
                      anything else is counted and dropped. Each source has a rate (PACKETS_PER_SEC, with BURST saved up), a packet is
                      at most MAX_PACKET bytes, and lines are stored in batches every FLUSH_SECS through hostlogs.store, so the host's
                      own line rate, the scrubbing of secrets and the log rules apply as to every line.
    the lines         stored as the host's, with via 'netconsole', at the time they arrived (the kernel's own stamp counts from boot).
                      The extended format (level, sequence number, time since boot) gives each line its level; the plain format
                      does not, and its lines are stored as info. They are a second copy of kernel lines the journal also holds
                      when the host lives to write them, so they are not counted into the baselines (loganomaly.py).

What netconsole cannot prove: UDP carries no signature and no proof of where it came from. Anyone who can send packets from a host's
address and port, on the path or by spoofing them, can write lines in that host's name, and packets can be lost, repeated or come out
of order with nothing to say so. A line from here is "something sent this from that address", never the host's signed word as the
agent's lines are, and the UI says so. It is for seeing why a host died, not for evidence.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import threading
import time

from . import errlog, hostlogs
from .db import Conn, Database

DEFAULT_PORT = 6666             # what netconsole sends to when nothing else is said
DEFAULT_SOURCE_PORT = 6665      # and what it sends from
MAX_PACKET = 2048               # the kernel sends at most about 1,000 bytes of message in one packet
PACKETS_PER_SEC, BURST = 50, 1000
FLUSH_SECS, BATCH_LINES = 2.0, 500
MAX_KEPT = 5000          # lines a host keeps waiting for a database that would not take them
RELOAD_SECS = 30
_EXTENDED = re.compile(r'(\d{1,3}),(\d{1,20}),(\d{1,20}),([^;]{0,40});(.*)', re.S)
STATE = {'listening': None, 'unknown': 0, 'last_unknown': None, 'last_unknown_at': None, 'limited': 0, 'error': None}
_lock = threading.Lock()


def listen_address(value: str | None = None) -> tuple[str, int] | None:
    """(address, port) from STORAGEFORGE_NETCONSOLE_LISTEN: '0.0.0.0:6666', ':6666', '6666' or '[::]:6666'. None when off or unreadable."""
    v = (os.environ.get('STORAGEFORGE_NETCONSOLE_LISTEN', '') if value is None else value).strip()
    if not v or v.lower() in ('0', 'off', 'no', 'false'):
        return None
    m = re.fullmatch(r'(?:(?:\[([0-9a-fA-F:.]+)\]|([0-9.]*)):)?(\d{1,5})', v)
    if not m:
        return None
    host, port = m[1] or m[2] or '0.0.0.0', int(m[3])
    return (host, port) if 0 < port < 65536 else None


def _address(a: str) -> str:
    """One way to write an address: an IPv4 address that came over an IPv6 socket is written as IPv4."""
    ip = ipaddress.ip_address(a.split('%', 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_packet(data: bytes, now: float | None = None) -> list[dict]:
    """The lines in one netconsole packet, as hostlogs lines. Never raises: a packet is anyone's bytes."""
    now = time.time() if now is None else now
    try:
        text = bytes(data[:MAX_PACKET]).decode('utf-8', 'replace')
    except (TypeError, ValueError):
        return []
    out = []
    m = _EXTENDED.match(text)
    if m:
        # extended: <prefix>,<seq>,<usecs since boot>,<flags>;<message>, then dictionary lines that start with a space
        priority, seq, since_boot = int(m[1]) & 7, m[2], m[3]
        body = m[5].split('\n')
        message = body[0]
        key = f'nc|x|{seq}|{since_boot}|{message}'
        out.append((priority, message, key))
    else:
        for n, raw in enumerate(text.split('\n')):
            if raw.strip():
                # check for syslog priority prefix <N> (0-7)
                pm = re.match(r'^<([0-7])>(.*)$', raw)
                if pm:
                    prio, msg = int(pm[1]), pm[2]
                else:
                    prio, msg = 6, raw
                out.append((prio, msg, f'nc|p|{now}|{n}|{msg}'))
    lines = []
    for priority, message, key in out:
        message = hostlogs.scrub(hostlogs._text(message, hostlogs.MESSAGE_CHARS))
        if not message:
            continue
        lines.append({'key': hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:32], 'at_us': int(now * 1e6), 'priority': priority, 'unit': None,
                      'ident': 'kernel', 'pid': None, 'message': message, 'uid': None, 'comm': None, 'exe': None, 'seqnum': None, 'seqnum_id': None})
    return lines


# ── which host a packet is from ─────────────────────────────────────
def sources(conn: Conn) -> list[dict]:
    rows = conn.all('SELECT host, address, port, enabled, note, created_by, created_at, last_at, packets, dropped FROM netconsole_sources ORDER BY host')
    return [dict(zip(('host', 'address', 'port', 'enabled', 'note', 'by', 'at', 'last_at', 'packets', 'dropped'), r)) | {'enabled': bool(r[3])} for r in rows]


def save_source(conn: Conn, host: str, address: str, port, actor: str, enabled: bool = True, note: str = '') -> dict:
    """The address and port a host's netconsole sends from. ValueError for what cannot be one; LookupError for a host not known."""
    name = conn.scalar('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h)', {'h': str(host or '').strip()})
    if not name:
        raise LookupError('no such host')
    try:
        address = _address(str(address or '').strip())
    except ValueError:
        raise ValueError('the address is an IPv4 or IPv6 address, such as 10.42.0.7') from None
    try:
        port = int(DEFAULT_SOURCE_PORT if port in (None, '') else port)
    except (TypeError, ValueError):
        raise ValueError('the port is a whole number') from None
    if not 0 < port < 65536:
        raise ValueError('the port is from 1 to 65535')
    if ipaddress.ip_address(address).is_unspecified or ipaddress.ip_address(address).is_multicast:
        raise ValueError('that address cannot be where a host sends from')
    taken = conn.scalar('SELECT host FROM netconsole_sources WHERE address = :a AND port = :p AND host <> :h', {'a': address, 'p': port, 'h': name})
    if taken:
        raise ValueError(f'{address} port {port} is already {taken}\'s')
    now = int(time.time())
    with conn.tx():
        conn.execute("""INSERT INTO netconsole_sources (host, address, port, enabled, note, created_by, created_at) VALUES (:h, :a, :p, :e, :n, :by, :t)
                        ON CONFLICT (host) DO UPDATE SET address = :a, port = :p, enabled = :e, note = :n, created_by = :by, created_at = :t""",
                     {'h': name, 'a': address, 'p': port, 'e': 1 if enabled else 0, 'n': str(note or '')[:300], 'by': actor, 't': now})
    return next(s for s in sources(conn) if s['host'] == name)


def delete_source(conn: Conn, host: str) -> bool:
    with conn.tx():
        return conn.execute('DELETE FROM netconsole_sources WHERE lower(host) = lower(:h)', {'h': str(host or '')}).rowcount > 0


def status() -> dict:
    with _lock:
        return dict(STATE)


# ── the receiver ────────────────────────────────────────────────────
class Receiver:
    """What one listening socket does with what arrives. take() is called for each packet and never touches the database; flush() stores
    what was taken, every FLUSH_SECS or BATCH_LINES, in one connection of its own."""

    def __init__(self, db: Database):
        self.db = db
        self.by_peer: dict[tuple[str, int], str] = {}
        self.loaded_at = 0.0
        self.tokens: dict[str, list[float]] = {}
        self.pending: dict[str, list] = {}
        self.counted: dict[str, list[int]] = {}
        self.flushed_at = 0.0

    def reload(self, now: float):
        conn = self.db.connect()
        try:
            self.by_peer = {(a, int(p)): h for h, a, p in conn.all('SELECT host, address, port FROM netconsole_sources WHERE enabled = 1')}
        finally:
            conn.close()
        self.loaded_at = now

    def take(self, data: bytes, peer: tuple, now: float) -> str:
        """'taken', 'unknown', 'limited', 'too-big' or 'empty': what became of one packet."""
        if now - self.loaded_at >= RELOAD_SECS:
            try:
                self.reload(now)
            except Exception:       # a database that is busy or down for a moment must not end the receiver: keep the sources it knew and try again later
                errlog.trace()
                self.loaded_at = now
        try:
            who = (_address(str(peer[0])), int(peer[1]))
        except (ValueError, TypeError, IndexError):
            who = None
        host = self.by_peer.get(who) if who else None
        if not host:
            with _lock:
                STATE['unknown'] += 1
                STATE['last_unknown'], STATE['last_unknown_at'] = (f'{who[0]} port {who[1]}' if who else '?'), int(now)
            return 'unknown'
        c = self.counted.setdefault(host, [0, 0])
        if len(data) > MAX_PACKET:
            c[1] += 1
            return 'too-big'
        t = self.tokens.setdefault(host, [float(BURST), now])
        t[0] = min(float(BURST), t[0] + (now - t[1]) * PACKETS_PER_SEC)
        t[1] = now
        if t[0] < 1:
            c[1] += 1
            with _lock:
                STATE['limited'] += 1
            return 'limited'
        t[0] -= 1
        lines = parse_packet(data, now)
        c[0] += 1
        if not lines:
            return 'empty'
        self.pending.setdefault(host, []).extend(lines)
        return 'taken'

    def due(self, now: float) -> bool:
        return bool(self.pending or self.counted) and (now - self.flushed_at >= FLUSH_SECS or sum(len(v) for v in self.pending.values()) >= BATCH_LINES)

    def flush(self, now: float, counts: dict | None = None) -> int:
        pending, counted, self.pending, self.counted, self.flushed_at = self.pending, self.counted, {}, {}, now
        if not pending and not counted:
            return 0
        stored, error = 0, None
        try:
            conn = self.db.connect()
        except Exception as exc:
            self._keep(pending, counted)
            raise exc
        try:
            for host, lines in list(pending.items()):
                try:
                    stored += hostlogs.store(conn, host, {'state': 'ok', 'lines': lines, 'cut': False}, now, via='netconsole', counts=counts)
                    del pending[host]
                except Exception as exc:                # one host failing must not drop the others' lines
                    error = error or exc
            try:
                with conn.tx():
                    for host, (packets, dropped) in counted.items():
                        conn.execute('UPDATE netconsole_sources SET packets = packets + :p, dropped = dropped + :d, last_at = CASE WHEN :p > 0 THEN :t ELSE last_at END WHERE host = :h',
                                     {'p': packets, 'd': dropped, 't': int(now), 'h': host})
                counted = {}
            except Exception as exc:
                error = error or exc
        finally:
            conn.close()
            if error is not None:
                self._keep(pending, counted)
        if error is not None:
            raise error
        return stored

    def _keep(self, pending: dict, counted: dict) -> None:
        """Put back what a failed flush did not store, so the next flush tries again. A host keeps at most MAX_KEPT lines, the newest."""
        for host, lines in pending.items():
            self.pending[host] = (lines + self.pending.get(host, []))[-MAX_KEPT:]
        for host, (packets, dropped) in counted.items():
            c = self.counted.setdefault(host, [0, 0])
            c[0] += packets
            c[1] += dropped


def serve(db: Database, sock: socket.socket, stop: threading.Event | None = None, wake=None):
    """Reads packets from a bound UDP socket until stop is set. A log rule a line matched wakes the notification center at once."""
    r = Receiver(db)
    sock.settimeout(0.5)
    while not (stop and stop.is_set()):
        try:
            data, peer = sock.recvfrom(MAX_PACKET + 1)
            r.take(data, peer, time.time())
        except socket.timeout:
            pass
        except OSError:
            if stop and stop.is_set():
                break
            time.sleep(0.5)
        except Exception:
            errlog.trace()
        now = time.time()
        if r.due(now):
            try:
                counts: dict = {}
                r.flush(now, counts)
                if wake and counts.get('hits'):
                    wake()
            except Exception:
                errlog.trace()
    r.flush(time.time())


def bind(address: tuple[str, int]) -> socket.socket:
    family = socket.AF_INET6 if ':' in address[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    sock.bind(address)
    return sock


def run(db: Database, wake=None, address: tuple[str, int] | None = None):
    """The thread server.App starts when STORAGEFORGE_NETCONSOLE_LISTEN is set."""
    address = address or listen_address()
    if not address:
        return
    try:
        sock = bind(address)
    except OSError as exc:
        with _lock:
            STATE['error'] = f'could not listen on {address[0]} port {address[1]}: {exc}'
        return
    with _lock:
        STATE['listening'], STATE['error'] = f'{address[0]} port {sock.getsockname()[1]}', None
    try:
        serve(db, sock, wake=wake)
    finally:
        sock.close()
