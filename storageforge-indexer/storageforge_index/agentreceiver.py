"""The agent receiver: a process of its own, behind the agent's tunnel (roadmap section 11.2; agenttunnel.py; docs/agent.md).

    python -m storageforge_index.agentreceiver [--listen ADDRESS:PORT]     the receiver; STORAGEFORGE_AGENT_RECEIVER_DB names its database
    python -m storageforge_index.agentreceiver grant ROLE                   on PostgreSQL: the grants its own role needs, and no more

It is the one place where what an agent says enters StorageForge, and it treats every byte as hostile:

- **Who is speaking comes from the key alone.** The Noise handshake shows the agent's static key; the receiver looks it up among the
  keys pinned at enrollment and takes the host from that row. A hostname, address or machine id inside a message is a claim, kept as
  one and never used to decide where anything goes.
- **It writes about the sender and nothing else**, into three tables that hold nothing but what agents said (agent_peers,
  agent_records, agent_events). On PostgreSQL its role can write those and read five columns of `agents` and the deliveries; on
  SQLite, which has no roles, an authorizer on its connection refuses every other table, which holds as long as the process is not
  itself taken over (the separation that holds then is PostgreSQL's).
- **Every batch is counted and signed.** The counter only goes up per key; a repeat with the same bytes is a resend and is answered
  without being stored again, a repeat with other bytes is a replay and is refused, and a gap is recorded. The signature is the
  agent's own key's, checked before the body is read.
- **Limits per agent, off the web threads.** A frame is at most 1 MiB, a batch 512 KiB and 512 records, a record's body 64 KiB and 16
  levels deep. Each key gets a rate of batches and bytes a minute, one session at a time, and a number of rows; past that its own
  oldest rows go, by the time they arrived, and that is recorded. Handshakes are limited per address before any key is known, and the
  number of connections is capped, so one agent, or something that is no agent, cannot starve the others or the web app, which is
  another process altogether.
- **Sessions are short.** A session ends after SESSION_SECS and the agent opens another with fresh keys. A key taken off the pinned
  list (the agent removed, or wiped) ends its session within seconds, and no new one opens.
- **Where each plugin is up to.** The cursor in the last reading of a plugin that resumes (the logs plugin's place in the journal)
  is kept per key in agent_peers and handed back when a session opens, so after a reboot the plugin starts after the last line the
  controller has. A cursor is the agent's claim about its own host, and moves nothing but its own plugin's place.
- **No vault, no SSH.** It holds its own tunnel key and nothing else: it reads no vault secret, opens no SSH connection and imports
  nothing that could. What it stores reaches SSH only through a person.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path

from . import agenttunnel as t
from .db import Database

SESSION_SECS = 900
IDLE_SECS = 180
HANDSHAKE_SECS = 10
MAX_CONNECTIONS = 256
HANDSHAKES_PER_MINUTE = 30          # per address, before any key is known
BATCHES_PER_MINUTE = 120            # per key
BYTES_PER_MINUTE = 8 << 20          # per key
ROWS_PER_HOST = 200_000
MALFORMED_LIMIT = 5                 # in one session; then the session ends and the key waits BLOCK_SECS
BLOCK_SECS = 600
MAX_BATCH = 512 << 10
MAX_RECORDS = 512
MAX_BODY = 64 << 10
MAX_DEPTH = 16
MAX_CLAIMS = 4096
EVENT_DAYS = 30
PIN_REFRESH = 5
PRUNE_EVERY = 20                    # batches between two looks at a host's quota
MAX_CURSOR = 1024                   # the most a plugin's cursor may be, as JSON
NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
TABLES_WRITTEN = ('agent_peers', 'agent_records', 'agent_events')
READ_COLUMNS = {'agents': ('host', 'enabled', 'state', 'public_key', 'fingerprint'), 'agent_deliveries': None}


class Refused(Exception):
    """A batch not taken. `kind` is what is counted; `why` goes back to the agent."""

    def __init__(self, kind: str, why: str):
        super().__init__(why)
        self.kind, self.why = kind, why


# ── the database ────────────────────────────────────────────────────
def grants(role: str) -> list[str]:
    """What the receiver's own role on PostgreSQL is given: reading the pinned keys and the deliveries, writing its three tables."""
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', role):
        raise ValueError('a role name is lower-case letters, digits and _')
    out = [f'GRANT SELECT ({", ".join(READ_COLUMNS["agents"])}) ON agents TO {role}', f'GRANT SELECT ON agent_deliveries TO {role}']
    out += [f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role}' for table in TABLES_WRITTEN]
    out += [f'GRANT USAGE ON SEQUENCE agent_records_record_id_seq TO {role}', f'GRANT USAGE ON SEQUENCE agent_events_event_id_seq TO {role}']
    return out


def _authorizer(action, arg1, arg2, _db, _trigger):
    """SQLite's stand-in for a role: the receiver's connection reads the pinned keys and the deliveries and writes its own tables."""
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT, sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        if arg1 in TABLES_WRITTEN or arg1 == 'agent_deliveries' or arg1 == 'sqlite_sequence':
            return sqlite3.SQLITE_OK
        if arg1 == 'agents' and arg2 in READ_COLUMNS['agents']:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
        return sqlite3.SQLITE_OK if arg1 in TABLES_WRITTEN or arg1 == 'sqlite_sequence' else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and arg1 in ('journal_mode', 'synchronous', 'foreign_keys', 'cache_size', 'mmap_size', 'busy_timeout'):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def connect(db: Database):
    conn = db.connect()
    if conn.dialect == 'sqlite':
        conn.raw.set_authorizer(_authorizer)
    return conn


# ── limits ──────────────────────────────────────────────────────────
class Bucket:
    """A token bucket: `per_minute` a minute, with a minute saved up at most."""

    def __init__(self, per_minute: float):
        self.per_minute, self.tokens, self.at = per_minute, per_minute, time.monotonic()

    def take(self, n: float = 1) -> bool:
        now = time.monotonic()
        self.tokens = min(self.per_minute, self.tokens + (now - self.at) * self.per_minute / 60)
        self.at = now
        if self.tokens < n:
            return False
        self.tokens -= n
        return True


def depth_ok(value, most: int = MAX_DEPTH) -> bool:
    """Whether a decoded JSON value nests no deeper than `most`, walked without recursion."""
    stack = [(value, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            if d > most:
                return False
            stack.extend((x, d + 1) for x in (v.values() if isinstance(v, dict) else v))
    return True


def read_batch(body: bytes) -> dict:
    """A batch body, read strictly: exactly its fields, each of its shape, or Refused('malformed')."""
    if len(body) > MAX_BATCH:
        raise Refused('over-quota', 'the batch is larger than a batch may be')
    try:
        b = json.loads(body)
    except (ValueError, RecursionError):
        raise Refused('malformed', 'the batch is not JSON') from None
    if not isinstance(b, dict) or set(b) != {'counter', 'run', 'sent', 'dropped', 'records'}:
        raise Refused('malformed', 'the batch does not have the fields a batch has')
    ints = [b['counter'], b['run'], b['sent'], b['dropped']]
    if not all(type(x) is int and 0 <= x < 2 ** 63 for x in ints) or b['counter'] < 1:
        raise Refused('malformed', 'a number in the batch is not one')
    if not isinstance(b['records'], list) or len(b['records']) > MAX_RECORDS:
        raise Refused('malformed', 'the records are not a list of the size allowed')
    for r in b['records']:
        if not isinstance(r, dict) or set(r) != {'seq', 'at', 'plugin', 'kind', 'body'}:
            raise Refused('malformed', 'a record does not have the fields a record has')
        if not (type(r['seq']) is int and type(r['at']) is int and 0 < r['seq'] < 2 ** 63 and 0 <= r['at'] < 2 ** 63):
            raise Refused('malformed', 'a record is not numbered')
        if not (isinstance(r['plugin'], str) and NAME.fullmatch(r['plugin']) and isinstance(r['kind'], str) and NAME.fullmatch(r['kind'])):
            raise Refused('malformed', 'a record names no proper plugin or kind')
        if not isinstance(r['body'], dict) or not depth_ok(r['body']):
            raise Refused('malformed', 'a record body is not an object of the depth allowed')
        r['body_json'] = json.dumps(r['body'], separators=(',', ':'), ensure_ascii=True)
        if len(r['body_json']) > MAX_BODY:
            raise Refused('malformed', 'a record body is larger than a record may be')
    return b


# ── the pinned keys ─────────────────────────────────────────────────
class Pins:
    """The keys of enrolled agents, read from `agents` every few seconds: X25519 key -> (host, fingerprint, ed25519 key)."""

    def __init__(self, db: Database):
        self.db, self.by_key, self.at, self.lock = db, {}, 0.0, threading.Lock()

    def refresh(self, force: bool = False):
        if not force and time.monotonic() - self.at < PIN_REFRESH:
            return
        conn = connect(self.db)
        try:
            rows = conn.all("SELECT host, public_key, fingerprint FROM agents WHERE enabled = 1 AND public_key IS NOT NULL "
                            "AND fingerprint IS NOT NULL AND state IN ('running', 'stopped')")
        finally:
            conn.close()
        out = {}
        for host, line, fp in rows:
            try:
                ed = t.ed25519_of_line(line)
                out[t.ed25519_to_x25519(ed)] = (host, fp, ed)
            except ValueError:
                continue
        with self.lock:
            self.by_key, self.at = out, time.monotonic()

    def get(self, x25519: bytes):
        self.refresh()
        with self.lock:
            return self.by_key.get(x25519)

    def still(self, x25519: bytes, host: str, fp: str) -> bool:
        """Whether the key is still the pinned key of that host: false once the agent is removed, wiped or enrolled anew."""
        pin = self.get(x25519)
        return pin is not None and pin[0] == host and pin[1] == fp


# ── the store ───────────────────────────────────────────────────────
PEER_COLUMNS = ('fingerprint', 'host', 'last_counter', 'last_digest', 'last_run', 'last_seq', 'last_dropped', 'batches', 'resume_json')


class Store:
    def __init__(self, db: Database, rows_per_host: int = ROWS_PER_HOST):
        self.db, self.rows_per_host = db, rows_per_host

    def peer(self, conn, fp: str, host: str) -> dict:
        rows = conn.all(f'SELECT {", ".join(PEER_COLUMNS)} FROM agent_peers WHERE fingerprint = :f', {'f': fp})
        if not rows:
            now = int(time.time())
            conn.execute('INSERT INTO agent_peers (fingerprint, host, first_seen) VALUES (:f, :h, :t)', {'f': fp, 'h': host, 't': now})
            rows = conn.all(f'SELECT {", ".join(PEER_COLUMNS)} FROM agent_peers WHERE fingerprint = :f', {'f': fp})
        return dict(zip(PEER_COLUMNS, rows[0]))

    def bump(self, conn, fp: str, **counts):
        sets = ', '.join(f'{k} = {k} + :{k}' for k in counts)
        conn.execute(f'UPDATE agent_peers SET {sets} WHERE fingerprint = :f', {**counts, 'f': fp})

    def event(self, conn, host, fp, kind: str, count: int = 1, detail: str = ''):
        conn.execute('INSERT INTO agent_events (host, fingerprint, at, kind, count, detail) VALUES (:h, :f, :t, :k, :c, :d)',
                     {'h': host, 'f': fp, 't': int(time.time()), 'k': kind, 'c': int(count), 'd': detail[:500]})

    def hello(self, conn, fp: str, host: str, hello: dict, address: str):
        claims = json.dumps({'version': str(hello.get('version') or '')[:32], 'claims': hello.get('claims'), 'manifest': hello.get('manifest'),
                             'have': hello.get('have')}, separators=(',', ':'), ensure_ascii=True)
        if len(claims) > MAX_CLAIMS:
            claims = json.dumps({'too_large': True})
        self.peer(conn, fp, host)
        conn.execute('UPDATE agent_peers SET sessions = sessions + 1, last_seen = :t, last_address = :a, version = :v, claims_json = :c, host = :h '
                     'WHERE fingerprint = :f', {'t': int(time.time()), 'a': address[:64], 'v': str(hello.get('version') or '')[:32], 'c': claims, 'h': host, 'f': fp})

    def last_counter(self, conn, fp: str) -> int:
        return conn.scalar('SELECT last_counter FROM agent_peers WHERE fingerprint = :f', {'f': fp}) or 0

    def cursors(self, conn, fp: str, delivery: dict | None) -> dict | None:
        """Where the receiver has each plugin of the delivered manifest up to: plugin name -> the cursor of its last reading stored,
        or None. None as a whole when there is no manifest to name plugins."""
        if not delivery:
            return None
        try:
            names = [e['name'] for e in json.loads(delivery['manifest']).get('plugins') or [] if isinstance(e, dict) and NAME.fullmatch(str(e.get('name') or ''))]
        except (ValueError, TypeError, AttributeError):
            return None
        stored = conn.scalar('SELECT resume_json FROM agent_peers WHERE fingerprint = :f', {'f': fp})
        try:
            stored = json.loads(stored) if stored else {}
        except ValueError:
            stored = {}
        return {n: stored.get(n) if isinstance(stored.get(n), dict) else None for n in names}

    def delivery(self, conn, host: str, fp: str) -> dict | None:
        rows = conn.all('SELECT manifest, signature, plugins_json FROM agent_deliveries WHERE host = :h AND fingerprint = :f', {'h': host, 'f': fp})
        if not rows:
            return None
        return {'manifest': rows[0][0], 'signature': rows[0][1], 'plugins': json.loads(rows[0][2] or '[]')}

    def take(self, conn, fp: str, host: str, raw: bytes) -> str:
        """Stores one verified batch under `host`, the host its key belongs to. Returns 'ack' or 'resent'; raises Refused."""
        b = read_batch(raw)
        digest = hashlib.sha256(raw).hexdigest()
        now = int(time.time())
        replay = None
        with conn.tx():
            p = self.peer(conn, fp, host)
            counter, last = b['counter'], p['last_counter']
            if counter <= last:
                if counter == last and digest == p['last_digest']:
                    self.bump(conn, fp, resent=1)
                    conn.execute('UPDATE agent_peers SET last_seen = :t WHERE fingerprint = :f', {'t': now, 'f': fp})
                    return 'resent'
                replay = counter
        if replay is not None:
            # counted on its own, so that the count stays whatever is refused
            self.bump(conn, fp, repeats=1)
            self.event(conn, host, fp, 'repeat', 1, f'batch {replay} came again with other bytes, after {last}')
            raise Refused('repeat', f'batch {replay} was taken already')
        with conn.tx():
            p = self.peer(conn, fp, host)
            counter, last = b['counter'], p['last_counter']
            if counter <= last:
                raise Refused('repeat', f'batch {counter} was taken already')       # another session of the same key got there first
            if counter > last + 1 and last > 0:
                self.bump(conn, fp, gaps=counter - last - 1)
                self.event(conn, host, fp, 'gap', counter - last - 1, f'batches {last + 1} to {counter - 1} never came')
            lost = 0
            seqs = [r['seq'] for r in b['records']]
            if p['last_run'] == b['run']:
                if seqs and seqs[0] > p['last_seq'] + 1:
                    lost += seqs[0] - p['last_seq'] - 1
                lost += max(0, b['dropped'] - p['last_dropped'])
            if lost:
                self.bump(conn, fp, lost=lost)
                self.event(conn, host, fp, 'lost', lost, 'records the agent made and never sent: its queue was full, or they were dropped')
            cursors = {}
            for r in b['records']:
                c = r['body'].get('cursor')
                if isinstance(c, dict) and len(json.dumps(c)) <= MAX_CURSOR:
                    cursors[r['plugin']] = c
            if cursors:
                try:
                    kept = json.loads(p['resume_json']) if p['resume_json'] else {}
                except ValueError:
                    kept = {}
                kept = (kept if isinstance(kept, dict) else {}) | cursors
                conn.execute('UPDATE agent_peers SET resume_json = :j WHERE fingerprint = :f',
                             {'j': json.dumps(dict(list(kept.items())[:64]), separators=(',', ':')), 'f': fp})
            for r in b['records']:
                conn.execute("""INSERT INTO agent_records (host, fingerprint, source, counter, seq, plugin, kind, claimed_at, received_at, body_json)
                                VALUES (:h, :f, 'agent', :c, :s, :p, :k, :a, :t, :b)""",
                             {'h': host, 'f': fp, 'c': counter, 's': r['seq'], 'p': r['plugin'], 'k': r['kind'], 'a': r['at'], 't': now, 'b': r['body_json']})
            conn.execute("""UPDATE agent_peers SET last_counter = :c, last_digest = :d, last_run = :r, last_seq = :s, last_dropped = :dr,
                            batches = batches + 1, records = records + :n, bytes = bytes + :by, last_seen = :t WHERE fingerprint = :f""",
                         {'c': counter, 'd': digest, 'r': b['run'], 's': max(seqs) if seqs else (p['last_seq'] if p['last_run'] == b['run'] else 0),
                          'dr': b['dropped'], 'n': len(seqs), 'by': len(raw), 't': now, 'f': fp})
            if (p['batches'] + 1) % PRUNE_EVERY == 0 or len(seqs) >= MAX_RECORDS // 2:
                self.prune(conn, fp, host)
        return 'ack'

    def prune(self, conn, fp: str, host: str):
        """The host's own oldest rows, by when they arrived, past its quota: a flood costs the flooder and nobody else."""
        n = conn.scalar('SELECT count(*) FROM agent_records WHERE host = :h', {'h': host}) or 0
        over = n - self.rows_per_host
        if over <= 0:
            return
        cut = conn.scalar('SELECT record_id FROM agent_records WHERE host = :h ORDER BY received_at, record_id LIMIT 1 OFFSET :o', {'h': host, 'o': over - 1})
        conn.execute('DELETE FROM agent_records WHERE host = :h AND record_id <= :c', {'h': host, 'c': cut})
        self.bump(conn, fp, pruned=over)
        self.event(conn, host, fp, 'pruned', over, f'its quota is {self.rows_per_host} rows: the oldest went')

    def tidy(self, conn):
        conn.execute('DELETE FROM agent_events WHERE at < :t', {'t': int(time.time()) - EVENT_DAYS * 86400})


# ── the server ──────────────────────────────────────────────────────
class Receiver:
    def __init__(self, db: Database, secret: bytes, *, session_secs: int = SESSION_SECS, rows_per_host: int = ROWS_PER_HOST,
                 batches_per_minute: float = BATCHES_PER_MINUTE, bytes_per_minute: float = BYTES_PER_MINUTE,
                 handshakes_per_minute: float = HANDSHAKES_PER_MINUTE, max_connections: int = MAX_CONNECTIONS, log=None):
        self.db, self.secret = db, secret
        self.pins, self.store = Pins(db), Store(db, rows_per_host)
        self.session_secs, self.bpm, self.bytes_pm, self.hpm = session_secs, batches_per_minute, bytes_per_minute, handshakes_per_minute
        self.slots = threading.BoundedSemaphore(max_connections)
        self.lock = threading.Lock()
        self.by_address: dict[str, Bucket] = {}
        self.rates: dict[str, tuple[Bucket, Bucket]] = {}
        self.blocked: dict[str, float] = {}
        self.sessions: dict[str, socket.socket] = {}
        self.unknown = 0
        self.unknown_at = time.monotonic()
        self.stopping = threading.Event()
        self.log = log or (lambda line: print(f'agent-receiver: {line}', file=sys.stderr, flush=True))
        self.listener: socket.socket | None = None

    def listen(self, address: str = '0.0.0.0', port: int = t.DEFAULT_PORT) -> int:
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((address, port))
        s.listen(128)
        self.listener = s
        return s.getsockname()[1]

    def serve_forever(self):
        self.pins.refresh(force=True)
        threading.Thread(target=self._housekeeping, daemon=True).start()
        while not self.stopping.is_set():
            try:
                conn, peer = self.listener.accept()
            except OSError:
                if self.stopping.is_set():
                    return
                continue
            if not self.slots.acquire(blocking=False):
                conn.close()                # full: refused before a byte is read
                continue
            threading.Thread(target=self._connection, args=(conn, peer[0]), daemon=True).start()

    def stop(self):
        self.stopping.set()
        if self.listener:
            self.listener.close()
        with self.lock:
            for s in list(self.sessions.values()):
                _shut(s)

    def _housekeeping(self):
        while not self.stopping.wait(PIN_REFRESH):
            try:
                self.pins.refresh(force=True)
                # sessions whose key is no longer pinned end now: removing an agent ends what it has open
                with self.lock:
                    live = {fp for (_h, fp, _e) in self.pins.by_key.values()}
                    for fp, s in list(self.sessions.items()):
                        if fp not in live:
                            _shut(s)
                self._flush_unknown()
            except Exception as exc:          # the database may be away a moment: the receiver goes on
                self.log(f'housekeeping: {exc}')

    def _flush_unknown(self, force: bool = False):
        with self.lock:
            n, self.unknown = self.unknown, 0
        if n:
            conn = connect(self.db)
            try:
                self.store.event(conn, None, None, 'unknown-key', n, 'handshakes with a key that is no enrolled agent\'s')
            finally:
                conn.close()

    def _admit(self, address: str) -> bool:
        with self.lock:
            b = self.by_address.get(address)
            if b is None:
                if len(self.by_address) > 10_000:
                    self.by_address.clear()
                b = self.by_address[address] = Bucket(self.hpm)
            return b.take()

    def _connection(self, conn: socket.socket, address: str):
        try:
            if not self._admit(address):
                return
            self._session(conn, address)
        except (OSError, ConnectionError, t.TunnelError):
            pass
        except Exception as exc:
            self.log(f'a session from {address} failed: {type(exc).__name__}: {exc}')
        finally:
            _shut(conn)
            self.slots.release()

    def _session(self, conn: socket.socket, address: str):
        conn.settimeout(HANDSHAKE_SECS)
        found = {}

        def admit(key: bytes) -> bool:
            pin = self.pins.get(key)
            if pin is None:
                with self.lock:
                    self.unknown += 1
                return False
            if self.blocked.get(pin[1], 0) > time.monotonic():
                return False
            found['pin'] = pin
            return True

        db_conn = None
        try:
            def answer(_key, _payload):
                nonlocal db_conn
                db_conn = connect(self.db)
                return json.dumps({'last_counter': self.store.last_counter(db_conn, found['pin'][1]), 'session_ends': int(time.time()) + self.session_secs}).encode()
            s, _ = t.respond(conn, self.secret, admit, answer)
            host, fp, ed = found['pin']
            x25519 = s.remote
            with self.lock:
                old = self.sessions.get(fp)
                self.sessions[fp] = conn
            if old is not None:
                _shut(old)                     # one session per key: the newer one wins
            try:
                self._converse(conn, s, db_conn, host, fp, ed, x25519, address)
            finally:
                with self.lock:
                    if self.sessions.get(fp) is conn:
                        del self.sessions[fp]
        finally:
            if db_conn is not None:
                db_conn.close()

    def _converse(self, conn, s: t.Session, db_conn, host: str, fp: str, ed: bytes, x25519: bytes, address: str):
        ends = time.monotonic() + self.session_secs
        conn.settimeout(IDLE_SECS)
        hello = _json(s.read(conn, MAX_CLAIMS * 4))
        if hello.get('op') != 'hello' or not set(hello) <= {'op', 'version', 'run', 'claims', 'manifest', 'have'}:
            self._count(db_conn, host, fp, 'malformed', 'the session did not start with a hello')
            return
        self.store.hello(db_conn, fp, host, hello, address)
        have = [h for h in hello.get('have') or [] if isinstance(h, str) and NAME.fullmatch(h)][:64]
        delivery = self.store.delivery(db_conn, host, fp)
        for frame in t.delivery_frames(delivery, have, self.store.cursors(db_conn, fp, delivery)):
            s.send_json(conn, frame)
        with self.lock:
            rates = self.rates.setdefault(fp, (Bucket(self.bpm), Bucket(self.bytes_pm)))
        malformed = 0
        while True:
            if time.monotonic() > ends:
                s.send_json(conn, {'op': 'bye', 'why': 'the session is over: open another'})
                return
            if not self.pins.still(x25519, host, fp):
                s.send_json(conn, {'op': 'bye', 'why': 'this key is no longer pinned'})
                return
            conn.settimeout(max(1.0, min(IDLE_SECS, ends - time.monotonic())))
            try:
                frame = s.read(conn)
            except socket.timeout:
                continue
            counter = None
            try:
                msg = _json(frame)
                if set(msg) != {'op', 'body', 'signature'} or msg['op'] != 'batch' or not isinstance(msg['body'], str) or not isinstance(msg['signature'], str):
                    raise Refused('malformed', 'the agent sent what is not a batch')
                raw = msg['body'].encode()
                if not (rates[0].take() and rates[1].take(len(raw))):
                    raise Refused('over-quota', 'more batches or bytes this minute than an agent may send')
                if not t.verify_batch(ed, raw, msg['signature']):
                    raise Refused('malformed', 'the batch is not signed by this agent\'s key')
                try:
                    counter = json.loads(raw).get('counter')
                except (ValueError, AttributeError, RecursionError):
                    counter = None
                self.store.take(db_conn, fp, host, raw)
                s.send_json(conn, {'op': 'ack', 'counter': counter})
            except Refused as r:
                if r.kind in ('malformed', 'over-quota'):
                    self._count(db_conn, host, fp, r.kind, r.why)
                # over its quota for this minute: the agent sends the same batch again later, so a burst waits instead of being lost
                s.send_json(conn, {'op': 'refused', 'counter': counter if type(counter) is int else None, 'why': r.why}
                            | ({'retry': True} if r.kind == 'over-quota' else {}))
                if r.kind == 'malformed':
                    malformed += 1
                    if malformed >= MALFORMED_LIMIT:
                        with self.lock:
                            self.blocked[fp] = time.monotonic() + BLOCK_SECS
                        return

    def _count(self, conn, host, fp, kind: str, why: str):
        column = {'malformed': 'malformed', 'over-quota': 'over_quota'}[kind]
        self.store.peer(conn, fp, host)
        self.store.bump(conn, fp, **{column: 1})
        self.store.event(conn, host, fp, kind, 1, why)


def _json(frame: bytes) -> dict:
    try:
        v = json.loads(frame)
    except (ValueError, RecursionError):
        raise Refused('malformed', 'a frame that is not JSON') from None
    if not isinstance(v, dict):
        raise Refused('malformed', 'a frame that is not a JSON object')
    return v


def _shut(s):
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def database_url() -> str:
    url = os.environ.get('STORAGEFORGE_AGENT_RECEIVER_DB', '').strip() or os.environ.get('STORAGEFORGE_DB', '').strip()
    if not url:
        raise SystemExit('STORAGEFORGE_AGENT_RECEIVER_DB names the receiver\'s database: on PostgreSQL a URL with its own role')
    return url


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='python -m storageforge_index.agentreceiver', description='the agent receiver (docs/agent.md)')
    sub = ap.add_subparsers(dest='cmd')
    g = sub.add_parser('grant', help='print the PostgreSQL grants of the receiver\'s own role')
    g.add_argument('role')
    ap.add_argument('--listen', default=os.environ.get('STORAGEFORGE_AGENT_LISTEN', f'0.0.0.0:{t.DEFAULT_PORT}'))
    args = ap.parse_args(argv)
    if args.cmd == 'grant':
        print(';\n'.join(grants(args.role)) + ';')
        return 0
    folder = t.receiver_dir()
    if folder is None:
        raise SystemExit('STORAGEFORGE_AGENT_RECEIVER_DIR names the receiver\'s folder, where its key is kept')
    for name in ('STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_SECRET_FILE'):
        if os.environ.get(name):
            raise SystemExit(f'{name} is set: the receiver runs without the vault, so give it to the web app and not here')
    secret = t.load_or_make_key(folder)
    host, _, port = args.listen.rpartition(':')
    r = Receiver(Database(database_url()), secret)
    bound = r.listen(host.strip('[]') or '0.0.0.0', int(port))
    r.log(f'listening on {host}:{bound}, key {(folder / t.PUBLIC_FILE).read_text().strip()}')
    try:
        r.serve_forever()
    except KeyboardInterrupt:
        r.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
