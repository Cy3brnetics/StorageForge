"""Consoles: a terminal in the browser on a host or VM, over SSH by LAN or Tailscale, or its serial console through
its libvirt host, plus the command that opens its graphical console in virt-viewer.

Who: the console.open permission (admins only, as built in), with the password typed in the last few minutes for each
session. A session belongs to the account that opened it: nobody else can read it or type into it, admins included.

What is kept: every session is in the audit log when it opens and when it ends (who, host, kind, route, address, how
long, bytes each way, why it ended). With recording on (off unless an admin turns it on), the whole session is kept as an
asciicast v2 file, input and output with their timing, for console.recordings to list and download. A recording holds
whatever was typed, passwords included, and says so where it is turned on.

How: ssh (or virsh console) runs on a pseudo-terminal of its own here. The browser long-polls for output and posts what
is typed: no WebSocket, so it works with the plain HTTP server and any proxy in front of it. Keys come from the vault, by
a binding that allows "console", through a private agent that is torn down once the login is made. Only a host key a
scan already confirmed is accepted: over Tailscale the key of the host's LAN address is checked (HostKeyAlias).
"""
from __future__ import annotations

import datetime as dt
import errno
import fcntl
import ipaddress
import json
import os
import pty
import re
import secrets
import signal
import struct
import subprocess
import termios
import threading
import time
from collections import deque
from pathlib import Path

MAX_SESSIONS = 4              # each open console holds a server thread while it waits for output
IDLE = 15 * 60                # a session nobody typed into or read from for this long is closed
MAX_LIFE = 8 * 3600
BUFFER = 1 << 20              # output kept for a reader that fell behind
WAIT = 20                     # how long one output request waits for something to send
AGENT_HOLD = 60               # the private agent lives this long after ssh starts: enough to log in, then gone
TAILNET = ipaddress.ip_network('100.64.0.0/10')
SETTINGS_KEY = 'console'
DEFAULTS = {'record': False, 'keep_days': 90}
VM = re.compile(r'[A-Za-z0-9_.+-]{1,64}')
_REGISTRY: dict[str, 'Session'] = {}
_LOCK = threading.Lock()


class ConsoleError(RuntimeError):
    pass


# ── where a host can be reached ──────────────────────────────────────
def routes(conn, host: str) -> list[dict]:
    """The addresses a console can use: the LAN address the host is scanned at, and its Tailscale address if a scan
    saw one on tailscale0 (or any address in 100.64.0.0/10)."""
    from .db import loads
    row = conn.all('SELECT host_id, ssh_host, ssh_port FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
    if not row:
        raise LookupError(f'{host} has not been scanned')
    hid, lan, port = row[0]
    out = [{'route': 'lan', 'address': lan, 'port': port or 22}] if lan else []
    net = loads(conn.scalar('SELECT data_json FROM host_network WHERE host_id = :h', {'h': hid}) or '{}') or {}
    for iface in net.get('interfaces') or []:
        for a in iface.get('addresses') or []:
            try:
                ip = ipaddress.ip_address(a.get('ip') or '')
            except ValueError:
                continue
            if ip.version == 4 and (iface.get('name') == 'tailscale0' or ip in TAILNET) and not any(r['address'] == str(ip) for r in out):
                out.append({'route': 'tailscale', 'address': str(ip), 'port': port or 22})
    return out


def serial_via(conn, host: str) -> dict | None:
    """Where the serial console of a VM is reached: its libvirt host as scanned, or this machine when the VM is one of
    its own libvirt domains. None when it is no VM either knows."""
    from .clone import _libvirt_home
    if not VM.fullmatch(host):
        return None
    kvm = _libvirt_home(conn, host)
    if kvm:
        return {'via': 'host', 'host': kvm}
    try:
        p = subprocess.run(['virsh', '-c', 'qemu:///system', 'domstate', host], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return {'via': 'local', 'host': None, 'state': p.stdout.strip()} if p.returncode == 0 else None


def viewer(conn, host: str) -> dict | None:
    """The command that opens a VM's graphical console in virt-viewer (or Remote Viewer), through SSH to its libvirt
    host: SPICE or VNC as the VM has it, at native speed, with the clipboard and resizing the browser cannot match."""
    s = serial_via(conn, host)
    if not s:
        return None
    if s['via'] == 'local':
        return {'uri': 'qemu:///system', 'vm': host, 'command': f'virt-viewer --connect qemu:///system {host}',
                'note': 'the VM runs on the machine StorageForge runs on: run this there, or over SSH to it with -X'}
    rows = conn.all('SELECT ssh_host, ssh_user, ssh_port FROM hosts WHERE lower(hostname) = lower(:h)', {'h': s['host']})
    addr, user, port = rows[0] if rows else (s['host'], None, 22)
    where = f'{user + "@" if user else ""}{addr}' + (f':{port}' if port and port != 22 else '')
    uri = f'qemu+ssh://{where}/system'
    return {'uri': uri, 'vm': host, 'command': f'virt-viewer --connect {uri} {host}',
            'note': f'your own SSH login to {s["host"]} is used, and it needs access to libvirt there'}


# ── settings and recordings ──────────────────────────────────────────
def settings(conn) -> dict:
    from .alerts import get_setting
    got = get_setting(conn, SETTINGS_KEY) or {}
    return {**DEFAULTS, **{k: got[k] for k in DEFAULTS if k in got}}


def save_settings(conn, body: dict, actor: str) -> dict:
    from .alerts import set_setting
    s = settings(conn)
    if 'record' in body:
        s['record'] = bool(body['record'])
    if 'keep_days' in body:
        s['keep_days'] = max(1, min(int(body['keep_days']), 3650))
    set_setting(conn, SETTINGS_KEY, s, actor)
    return s


def recordings_dir() -> Path:
    from .runner import data_dir
    d = data_dir() / 'console-recordings'
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def recordings(conn) -> list[dict]:
    prune(conn)
    out = []
    for f in sorted(recordings_dir().glob('*.cast'), reverse=True):
        try:
            head = json.loads(f.open().readline())
        except (OSError, ValueError):
            continue
        out.append({'name': f.name, 'bytes': f.stat().st_size, 'started': head.get('timestamp'), 'host': (head.get('sf') or {}).get('host'),
                    'user': (head.get('sf') or {}).get('user'), 'kind': (head.get('sf') or {}).get('kind'), 'title': head.get('title')})
    return out


def recording_path(name: str) -> Path:
    if not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{12}-[A-Za-z0-9_.+-]{1,64}\.cast', name):
        raise LookupError('no such recording')
    p = recordings_dir() / name
    if not p.is_file():
        raise LookupError('no such recording')
    return p


def prune(conn):
    cut = time.time() - settings(conn)['keep_days'] * 86400
    for f in recordings_dir().glob('*.cast'):
        try:
            if f.stat().st_mtime < cut:
                f.unlink()
        except OSError:
            pass


# ── a session ────────────────────────────────────────────────────────
class Session:
    def __init__(self, owner: str, host: str, kind: str, route: str, address: str | None, cols: int, rows: int):
        self.id = secrets.token_hex(12)
        self.owner, self.host, self.kind, self.route, self.address = owner, host, kind, route, address
        self.cols, self.rows = cols, rows
        self.started = self.active = time.time()
        self.proc = None
        self.fd = None
        self.out: deque = deque()      # (seq, bytes)
        self.size = 0
        self.seq = 0
        self.cond = threading.Condition()
        self.closed = None             # why it ended, once it has
        self.bytes_in = self.bytes_out = 0
        self.rec = None
        self.rec_name = None
        self._audit = None

    # what goes to the browser
    def _push(self, data: bytes):
        with self.cond:
            self.seq += 1
            self.out.append((self.seq, data))
            self.size += len(data)
            while self.size > BUFFER and len(self.out) > 1:
                self.size -= len(self.out.popleft()[1])
            self.bytes_out += len(data)
            self.cond.notify_all()
        self._record('o', data)

    def read_after(self, after: int, wait: float = WAIT) -> dict:
        self.active = time.time()
        deadline = time.time() + wait
        with self.cond:
            while not self.closed and (not self.out or self.out[-1][0] <= after):
                left = deadline - time.time()
                if left <= 0:
                    break
                self.cond.wait(left)
            chunks = [d for s, d in self.out if s > after]
            gap = bool(self.out) and self.out[0][0] > after + 1 and after > 0      # the reader fell behind the buffer
            return {'data': b''.join(chunks), 'next': self.seq, 'closed': self.closed, 'gap': gap}

    def write(self, data: bytes):
        if self.closed or self.fd is None:
            raise ConsoleError('this console has ended')
        self.active = time.time()
        self.bytes_in += len(data)
        self._record('i', data)
        view = memoryview(data)
        while view:
            try:
                n = os.write(self.fd, view)
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    time.sleep(0.01)
                    continue
                raise ConsoleError('the console is not taking input') from exc
            view = view[n:]

    def resize(self, cols: int, rows: int):
        self.cols, self.rows = cols, rows
        if self.fd is not None and not self.closed:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
            if self.proc and self.proc.poll() is None:
                os.kill(self.proc.pid, signal.SIGWINCH)     # it has no controlling terminal, so it is told directly
        if self.rec:
            self._event('r', f'{cols}x{rows}')

    # recording: asciicast v2, one JSON event per line
    def _start_recording(self, conn, title: str):
        if not settings(conn)['record']:
            return
        prune(conn)
        self.rec_name = f'{time.strftime("%Y%m%d-%H%M%S")}-{self.id[:12]}-{self.host}.cast'
        fd = os.open(recordings_dir() / self.rec_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.rec = os.fdopen(fd, 'w', encoding='utf-8')
        self.rec.write(json.dumps({'version': 2, 'width': self.cols, 'height': self.rows, 'timestamp': int(self.started), 'title': title,
                                   'env': {'TERM': 'xterm-256color'},
                                   'sf': {'host': self.host, 'user': self.owner, 'kind': self.kind, 'route': self.route, 'address': self.address}}) + '\n')
        self.rec.flush()

    def _event(self, code: str, text: str):
        try:
            self.rec.write(json.dumps([round(time.time() - self.started, 6), code, text]) + '\n')
            self.rec.flush()
        except (OSError, ValueError):
            pass

    def _record(self, code: str, data: bytes):
        if self.rec:
            self._event(code, data.decode('utf-8', errors='replace'))

    # the process
    def spawn(self, argv: list[str], env: dict):
        master, slave = pty.openpty()
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', self.rows, self.cols, 0, 0))
        try:
            self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True, close_fds=True)
        finally:
            os.close(slave)
        self.fd = master
        threading.Thread(target=self._pump, name=f'console-{self.id[:6]}', daemon=True).start()

    def _pump(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                data = b''
            if not data:
                break
            self._push(data)
        code = self.proc.wait() if self.proc else None
        self.close('ended' if code == 0 else f'ended (exit {code})')

    def close(self, reason: str):
        with self.cond:
            if self.closed:
                return
            self.closed = reason
            self.cond.notify_all()
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGHUP)
                self.proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        if self.rec:
            self._event('x', reason)
            self.rec.close()
            if self._audit is None and self.rec_name:      # it never opened: nothing to keep
                (recordings_dir() / self.rec_name).unlink(missing_ok=True)
                self.rec_name = None
        with _LOCK:
            _REGISTRY.pop(self.id, None)
        if self._audit:
            self._audit('console.close', {'reason': reason, 'seconds': int(time.time() - self.started),
                                          'bytes_in': self.bytes_in, 'bytes_out': self.bytes_out, 'recording': self.rec_name})

    def info(self) -> dict:
        return {'id': self.id, 'host': self.host, 'kind': self.kind, 'route': self.route, 'address': self.address,
                'started': int(self.started), 'recording': self.rec_name, 'closed': self.closed}


def _ssh_argv(sock: str, user: str, address: str, port: int, alias: str, remote: list[str] | None = None) -> list[str]:
    from .runner import known_hosts_path
    argv = ['ssh', '-F', '/dev/null', '-tt', '-p', str(port),
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=4',
            # only a host key a scan already confirmed; over Tailscale, the key of the LAN address is the one checked
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known_hosts_path()}', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', f'HostKeyAlias={alias}',
            '-o', f'IdentityAgent={sock}', '-o', 'IdentitiesOnly=no', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            # nothing of this machine goes along: no agent, no X11, no ports
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'SetEnv=TERM=xterm-256color', '--', f'{user}@{address}']
    return argv + (remote or [])


def open_session(db, conn, *, owner: str, host: str, kind: str, route: str, cols: int, rows: int, audit) -> Session:
    """audit(action, detail): writes to the audit log as the owner, against host."""
    from .remote import child_env
    from .runner import ephemeral_agent
    from .vault import NoBinding, Vault, VaultError
    if kind not in ('ssh', 'serial'):
        raise ValueError('kind is ssh or serial')
    cols, rows = max(20, min(int(cols), 500)), max(5, min(int(rows), 200))
    with _LOCK:
        mine = [s for s in _REGISTRY.values() if not s.closed]
        if len(mine) >= MAX_SESSIONS:
            raise ConsoleError(f'{MAX_SESSIONS} consoles are open already: close one first')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'TERM': 'xterm-256color', 'LANG': os.environ.get('LANG', 'C.UTF-8')}

    if kind == 'ssh':
        rs = routes(conn, host)
        pick = next((r for r in rs if r['route'] == route), None) if route != 'auto' else (rs[0] if rs else None)
        if not pick:
            raise ConsoleError(f'{host} has no {route} address in its last scan' if route != 'auto' else f'{host} has no address to reach')
        lan = next((r['address'] for r in rs if r['route'] == 'lan'), pick['address'])
        s = Session(owner, host, 'ssh', pick['route'], pick['address'], cols, rows)
        target, alias, port, remote_cmd = pick['address'], lan, pick['port'], None
        bind_for = lan
    else:
        via = serial_via(conn, host)
        if not via:
            raise ConsoleError(f'{host} is no VM a scanned libvirt host or this machine runs')
        s = Session(owner, host, 'serial', via['via'], via['host'], cols, rows)
        if via['via'] == 'local':
            target = None
        else:
            r = routes(conn, via['host'])
            if not r:
                raise ConsoleError(f'{via["host"]} has no address to reach')
            target, alias, port, bind_for = r[0]['address'], r[0]['address'], r[0]['port'], r[0]['address']
            remote_cmd = ['virsh', '-c', 'qemu:///system', 'console', '--force', host]

    def audited(action, detail):
        audit(action, {'session': s.id, 'kind': s.kind, 'route': s.route, 'address': s.address, **detail})
    s._audit = audited
    s._start_recording(conn, f'{host} ({s.kind}, {s.route})')

    if kind == 'serial' and target is None:
        s.spawn(['virsh', '-c', 'qemu:///system', 'console', '--force', host], {**child_env(), **env})
    else:
        try:
            with Vault(db, conn).unlock() as vault:
                b = vault.resolve(bind_for, 'console')
                key = vault.decrypt_key(b.key_id)
        except NoBinding as exc:
            s._audit = None
            s.close('no console key')
            # the web UI does it now: the command alone sent people into the container as root, where it cannot reach the database
            why = str(exc).split('. Add one with')[0]
            raise ConsoleError(f'{why}. Allow it in Keys → Bindings (Console: on), or bind a key there with Web console ticked; or run '
                               'storageforge-index vault bind --actions console --key <name> --host <host> --user <user>') from None
        except VaultError as exc:
            s._audit = None
            s.close('vault locked')
            raise ConsoleError(str(exc)) from None
        started = threading.Event()
        failed: list = []

        def hold_agent():
            try:
                with ephemeral_agent(key, ttl=AGENT_HOLD) as sock:
                    s.spawn(_ssh_argv(str(sock), b.user, target, b.port or port, alias, remote_cmd), env)
                    started.set()
                    deadline = time.time() + AGENT_HOLD
                    while time.time() < deadline and not s.closed:
                        time.sleep(1)
            except Exception as exc:          # VaultError and OSError: the console says why, and the audit log too
                failed.append(str(exc))
                started.set()
        threading.Thread(target=hold_agent, name=f'console-agent-{s.id[:6]}', daemon=True).start()
        started.wait(15)
        if failed or s.proc is None:
            s._audit = None      # it never opened: the caller logs the failed open
            s.close('could not start')
            raise ConsoleError(f'could not start ssh: {failed[0] if failed else "timed out"}')
    with _LOCK:
        _REGISTRY[s.id] = s
    audited('console.open', {'recording': s.rec_name, 'cols': cols, 'rows': rows})
    return s


def get(sid: str, owner: str) -> Session:
    """A session of this account. Another account's, admins' included, is not found."""
    with _LOCK:
        s = _REGISTRY.get(sid)
    if not s or s.owner != owner:
        raise LookupError('no such console')
    return s


def mine(owner: str) -> list[dict]:
    with _LOCK:
        return [s.info() for s in _REGISTRY.values() if s.owner == owner and not s.closed]


def reap():
    """Close sessions idle too long or open too long. The server calls it every half minute."""
    now = time.time()
    with _LOCK:
        all_ = list(_REGISTRY.values())
    for s in all_:
        if now - s.active > IDLE:
            s.close(f'idle for {IDLE // 60} minutes')
        elif now - s.started > MAX_LIFE:
            s.close(f'open for {MAX_LIFE // 3600} hours')


def close_all(reason: str = 'StorageForge stopped'):
    with _LOCK:
        all_ = list(_REGISTRY.values())
    for s in all_:
        s.close(reason)


def stamp(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(ts or 0, dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
