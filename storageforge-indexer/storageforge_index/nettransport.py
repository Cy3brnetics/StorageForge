"""Talking to routers and switches, whose shells are not POSIX: a command line over an SSH terminal or Telnet, and single commands over plain SSH.

remote.Transport hands a script to sh -c, which RouterOS and IOS don't have. CliSession is what the other two share: it finds the device's prompt,
answers its pager, knows where a command's output ends, and takes secrets back out of anything it returns or raises. What a device sends is not
trusted: output is capped, control sequences go, and a command holding a control character is refused, so nothing a caller passes can become a second line.

Telnet is plain text, so `encrypted` says so for the Security panel. It also proves nothing about who answered: `host_keys()` is empty. Old SSH ciphers
only come with legacy=True, a choice made per device, and only those the local OpenSSH still has.
"""
from __future__ import annotations

import contextlib
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import tempfile
import termios
import time
import fcntl
import struct
import threading
import tty
from dataclasses import dataclass, field

from .remote import MAX_REMOTE_OUTPUT, RemoteError, Transport, child_env, known_host_keys

LOGIN_TIMEOUT = 10
SETTLE = 0.15
REDACTED = '***'
ANSI = re.compile(rb'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07|[@-Z\\-_])')
PROMPT_END = r'[>#$%]'
ANY_PROMPT = re.compile(rf'^[^\n]{{0,120}}{PROMPT_END}\s?$')
LOGIN_NAME = re.compile(r'(?:user\s?name|login)\s*:\s*$', re.I)
PASSWORD = re.compile(r'pass(?:word|code)?\s*:\s*$', re.I)
REFUSED = re.compile(r'(?:incorrect|invalid|fail|denied|bad password|try again)', re.I)
BAD_COMMAND = re.compile(r'[\x00-\x1f\x7f]')

# Offered on top of what OpenSSH allows, and only where someone said legacy. Each is broken: that is why they are off.
LEGACY = {'KexAlgorithms': ('kex', ('diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1')),
          'HostKeyAlgorithms': ('key', ('ssh-rsa', 'ssh-dss')),
          'PubkeyAcceptedAlgorithms': ('key', ('ssh-rsa',)),
          'Ciphers': ('cipher', ('aes128-cbc', 'aes256-cbc', '3des-cbc'))}


@dataclass(frozen=True)
class CliProfile:
    """How one kind of device behaves at its prompt."""
    name: str
    setup: tuple = ()                   # sent once, after login: what turns its pager off
    more: str = r'(?:--\s?more\s?--|<--- more --->|\[more\]|press any key to continue)\s*$'        # a pager waiting at the end of the text
    more_reply: bytes = b' '
    user_suffix: str = ''               # RouterOS takes terminal settings in the user name


PROFILES = {
    'generic': CliProfile('generic'),
    'cisco': CliProfile('cisco', setup=('terminal length 0', 'terminal width 512')),
    # c: no colour, e: a dumb terminal, t: no probing what the terminal can do, 512w: lines don't wrap. The pager is answered if one still shows
    'routeros': CliProfile('routeros', user_suffix='+cet512w', more=r'-- \[Q quit\|D dump\|down\]\s*$', more_reply=b'd'),
    'openwrt': CliProfile('openwrt'),
    'pfsense': CliProfile('pfsense'),
}


def legacy_options(query=None) -> list[str]:
    """ssh -o values for old devices, each algorithm only if this OpenSSH still knows it: naming a removed one makes ssh refuse to start."""
    def known(kind: str) -> set[str]:
        return set(subprocess.run(['ssh', '-Q', kind], capture_output=True, text=True, timeout=10, env=child_env()).stdout.split())
    query = query or known
    out = []
    for option, (kind, names) in LEGACY.items():
        have = query(kind)
        usable = [n for n in names if n in have]
        if usable:
            out.append(f'{option}=+{",".join(usable)}')
    return out


def check_command(command: str) -> None:
    if not command or BAD_COMMAND.search(command):
        raise ValueError('a device command is one line, with no control characters')


class CliSession:
    """A prompt-driven shell. Subclasses give it _read and _write."""
    encrypted = True
    eol = b'\n'

    def __init__(self, host: str, profile: str = 'generic', secrets: tuple = (), command_timeout: int = 120):
        if profile not in PROFILES:
            raise ValueError(f'no device profile {profile!r}')
        self.host, self.profile, self.command_timeout = host, PROFILES[profile], command_timeout
        self._secrets = tuple(s for s in secrets if s)
        self._more = re.compile(self.profile.more, re.I)
        self._prompt: re.Pattern | None = None
        self._lock = threading.Lock()
        self._closed = False

    # ── what a subclass gives ───────────────────────────────────────
    def _read(self, wait: float) -> bytes:
        """What has arrived, b'' if nothing did in wait seconds. EOFError once the other end has gone."""
        raise NotImplementedError

    def _write(self, data: bytes) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def host_keys(self) -> list[str]:
        return []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ── text ────────────────────────────────────────────────────────
    def scrub(self, text: str) -> str:
        """Secrets out of anything leaving this class: a device may echo what it was sent."""
        for s in self._secrets:
            text = text.replace(s, REDACTED)
        return text

    @staticmethod
    def _clean(raw: bytes) -> str:
        """Bytes as a terminal would show them: no control sequences, carriage returns or rubbed-out characters."""
        raw = ANSI.sub(b'', raw)
        out = bytearray()
        i = 0
        while i < len(raw):
            b = raw[i]
            i += 1
            if b == 8:
                if out and out[-1] != 10:
                    out.pop()
            elif b == 13:
                # a return with no newline after it starts the line over, which is how RouterOS redraws its prompt
                while i < len(raw) and raw[i] == 13:
                    i += 1
                if i < len(raw) and raw[i] != 10:
                    cut = out.rfind(b'\n') + 1
                    del out[cut:]
            elif b == 10 or b == 9 or b >= 32:
                if b != 127:
                    out.append(b)
        return out.decode('utf-8', 'replace')

    def _is_prompt(self, line: str) -> bool:
        if self._prompt is not None:
            return bool(self._prompt.fullmatch(line))
        return bool(ANY_PROMPT.fullmatch(line))

    def _learn_prompt(self, line: str) -> None:
        """From here a prompt is this device's own, not anything ending in #: output may well hold one. Its other modes still count: R1(config)#, [a@b] /ip>."""
        name = re.sub(rf'{PROMPT_END}\s*$', '', line.rstrip()).rstrip()
        self._prompt = re.compile(rf'{re.escape(name)}(?:\([^)\n]*\)|\s/[^\n>#$%]*)?\s*{PROMPT_END}\s?')

    def _until_prompt(self, deadline: float, what: str) -> str:
        """Everything up to and including the next prompt, answering the pager. The prompt is the last line, with nothing after it."""
        raw = bytearray()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise subprocess.TimeoutExpired(self.scrub(what), self.command_timeout)
            try:
                chunk = self._read(min(left, 1.0))
            except EOFError:
                said = self.scrub(self._clean(bytes(raw))).strip()[-300:]
                raise RemoteError(f'{self.host}: the connection ended during {self.scrub(what)}' + (f': {said}' if said else '')) from None
            if not chunk:
                continue
            raw += chunk
            while True:     # everything that has arrived is judged before waiting for more
                if len(raw) > MAX_REMOTE_OUTPUT:
                    self.close()
                    raise RemoteError(f'{self.host}: the device sent more than {MAX_REMOTE_OUTPUT >> 20} MiB; refused')
                text = self._clean(bytes(raw))
                tail = text.rsplit('\n', 1)[-1]
                if self._more.search(tail):
                    # the pager's own words are not output: drop them where they sit
                    cut = raw.rfind(b'\n') + 1
                    del raw[cut:]
                    self._write(self.profile.more_reply)
                    break
                if not self._is_prompt(tail):
                    break
                # a device that redraws its prompt is still talking: this one only counts once it has finished
                try:
                    more = self._read(SETTLE)
                except EOFError:
                    return text
                if not more:
                    return text
                raw += more

    def _drain(self) -> None:
        """What's still arriving from before now, so a redrawn prompt isn't taken for the end of the next command."""
        with contextlib.suppress(EOFError):
            while self._read(SETTLE):
                pass

    def _ready(self, first_text: str = '') -> None:
        """Logged in, at some prompt. Ask for a fresh one, since a login banner can end in anything, then learn it and turn the pager off."""
        self._write(self.eol)
        text = self._until_prompt(time.monotonic() + LOGIN_TIMEOUT, 'waiting for its prompt')
        self._learn_prompt(text.rsplit('\n', 1)[-1])
        for command in self.profile.setup:
            self.run(command, timeout=LOGIN_TIMEOUT)

    # ── the point of it ─────────────────────────────────────────────
    def run(self, command: str, timeout: int | None = None) -> str:
        """The command's output: no echo of it, and no prompt after it. Takes the place of Transport.run for a device."""
        check_command(command)
        with self._lock:
            if self._closed:
                raise RemoteError(f'{self.host}: this session has been closed')
            self._drain()
            self._write(command.encode() + self.eol)
            text = self._until_prompt(time.monotonic() + (timeout or self.command_timeout), command)
        lines = text.split('\n')[:-1]
        # a device echoes the command, wrapped or not. Compared without spaces: wrapping may add some
        if lines and lines[0].replace(' ', '').endswith(command.replace(' ', '')):
            lines = lines[1:]
        return self.scrub('\n'.join(line.rstrip() for line in lines))

    def enable(self, password: str | None) -> None:
        """Cisco's privileged mode, from > to #. Refused is an error: everything after it would read as empty."""
        with self._lock:
            self._write(b'enable' + self.eol)
            deadline, raw = time.monotonic() + LOGIN_TIMEOUT, bytearray()
            while time.monotonic() < deadline:
                raw += self._read(0.5)
                tail = self._clean(bytes(raw)).rsplit('\n', 1)[-1]
                if PASSWORD.search(tail):
                    if not password:
                        raise RemoteError(f'{self.host}: enable wants a password, and none is stored')
                    self._write(password.encode() + self.eol)
                    raw.clear()
                elif tail.rstrip().endswith('#'):
                    self._learn_prompt(tail)
                    return
                elif tail.rstrip().endswith('>') and raw.count(b'\n') > 1:
                    raise RemoteError(f'{self.host}: enable was refused')
            raise RemoteError(f'{self.host}: enable was refused')


# ── SSH, with a terminal ────────────────────────────────────────────
class NetworkTransport(CliSession):
    """ssh -tt, for a device that gives a shell and no way to run a single command. A password goes through SSH_ASKPASS and only to a host key already pinned."""

    def __init__(self, host: str, user: str, profile: str = 'generic', port: int = 22, password: str | None = None, agent_sock: str | None = None, key: str | None = None,
                 known_hosts: str | None = None, legacy: bool = False, connect_timeout: int = 10, command_timeout: int = 120, enable_password: str | None = None):
        super().__init__(host, profile, (password, enable_password), command_timeout)
        self.user, self.port, self.known_hosts, self.legacy = user, port, known_hosts, legacy
        self._work = tempfile.mkdtemp(prefix='sfnet-ssh-')
        argv = ['ssh', '-F', '/dev/null', '-tt', '-p', str(port), '-o', f'ConnectTimeout={connect_timeout}', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=4',
                '-o', 'StrictHostKeyChecking=' + ('yes' if password else 'accept-new'), '-o', 'LogLevel=ERROR']
        if known_hosts:
            argv += ['-o', f'UserKnownHostsFile={known_hosts}', '-o', 'GlobalKnownHostsFile=/dev/null']
        env = child_env()
        if password:
            from .keyinstall import askpass_path
            argv += ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'NumberOfPasswordPrompts=1']
            env.update(SSH_ASKPASS=askpass_path(), SSH_ASKPASS_REQUIRE='force', DISPLAY='none', STORAGEFORGE_ASKPASS_SECRET=password)
        else:
            argv += ['-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no']
        if agent_sock:
            argv += ['-o', f'IdentityAgent={agent_sock}']
        if key:
            argv += ['-i', os.path.expanduser(key), '-o', 'IdentitiesOnly=yes']
        if legacy:
            for opt in legacy_options():
                argv += ['-o', opt]
        argv += ['--', f'{user}{self.profile.user_suffix}@{host}']
        self._fd, slave = pty.openpty()
        tty.setraw(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 0, 512, 0, 0))     # no lines to page, and none to wrap
        try:
            self._proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=self._work, start_new_session=True)
        except BaseException:
            os.close(self._fd)
            shutil.rmtree(self._work, ignore_errors=True)
            raise
        finally:
            os.close(slave)
        try:
            self._ready()
        except subprocess.TimeoutExpired:
            self.close()
            raise RemoteError(f'{host}: no prompt within {LOGIN_TIMEOUT} s of connecting') from None
        except BaseException:
            self.close()
            raise

    def _read(self, wait: float) -> bytes:
        ready, _, _ = select.select([self._fd], [], [], wait)
        if not ready:
            return b''
        try:
            data = os.read(self._fd, 1 << 16)
        except OSError:                     # Linux: EIO once the other side of the terminal has closed
            raise EOFError from None
        if not data:
            raise EOFError
        return data

    def _write(self, data: bytes) -> None:
        try:
            os.write(self._fd, data)
        except OSError:
            raise RemoteError(f'{self.host}: the connection has gone') from None

    def host_keys(self) -> list[str]:
        return known_host_keys(self.host, self.port, self.known_hosts)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._proc.kill()
        self._proc.wait()
        os.close(self._fd)
        shutil.rmtree(self._work, ignore_errors=True)


# ── Telnet ──────────────────────────────────────────────────────────
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA = 1, 3


class TelnetFilter:
    """RFC 854, split from the socket so it can be tested byte by byte: a negotiation may arrive across two reads. feed() gives the data, and what to answer."""

    def __init__(self):
        self._state, self._verb, self._sent = 'data', 0, set()

    def _answer(self, verb: int, option: int) -> bytes:
        # the server may echo and suppress go-ahead, and nothing else. An option already answered isn't answered again: that is how two ends loop forever
        if verb in (WILL, WONT):
            reply = DO if verb == WILL and option in (ECHO, SGA) else DONT
        else:
            reply = WILL if verb == DO and option == SGA else WONT
        if (reply, option) in self._sent:
            return b''
        self._sent.add((reply, option))
        return bytes((IAC, reply, option))

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        out, reply = bytearray(), bytearray()
        for b in data:
            if self._state == 'data':
                if b == IAC:
                    self._state = 'iac'
                else:
                    out.append(b)
            elif self._state == 'iac':
                if b == IAC:
                    out.append(IAC)
                    self._state = 'data'
                elif b in (WILL, WONT, DO, DONT):
                    self._verb, self._state = b, 'option'
                elif b == SB:
                    self._state = 'sub'
                else:                       # NOP, AYT and the like: nothing a client must do
                    self._state = 'data'
            elif self._state == 'option':
                reply += self._answer(self._verb, b)
                self._state = 'data'
            elif self._state == 'sub':
                if b == IAC:
                    self._state = 'sub-iac'
            elif self._state == 'sub-iac':
                self._state = 'data' if b == SE else 'sub'
        return bytes(out), bytes(reply)


class TelnetTransport(CliSession):
    """A device that only offers Telnet. No external binary, and no telnetlib, which Python 3.13 removed. Everything here, the password included, crosses the network in the clear."""
    encrypted = False
    eol = b'\r\n'

    def __init__(self, host: str, user: str | None = None, password: str | None = None, profile: str = 'generic', port: int = 23, connect_timeout: int = 10,
                 command_timeout: int = 120, enable_password: str | None = None):
        super().__init__(host, profile, (password, enable_password), command_timeout)
        self.user, self.password, self._filter, self._pending = user, password, TelnetFilter(), b''
        try:
            self._sock = socket.create_connection((host, port), timeout=connect_timeout)
        except OSError as exc:
            raise RemoteError(f'{host}:{port}: {exc}') from None
        self._sock.setblocking(False)
        try:
            self._login()
            self._ready()
        except subprocess.TimeoutExpired:
            self.close()
            raise RemoteError(f'{host}: no prompt within {LOGIN_TIMEOUT} s of logging in') from None
        except BaseException:
            self.close()
            raise

    def _login(self) -> None:
        """Answers what it is asked, and each thing once: asked again means refused. Ends at the first thing that looks like a prompt."""
        deadline, raw, gave_user, gave_password = time.monotonic() + LOGIN_TIMEOUT, bytearray(), False, False
        while True:
            if time.monotonic() >= deadline:
                raise RemoteError(f'{self.host}: the login did not finish within {LOGIN_TIMEOUT} s')
            try:
                chunk = self._read(0.2)
            except EOFError:
                raise RemoteError(f'{self.host}: it hung up during the login' + (': the password may be wrong' if gave_password else '')) from None
            if not chunk:
                continue
            raw += chunk
            text = self._clean(bytes(raw))
            tail = text.rsplit('\n', 1)[-1]
            if LOGIN_NAME.search(tail):
                if gave_user or not self.user:
                    raise RemoteError(f'{self.host}: the login was refused' if gave_user else f'{self.host}: it asks for a user name, and none is stored')
                self._write((self.user + self.profile.user_suffix).encode() + self.eol)
                gave_user = True
                raw.clear()
            elif PASSWORD.search(tail):
                if gave_password or self.password is None:
                    raise RemoteError(f'{self.host}: the login was refused' if gave_password else f'{self.host}: it asks for a password, and none is stored')
                self._write(self.password.encode() + self.eol)
                gave_password = True
                raw.clear()
            elif gave_password and REFUSED.search(text) and not ANY_PROMPT.fullmatch(tail):
                raise RemoteError(f'{self.host}: the login was refused')
            elif ANY_PROMPT.fullmatch(tail):
                return

    def _read(self, wait: float) -> bytes:
        if self._closed:
            raise EOFError
        ready, _, _ = select.select([self._sock], [], [], wait)
        if not ready:
            return b''
        try:
            data = self._sock.recv(1 << 16)
        except BlockingIOError:
            return b''
        except OSError:
            raise EOFError from None
        if not data:
            raise EOFError
        out, reply = self._filter.feed(data)
        if reply:
            self._send_raw(reply)
        return out

    def _send_raw(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except BlockingIOError:
            self._sock.setblocking(True)
            self._sock.settimeout(LOGIN_TIMEOUT)
            try:
                self._sock.sendall(data)
            except OSError:
                raise RemoteError(f'{self.host}: the connection has gone') from None
            finally:
                self._sock.setblocking(False)
        except OSError:
            raise RemoteError(f'{self.host}: the connection has gone') from None

    def _write(self, data: bytes) -> None:
        self._send_raw(data.replace(bytes((IAC,)), bytes((IAC, IAC))))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._sock.close()


# ── SSH, one command at a time ──────────────────────────────────────
@dataclass
class DirectTransport(Transport):
    """A device whose SSH runs a command it is given, with no terminal: ssh admin@router "/ip/address/print as-value". The command goes as it is, since there is no sh to quote for."""
    legacy: bool = False
    extra_opts: list[str] = field(default_factory=list)
    password: str | None = None         # through SSH_ASKPASS, and only to a host key already pinned: set strict
    posix: bool = False                 # it has a shell (OpenWrt, pfSense): the script goes to sh as on any host

    def __post_init__(self):
        super().__post_init__()
        if self.legacy:
            self.extra_opts = [*self.extra_opts, *legacy_options()]
        if self.password and not self.strict:
            raise ValueError('a password only goes to a host key already pinned: set strict')

    def env(self) -> dict:
        env = super().env()
        if self.password:
            from .keyinstall import askpass_path
            env.update(SSH_ASKPASS=askpass_path(), SSH_ASKPASS_REQUIRE='force', DISPLAY='none', STORAGEFORGE_ASKPASS_SECRET=self.password)
        return env

    def argv(self, script: str) -> list[str]:
        if not self.posix:
            check_command(script)
        argv = super().argv(script)
        if self.password:
            kept = []
            for i, a in enumerate(argv):
                if a == 'BatchMode=yes' or (a == '-o' and i + 1 < len(argv) and argv[i + 1] == 'BatchMode=yes'):
                    continue
                kept.append(a)
            argv = kept
            at = argv.index('--')
            argv[at:at] = ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'NumberOfPasswordPrompts=1']
        return argv if self.posix else [*argv[:-1], script]
