"""Talking to routers: Telnet against a real socket server that negotiates as RFC 854 says, and SSH against a real sshd whose login shell acts like a switch, pager
included. Real router VMs come with lab tier 12. Run with: python3 -m unittest discover -s tests -v"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import backup, nettransport as nt, vault
from storageforge_index.db import Database
from storageforge_index.remote import RemoteError

SSHD = shutil.which('sshd') or next((p for p in ('/usr/sbin/sshd', '/usr/bin/sshd') if os.path.exists(p)), None)
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
SECRET = 'device tests secret, thrown away with its database'
PW = 'hunter2-not-real'

# A switch, as far as a terminal can tell: a banner, a prompt, a pager until told to stop, and modes that change the prompt.
SWITCH = r'''
import os, sys, tty
log = os.environ['SWITCH_LOG']
out = lambda s: (sys.stdout.write(s), sys.stdout.flush())
if sys.stdin.isatty():
    tty.setcbreak(0)
paging, prompt, lines = True, 'SW1>', [f'interface Gi0/{i}' for i in range(60)]
out('*** authorised use only. Disconnect now # \r\n')
out(prompt)
def page():
    for i, line in enumerate(lines):
        out(line + '\r\n')
        if paging and i % 20 == 19 and i != len(lines) - 1:
            out(' --More-- ')
            sys.stdin.read(1)
            out('\b' * 10 + ' ' * 10 + '\b' * 10)
line = ''
while True:
    c = sys.stdin.read(1)
    if not c:
        break
    if c not in '\r\n':
        line += c
        out(c)
        continue
    out('\r\n')
    open(log, 'a').write(line + '\n')
    if line == 'terminal length 0':
        paging = False
    elif line == 'show interfaces':
        page()
    elif line == 'show hash':
        out('a line of output that ends in a hash #\r\nand another that looks like one>\r\nSW2#\r\n')
    elif line == 'colour':
        out('\x1b[31mred\x1b[0m and bo\bold\r\n')
    elif line == 'enable':
        out('Password: ')
        got = ''
        while (c := sys.stdin.read(1)) not in '\r\n':
            got += c
        out('\r\n')
        if got == 'enable-secret':
            prompt = 'SW1#'
    elif line == 'configure terminal':
        prompt = 'SW1(config)#'
    elif line == 'end':
        prompt = 'SW1#'
    elif line == 'leak':
        out('the password is ' + os.environ.get('LEAK', '') + '\r\n')
    elif line == 'hang':
        sys.stdin.read()
    elif line == 'die':
        out('going down\r\n')
        sys.exit(0)
    elif line == 'flood':
        chunk = 'x' * 65536 + '\r\n'
        while True:
            out(chunk)
    line = ''
    out(prompt)
'''


class FakeTelnet(threading.Thread):
    """Serves one kind of device. It speaks the bytes itself, as telnetd would, and keeps what it was told."""

    def __init__(self, user='admin', password=PW, prompt=b'R1>', banner=b'Welcome to R1\r\n', ask_user=True, negotiate=True, split=False, chatty=False, silent=False):
        super().__init__(daemon=True)
        self.user, self.password, self.prompt, self.banner, self.ask_user = user, password, prompt, banner, ask_user
        self.negotiate, self.split, self.chatty, self.silent = negotiate, split, chatty, silent
        self.replies, self.commands, self.raw = [], [], bytearray()
        self.srv = socket.create_server(('127.0.0.1', 0))
        self.port = self.srv.getsockname()[1]
        self.start()

    def send(self, conn, data: bytes):
        if self.split:      # one byte a read: negotiation sits across reads
            for i in range(len(data)):
                conn.sendall(data[i:i + 1])
                time.sleep(0.0005)
        else:
            conn.sendall(data)

    def read_line(self, conn) -> bytes:
        out = bytearray()
        while True:
            c = conn.recv(1)
            if not c:
                raise EOFError
            self.raw += c
            if c[0] == IAC:
                a = conn.recv(1)
                self.raw += a
                if a[0] == IAC:
                    out.append(IAC)
                elif a[0] in (WILL, WONT, DO, DONT):
                    opt = conn.recv(1)
                    self.raw += opt
                    self.replies.append((a[0], opt[0]))
                continue
            if c == b'\n':
                return bytes(out).rstrip(b'\r')
            out += c

    def run(self):
        conn, _ = self.srv.accept()
        try:
            if self.silent:
                time.sleep(30)
            if self.negotiate:
                self.send(conn, bytes((IAC, WILL, 1, IAC, WILL, 3, IAC, DO, 24, IAC, DO, 31, IAC, SB, 24, 1, IAC, SE)))
            if self.ask_user:
                self.send(conn, b'\r\nUsername: ')
                got_user = self.read_line(conn).decode()
            else:
                got_user = self.user
            self.send(conn, b'Password: ')
            got = self.read_line(conn).decode()
            if got != self.password or got_user != self.user:
                self.send(conn, b'\r\n% Authentication failed\r\n')
                if self.ask_user:
                    self.send(conn, b'Username: ')
                return
            self.send(conn, self.banner + self.prompt)
            if self.chatty:     # asks the same again: a client that answers each time would loop for ever
                self.send(conn, bytes((IAC, WILL, 1, IAC, DO, 24)))
            while True:
                line = self.read_line(conn).decode('latin-1')
                if line:
                    self.commands.append(line)
                if line == 'data':
                    self.send(conn, b'value ' + bytes((IAC, IAC)) + b' end\r\n')
                elif line == 'show version':
                    self.send(conn, b'IOS 15.2\r\n')
                elif line == 'echo-secret':
                    self.send(conn, f'stored as {self.password}\r\n'.encode())
                elif line == 'hang':
                    time.sleep(30)
                self.send(conn, self.prompt)
        except (EOFError, OSError):
            pass
        finally:
            conn.close()
            self.srv.close()


class TheFilter(unittest.TestCase):
    def test_data_passes_and_a_doubled_iac_is_one_byte(self):
        self.assertEqual(nt.TelnetFilter().feed(b'ab' + bytes((IAC, IAC)) + b'c'), (b'ab\xffc', b''))

    def test_what_it_agrees_to_and_refuses(self):
        f = nt.TelnetFilter()
        _, reply = f.feed(bytes((IAC, WILL, 1, IAC, WILL, 3, IAC, WILL, 5, IAC, DO, 3, IAC, DO, 24)))
        self.assertEqual(reply, bytes((IAC, DO, 1, IAC, DO, 3, IAC, DONT, 5, IAC, WILL, 3, IAC, WONT, 24)))

    def test_an_option_is_answered_once(self):
        f = nt.TelnetFilter()
        f.feed(bytes((IAC, DO, 24)))
        self.assertEqual(f.feed(bytes((IAC, DO, 24)))[1], b'')

    def test_a_negotiation_may_split_anywhere(self):
        whole = b'x' + bytes((IAC, WILL, 1)) + b'y' + bytes((IAC, SB, 24, 1, 2, IAC, SE)) + b'z' + bytes((IAC, IAC))
        f, out, reply = nt.TelnetFilter(), bytearray(), bytearray()
        for i in range(len(whole)):
            o, r = f.feed(whole[i:i + 1])
            out += o
            reply += r
        self.assertEqual(bytes(out), b'xyz\xff')
        self.assertEqual(bytes(reply), bytes((IAC, DO, 1)))


class Telnet(unittest.TestCase):
    def connect(self, server=None, **kw):
        server = server or FakeTelnet()
        t = nt.TelnetTransport('127.0.0.1', **{'user': 'admin', 'password': PW, 'port': server.port, 'command_timeout': 5, **kw})
        self.addCleanup(t.close)
        return server, t

    def test_a_login_negotiation_and_a_command(self):
        server, t = self.connect()
        self.assertEqual(t.run('show version'), 'IOS 15.2')
        self.assertEqual(server.commands, ['show version'])
        self.assertIn((DO, 1), server.replies)
        self.assertIn((WONT, 24), server.replies)
        self.assertFalse(t.encrypted)
        self.assertEqual(t.host_keys(), [], 'Telnet proves nothing about who answered')

    def test_commands_end_in_cr_lf(self):
        server, t = self.connect()
        t.run('show version')
        self.assertIn(b'show version\r\n', bytes(server.raw))

    def test_the_login_survives_one_byte_at_a_time(self):
        _, t = self.connect(FakeTelnet(split=True))
        self.assertEqual(t.run('show version'), 'IOS 15.2')

    def test_a_password_only_vty_line(self):
        _, t = self.connect(FakeTelnet(ask_user=False), user=None)
        self.assertEqual(t.run('show version'), 'IOS 15.2')

    def test_a_doubled_iac_in_output_and_in_what_is_sent(self):
        server, t = self.connect()
        self.assertEqual(t.run('data').encode('utf-8', 'surrogateescape').count(b'end'), 1)
        t._write(b'x\xffy\r\n')
        t._until_prompt(time.monotonic() + 5, 'test')
        self.assertIn(bytes((ord('x'), IAC, IAC, ord('y'))), bytes(server.raw))

    def test_a_server_repeating_itself_gets_no_second_answer(self):
        server, t = self.connect(FakeTelnet(chatty=True))
        t.run('show version')
        self.assertEqual(server.replies.count((DO, 1)), 1)

    def test_a_wrong_password_says_so_and_never_says_the_password(self):
        with self.assertRaises(RemoteError) as seen:
            self.connect(password='wrong-password')
        self.assertIn('refused', str(seen.exception))
        self.assertNotIn('wrong-password', str(seen.exception))

    def test_asked_for_what_it_does_not_have(self):
        with self.assertRaisesRegex(RemoteError, 'user name'):
            self.connect(user=None)
        with self.assertRaisesRegex(RemoteError, 'password'):
            self.connect(password=None)

    def test_a_silent_server_times_out_on_the_login(self):
        server = FakeTelnet(silent=True)
        with mock.patch.object(nt, 'LOGIN_TIMEOUT', 1):
            started = time.monotonic()
            with self.assertRaisesRegex(RemoteError, 'did not finish'):
                self.connect(server)
            self.assertLess(time.monotonic() - started, 5)

    def test_a_port_nobody_listens_on(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            free = s.getsockname()[1]
        with self.assertRaises(RemoteError):
            nt.TelnetTransport('127.0.0.1', 'admin', PW, port=free)

    def test_a_command_that_never_ends_times_out(self):
        _, t = self.connect(command_timeout=1)
        with self.assertRaises(subprocess.TimeoutExpired):
            t.run('hang')

    def test_a_password_the_device_echoes_is_taken_out(self):
        _, t = self.connect()
        got = t.run('echo-secret')
        self.assertNotIn(PW, got)
        self.assertIn(nt.REDACTED, got)

    def test_a_second_line_cannot_be_smuggled_in(self):
        server, t = self.connect()
        for bad in ('show version\nreload', 'show\r\nreload', 'a\x03', '', 'a\x7f'):
            with self.assertRaises(ValueError):
                t.run(bad)
        self.assertEqual(server.commands, [])

    def test_after_closing_nothing_runs(self):
        _, t = self.connect()
        t.close()
        t.close()
        with self.assertRaises(RemoteError):
            t.run('show version')


class Text(unittest.TestCase):
    def session(self, profile='generic'):
        return nt.CliSession('h', profile)

    def test_a_terminal_rubbing_out_and_colouring(self):
        self.assertEqual(self.session()._clean(b'\x1b[31mred\x1b[0m bo\x08\x08no\r\n'), 'red no\n')

    def test_a_learned_prompt_is_this_device_only(self):
        s = self.session()
        self.assertTrue(s._is_prompt('anything#'))
        s._learn_prompt('R1#')
        for yes in ('R1#', 'R1>', 'R1(config)#', 'R1(config-if)#'):
            self.assertTrue(s._is_prompt(yes), yes)
        for no in ('R2#', 'a line ending in #', 'R1', 'xR1#'):
            self.assertFalse(s._is_prompt(no), no)

    def test_routeros_prompts_with_a_path(self):
        s = self.session('routeros')
        s._learn_prompt('[admin@MikroTik] > ')
        self.assertTrue(s._is_prompt('[admin@MikroTik] > '))
        self.assertTrue(s._is_prompt('[admin@MikroTik] /ip> '))
        self.assertFalse(s._is_prompt('[admin@Other] > '))

    def test_an_unknown_profile(self):
        with self.assertRaises(ValueError):
            nt.CliSession('h', 'juniper')


class Legacy(unittest.TestCase):
    def test_only_what_this_openssh_still_has_is_offered(self):
        have = {'kex': {'diffie-hellman-group14-sha1'}, 'key': {'ssh-rsa'}, 'cipher': set()}
        self.assertEqual(nt.legacy_options(have.__getitem__), ['KexAlgorithms=+diffie-hellman-group14-sha1', 'HostKeyAlgorithms=+ssh-rsa', 'PubkeyAcceptedAlgorithms=+ssh-rsa'])

    def test_this_machines_openssh_accepts_what_it_is_given(self):
        opts = nt.legacy_options()
        args = [x for o in opts for x in ('-o', o)]
        r = subprocess.run(['ssh', '-G', *args, 'example.invalid'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_direct_command_goes_as_it_is(self):
        t = nt.DirectTransport(host='router', user='admin', extra_opts=['ConnectTimeout=3'])
        self.addCleanup(t.close)
        argv = t.argv('/ip/address/print as-value')
        self.assertEqual(argv[-1], '/ip/address/print as-value')
        self.assertEqual(argv[-2], 'admin@router')
        self.assertIn('-T', argv)
        with self.assertRaises(ValueError):
            t.argv('/ip/address/print\n/system/reset-configuration')

    def test_legacy_is_asked_for(self):
        t = nt.DirectTransport(host='router', user='admin')
        self.addCleanup(t.close)
        self.assertFalse(any('=+' in x for x in t.argv('x')))
        with mock.patch.object(nt, 'legacy_options', lambda: ['Ciphers=+aes128-cbc']):
            old = nt.DirectTransport(host='router', user='admin', legacy=True)
        self.addCleanup(old.close)
        self.assertIn('Ciphers=+aes128-cbc', old.argv('x'))


@unittest.skipUnless(SSHD, 'needs sshd (CI has it)')
class RealSshTerminal(unittest.TestCase):
    """ssh -tt to a real sshd. Password logins need root's sshd, so they wait for the lab: everything else here is the real path."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        key, cls.client_key = cls.tmp / 'host_key', cls.tmp / 'client_key'
        for k in (key, cls.client_key):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(k)], check=True)
        (cls.tmp / 'authorized').write_text((cls.tmp / 'client_key.pub').read_text())
        (cls.tmp / 'authorized').chmod(0o600)
        shell = cls.tmp / 'switch.py'
        shell.write_text(SWITCH)
        cls.log = cls.tmp / 'commands'
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            cls.port = s.getsockname()[1]
        conf = cls.tmp / 'sshd_config'
        conf.write_text(f'Port {cls.port}\nListenAddress 127.0.0.1\nHostKey {key}\nPidFile {cls.tmp}/pid\nAuthorizedKeysFile {cls.tmp}/authorized\nPasswordAuthentication no\n'
                        f'KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nSetEnv SWITCH_LOG={cls.log} LEAK={PW}\nForceCommand {sys.executable} {shell}\n')
        cls.sshd = subprocess.Popen([SSHD, '-D', '-e', '-f', str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls.sshd.wait)
        cls.addClassCleanup(cls.sshd.kill)
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1', cls.port)) == 0:
                    return
            time.sleep(0.05)
        raise unittest.SkipTest('sshd would not start here')

    def connect(self, profile='cisco', **kw):
        t = nt.NetworkTransport('127.0.0.1', os.environ.get('USER') or 'root', profile, port=self.port, key=str(self.client_key), known_hosts=str(self.tmp / 'known_hosts'), command_timeout=8, **kw)
        self.addCleanup(t.close)
        return t

    def test_it_finds_the_prompt_past_a_banner_and_turns_the_pager_off(self):
        t = self.connect()
        lines = t.run('show interfaces').splitlines()
        self.assertEqual(lines, [f'interface Gi0/{i}' for i in range(60)])
        self.assertIn('terminal length 0', self.log.read_text())
        self.assertTrue(t.encrypted)

    def test_a_device_with_no_pager_setting_has_its_pager_answered(self):
        t = self.connect('generic')
        lines = t.run('show interfaces').splitlines()
        self.assertEqual(lines, [f'interface Gi0/{i}' for i in range(60)], 'a line went missing, or the pager is in the output')

    def test_output_that_looks_like_a_prompt_does_not_end_the_command(self):
        t = self.connect()
        self.assertEqual(t.run('show hash').splitlines(), ['a line of output that ends in a hash #', 'and another that looks like one>', 'SW2#'])
        self.assertEqual(t.run('show interfaces').splitlines()[0], 'interface Gi0/0')

    def test_colour_and_rubbing_out_are_gone(self):
        self.assertEqual(self.connect().run('colour'), 'red and bold')

    def test_enable_and_a_mode_that_changes_the_prompt(self):
        t = self.connect(enable_password='enable-secret')
        t.enable('enable-secret')
        self.assertEqual(t.run('configure terminal'), '')
        self.assertEqual(t.run('end'), '')
        self.assertEqual(t.run('colour'), 'red and bold')

    def test_enable_refused_is_an_error(self):
        t = self.connect()
        with mock.patch.object(nt, 'LOGIN_TIMEOUT', 2):
            with self.assertRaisesRegex(RemoteError, 'refused'):
                t.enable('wrong')

    def test_enable_with_no_password_says_so(self):
        with self.assertRaisesRegex(RemoteError, 'none is stored'):
            self.connect().enable(None)

    def test_a_secret_the_device_prints_is_taken_out(self):
        t = self.connect(enable_password=PW)
        got = t.run('leak')
        self.assertNotIn(PW, got)
        self.assertIn(nt.REDACTED, got)

    def test_a_dying_device_is_an_error_with_what_it_said(self):
        t = self.connect()
        with self.assertRaisesRegex(RemoteError, 'going down'):
            t.run('die')

    def test_a_hung_command_times_out(self):
        t = self.connect()
        with self.assertRaises(subprocess.TimeoutExpired):
            t.run('hang', timeout=1)

    def test_a_flood_is_refused_at_the_cap(self):
        t = self.connect()
        with mock.patch.object(nt, 'MAX_REMOTE_OUTPUT', 1 << 20):
            with self.assertRaisesRegex(RemoteError, 'refused'):
                t.run('flood', timeout=30)

    def test_the_host_key_is_pinned_and_a_changed_one_is_refused(self):
        t = self.connect()
        self.assertTrue(t.host_keys())
        wrong = self.tmp / 'known_hosts_wrong'
        other = self.tmp / 'other'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True)
        wrong.write_text(f'[127.0.0.1]:{self.port} {(self.tmp / "other.pub").read_text()}')
        with self.assertRaises(RemoteError):
            nt.NetworkTransport('127.0.0.1', 'x', 'cisco', port=self.port, key=str(self.client_key), known_hosts=str(wrong), command_timeout=8)

    def test_no_key_it_accepts_is_an_error_and_not_a_hang(self):
        other = self.tmp / 'stranger'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True)
        started = time.monotonic()
        with self.assertRaises(RemoteError):
            nt.NetworkTransport('127.0.0.1', os.environ.get('USER') or 'root', 'cisco', port=self.port, key=str(other), known_hosts=str(self.tmp / 'known_hosts'))
        self.assertLess(time.monotonic() - started, 15)

    def test_a_direct_command_reaches_the_device(self):
        t = nt.DirectTransport(host='127.0.0.1', user=os.environ.get('USER') or 'root', port=self.port, key=str(self.client_key), known_hosts=str(self.tmp / 'known_hosts'))
        self.addCleanup(t.close)
        # ForceCommand runs the switch, which reads stdin: with no stdin it ends after its banner
        self.assertIn('authorised use only', t.run('show version', timeout=8))


class Credentials(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        vault.KDF_DEFAULTS.update(time_cost=1, memory_kib=8192, lanes=1)
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET, 'STORAGEFORGE_BACKUP_DIR': str(self.tmp / 'backups'), 'STORAGEFORGE_DATA_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        self.path = self.tmp / 'index.db'
        self.db = Database(str(self.path))
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        vault.Vault(self.db, self.conn, SECRET.encode()).init()

    def test_kept_sealed_read_back_listed_without_it_and_removed(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw1', 'admin', PW, 'enable-secret')
            self.assertEqual(v.credential('sw1'), {'username': 'admin', 'password': PW, 'enable': 'enable-secret'})
            listed = v.list_credentials()
            self.assertEqual(listed[0]['name'], 'sw1')
            self.assertNotIn(PW, str(listed))
        self.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self.assertNotIn(PW.encode(), self.path.read_bytes())
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.remove_credential('sw1'), 1)
            with self.assertRaisesRegex(vault.VaultError, 'no credential'):
                v.credential('sw1')

    def test_saving_again_replaces_it(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw1', 'admin', 'first')
            v.store_credential('sw1', 'admin', 'second')
            self.assertEqual(v.credential('sw1')['password'], 'second')
            self.assertEqual(len(v.list_credentials()), 1)

    def test_a_locked_vault_gives_nothing(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw1', 'admin', PW)
        with self.assertRaises(vault.VaultError):
            vault.Vault(self.db, self.conn).credential('sw1')

    def test_bad_names_and_empty_passwords(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            for name, pw in (('two words', 'x'), ('', 'x'), ('-dash', 'x'), ('ok', '')):
                with self.assertRaises(vault.VaultError):
                    v.store_credential(name, 'admin', pw)

    def test_one_row_cannot_be_opened_as_another(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('a', 'admin', 'a-pass')
            v.store_credential('b', 'admin', 'b-pass')
        self.conn.execute("""UPDATE device_credentials SET ciphertext = (SELECT ciphertext FROM device_credentials WHERE name = 'b'),
                             nonce = (SELECT nonce FROM device_credentials WHERE name = 'b') WHERE name = 'a'""")
        with vault.Vault(self.db, self.conn).unlock() as v:
            with self.assertRaises(vault.VaultError):
                v.credential('a')

    def test_rotating_the_vault_secret_keeps_them(self):
        new = 'a different secret for this device test'
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw1', 'admin', PW)
            v.rotate_secret(new.encode())
        with vault.Vault(self.db, self.conn, new.encode()).unlock() as v:
            self.assertEqual(v.credential('sw1')['password'], PW)
        with self.assertRaises(vault.VaultError):
            vault.Vault(self.db, self.conn, SECRET.encode()).unlock()

    def test_an_essentials_backup_holds_them(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw1', 'admin', PW)
        made = backup.create(self.db)
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.remove_credential('sw1')
        self.conn.close()
        backup.restore(self.db, made['path'])
        self.conn = self.db.connect()
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.credential('sw1')['password'], PW)


class CredentialsOnEitherDatabase(unittest.TestCase):
    def test_sealed_read_back_and_rotated(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        vault.KDF_DEFAULTS.update(time_cost=1, memory_kib=8192, lanes=1)
        db = dbfactory.make(self, Path(tmp) / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        vault.Vault(db, conn, SECRET.encode()).init()
        with vault.Vault(db, conn, SECRET.encode()).unlock() as v:
            v.store_credential('sw1', 'admin', PW, 'enable-secret')
            v.store_credential('sw1', 'admin', PW, 'enable-again')
            self.assertEqual(v.credential('sw1')['enable'], 'enable-again')
            v.rotate_secret(b'another secret for either database')
        with vault.Vault(db, conn, b'another secret for either database').unlock() as v:
            self.assertEqual(v.credential('sw1')['password'], PW)
            self.assertEqual(v.remove_credential('sw1'), 1)


if __name__ == '__main__':
    unittest.main()
