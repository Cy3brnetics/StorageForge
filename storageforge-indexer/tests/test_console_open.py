"""Opening a web console (console.open_session): the route and key it takes, what it refuses, and what it spawns. A stand-in ssh and virsh
on PATH write down their arguments and stay open like a terminal would; the vault, its bindings and the private agent are real."""
import json
import os
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

from storageforge_index import console, vault
from test_console import Base, until

SECRET = b'correct horse battery staple, but longer than 32'
# the console gives ssh only PATH, TERM and LANG, so where to write is in the script itself
# virsh domstate answers as it does for a domain this machine doesn't run; anything else stays open like a terminal
STAND_IN = ('#!/bin/sh\ncase " $* " in *" domstate "*) echo "error: failed to get domain" >&2; exit 1 ;; esac\n'
            'printf "%s\\n" "$0" "$@" > "@LOG@.$(basename "$0")"\necho "stand-in ready"\nexec cat\n')


class Open(Base):
    def setUp(self):
        super().setUp()
        bin_ = Path(self.tmp) / 'bin'
        bin_.mkdir()
        for name in ('ssh', 'virsh'):
            (bin_ / name).write_text(STAND_IN.replace('@LOG@', str(Path(self.tmp) / 'argv')))
            (bin_ / name).chmod(0o755)
        self.log = Path(self.tmp) / 'argv'
        p = mock.patch.dict(os.environ, {'PATH': f'{bin_}:{os.environ["PATH"]}', 'SF_ARGV_LOG': str(self.log), 'STORAGEFORGE_VAULT_SECRET': SECRET.decode()})
        p.start()
        self.addCleanup(p.stop)
        self.add('web-01', '10.0.0.5', [{'name': 'eth0', 'addresses': [{'ip': '10.0.0.5'}]}, {'name': 'tailscale0', 'addresses': [{'ip': '100.100.1.2'}]}])
        self.audit = []

    def add(self, name, ssh_host, interfaces):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user) VALUES (:n, :a, 'scan')", {'n': name, 'a': ssh_host})
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :n', {'n': name})
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 0)', {'h': hid, 'd': json.dumps({'interfaces': interfaces})})

    def vault(self, bind=True):
        v = vault.Vault(self.db, self.conn, SECRET)
        v.init()
        with v.unlock() as u:
            u.generate_key('console-key')
            if bind:
                u.bind('console-key', '10.0.0.5', 'admin', 2222, actions='console')

    def open(self, **kw):
        args = {'owner': 'alice', 'host': 'web-01', 'kind': 'ssh', 'route': 'auto', 'cols': 100, 'rows': 30,
                'audit': lambda action, detail: self.audit.append((action, detail)), **kw}
        return console.open_session(self.db, self.conn, **args)

    def argv(self, name):
        got = until(lambda: (Path(f'{self.log}.{name}').exists() and Path(f'{self.log}.{name}').read_text()) or None, 10)
        return (got or '').splitlines()[1:]

    def test_a_console_over_ssh_takes_the_bound_key_and_carries_nothing_along(self):
        self.vault()
        s = self.open()
        self.addCleanup(s.close, 'test over')
        argv = self.argv('ssh')
        self.assertEqual(argv[-2:], ['--', 'admin@10.0.0.5'])
        self.assertIn('-p', argv)
        self.assertEqual(argv[argv.index('-p') + 1], '2222', 'the port of the binding')
        for want in ('StrictHostKeyChecking=yes', 'ForwardAgent=no', 'ClearAllForwardings=yes', 'PasswordAuthentication=no'):
            self.assertIn(want, argv)
        self.assertEqual(self.audit[-1][0], 'console.open')
        self.assertEqual((self.audit[-1][1]['route'], self.audit[-1][1]['cols']), ('lan', 100))
        self.assertIn(s.id, console._REGISTRY)
        self.assertIn('stand-in ready', until(lambda: s.read_after(0, wait=0.2)['data'].decode() or None))

    def test_the_tailscale_route_reaches_the_host_by_its_lan_name(self):
        """The host key was confirmed for the address it is scanned at, so that is the alias, whatever route carries it."""
        self.vault()
        s = self.open(route='tailscale')
        self.addCleanup(s.close, 'test over')
        argv = self.argv('ssh')
        self.assertEqual(argv[-1], 'admin@100.100.1.2')
        self.assertIn('HostKeyAlias=10.0.0.5', argv)

    def test_the_size_is_held_to_what_a_terminal_can_be(self):
        self.vault()
        s = self.open(cols=99999, rows=1)
        self.addCleanup(s.close, 'test over')
        self.assertEqual((s.cols, s.rows), (500, 5))

    def test_what_is_refused_before_anything_is_spawned(self):
        self.vault(bind=False)
        with self.assertRaisesRegex(ValueError, 'ssh or serial'):
            self.open(kind='telnet')
        with self.assertRaisesRegex(console.ConsoleError, 'has no wireguard address'):
            self.open(route='wireguard')
        with self.assertRaisesRegex(console.ConsoleError, 'Keys → Bindings'):
            self.open()
        with self.assertRaisesRegex(console.ConsoleError, 'is no VM'):
            self.open(kind='serial')
        self.assertFalse(Path(f'{self.log}.ssh').exists(), 'ssh never ran')
        self.assertEqual(self.audit, [], 'nothing opened, so nothing is logged as open: the caller logs the failed open')
        self.assertEqual([s for s in console._REGISTRY.values() if not s.closed], [])

    def test_a_locked_vault_says_so(self):
        self.vault()
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'x' * 48}), self.assertRaises(console.ConsoleError):
            self.open()

    def test_no_more_consoles_than_the_server_can_hold_threads_for(self):
        self.vault()
        opened = [self.open() for _ in range(console.MAX_SESSIONS)]
        for s in opened:
            self.addCleanup(s.close, 'test over')
        with self.assertRaisesRegex(console.ConsoleError, 'open already'):
            self.open()
        opened[0].close('done')
        self.addCleanup(self.open().close, 'test over')

    def test_a_vm_on_this_machine_gets_its_serial_console_here(self):
        with mock.patch.object(console, 'serial_via', return_value={'via': 'local', 'host': 'this machine'}):
            s = self.open(host='vm9', kind='serial')
        self.addCleanup(s.close, 'test over')
        self.assertEqual(self.argv('virsh'), ['-c', 'qemu:///system', 'console', '--force', 'vm9'])
        self.assertEqual((s.kind, s.route), ('serial', 'local'))

    def test_a_vm_on_a_scanned_host_gets_virsh_over_ssh_to_that_host(self):
        self.vault()
        with mock.patch.object(console, 'serial_via', return_value={'via': 'web-01', 'host': 'web-01'}):
            s = self.open(host='vm9', kind='serial')
        self.addCleanup(s.close, 'test over')
        argv = self.argv('ssh')
        self.assertEqual(argv[-6:], ['virsh', '-c', 'qemu:///system', 'console', '--force', 'vm9'])
        self.assertIn('admin@10.0.0.5', argv)


if __name__ == '__main__':
    unittest.main()
