"""The scan key's line in authorized_keys (a machine audit of 2026-11-20): StorageForge wrote the bare key, a full login with
port and agent forwarding, into accounts that were in docker and wheel. What must hold: every line StorageForge writes is
restricted, with from= where the operator named the controller's addresses; sshd's own parser accepts it; and a scan that finds a
StorageForge key unrestricted, or in an account that is root in effect, says so."""
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import authkeys, keyinstall, rotation
from json import dumps

PUBLIC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuMmXtdGQ0G5WyQG7HfxFqX3bhO0PwFQ0d3m7H6b6Zr storageforge:sf-dev'


def real_key() -> str:
    d = tempfile.mkdtemp()
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'storageforge:t', '-f', f'{d}/k'], check=True)
    return Path(f'{d}/k.pub').read_text().strip()


class Line(unittest.TestCase):
    def test_restricted_with_a_terminal_and_nothing_else_by_default(self):
        with mock.patch.dict(os.environ, {keyinstall.FROM_ENV: ''}):
            self.assertEqual(keyinstall.restricted_line(PUBLIC), 'restrict,pty ' + PUBLIC)

    def test_from_names_the_controllers_networks(self):
        with mock.patch.dict(os.environ, {keyinstall.FROM_ENV: '10.42.0.3, 172.30.0.0/16'}):
            self.assertEqual(keyinstall.restricted_line(PUBLIC), 'restrict,pty,from="10.42.0.3/32,172.30.0.0/16" ' + PUBLIC)

    def test_options_already_on_the_line_are_not_carried(self):
        with mock.patch.dict(os.environ, {keyinstall.FROM_ENV: ''}):
            self.assertEqual(keyinstall.restricted_line('command="sh",permitopen="*:*" ' + PUBLIC), 'restrict,pty ' + PUBLIC)

    def test_a_value_that_is_not_an_address_is_refused_not_written(self):
        for bad in ('10.42.0.3" command="sh', '*', 'example.com'):
            with self.subTest(bad), mock.patch.dict(os.environ, {keyinstall.FROM_ENV: bad}):
                with self.assertRaises(ValueError):
                    keyinstall.restricted_line(PUBLIC)

    def test_sshd_reads_the_line_as_the_key_it_holds(self):
        pub = real_key()
        with mock.patch.dict(os.environ, {keyinstall.FROM_ENV: '10.42.0.3'}):
            line = keyinstall.restricted_line(pub)
        f = Path(tempfile.mkdtemp()) / 'authorized_keys'
        f.write_text(line + '\n')
        got = subprocess.run(['ssh-keygen', '-l', '-f', str(f)], capture_output=True, text=True)
        want = subprocess.run(['ssh-keygen', '-l', '-f', '-'], input=pub, capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(got.stdout.split()[1], want.stdout.split()[1])

    def test_rotation_adds_the_new_key_restricted(self):
        with mock.patch.dict(os.environ, {keyinstall.FROM_ENV: ''}):
            self.assertIn("'restrict,pty " + PUBLIC + "'", rotation.add_line(PUBLIC))


SCAN_LINES = ('archie\tAAAAC3NzaC1lZDI1NTE5AAAAIDuMmXtdGQ0G5WyQG7HfxFqX3bhO0PwFQ0d3m7H6b6Zr\t storageforge:sf-dev\t\n'
              'scan\tAAAAC3NzaC1lZDI1NTE5AAAAIDuMmXtdGQ0G5WyQG7HfxFqX3bhO0PwFQ0d3m7H6b6Zr\t storageforge:sf-dev\trestrict,pty,from\n')


class Read(unittest.TestCase):
    def test_option_names_are_kept_and_an_old_scan_says_not_known(self):
        keys = authkeys.parse(SCAN_LINES)['keys']
        self.assertEqual([k['options'] for k in keys], [[], ['from', 'pty', 'restrict']])
        old = authkeys.parse('archie\tAAAAC3NzaC1lZDI1NTE5AAAAIDuMmXtdGQ0G5WyQG7HfxFqX3bhO0PwFQ0d3m7H6b6Zr\t c\n')['keys']
        self.assertIsNone(old[0]['options'])

    def test_the_host_script_cuts_option_values_off(self):
        """The awk the scan runs, on a line whose forced command holds a secret: only the names leave the host."""
        from storageforge_index import remote
        script = next(l for l in remote.__dict__.values() if isinstance(l, str) and "echo '@@authkeys'" in l)
        awk = script[script.index("awk -v u=\"$u\" '") + len("awk -v u=\"$u\" '"):]
        awk = awk[:awk.index("'\n")]
        line = 'from="10.0.0.0/8",command="backup --token s3cr3t" ' + PUBLIC + '\n'
        out = subprocess.run(['awk', '-v', 'u=archie', awk], input=line, capture_output=True, text=True).stdout
        self.assertNotIn('s3cr3t', out)
        self.assertNotIn('10.0.0.0', out)
        self.assertEqual(authkeys.parse(out)['keys'][0]['options'], ['command', 'from'])


class Findings(unittest.TestCase):
    def setUp(self):
        self.db = dbfactory.make(self, Path(tempfile.mkdtemp()) / 'sf.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        from storageforge_index.remote import key_fingerprint
        fp = key_fingerprint(PUBLIC.split()[1])
        now = int(time.time())
        self.conn.execute("""INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin)
                             VALUES ('u1', 'sf-dev', 'ssh-ed25519', :p, :f, :b, :b, :b, :b, :t, 'generated')""", {'p': PUBLIC, 'f': fp, 't': now, 'b': b'\0'})

    def host(self, name, lines, accounts):
        inv = {'authkeys': authkeys.parse(lines), 'accounts': accounts}
        self.conn.execute('INSERT INTO hosts (hostname, inventory_json) VALUES (:h, :i)', {'h': name, 'i': dumps(inv)})

    def test_a_bare_line_in_a_docker_and_wheel_account_is_both_findings(self):
        self.host('nas', SCAN_LINES.splitlines()[0] + '\n', 'u\tarchie\t1000\t1000\t/home/archie\t/bin/bash\ng\twheel\t10\tarchie\ng\tdocker\t961\tarchie\ng\tarchie\t1000\t')
        got = authkeys.problems(self.conn)
        self.assertEqual(sorted(got), ['key-account-root:nas:archie', 'key-unrestricted:nas:archie'])
        self.assertIn('docker, wheel', got['key-account-root:nas:archie'][3])

    def test_a_restricted_line_in_a_plain_account_is_neither(self):
        self.host('nas', SCAN_LINES.splitlines()[1] + '\n', 'u\tscan\t1001\t1001\t/home/scan\t/bin/sh\ng\tscan\t1001\t\ng\tstorageforge-scan\t1002\tscan')
        self.assertEqual(authkeys.problems(self.conn), {})

    def test_a_scan_that_did_not_read_options_raises_no_unrestricted_finding(self):
        self.host('nas', 'scan\tAAAAC3NzaC1lZDI1NTE5AAAAIDuMmXtdGQ0G5WyQG7HfxFqX3bhO0PwFQ0d3m7H6b6Zr\t c\n', 'u\tscan\t1001\t1001\t/h\t/bin/sh')
        self.assertEqual(authkeys.problems(self.conn), {})


if __name__ == '__main__':
    unittest.main()
