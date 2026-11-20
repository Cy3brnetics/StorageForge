"""The SSH CA as StorageForge runs it (sshcerts.py) and the two plan steps that reach a host (steps_sshca.py). What must hold: the
CA is a vault key that logs in nowhere; a login certificate is for one user on one host and for minutes; a host that was not opted
in gets none; a revoked certificate is refused once the list is on the host; and the trust step never takes away a login that
worked before it. The steps run against a real sshd, with the real ssh and ssh-keygen."""
import base64
import getpass
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization

import dbfactory
from storageforge_index import alerts, changes, server, sshca, sshcerts, steps_sshca, users, vault
from storageforge_index.runner import ephemeral_agent

SECRET = b's' * 48
PW = 'correct horse battery staple 9'
ME = getpass.getuser()
SSHD = shutil.which('sshd') or '/usr/sbin/sshd'

HARNESS = r'''
set -euo pipefail
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; later() { echo "later: $*"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
durable() { :; }; fw_tool() { :; }; fw_arm() { echo "armed $1: $2"; }
PROBLEMS=0 STAMP=20261120-120000
'''


class Kept(unittest.TestCase):
    """A database with two hosts, a vault with one key bound to nas for scans and the console, and nothing else."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = mock.patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.tmp), 'STORAGEFORGE_RUNTIME_DIR': str(self.tmp), 'STORAGEFORGE_VAULT_SECRET': SECRET.decode()})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('STORAGEFORGE_ENCLAVE', None)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.port = 22
        self.hosts()
        self.vault = vault.Vault(self.db, self.conn, SECRET)
        self.vault.init()
        self.vault.unlock()
        self.addCleanup(self.vault.close)
        self.vault.generate_key('scan-key')
        self.vault.bind('scan-key', '127.0.0.1', ME, self.port, 'scan,console')

    def hosts(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, ssh_user) VALUES ('nas', '127.0.0.1', :p, :u)", {'p': self.port, 'u': ME})
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user) VALUES ('pi', '10.42.0.20', 'scan')")

    def read(self, line):
        cert = serialization.load_ssh_public_identity(line.encode())
        cert.verify_cert_signature()
        return cert


class Authority(Kept):
    def test_the_ca_is_one_vault_key_that_logs_in_nowhere(self):
        self.assertIsNone(sshcerts.ca_public(self.conn))
        made = sshcerts.ensure_ca(self.vault)
        self.assertTrue(made['made'])
        self.assertTrue(made['public_key'].startswith('ssh-ed25519 '))
        self.assertEqual(len(made['public_key'].split()), 2, 'the key and nothing after it')
        again = sshcerts.ensure_ca(self.vault)
        self.assertEqual((again['made'], again['public_key']), (False, made['public_key']))
        self.assertEqual([k['name'] for k in self.vault.list_keys()], ['scan-key', sshcerts.CA_KEY])
        with self.assertRaises(vault.VaultError):
            self.vault.bind(sshcerts.CA_KEY, 'nas', 'root')

    def test_a_login_certificate_is_for_one_user_on_one_host_and_for_minutes(self):
        with self.assertRaises(sshcerts.CAError):
            sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='console', actor='web:gabe')
        ca = sshcerts.ensure_ca(self.vault)['public_key']
        started = int(time.time())
        made = sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='console', actor='web:gabe')
        cert = self.read(made['certificate'])
        self.assertEqual(cert.valid_principals, [f'{ME}@nas'.encode()])
        self.assertEqual(cert.type, serialization.SSHCertificateType.USER)
        self.assertEqual((cert.extensions, cert.critical_options), ({b'permit-pty': b''}, {}))
        self.assertLessEqual(cert.valid_before, started + sshcerts.CONSOLE_SECONDS + 2)
        self.assertEqual(cert.serial, made['serial'])
        self.assertEqual(cert.key_id, b'storageforge console nas web:gabe')
        signed_by = cert.signature_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(signed_by, ca)
        subject = cert.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(subject, ' '.join(self.vault.public_key('scan-key').split()[:2]))
        scan = self.read(sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='scan', actor='scheduler')['certificate'])
        self.assertEqual(scan.extensions, {}, 'a scan gets no terminal and no forwarding')
        self.assertLessEqual(scan.valid_before - scan.valid_after, sshcerts.SCAN_SECONDS + sshca.BACKDATE)
        rows = self.conn.all('SELECT kind, purpose, host, principals, issued_by, certificate FROM ssh_certificates ORDER BY issued_at, purpose')
        self.assertEqual(rows, [('user', 'console', 'nas', f'{ME}@nas', 'web:gabe', None), ('user', 'scan', 'nas', f'{ME}@nas', 'scheduler', None)])
        for bad in ({'purpose': 'deploy'}, {'user': 'root nas'}, {'host': 'nas;id'}, {'key_name': 'no-such-key'}):
            with self.subTest(bad), self.assertRaises((sshcerts.CAError, vault.VaultError)):
                sshcerts.issue_user(self.vault, **({'host': 'nas', 'user': ME, 'key_name': 'scan-key', 'purpose': 'scan', 'actor': 'x'} | bad))

    def test_only_a_host_that_was_opted_in_is_given_one(self):
        said = []
        ask = lambda purpose, address='127.0.0.1': sshcerts.login_line(self.vault, self.conn, address=address, user=ME, key_name='scan-key', purpose=purpose, actor='web:gabe',
                                                                         audit=lambda outcome, detail: said.append((outcome, detail)))
        sshcerts.ensure_ca(self.vault)
        self.assertIsNone(ask('console'))
        self.assertEqual(sshcerts.set_host(self.conn, '127.0.0.1', {'console': True, 'scan': False}, 'gabe')['host'], 'nas', 'named by its address, kept by its name')
        self.assertIsNone(ask('scan'))
        self.assertIsNone(ask('console', '10.42.0.20'), 'another host')
        self.assertEqual(said, [])
        line = ask('console')
        self.assertEqual(self.read(line).valid_principals, [f'{ME}@nas'.encode()])
        self.assertEqual((said[0][0], said[0][1]['principal'], said[0][1]['seconds']), ('ok', f'{ME}@nas', sshcerts.CONSOLE_SECONDS))
        self.assertEqual(sshcerts.set_host(self.conn, 'nas', {'console': False, 'scan': False}, 'gabe')['console'], False)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM ssh_ca_hosts'), 0)
        self.assertIsNone(ask('console'))
        with self.assertRaises(sshcerts.CAError):
            sshcerts.set_host(self.conn, 'nas', {'console': 'yes', 'scan': False}, 'gabe')
        with self.assertRaises(LookupError):
            sshcerts.set_host(self.conn, 'nobody', {'console': True, 'scan': True}, 'gabe')

    def test_a_certificate_that_cannot_be_made_is_said_and_the_login_goes_on_with_the_key(self):
        sshcerts.ensure_ca(self.vault)
        sshcerts.set_host(self.conn, 'nas', {'console': True, 'scan': True}, 'gabe')
        said = []
        got = sshcerts.login_line(self.vault, self.conn, address='127.0.0.1', user=ME, key_name='gone', purpose='scan', actor='scheduler', audit=lambda *a: said.append(a))
        self.assertIsNone(got)
        self.assertEqual((said[0][0], said[0][1]['error']), ('failed', 'No key named gone'))

    def test_the_file_ssh_reads_is_there_for_the_login_and_gone_after_it(self):
        sshcerts.ensure_ca(self.vault)
        binding = self.vault.resolve('127.0.0.1', 'scan')
        with sshcerts.login_options(self.vault, address='127.0.0.1', binding=binding, purpose='scan', actor='scheduler') as options:
            self.assertEqual(options, [], 'not opted in: ssh is told nothing more')
        sshcerts.set_host(self.conn, 'nas', {'console': False, 'scan': True}, 'gabe')
        with sshcerts.login_options(self.vault, address='127.0.0.1', binding=binding, purpose='scan', actor='scheduler') as options:
            path = Path(options[0].removeprefix('CertificateFile='))
            self.assertEqual(self.read(path.read_text().strip()).valid_principals, [f'{ME}@nas'.encode()])
        self.assertFalse(path.exists())

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'needs ssh-keygen')
    def test_openssh_reads_the_revocation_list_and_refuses_what_it_names(self):
        self.assertIsNone(sshcerts.krl(self.conn))
        ca = sshcerts.ensure_ca(self.vault)['public_key']
        (self.tmp / 'ca.pub').write_text(ca + '\n')
        one, two = (sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='scan', actor='scheduler') for _ in range(2))
        for name, made in (('one', one), ('two', two)):
            (self.tmp / f'{name}-cert.pub').write_text(made['certificate'] + '\n')

        def asked(name):
            blob, version = sshcerts.krl(self.conn)
            (self.tmp / 'krl').write_bytes(blob)
            self.assertEqual(sshca.krl_version(blob), version)
            got = subprocess.run(['ssh-keygen', '-Q', '-f', str(self.tmp / 'krl'), str(self.tmp / f'{name}-cert.pub')], capture_output=True, text=True)
            return got.returncode, got.stdout + got.stderr
        self.assertEqual(asked('one')[0], 0, 'a list that names nothing is a list, and revokes nothing')
        got = sshcerts.revoke(self.conn, one['serial'], 'gabe', 'a  test\nof it')
        self.assertEqual((got['krl_version'], got['host'], got['kind']), (1, 'nas', 'user'))
        code, text = asked('one')
        self.assertNotEqual(code, 0, text)
        self.assertIn('REVOKED', text)
        self.assertEqual(asked('two')[0], 0, 'and only that one')
        self.assertEqual(self.conn.all('SELECT revoked_by, revoked_reason FROM ssh_certificates WHERE serial = :s', {'s': one['serial']}), [('gabe', 'a test of it')])
        with self.assertRaises(sshcerts.CAError):
            sshcerts.revoke(self.conn, one['serial'], 'gabe')
        with self.assertRaises(LookupError):
            sshcerts.revoke(self.conn, 12345, 'gabe')
        with self.assertRaises(sshcerts.CAError):
            sshcerts.revoke(self.conn, True, 'gabe')
        sshcerts.revoke(self.conn, two['serial'], 'gabe')
        self.assertEqual((sshcerts.krl_version(self.conn), sshcerts.revoked_serials(self.conn)), (2, sorted([one['serial'], two['serial']])))
        self.assertNotEqual(asked('two')[0], 0)
        self.assertIsNone(sshca.krl_version(b'not a list'))
        for bad in ({'version': -1}, {'serials': [0]}, {'serials': ['7']}, {'comment': 'two\nlines'}):
            with self.subTest(bad), self.assertRaises(sshca.CertificateError):
                sshca.krl(ca, **({'serials': [7], 'version': 1} | bad))

    def test_a_host_certificate_is_for_the_key_a_scan_pinned(self):
        sshcerts.ensure_ca(self.vault)
        known = self.tmp / 'known_hosts'
        known.write_text('')
        with self.assertRaises(sshcerts.CAError) as raised:
            sshcerts.issue_host(self.vault, 'nas', 'gabe', str(known))
        self.assertIn('scan it first', str(raised.exception))
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tmp / 'hostkey')], check=True)
        public = ' '.join((self.tmp / 'hostkey.pub').read_text().split()[:2])
        known.write_text(f'127.0.0.1 {public}\n')
        made = sshcerts.issue_host(self.vault, 'nas', 'gabe', str(known))
        cert = self.read(made['certificate'])
        self.assertEqual((cert.type, cert.valid_principals), (serialization.SSHCertificateType.HOST, [b'nas', b'127.0.0.1']))
        self.assertEqual(sshcerts.host_certificate(self.conn, 'nas')['serial'], made['serial'])
        self.assertEqual(sshcerts.problems(self.conn), {})
        self.conn.execute('UPDATE ssh_certificates SET expires_at = :t', {'t': int(time.time()) + 3 * 86400 + 60})
        found = sshcerts.problems(self.conn)
        self.assertEqual(list(found), ['sshca-host:nas'])
        self.assertIn('ends in 3 day(s)', found['sshca-host:nas'][2])
        self.assertIn('sshca-host:nas', alerts.problems(self.conn))
        sshcerts.revoke(self.conn, made['serial'], 'gabe')
        self.assertIsNone(sshcerts.host_certificate(self.conn, 'nas'))
        self.assertEqual(sshcerts.problems(self.conn), {}, 'a revoked certificate is not one to renew')

    def test_what_reaches_a_host_is_a_saved_plan(self):
        with self.assertRaises(sshcerts.CAError):
            sshcerts.plan(self.conn, {'kind': 'trust', 'hosts': ['nas']}, 'gabe')
        sshcerts.ensure_ca(self.vault)
        made = sshcerts.plan(self.conn, {'kind': 'trust', 'hosts': ['127.0.0.1'], 'host_cert': True}, 'gabe')
        plan = changes.get_plan(self.conn, made['plan_id'])
        self.assertEqual([(t['type'], t['host'], t['params']['users'], t['params']['host_cert'], t['params']['rollback']) for t in plan['tasks']],
                         [('ssh-ca-trust', 'nas', ME, False, '10')], 'the user the vault logs in as, no host certificate where none was issued, and a rollback timer')
        checked = changes.check(self.conn, plan)
        self.assertFalse([i for t in checked['tasks'] for i in t['items'] if i['level'] == 'crit'], checked)
        text = changes.script(self.conn, plan)
        self.assertIn('t_ssh_ca_trust', text)
        self.assertIn(sshcerts.ca_public(self.conn), text)
        with self.assertRaises(sshcerts.CAError) as raised:
            sshcerts.plan(self.conn, {'kind': 'trust', 'hosts': ['pi']}, 'gabe')
        self.assertIn('name the users', str(raised.exception))
        for bad in ({'kind': 'trust'}, {'kind': 'other'}, {'kind': 'trust', 'hosts': 'nas'}, {'kind': 'trust', 'hosts': ['nas'], 'rollback': 0}):
            with self.subTest(bad), self.assertRaises(sshcerts.CAError):
                sshcerts.plan(self.conn, bad, 'gabe')
        with self.assertRaises(LookupError):
            sshcerts.plan(self.conn, {'kind': 'trust', 'hosts': ['nobody']}, 'gabe')
        self.assertEqual(sshcerts.plan(self.conn, {'kind': 'krl'}, 'gabe')['tasks'], 0, 'no host is given certificates yet')
        sshcerts.set_host(self.conn, 'nas', {'console': True, 'scan': False}, 'gabe')
        made = sshcerts.plan(self.conn, {'kind': 'krl'}, 'gabe')
        self.assertEqual([(t['type'], t['host']) for t in changes.get_plan(self.conn, made['plan_id'])['tasks']], [('ssh-ca-krl', 'nas')])

    def test_the_check_of_a_trust_step(self):
        def items(params):
            plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'ssh-ca-trust', 'host': 'nas', 'params': {'users': ME, 'principals': '', 'host_cert': False, 'state': 'present', 'rollback': ''} | params}]})
            return [(i['level'], i['text']) for i in changes.check(self.conn, plan)['tasks'][0]['items']]
        self.assertIn(('crit', 'there is no SSH CA yet: make it under Keys'), items({}))
        sshcerts.ensure_ca(self.vault)
        self.assertFalse([i for i in items({}) if i[0] == 'crit'])
        for bad in ({'users': 'root; id'}, {'users': 'root$(id)'}, {'principals': 'a;b'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                [i for i in items(bad) if i[0] == 'crit'].pop()          # refused when the plan is read, or by the check
        self.assertTrue([i for i in items({'host_cert': True}) if i[0] == 'crit' and 'no host certificate' in i[1]])
        self.assertTrue([i for i in items({'principals': 'storage-admins'}) if i[0] == 'warn' and 'not tied to this host' in i[1]])
        sshcerts.set_host(self.conn, 'nas', {'console': True, 'scan': False}, 'gabe')
        self.assertTrue([i for i in items({'state': 'absent'}) if i[0] == 'warn' and 'logs in to nas with certificates' in i[1]])

    def test_the_routes(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        writes = (('post', '/api/keys/ssh-ca', {}), ('put', '/api/keys/ssh-ca/hosts/nas', {'console': True, 'scan': True}), ('post', '/api/keys/ssh-ca/hosts/nas/certificate', {}),
                  ('post', '/api/keys/ssh-ca/certificates/7/revoke', {}), ('post', '/api/keys/ssh-ca/plan', {'kind': 'krl'}))
        for method, path, body in writes:
            self.assertEqual(getattr(viewer, method)(path, json=body).status_code, 403, path)
        self.assertEqual(admin.post('/api/reauth', json={'password': PW}).status_code, 200)
        self.assertIsNone(admin.get('/api/keys/ssh-ca').get_json()['ca'])
        self.assertEqual(admin.post('/api/keys/ssh-ca/plan', json={'kind': 'krl'}).status_code, 400, 'no CA yet')
        made = admin.post('/api/keys/ssh-ca', json={})
        self.assertEqual(made.status_code, 201)
        self.assertEqual(admin.post('/api/keys/ssh-ca', json={}).status_code, 200, 'asked again, it is the same CA')
        self.assertEqual(admin.put('/api/keys/ssh-ca/hosts/nas', json={'console': True, 'scan': True}).get_json()['scan'], True)
        self.assertEqual(admin.put('/api/keys/ssh-ca/hosts/nobody', json={'console': True, 'scan': True}).status_code, 404)
        self.assertEqual(admin.post('/api/keys/ssh-ca/hosts/nas/certificate', json={}).status_code, 400, 'never scanned: no host key on record')
        with vault.Vault(self.db, self.conn).unlock() as v:
            issued = sshcerts.issue_user(v, host='nas', user=ME, key_name='scan-key', purpose='scan', actor='scheduler')
        seen = viewer.get('/api/keys/ssh-ca').get_json()
        self.assertEqual(seen['ca']['public_key'], made.get_json()['public_key'])
        self.assertEqual([(h['host'], h['console'], h['scan']) for h in seen['hosts']], [('nas', True, True), ('pi', False, False)])
        self.assertEqual([(c['serial'], c['purpose'], c['revoked_at']) for c in seen['certificates']], [(str(issued['serial']), 'scan', None)])
        self.assertNotIn('certificate', seen['certificates'][0])
        revoked = admin.post(f'/api/keys/ssh-ca/certificates/{issued["serial"]}/revoke', json={'reason': 'test'})
        self.assertEqual((revoked.status_code, revoked.get_json()['krl_version']), (200, 1))
        self.assertEqual(admin.post(f'/api/keys/ssh-ca/certificates/{issued["serial"]}/revoke', json={}).status_code, 400)
        self.assertEqual(admin.post('/api/keys/ssh-ca/certificates/5/revoke', json={}).status_code, 404)
        self.assertEqual(admin.post('/api/keys/ssh-ca/plan', json={'kind': 'krl'}).get_json()['tasks'], 1)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'sshca.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['sshca.create', 'sshca.host', 'sshca.revoke', 'sshca.plan'])


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the enclave (CI builds it)')
class CaInTheEnclave(unittest.TestCase):
    """With the key enclave configured the CA is made inside it and signs inside it: this process never holds the key."""

    def test_the_ca_signs_inside_the_enclave(self):
        import test_enclave
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, tmp / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        made = vault.Vault(db, conn, SECRET)
        made.init()
        made.close()
        path = tmp / 'enclave.sock'
        proc = subprocess.Popen([str(test_enclave.build()), '--unix', str(path)], stderr=subprocess.PIPE)
        self.addCleanup(lambda: (proc.kill(), proc.wait(), proc.stderr.close()))
        for _ in range(100):
            if path.exists():
                break
            time.sleep(0.05)
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': f'unix:{path}', 'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'XDG_RUNTIME_DIR': str(tmp)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('STORAGEFORGE_VAULT_SECRET_FILE', None)
        conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user) VALUES ('nas', '10.42.0.10', 'scan')")
        with vault.Vault(db, conn).unlock() as v:
            self.assertIsNone(v._kek, 'the KEK was not derived here')
            ca = sshcerts.ensure_ca(v)
            v.generate_key('scan-key')
            kid = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': sshcerts.CA_KEY})
            self.assertIsInstance(v.decrypt_key(kid), vault.EnclaveKey)
            line = sshcerts.issue_user(v, host='nas', user='scan', key_name='scan-key', purpose='scan', actor='scheduler')['certificate']
        cert = serialization.load_ssh_public_identity(line.encode())
        cert.verify_cert_signature()
        self.assertEqual(cert.signature_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(), ca['public_key'])
        self.assertEqual(cert.valid_principals, [b'scan@nas'])


@unittest.skipUnless(os.access(SSHD, os.X_OK) and shutil.which('ssh-keygen'), 'needs sshd and ssh-keygen')
class TrustStep(Kept):
    """t_ssh_ca_trust and t_ssh_ca_krl against a real sshd on this machine, with its files in a folder of the test. sshd -t and
    sshd -T are the real ones; reloading is SIGHUP to that sshd. The operator key in authorized_keys must log in after every step."""

    def hosts(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        super().hosts()

    def setUp(self):
        super().setUp()
        self.etc, self.bin = self.tmp / 'etc', self.tmp / 'bin'
        (self.etc / 'sshd_config.d').mkdir(parents=True)
        self.bin.mkdir()
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.etc / 'ssh_host_ed25519_key')], check=True)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tmp / 'operator')], check=True)
        shutil.copy(self.tmp / 'operator.pub', self.etc / 'authorized_keys')
        self.config(f'Include {self.etc}/sshd_config.d/*.conf\n')
        (self.bin / 'sshd').write_text(f'#!/bin/bash\nif [[ -e {self.tmp}/reject && " $* " == *" -t "* ]]; then echo "{self.etc}/sshd_config: terminating, 1 bad configuration options" >&2; exit 255; fi\n'
                                       f'exec {SSHD} -f {self.etc}/sshd_config "$@"\n')
        (self.bin / 'systemctl').write_text(f'#!/bin/bash\necho "systemctl $*" >>{self.tmp}/calls\n[[ "$*" == "reload sshd" && ! -e {self.tmp}/no-reload ]] && exec kill -HUP "$(cat {self.etc}/pid)"\nexit 1\n')
        for name in ('sshd', 'systemctl'):
            (self.bin / name).chmod(0o755)
        self.daemon = subprocess.Popen([SSHD, '-D', '-e', '-f', str(self.etc / 'sshd_config')], stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop)
        sshcerts.ensure_ca(self.vault)
        sshcerts.set_host(self.conn, 'nas', {'console': True, 'scan': True}, 'gabe')
        self.binding = self.vault.resolve('127.0.0.1', 'scan')
        first = self.with_key()
        if first.returncode != 0 and self.daemon.poll() is not None:
            self.skipTest('sshd would not start here')
        self.assertEqual(first.stdout.strip(), 'in', first.stderr)

    def stop(self):
        try:
            os.kill(int((self.etc / 'pid').read_text()), 15)
        except (OSError, ValueError):
            pass
        self.daemon.kill()
        self.daemon.wait()

    def config(self, head='', tail=''):
        (self.etc / 'sshd_config').write_text(f'{head}Port {self.port}\nListenAddress 127.0.0.1\nHostKey {self.etc}/ssh_host_ed25519_key\nAuthorizedKeysFile {self.etc}/authorized_keys\n'
                                              f'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile {self.etc}/pid\nLogLevel VERBOSE\n{tail}')

    # ── logging in ──
    def ssh(self, options, known=None, strict='no'):
        argv = ['ssh', '-F', '/dev/null', '-p', str(self.port), '-o', 'BatchMode=yes', '-o', f'StrictHostKeyChecking={strict}', '-o', f'UserKnownHostsFile={known or self.tmp / "known"}',
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5', '-o', 'PasswordAuthentication=no', *(x for o in options for x in ('-o', o)), f'{ME}@127.0.0.1', 'echo', 'in']
        for _ in range(50):          # a reload closes the port for a moment
            got = subprocess.run(argv, capture_output=True, text=True, env={'PATH': os.environ['PATH'], 'HOME': str(self.tmp)})
            if 'Connection refused' not in got.stderr and 'Connection reset' not in got.stderr and 'closed by remote host' not in got.stderr:
                break
            time.sleep(0.1)
        return got

    def with_key(self, **kw):
        """The operator, with the key that was in authorized_keys before StorageForge came."""
        return self.ssh([f'IdentityFile={self.tmp}/operator', 'IdentitiesOnly=yes', 'IdentityAgent=none'], **kw)

    def with_certificate(self, line=None, **kw):
        """As a scan logs in: the vault key in an agent of its own, and the certificate in a file beside it. The key is in no authorized_keys."""
        with ephemeral_agent(self.vault.decrypt_key(self.binding.key_id)) as sock:
            if line:
                with sshcerts.certificate_file(line) as option:
                    return self.ssh([f'IdentityAgent={sock}', 'IdentitiesOnly=no', option], **kw)
            with sshcerts.login_options(self.vault, address='127.0.0.1', binding=self.binding, purpose='scan', actor='scheduler') as options:
                return self.ssh([f'IdentityAgent={sock}', 'IdentitiesOnly=no', *options], **kw)

    # ── running a step ──
    def step(self, apply, kind='ssh-ca-trust', args=None, **params):
        task = changes.normalize({'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params if kind == 'ssh-ca-krl' else
                                                         {'users': ME, 'principals': '', 'host_cert': False, 'state': 'present', 'rollback': ''} | params}]})['tasks'][0]
        own = [('1' if task['params'][a] else '') if isinstance(task['params'][a], bool) else str(task['params'][a]) for a in changes.ARGS[kind]]
        words = own + (args if args is not None else changes.EXTRA[kind]['args_of'](self.conn, task))
        call = f't_{kind.replace("-", "_")} ' + ' '.join(f"'{w}'" for w in words)
        got = subprocess.run(['bash', '-c', HARNESS + f'APPLY={int(apply)}\n' + steps_sshca.BASH + '\n' + call + '\nexit $((PROBLEMS > 0))\n'], capture_output=True, text=True, timeout=60,
                             env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_SSH_DIR': str(self.etc), 'SF_SSHCA_STATE': str(self.tmp / 'state')})
        return got.returncode, got.stdout + got.stderr

    def written(self):
        return sorted(str(p.relative_to(self.etc)) for p in self.etc.rglob('*') if p.is_file() and 'storageforge' in str(p.relative_to(self.etc)))

    def reloads(self):
        calls = self.tmp / 'calls'
        return calls.read_text().count('reload sshd') if calls.exists() else 0

    def test_trusted_then_revoked_then_not_trusted_and_the_operator_key_works_throughout(self):
        self.assertNotEqual(self.with_certificate().returncode, 0, 'sshd does not trust the CA yet')
        code, out = self.step(False)
        self.assertEqual(code, 0, out)
        self.assertIn(f'would: trust the StorageForge CA for {ME}', out)
        self.assertEqual((self.written(), self.reloads()), ([], 0), 'a report writes nothing')
        code, out = self.step(True)
        self.assertEqual(code, 0, out)
        self.assertIn('Keys in authorized_keys work as before', out)
        self.assertEqual(self.written(), ['sshd_config.d/50-storageforge-ca.conf', f'storageforge_principals/{ME}', 'storageforge_revoked_keys', 'storageforge_revoked_keys.version', 'storageforge_user_ca.pub'])
        self.assertEqual((self.etc / 'storageforge_principals' / ME).read_text(), f'{ME}@nas\n')
        self.assertNotIn('AuthorizedKeysFile ', (self.etc / 'sshd_config.d/50-storageforge-ca.conf').read_text().replace('# AuthorizedKeysFile', ''))
        got = self.with_certificate()
        self.assertEqual((got.returncode, got.stdout.strip()), (0, 'in'), got.stderr)
        self.assertEqual(self.with_key().stdout.strip(), 'in', 'the operator is not locked out')
        elsewhere = sshcerts.issue_user(self.vault, host='pi', user=ME, key_name='scan-key', purpose='scan', actor='scheduler')
        self.assertNotEqual(self.with_certificate(elsewhere['certificate']).returncode, 0, 'a certificate for this user on another host does not log in here')
        code, out = self.step(True)
        self.assertIn('ok: trusts the StorageForge CA', out)
        self.assertEqual(self.reloads(), 1, 'a second run changes nothing and reloads nothing')

        # one certificate is revoked: the list reaches the host by the other step, and sshd needs no reload to read it
        bad = sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='scan', actor='scheduler')
        self.assertEqual(self.with_certificate(bad['certificate']).returncode, 0)
        old_args = steps_sshca._krl_args(self.conn)
        sshcerts.revoke(self.conn, bad['serial'], 'gabe', 'test')
        self.assertEqual(self.with_certificate(bad['certificate']).returncode, 0, 'revoked here, and the host has not been told yet')
        code, out = self.step(False, 'ssh-ca-krl')
        self.assertIn('would: install revocation list version 1 (it has version 0)', out)
        code, out = self.step(True, 'ssh-ca-krl')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.reloads(), 1)
        self.assertNotEqual(self.with_certificate(bad['certificate']).returncode, 0, 'the revoked certificate is refused')
        self.assertEqual(self.with_certificate().returncode, 0, 'another certificate for the same key is not')
        self.assertEqual(self.with_key().stdout.strip(), 'in')
        code, out = self.step(True, 'ssh-ca-krl', args=old_args)
        self.assertIn('newer than this plan was written with (0): left as it is', out)
        self.assertEqual((self.etc / 'storageforge_revoked_keys.version').read_text(), '1\n')
        self.assertIn('ok: has revocation list version 1', self.step(True, 'ssh-ca-krl')[1])

        # a list that is not one never replaces the list in place: sshd would refuse every key
        before = (self.etc / 'storageforge_revoked_keys').read_bytes()
        ca = sshcerts.ca_public(self.conn)
        for what, blob in (('not base64', '!!!'), ('not a list', base64.b64encode(b'no list at all').decode()), ('empty', '')):
            code, out = self.step(True, 'ssh-ca-krl', args=[ca, blob, '9'])
            self.assertEqual(code, 1, what)
            self.assertIn('does not read as one on this host', out)
            self.assertEqual((self.etc / 'storageforge_revoked_keys').read_bytes(), before, what)
        self.assertEqual(self.with_key().stdout.strip(), 'in')
        self.assertEqual(self.with_certificate().returncode, 0)

        # and trust taken away again
        code, out = self.step(True, state='absent')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.written(), [])
        self.assertNotEqual(self.with_certificate().returncode, 0)
        self.assertEqual(self.with_key().stdout.strip(), 'in')
        self.assertIn('does not trust the StorageForge CA', self.step(True, state='absent')[1])
        self.assertIn('the ssh-ca-trust step comes first', self.step(True, 'ssh-ca-krl')[1])

    def test_a_change_sshd_rejects_is_put_back(self):
        (self.tmp / 'reject').touch()
        code, out = self.step(True)
        self.assertEqual(code, 1)
        self.assertIn('sshd -t rejected it, so everything was put back', out)
        self.assertEqual(self.written(), [])
        self.assertEqual(self.with_key().stdout.strip(), 'in')
        # the same over a trust that was in place: what was there before is there after
        (self.tmp / 'reject').unlink()
        self.assertEqual(self.step(True)[0], 0)
        kept = {p: (self.etc / p).read_bytes() for p in self.written()}
        (self.tmp / 'reject').touch()
        code, out = self.step(True, principals='storage-admins')
        self.assertEqual(code, 1, out)
        self.assertEqual({p: (self.etc / p).read_bytes() for p in self.written()}, kept)
        (self.tmp / 'reject').unlink()
        self.assertEqual(self.with_certificate().returncode, 0)
        self.assertEqual(self.with_key().stdout.strip(), 'in')

    def test_an_sshd_that_does_not_reload_is_put_back(self):
        (self.tmp / 'no-reload').touch()
        code, out = self.step(True)
        self.assertEqual(code, 1)
        self.assertIn('sshd did not reload, so everything was put back', out)
        # the line that names the CA is gone. The CA key and the list stay until an sshd has reloaded without them: they are named by nothing
        self.assertEqual(self.written(), ['storageforge_revoked_keys', 'storageforge_revoked_keys.version', 'storageforge_user_ca.pub'])
        self.assertEqual(subprocess.run([str(self.bin / 'sshd'), '-t'], capture_output=True).returncode, 0)
        self.assertEqual(self.with_key().stdout.strip(), 'in')

    def test_a_host_with_a_ca_or_principals_of_its_own_is_left_alone(self):
        for line in ('TrustedUserCAKeys /etc/ssh/company_ca.pub', 'AuthorizedPrincipalsFile /etc/ssh/principals/%u', 'RevokedKeys /etc/ssh/revoked'):
            with self.subTest(line):
                self.config(f'Include {self.etc}/sshd_config.d/*.conf\n', line + '\n')
                code, out = self.step(True)
                self.assertEqual(code, 1)
                self.assertIn('takes only one: StorageForge does not replace it', out)
                self.assertEqual(self.written(), [])
        self.config()
        code, out = self.step(True)
        self.assertIn('does not include sshd_config.d', out)
        self.config(f'Include {self.etc}/sshd_config.d/*.conf\n', 'PubkeyAuthentication no\n')
        self.assertIn('PubkeyAuthentication is off', self.step(True)[1])
        self.config(f'Include {self.etc}/sshd_config.d/*.conf\n')
        self.assertIn('there is no account no-such-user-here', self.step(True, users='no-such-user-here')[1])
        self.assertEqual((self.written(), self.reloads()), ([], 0))

    def test_more_principals_and_the_rollback_timer(self):
        code, out = self.step(True, principals='storage-admins', rollback='10')
        self.assertEqual(code, 0, out)
        self.assertIn(f'armed 10: sh {self.tmp}/state/before-20261120-120000/restore.sh', out)
        self.assertEqual((self.etc / 'storageforge_principals' / ME).read_text(), f'{ME}@nas\nstorage-admins\n')
        wide = sshca.issue(self.vault.public_key('scan-key'), sshcerts.ca_public(self.conn), sshcerts.signer(self.vault), key_id='team', principals=['storage-admins'], serial=99, seconds=300)
        self.assertEqual(self.with_certificate(wide).returncode, 0)
        # the timer ran out: what it runs puts sshd back as it was, and the list goes only once sshd has let go of it
        got = subprocess.run(['sh', f'{self.tmp}/state/before-20261120-120000/restore.sh'], capture_output=True, text=True, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}'})
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(self.written(), [])
        self.assertNotEqual(self.with_certificate(wide).returncode, 0)
        self.assertEqual(self.with_key().stdout.strip(), 'in')

    def test_the_host_certificate(self):
        code, out = self.step(True, args=[sshcerts.ca_public(self.conn), 'nas', '', '0', ''], host_cert=True)
        self.assertIn('no host certificate is on record', out)
        known = self.tmp / 'pinned'
        known.write_text(f'[127.0.0.1]:{self.port} ' + ' '.join((self.etc / 'ssh_host_ed25519_key.pub').read_text().split()[:2]) + '\n')
        made = sshcerts.issue_host(self.vault, 'nas', 'gabe', str(known))
        code, out = self.step(True, host_cert=True)
        self.assertEqual(code, 0, out)
        self.assertIn('and presents its host certificate', out)
        self.assertEqual((self.etc / 'ssh_host_ed25519_key-cert.pub').read_text().strip(), made['certificate'])
        # a client that knows only the CA, and no key of this host
        only_ca = self.tmp / 'only-ca'
        only_ca.write_text(sshca.known_hosts_line(sshcerts.ca_public(self.conn), '*') + '\n')
        got = self.with_key(known=only_ca, strict='yes')
        self.assertEqual((got.returncode, got.stdout.strip()), (0, 'in'), got.stderr)
        self.assertEqual(only_ca.read_text().count('\n'), 1, 'and learned none')
        self.assertIn('ok: trusts the StorageForge CA', self.step(True, host_cert=True)[1])
        # a certificate for a key this sshd does not use is not installed
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tmp / 'other')], check=True)
        known.write_text(f'[127.0.0.1]:{self.port} ' + ' '.join((self.tmp / 'other.pub').read_text().split()[:2]) + '\n')
        self.conn.execute('UPDATE ssh_certificates SET issued_at = issued_at - 60')          # the newest one counts, and both were made in one second
        sshcerts.issue_host(self.vault, 'nas', 'gabe', str(known))
        code, out = self.step(True, host_cert=True)
        self.assertIn('is for a host key this sshd does not use', out)
        self.assertEqual((self.etc / 'ssh_host_ed25519_key-cert.pub').read_text().strip(), made['certificate'])


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserSshCa(Kept):
    """Keys, SSH certificates, in a real browser: the CA is made, a host is opted in, trust is staged as a plan, a certificate is revoked."""

    def test_the_section_under_keys(self):
        import threading
        from werkzeug.serving import make_server
        users.create(self.conn, 'admin', PW, 'admin')
        http = make_server('127.0.0.1', 0, server.create_app(server.App(self.db), 's' * 48), threaded=True)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        self.addCleanup(http.shutdown)
        pw = sync_playwright().start()
        self.addCleanup(pw.stop)
        browser = pw.chromium.launch()
        self.addCleanup(browser.close)
        page, errors = browser.new_page(), []
        page.on('pageerror', lambda e: errors.append(str(e)))
        base = f'http://127.0.0.1:{http.server_port}'
        page.goto(base + '/login')
        page.fill('input[type=text], input[name=username], #username', 'admin')
        page.fill('input[type=password]', PW)
        page.press('input[type=password]', 'Enter')
        page.wait_for_url(base + '/**')
        page.wait_for_selector('html[data-route-ready]', state='attached')
        page.evaluate("showTab('keys')")
        page.click('#sshcabox button:has-text("Make the SSH CA")')
        page.wait_for_selector('#sshcabox code.pub')
        self.assertEqual(page.inner_text('#sshcabox code.pub'), sshcerts.ca_public(self.conn))
        row = '#sshcabox li:has-text("nas")'
        page.click(f'{row} button:has-text("Scans: off")')
        page.wait_for_selector(f'{row} button:has-text("Scans: on")')
        self.assertEqual(sshcerts.host_setting(self.conn, 'nas')['scan'], True)
        page.click(f'{row} button:has-text("Stage trust")')
        page.wait_for_selector('#sshcamsg:has-text("1 step staged in plan")')
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM change_plans WHERE name LIKE 'Trust the SSH CA%'"), 1)
        made = sshcerts.issue_user(self.vault, host='nas', user=ME, key_name='scan-key', purpose='scan', actor='scheduler')
        page.evaluate('loadSshCa()')
        cert = f'#sshcabox li:has-text("serial {made["serial"]}")'
        page.click(f'{cert} button:has-text("Revoke")')
        page.click('dialog[open] button[type=submit]')
        page.wait_for_selector(f'{cert}:has-text("revoked by web:admin")')
        self.assertIn('Revocation list version 1, naming 1 certificate.', page.inner_text('#sshcabox'))
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
