"""The secret store (roadmap section 5; secretstore.py): secrets generated per kind, shown once, sealed in the vault (inside the key
enclave when it is there), delivered to a plan step on the signed runner's stdin, rotated everywhere they went or nowhere, and
removed. What must hold above all: the value is on no command line, in no plan, script, playbook or log, and in no row of the
database but its own ciphertext. Each of those is searched for it here."""
import base64
import contextlib
import io
import json
import os
import shutil
import stat
import string
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
try:
    from test_enclave_stepup import Base as EnclaveBase
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_enclave_stepup import Base as EnclaveBase
from storageforge_index import changes, cli, deploy, secretstore, server, steps_secretfile, steps_tailscale, users, vault

SECRET = 's' * 48
PW = 'a long enough password'
HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; durable() { sync -- "$@"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
PROBLEMS=0
'''


def stand_ins(d: Path, log: Path) -> Path:
    """A PATH where every program the scripts start writes its command line to log before the real one runs: what ps would show."""
    b = d / 'bin'
    b.mkdir()
    for name in ('base64', 'mv', 'mkdir', 'chmod', 'rm', 'tailscale', 'cat', 'install', 'printf', 'cmp', 'chown', 'mktemp', 'stat', 'id', 'sync',
                 'systemctl'):
        real = shutil.which(name)
        # systemctl is a stand-in that succeeds: on a host with systemd the step would otherwise run the real one, which a user
        # without root is refused (CI's runner), and the step ends there
        body = 'exit 0' if name == 'systemctl' else f'exec {real} "$@"' if real and name != 'tailscale' else (
            'case $1 in status) [[ -e $FAKE/up ]] && echo \'  "BackendState": "Running",\' || echo \'  "BackendState": "NeedsLogin",\' ;; '
            'up) for a; do case $a in --auth-key=file:*) cp "${a#--auth-key=file:}" "$FAKE/key-seen" ;; esac; done; touch "$FAKE/up" ;; ip) echo 100.64.0.9 ;; esac')
        (b / name).write_text(f'#!/bin/bash\nprintf "%s\\n" "{name} $*" >>{log}\n{body}\n')
        (b / name).chmod(0o755)
    return b


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET})
        env.start()
        self.addCleanup(env.stop)
        for name in ('STORAGEFORGE_ENCLAVE', 'STORAGEFORGE_VAULT_SECRET_FILE'):
            os.environ.pop(name, None)
        vault.Vault(self.db, self.conn, SECRET.encode()).init()
        self.v = vault.Vault(self.db, self.conn).unlock()
        self.addCleanup(self.v.close)
        for host in ('web', 'nas'):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', '{}')", {'h': host})

    def everywhere(self, value: str) -> list[str]:
        """Every table and column of the database that holds the value as it is: the place it must never be."""
        if self.db.dialect == 'sqlite':
            tables = [r[0] for r in self.conn.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        else:
            tables = [r[0] for r in self.conn.all("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")]
        found = []
        for t in tables:
            for row in self.conn.all(f'SELECT * FROM {t}'):
                for cell in row:
                    text = bytes(cell).decode('latin-1') if isinstance(cell, (bytes, bytearray, memoryview)) else str(cell)
                    if value in text:
                        found.append(t)
        return found


class Generate(unittest.TestCase):
    def test_each_kind_has_its_alphabet_and_length(self):
        for kind, (_, alphabet, default, lo, hi) in secretstore.KINDS.items():
            if kind == 'wireguard':
                continue
            for n in (lo, default, hi):
                value = secretstore.generate(kind, n)
                self.assertEqual(len(value), n)
                self.assertTrue(set(value) <= set(alphabet), kind)
            with self.assertRaises(secretstore.SecretError):
                secretstore.generate(kind, lo - 1)
            with self.assertRaises(secretstore.SecretError):
                secretstore.generate(kind, hi + 1)
        self.assertEqual(len({secretstore.generate('token') for _ in range(50)}), 50)

    def test_a_password_has_every_class_and_nothing_a_shell_or_a_config_file_reads(self):
        for _ in range(200):
            value = secretstore.generate('password', 12)
            for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, secretstore._SYMBOLS):
                self.assertTrue(any(c in group for c in value), value)
            self.assertFalse(set(value) & set('\'"`$\\#; !&|<>(){}[]*?~\n\t'), value)

    def test_a_wireguard_key_is_32_bytes_that_wg_accepts(self):
        key = secretstore.generate('wireguard')
        self.assertEqual(len(base64.b64decode(key)), 32)
        with self.assertRaises(secretstore.SecretError):
            secretstore.generate('wireguard', 40)
        if shutil.which('wg'):
            p = subprocess.run(['wg', 'pubkey'], input=key + '\n', capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(len(base64.b64decode(p.stdout.strip())), 32)

    def test_an_unknown_kind_or_a_length_that_is_not_a_number_is_refused(self):
        for kind, length in (('ssh', None), ('token', 'long'), ('pin', 2.5)):
            with self.assertRaises(secretstore.SecretError):
                secretstore.generate(kind, length)


class Store(Db):
    def test_made_once_listed_without_its_value_and_sealed(self):
        row, value = secretstore.make(self.v, self.conn, 'db-admin', 'password', 30, {'steps': ['tailscale'], 'hosts': ['web']})
        self.assertEqual((row['kind'], row['length'], row['origin']), ('password', 30, 'generated'))
        self.assertEqual(row['policy']['hosts'], ['web'])
        self.assertEqual(len(value), 30)
        listed = secretstore.listing(self.conn)
        self.assertEqual([s['name'] for s in listed], ['db-admin'])
        self.assertNotIn(value, json.dumps(listed))
        self.assertEqual(self.everywhere(value), [])                       # sealed: not in any row, its own included
        self.assertEqual(self.v.credential('db-admin', host='web', step='tailscale')['password'], value)
        with self.assertRaises(vault.NotReleased):                          # bound to what its policy names
            self.v.credential('db-admin', host='nas', step='tailscale')
        with self.assertRaises(secretstore.SecretError):                   # a name in use changes by rotation
            secretstore.make(self.v, self.conn, 'db-admin', 'token')
        for bad in ('-x', '../x', 'a b', '', 'x' * 65):
            with self.assertRaises(secretstore.SecretError, msg=bad):
                secretstore.make(self.v, self.conn, bad, 'token')

    def test_a_device_password_is_not_a_step_secret(self):
        self.v.store_credential('sw1', 'admin', 'pw-123456')
        self.assertEqual(secretstore.listing(self.conn), [])
        self.assertEqual(secretstore.remove(self.conn, 'sw1'), 0)
        self.assertEqual(len(self.v.list_credentials()), 1)

    def test_removed_with_the_record_of_where_it_went(self):
        secretstore.make(self.v, self.conn, 'k', 'hex')
        secretstore.delivered(self.conn, 'k', 'web', 'tailscale', 'plan')
        secretstore.delivered(self.conn, 'k', 'web', 'tailscale', 'plan')
        self.assertEqual(len(secretstore.listing(self.conn)[0]['delivered']), 1)
        self.assertEqual(secretstore.remove(self.conn, 'k'), 1)
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM secret_deliveries'), 0)
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM device_credentials'), 0)

    def test_a_vault_rotation_rewraps_it_and_keeps_how_it_was_made(self):
        _, value = secretstore.make(self.v, self.conn, 'k', 'token', 20)
        self.v.rotate_secret(b't' * 48)
        os.environ['STORAGEFORGE_VAULT_SECRET'] = 't' * 48
        with vault.Vault(self.db, self.conn).unlock() as v2:
            self.assertEqual(v2.credential('k', step='x')['password'], value)
        self.assertEqual(secretstore.meta(self.conn, 'k')['kind'], 'token')

    def test_the_cli_prints_the_value_once_to_stdout_and_never_again(self):
        def run(*argv, stdin=''):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch('sys.stdin', io.StringIO(stdin)):
                rc = cli.main(['--db', self.db.url, 'vault', *argv])
            return rc, out.getvalue(), err.getvalue()
        rc, out, err = run('secret-generate', 'app-db', '--kind', 'hex', '--length', '32', '--step', 'tailscale')
        self.assertEqual(rc, 0, err)
        value = out.strip()
        self.assertEqual(len(value), 32)
        self.assertNotIn(value, err)
        rc, out, err = run('secret-list')
        self.assertIn('app-db', out)
        self.assertIn('hex of 32', out)
        self.assertNotIn(value, out + err)
        rc, out, err = run('secret-rotate', 'app-db')                      # a dry run: nothing changes
        self.assertIn('no host yet', err)
        self.assertEqual(self.v.credential('app-db', step='tailscale')['password'], value)
        rc, out, err = run('secret-policy', 'app-db', '--step', 'netbird')  # sealed again under a new policy: still what it was made as
        self.assertEqual(rc, 0, err)
        self.assertEqual(secretstore.meta(self.conn, 'app-db')['kind'], 'hex')
        rc, out, err = run('secret-add', 'ts-key', stdin='tskey-auth-given\n')
        self.assertEqual(secretstore.meta(self.conn, 'ts-key')['origin'], 'given')
        rc, out, err = run('secret-remove', 'app-db')
        self.assertEqual(rc, 0)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'vault.secret%' ORDER BY audit_id")]
        self.assertEqual(actions, ['vault.secret_generate', 'vault.secret_policy', 'vault.secret_add', 'vault.secret_remove'])
        self.assertEqual(self.everywhere(value), [])

    def test_secret_add_replaces_a_secret_and_nothing_of_another_kind(self):
        def run(*argv, stdin=''):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch('sys.stdin', io.StringIO(stdin)):
                rc = cli.main(['--db', self.db.url, 'vault', *argv])
            return rc, out.getvalue(), err.getvalue()
        self.v.store_credential('sw', 'admin', 'device-password', 'enable-password')
        self.v.store_credential('api-proxmox-pve', 'root@pam!sf', 'api-token-value', policy={'platforms': ['proxmox:pve']}, made={'origin': 'given'})
        self.conn.execute("""INSERT INTO platform_connections (kind, name, base_url, token_id, secret_name, created_by, created_at)
                             VALUES ('proxmox', 'pve', 'https://pve:8006', 'root@pam!sf', 'api-proxmox-pve', 'gabe', 1)""")
        for name, what in (('sw', 'a device credential'), ('api-proxmox-pve', 'the token of an API connection')):
            rc, out, err = run('secret-add', name, stdin='tskey-auth-given\n')
            self.assertEqual(rc, 1, err)
            self.assertIn(f'{name} is {what}', err)
        self.assertEqual(self.v.credential('sw'), {'username': 'admin', 'password': 'device-password', 'enable': 'enable-password'})
        self.assertEqual(self.v.credential('api-proxmox-pve', platform='proxmox:pve')['password'], 'api-token-value')
        self.assertEqual(secretstore.held_as(self.conn, 'sw'), 'device')
        self.assertEqual(secretstore.held_as(self.conn, 'api-proxmox-pve'), 'api')
        self.assertEqual(secretstore.held_as(self.conn, 'api-proxmox-pve.next'), None)
        outcomes = [r[0] for r in self.conn.all("SELECT outcome FROM audit_log WHERE action = 'vault.secret_add' ORDER BY audit_id")]
        self.assertEqual(outcomes, ['failed', 'failed'])
        # a secret is still replaced, under the policy this command names
        self.assertEqual(run('secret-add', 'ts-key', '--step', 'tailscale', stdin='tskey-one\n')[0], 0)
        made = secretstore.meta(self.conn, 'ts-key')['created_at']
        self.assertEqual(run('secret-add', 'ts-key', '--step', 'netbird', stdin='tskey-two\n')[0], 0)
        self.assertEqual(self.v.credential('ts-key', step='netbird')['password'], 'tskey-two')
        row = secretstore.meta(self.conn, 'ts-key')
        self.assertEqual((row['policy']['steps'], row['origin'], row['created_at']), (['netbird'], 'given', made))
        self.assertEqual(secretstore.held_as(self.conn, 'ts-key'), 'secret')

    def test_a_given_secret_sealed_again_keeps_its_policy_unless_one_is_named(self):
        secretstore.put_given(self.v, self.conn, 'hs-key', 'first-value', {'steps': ['tailscale'], 'hosts': ['web']})
        secretstore.put_given(self.v, self.conn, 'hs-key', 'second-value')
        row = secretstore.meta(self.conn, 'hs-key')
        self.assertEqual((row['policy']['steps'], row['policy']['hosts'], row['origin']), (['tailscale'], ['web'], 'given'))
        self.assertIsNotNone(row['value_rotated_at'])
        self.assertEqual(self.v.credential('hs-key', host='web', step='tailscale')['password'], 'second-value')
        secretstore.put_given(self.v, self.conn, 'hs-key', 'third-value', None)
        self.assertIsNone(secretstore.meta(self.conn, 'hs-key')['policy'])
        _, value = secretstore.make(self.v, self.conn, 'made', 'hex', 32)
        secretstore.put_given(self.v, self.conn, 'made', 'given-instead')
        row = secretstore.meta(self.conn, 'made')
        self.assertEqual((row['kind'], row['length'], row['origin']), (None, None, 'given'), 'the value is no longer one StorageForge made')


TS_PLAN = {'name': 'join web', 'tasks': [{'host': 'web', 'type': 'tailscale', 'params': {'secret': 'ts-key', 'state': 'present'}}]}


class Delivery(Db):
    def setUp(self):
        super().setUp()
        _, self.value = secretstore.make(self.v, self.conn, 'ts-key', 'token', 48, {'steps': ['tailscale'], 'hosts': ['web']})
        self.log = self.tmp / 'argv.log'
        self.bin = stand_ins(self.tmp, self.log)
        self.secrets = self.tmp / 'secrets'

    def bash(self, script: str, stdin: bytes, apply=1, extra=''):
        return subprocess.run(['bash', '-c', HARNESS + f'APPLY={apply}; SECRETS_STDIN=1\n' + script + extra], input=stdin, capture_output=True,
                              timeout=60, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_SECRET_DIR': str(self.secrets),
                                               'FAKE': str(self.tmp)})

    def items(self, mode):
        with mock.patch('storageforge_index.receiving.items', return_value=([], [])):
            return changes.deploy_items(self.db, self.conn, TS_PLAN, mode, 'gabe')

    def test_an_apply_carries_the_secret_on_stdin_and_a_report_carries_nothing(self):
        report = self.items('report')
        self.assertNotIn('data', report[0])
        self.assertNotIn('--secrets-stdin', report[0]['args'])
        item = self.items('apply')[0]
        self.assertEqual(item['args'], ['--apply', '--secrets-stdin'])
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM secret_deliveries'), 0)      # nothing released before the run starts
        data = b''.join(item['data'])
        self.assertTrue(data.startswith(b'SF-SECRETS 1\nts-key '))
        self.assertNotIn(self.value.encode(), data)                      # base64 on the wire, as a value of any bytes would be
        self.assertEqual(secretstore.listing(self.conn)[0]['delivered'][0]['host'], 'web')
        release = [json.loads(r[0]) for r in self.conn.all("SELECT detail_json FROM audit_log WHERE action = 'vault.secret_send'")]
        self.assertEqual(release, [])                                    # the run is what is audited (deploy.run), not a send

    def test_the_script_writes_it_to_memory_mode_600_and_the_step_reads_it_there(self):
        data = b''.join(self.items('apply')[0]['data'])
        body = secretstore.BASH + steps_tailscale.BASH.replace('/run/storageforge/secrets', str(self.secrets))
        out = self.bash(body, data, extra='\nt_tailscale ts-key "" "" "" "" present\n')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('1 secret(s) from StorageForge written', out.stdout.decode())
        self.assertIn('joined the tailnet', out.stdout.decode())
        self.assertEqual((self.tmp / 'key-seen').read_text(), self.value + '\n')          # what tailscale read from the file
        argv = self.log.read_text()
        self.assertIn('base64 -d', argv)
        self.assertIn('tailscale up', argv)
        for seen in (argv, out.stdout.decode(), out.stderr.decode()):                     # on no command line and in no output
            self.assertNotIn(self.value, seen)
        self.assertFalse((self.secrets / 'ts-key').exists())                               # tailscale removes it once joined

    def test_the_secret_file_step_writes_it_where_a_service_reads_it(self):
        import getpass
        import grp
        me, group = getpass.getuser(), grp.getgrgid(os.getgid()).gr_name
        out_dir = self.tmp / 'etc-app'
        out_dir.mkdir()
        target = out_dir / 'db-password'
        plan = {'name': 'app', 'tasks': [{'host': 'web', 'type': 'secret-file', 'params': {'secret': 'ts-key', 'path': str(target), 'owner': me, 'mode': '0640'}}]}
        self.conn.execute("UPDATE device_credentials SET policy_json = NULL WHERE name = 'ts-key'")      # sealed with its policy: it no longer opens
        self.v.store_credential('ts-key', 'secret', self.value, policy={'steps': ['secret-file'], 'hosts': ['web']}, made={'origin': 'generated', 'kind': 'token', 'length': 48})
        with mock.patch('storageforge_index.receiving.items', return_value=([], [])):
            item = changes.deploy_items(self.db, self.conn, plan, 'apply', 'gabe')[0]
            self.assertNotIn('data', changes.deploy_items(self.db, self.conn, plan, 'report', 'gabe')[0])
        data = b''.join(item['data'])
        call = f'\nt_secret_file ts-key {target} {me} "" 0640 present\n'
        report = self.bash(steps_secretfile.BASH, b'', apply=0, extra=call).stdout.decode()
        self.assertIn(f'would: write the secret ts-key to {target} ({me}:{group}, mode 0640)', report)
        out = self.bash(secretstore.BASH + steps_secretfile.BASH, data, extra=call)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f'ok: {target} holds the secret ts-key', out.stdout.decode())
        self.assertEqual(target.read_text(), self.value + '\n')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in out_dir.iterdir()), ['db-password'])          # no temporary file left
        again = self.bash(steps_secretfile.BASH, b'', extra=call).stdout.decode()          # from the copy in /run that the first run left
        self.assertIn(f'ok: {target} holds the secret ts-key ({me}:{group}, mode 0640)', again)
        self.assertNotIn('doing:', again)
        for seen in (self.log.read_text(), out.stdout.decode(), again):
            self.assertNotIn(self.value, seen)
        gone = self.bash(steps_secretfile.BASH, b'', extra=f'\nt_secret_file ts-key {target} {me} "" 0640 absent\n').stdout.decode()
        self.assertIn(f'ok: removed {target}', gone)
        items = []
        steps_secretfile._check(self.conn, None, {'name': 'web'}, {'secret': 'ts-key', 'path': '/run/storageforge/secrets/x', 'mode': '0644'}, lambda lvl, t: items.append(lvl))
        self.assertEqual(items.count('crit'), 1)
        for bad in ({'path': 'rel/x'}, {'path': '/etc/../x'}, {'owner': 'Bad Name'}, {'mode': '999'}, {'secret': '../x'}):
            items = []
            steps_secretfile._check(self.conn, None, {'name': 'web'}, {'secret': 'k', 'path': '/etc/x', **bad}, lambda lvl, t: items.append(lvl))
            self.assertIn('crit', items, bad)

    def test_the_file_is_private(self):
        data = b''.join(self.items('apply')[0]['data'])
        out = self.bash(secretstore.BASH, data)
        self.assertEqual(out.returncode, 0, out.stderr)
        f = self.secrets / 'ts-key'
        self.assertEqual(f.read_text(), self.value + '\n')
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.secrets.stat().st_mode), 0o700)
        self.assertEqual(list(self.secrets.iterdir()), [f])                                # no .part left behind

    def test_a_report_and_a_downloaded_script_never_read_stdin(self):
        for extra_env in ('APPLY=0', 'SECRETS_STDIN=0'):
            out = self.bash(f'{extra_env}\n' + secretstore.BASH + 'IFS= read -r first; echo "left: $first"\n', b'SF-SECRETS 1\nx eA==\nEND\n')
            self.assertIn('left: SF-SECRETS 1', out.stdout.decode(), extra_env)
            self.assertFalse(self.secrets.exists())

    def test_a_secret_its_policy_does_not_release_for_this_host_is_said_in_the_run(self):
        plan = {'name': 'join nas', 'tasks': [{'host': 'nas', 'type': 'tailscale', 'params': {'secret': 'ts-key', 'state': 'present'}},
                                               {'host': 'nas', 'type': 'tailscale', 'params': {'secret': 'missing-one', 'state': 'present'}}]}
        with mock.patch('storageforge_index.receiving.items', return_value=([], [])):
            item = changes.deploy_items(self.db, self.conn, plan, 'apply', 'gabe')[0]
        data = b''.join(item['data'])
        self.assertNotIn(b'ts-key ', data.split(b'\n', 1)[1].replace(b'REFUSED ts-key', b''))
        out = self.bash(secretstore.BASH, data).stdout.decode()
        self.assertIn('did not release the secret ts-key for this host: its policy does not name this host or step', out)
        self.assertIn('did not release the secret missing-one for this host', out)
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM secret_deliveries'), 0)

    def test_a_line_that_is_not_a_secret_is_skipped(self):
        for line in (b'../x eA==', b'-x eA==', b'x not-base64!', b'x.part'):
            out = self.bash(secretstore.BASH, b'SF-SECRETS 1\n' + line + b'\nEND\n')
            self.assertIn('not in the expected form', out.stdout.decode(), line)
        self.assertEqual(list(self.secrets.iterdir()), [])

    def test_the_value_is_in_no_plan_script_playbook_or_row(self):
        plan_id = changes.save_plan(self.conn, TS_PLAN, 'gabe')
        plan = changes.get_plan(self.conn, plan_id)
        text = changes.script(self.conn, plan)
        self.assertIn('sf_secrets_in() {', text)
        self.assertIn('--secrets-stdin) SECRETS_STDIN=1', text)
        playbook = changes.ansible(self.conn, plan)
        b''.join(self.items('apply')[0]['data'])
        for where in (text, playbook, json.dumps(plan)):
            self.assertNotIn(self.value, where)
        self.assertEqual(self.everywhere(self.value), [])


class Rotate(Db):
    """deploy.run is replaced by what storageforge-run does once it has checked a signature: bash runs the script with its arguments and
    the rest of stdin. The rotation script itself runs, against a folder standing in for /run/storageforge/secrets on each host."""

    def setUp(self):
        super().setUp()
        _, self.old = secretstore.make(self.v, self.conn, 'app', 'token', 32)
        self.dirs = {h: self.tmp / h for h in ('web', 'nas')}
        self.fail_on = set()
        self.runs, self.outputs = [], []
        for d in self.dirs.values():
            d.mkdir()
            (d / 'app').write_text(self.old + '\n')
            secretstore.delivered(self.conn, 'app', d.name, 'tailscale', 'plan')
        for name, fn in (('ready', lambda conn, h: True), ('canonical', lambda conn, h: h), ('run', self.fake_run)):
            p = mock.patch.object(deploy, name, fn)
            p.start()
            self.addCleanup(p.stop)

    def fake_run(self, db, host, script, args=(), *, kind, ref=None, mode='report', actor=None, data=None, timeout=1800, **kw):
        stdin = b''.join(data) if data and not isinstance(data, bytes) else (data or b'')
        self.runs.append((host, list(args)))
        if (host, args[1]) in self.fail_on:
            return {'status': 'failed', 'output': 'ssh: connect to host refused\n', 'run_id': len(self.runs)}
        p = subprocess.run(['bash', '-c', script, 'storageforge-run', *args], input=stdin, capture_output=True, timeout=30,
                           env={**os.environ, 'SF_SECRET_DIR': str(self.dirs[host])})
        out = (p.stdout + p.stderr).decode()
        self.outputs.append(out)
        return {'status': 'ok' if p.returncode == 0 else 'failed', 'output': out, 'run_id': len(self.runs)}

    def test_the_dry_run_changes_nothing(self):
        plan = secretstore.rotate_plan(self.conn, 'app')
        self.assertEqual([h['host'] for h in plan['hosts']], ['nas', 'web'])
        self.assertEqual(plan['blocked'], [])
        self.assertEqual(self.runs, [])
        self.assertEqual(self.v.credential('app', step='t')['password'], self.old)

    def test_every_host_gets_the_new_value_then_the_vault_switches(self):
        got = secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe')
        self.assertTrue(got['rotated'], got)
        new = got['value']
        self.assertNotEqual(new, self.old)
        self.assertEqual(len(new), 32)
        self.assertEqual(self.v.credential('app', step='t')['password'], new)
        for d in self.dirs.values():
            self.assertEqual((d / 'app').read_text(), new + '\n')
            self.assertFalse((d / 'app.next').exists())
            self.assertEqual(stat.S_IMODE((d / 'app').stat().st_mode), 0o600)
        self.assertEqual([r['commit'] for r in got['results']], ['switched', 'switched'])
        self.assertEqual([a[1] for _, a in self.runs], ['stage', 'stage', 'commit', 'commit'])
        self.assertIsNotNone(secretstore.meta(self.conn, 'app')['value_rotated_at'])
        self.assertEqual(self.everywhere(new), [])
        self.assertNotIn(new, ''.join(self.outputs))                     # in no run's output
        self.assertEqual([d['how'] for d in secretstore.listing(self.conn)[0]['delivered']], ['rotate', 'rotate'])

    def test_a_failed_commit_does_not_claim_delivery(self):
        self.fail_on.add(('web', 'commit'))
        got = secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe')
        self.assertEqual({r['host']: r['commit'] for r in got['results']}, {'nas': 'switched', 'web': 'failed'})
        deliveries = dict(self.conn.all("SELECT host, how FROM secret_deliveries WHERE name = 'app'"))
        self.assertEqual(deliveries, {'nas': 'rotate', 'web': 'plan'})
        self.assertEqual((self.dirs['web'] / 'app').read_text().strip(), self.old)

    def test_one_host_that_does_not_take_it_leaves_the_old_value_everywhere(self):
        self.fail_on = {('web', 'stage')}
        got = secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe')
        self.assertFalse(got['rotated'])
        self.assertNotIn('value', got)
        self.assertIn('web did not take the new value', got['why'])
        self.assertEqual(self.v.credential('app', step='t')['password'], self.old)
        for d in self.dirs.values():
            self.assertEqual((d / 'app').read_text(), self.old + '\n')
            self.assertFalse((d / 'app.next').exists())                    # nas had it staged, and it was discarded
        self.assertEqual(self.runs, [('nas', ['app', 'stage']), ('web', ['app', 'stage']), ('nas', ['app', 'discard'])])

    def test_a_host_where_the_step_removed_it_has_nothing_to_replace(self):
        (self.dirs['web'] / 'app').unlink()
        got = secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe')
        self.assertTrue(got['rotated'])
        self.assertEqual([r['stage'] for r in got['results']], ['staged', 'absent'])
        self.assertFalse((self.dirs['web'] / 'app').exists())

    def test_a_host_that_cannot_be_reached_by_a_signed_run_blocks_it(self):
        with mock.patch.object(deploy, 'ready', lambda conn, h: h != 'nas'):
            got = secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe')
        self.assertFalse(got['rotated'])
        self.assertIn('nas is not set up for deploys', got['why'])
        self.assertEqual(self.runs, [])

    def test_a_secret_a_person_gave_takes_its_new_value_from_them(self):
        self.v.store_credential('given', 'secret', 'old-given', made={'origin': 'given'})
        secretstore.delivered(self.conn, 'given', 'web', 'tailscale', 'send-secret')
        (self.dirs['web'] / 'given').write_text('old-given\n')
        with self.assertRaises(secretstore.SecretError):
            secretstore.rotate(self.db, self.conn, self.v, 'given', 'gabe')
        got = secretstore.rotate(self.db, self.conn, self.v, 'given', 'gabe', 'new-given-value')
        self.assertTrue(got['rotated'])
        self.assertIsNone(got['value'])                                      # theirs: nothing to show
        self.assertEqual((self.dirs['web'] / 'given').read_text(), 'new-given-value\n')
        with self.assertRaises(secretstore.SecretError):
            secretstore.rotate(self.db, self.conn, self.v, 'app', 'gabe', 'mine')


class Web(Db):
    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def test_an_admin_makes_one_sees_it_once_and_lists_names_only(self):
        c = self.client('admin')
        r = c.post('/api/keys/secrets', json={'name': 'grafana', 'kind': 'password', 'length': 20, 'hosts': 'web nas'})
        self.assertEqual(r.status_code, 201, r.get_json())
        value = r.get_json()['value']
        self.assertEqual(len(value), 20)
        self.assertEqual(r.headers['Cache-Control'], 'no-store')
        listed = c.get('/api/keys/secrets')
        self.assertNotIn(value, listed.get_data(as_text=True))
        self.assertEqual(listed.get_json()['secrets'][0]['policy']['hosts'], ['nas', 'web'])
        self.assertEqual({k['kind'] for k in listed.get_json()['kinds']}, set(secretstore.KINDS))
        self.assertEqual(c.post('/api/keys/secrets', json={'name': 'grafana', 'kind': 'password'}).status_code, 400)
        self.assertEqual(c.post('/api/keys/secrets', json={'name': 'x', 'kind': 'pin', 'length': 3}).status_code, 400)
        self.assertEqual(c.get('/api/keys/secrets/grafana/rotate').get_json()['hosts'], [])
        self.assertEqual(c.get('/api/keys/secrets/ghost/rotate').status_code, 404)
        self.assertEqual(c.delete('/api/keys/secrets/grafana').status_code, 200)
        self.assertEqual(c.delete('/api/keys/secrets/grafana').status_code, 404)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'secret.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['secret.generate', 'secret.remove', 'secret.remove'])
        self.assertEqual(self.everywhere(value), [])

    def test_a_viewer_lists_and_cannot_make_rotate_or_remove(self):
        secretstore.make(self.v, self.conn, 'k', 'token')
        c = self.client('viewer')
        self.assertEqual(c.get('/api/keys/secrets').status_code, 200)
        self.assertEqual(c.post('/api/keys/secrets', json={'name': 'y', 'kind': 'token'}).status_code, 403)
        self.assertEqual(c.post('/api/keys/secrets/k/rotate', json={}).status_code, 403)
        self.assertEqual(c.delete('/api/keys/secrets/k').status_code, 403)


class Enclave(EnclaveBase):
    """The same store with the key enclave: the value is sealed inside it and released by it for a named host and step, which it writes
    into the audit log itself."""

    def test_sealed_and_released_by_the_enclave_for_its_host_and_step(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertTrue(v.enclave)
            _, value = secretstore.make(v, self.conn, 'ts-key', 'token', 40, {'steps': ['tailscale'], 'hosts': ['web']})
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('web', 'web', 'scan', '{}')")
        with mock.patch('storageforge_index.receiving.items', return_value=([], [])):
            item = changes.deploy_items(self.db, self.conn, TS_PLAN, 'apply', 'gabe')[0]
        line = b''.join(item['data']).split(b'\n')[1].split(b' ')
        self.assertEqual(base64.b64decode(line[1]).decode(), value + '\n')
        said = [json.loads(r[0]) for r in self.conn.all("SELECT detail_json FROM audit_log WHERE action = 'enclave.release' AND outcome = 'ok'")]
        self.assertEqual([s['for'] for s in said], [{'host': 'web', 'platform': '', 'step': 'tailscale'}])
        self.assertEqual(self.e.status()['released'], 1)
        self.conn.execute("UPDATE device_credentials SET policy_json = NULL WHERE name = 'ts-key'")      # the policy is sealed with it
        with mock.patch('storageforge_index.receiving.items', return_value=([], [])):
            item = changes.deploy_items(self.db, self.conn, TS_PLAN, 'apply', 'gabe')[0]
        self.assertIn(b'REFUSED ts-key', b''.join(item['data']))


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserSecrets(Db):
    """Keys, Secrets for plan steps, in a real browser: one is made and shown once, the list never shows it, and it is removed."""

    def test_the_section_under_secrets(self):
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
        page.goto(base + '/admin#/secrets')
        page.wait_for_selector('html[data-route-ready]', state='attached')
        page.wait_for_selector('#secretbox li:has-text("No secrets yet.")')
        page.click('#secretbox summary')
        page.fill('#secname', 'grafana-admin')
        page.select_option('#seckind', 'pin')
        self.assertEqual(page.input_value('#seclength'), '8')
        page.fill('#seclength', '10')
        page.fill('#sechosts', 'web')
        page.click('#secretbox button:has-text("Make it")')
        page.wait_for_selector('#secretonce code.pub')
        shown = page.inner_text('#secretonce code.pub')
        self.assertEqual(shown, self.v.credential('grafana-admin', host='web')['password'])
        self.assertRegex(shown, r'^[0-9]{10}$')
        page.wait_for_selector('#secretbox li:has-text("grafana-admin")')
        self.assertIn('pin, 10 characters', page.inner_text('#secretbox'))
        self.assertIn('hosts web', page.inner_text('#secretbox'))
        page.click('#secretonce button:has-text("Hide it")')
        self.assertNotIn(shown, page.content())
        page.evaluate('loadSecrets()')
        page.wait_for_selector('#secretbox li:has-text("grafana-admin")')
        self.assertNotIn(shown, page.content())
        page.click('#secretbox li:has-text("grafana-admin") button:has-text("Remove")')
        page.fill('dialog[open] input[type=text]', 'grafana-admin')
        page.click('dialog[open] button[type=submit]')
        page.wait_for_selector('#secretbox li:has-text("No secrets yet.")')
        self.assertEqual(secretstore.listing(self.conn), [])
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
