"""rotation.py: every key changed, for when one may have leaked. The hosts here are a stand-in: each account is an authorized_keys list,
and a login works when the key's line is in it. The two shell lines that edit authorized_keys run for real, under /bin/sh in a temporary HOME."""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:
    from tests import dbfactory
from storageforge_index import rotation
from storageforge_index.vault import AuditLog, Vault

SECRET = 'r' * 40


class Fleet:
    """Accounts on hosts, each an authorized_keys list. `refuse` names hosts that do not take a new line."""

    def __init__(self, conn):
        self.conn, self.keys, self.refuse = conn, {}, set()

    def pub(self, name):
        return self.conn.scalar('SELECT public_key FROM ssh_keys WHERE name = :n', {'n': name})

    def run(self, v, conn, key_name, place, command):
        lines = self.keys.setdefault((place['host'], place['user']), [])
        if rotation._blob(self.pub(key_name)) not in ' '.join(lines):
            raise rotation.RotationError(f'{place["user"]}@{place["host"]}: Permission denied (publickey)')
        if command == 'echo ok':
            return 'ok'
        if 'added' in command:
            if place['host'] in self.refuse:
                return ''
            line = command.split("grep -qxF -- '")[1].split("'")[0]
            if line not in lines:
                lines.append(line)
            return 'added'
        if 'dropped' in command:
            blob = command.split('grep -vF -- ')[1].split(' ')[0].strip("'")
            lines[:] = [x for x in lines if blob not in x]
            return 'dropped'
        raise AssertionError(command)


class Rotation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sfrot-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        Vault(self.db, self.conn, SECRET.encode()).init()
        self.fleet = Fleet(self.conn)
        with Vault(self.db, self.conn).unlock() as v:
            v.generate_key('fleet')
            v.generate_key('spare')
            v.bind('fleet', 'nas', 'scan', actions='scan,checksum')
            v.bind('fleet', 'pc', 'scan', actions='scan,checksum,deploy')
        for h in ('nas', 'pc'):
            self.conn.execute('INSERT INTO hosts (hostname, ssh_host, ssh_user, last_scanned_at) VALUES (:h, :h, :u, :t)', {'h': h, 'u': 'scan', 't': int(time.time())})
            self.fleet.keys[(h, 'scan')] = ['from="10.0.0.0/8" ' + self.fleet.pub('fleet'), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOfThePersonxxxxxxxxxxxxxxxxxxxx you@laptop']
        p = mock.patch.object(rotation, '_run', self.fleet.run)
        p.start()
        self.addCleanup(p.stop)
        self.old = {'pub': self.fleet.pub('fleet'), 'fp': self.conn.scalar("SELECT fingerprint FROM ssh_keys WHERE name = 'fleet'")}

    def test_the_plan_names_each_key_with_its_hosts_and_changes_nothing(self):
        p = rotation.plan(self.db, self.conn)
        by = {k['key']: sorted(h['host'] for h in k['hosts']) for k in p['keys']}
        self.assertEqual(by, {'fleet': ['nas', 'pc'], 'spare': []})
        self.assertIn('session secret', [m['what'] for m in p['manual']])
        self.assertEqual(self.fleet.pub('fleet'), self.old['pub'])

    def test_a_key_is_changed_everywhere_and_nothing_else_is_touched(self):
        self.conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES ('a', 'x', 'admin', 1)")
        uid = self.conn.scalar("SELECT user_id FROM users WHERE username = 'a'")
        self.conn.execute('INSERT INTO web_sessions (sid_hash, user_id, created_at) VALUES (:s, :u, 1)', {'s': 'h' * 64, 'u': uid})
        r = rotation.apply(self.db, self.conn, 'test')
        fleet = next(x for x in r['results'] if x['key'] == 'fleet')
        self.assertTrue(fleet['ok'], fleet['steps'])
        new = self.fleet.pub('fleet')
        self.assertNotEqual(new, self.old['pub'])
        for h in ('nas', 'pc'):
            lines = self.fleet.keys[(h, 'scan')]
            self.assertFalse(any(rotation._blob(self.old['pub']) in x for x in lines), lines)     # the old one is out, options and all
            self.assertTrue(any(rotation._blob(new) in x for x in lines))
            self.assertTrue(any('you@laptop' in x for x in lines))                                # a person's own key stays
        with Vault(self.db, self.conn).unlock() as v:
            self.assertEqual({b['key'] for b in v.bindings()}, {'fleet'})                           # the same name, so nothing that names it changes
            self.assertEqual(v.resolve('pc', 'deploy').fingerprint, fleet['fingerprint'])
            self.assertNotIn('fleet.rotating', [k['name'] for k in v.list_keys()])
        self.assertEqual(next(x for x in r['results'] if x['key'] == 'spare')['ok'], None)       # used by no host: left alone, and said so
        self.assertEqual((r['sessions_ended'], self.conn.scalar('SELECT count(*) FROM web_sessions')), (1, 0))
        actions = [e['action'] for e in AuditLog(self.db, self.conn, None).tail(10)]
        self.assertIn('rotate.key', actions)

    def test_one_host_that_will_not_take_it_leaves_the_old_key_working_everywhere(self):
        self.fleet.refuse = {'pc'}
        r = rotation.apply(self.db, self.conn, 'test')
        fleet = next(x for x in r['results'] if x['key'] == 'fleet')
        self.assertFalse(fleet['ok'])
        self.assertIn('The old key is unchanged', fleet['steps'][-1])
        self.assertEqual(self.fleet.pub('fleet'), self.old['pub'])
        for h in ('nas', 'pc'):
            lines = self.fleet.keys[(h, 'scan')]
            self.assertEqual(sum(rotation._blob(self.old['pub']) in x for x in lines), 1, lines)
            self.assertEqual(len(lines), 2, f'{h} kept a line of the new key: {lines}')
        with Vault(self.db, self.conn).unlock() as v:
            self.assertNotIn('fleet.rotating', [k['name'] for k in v.list_keys()])
            self.assertEqual(v.resolve('nas').fingerprint, self.old['fp'])

    def test_a_key_in_authorized_keys_with_no_binding_is_named_and_not_hidden(self):
        import json
        spare = self.conn.scalar("SELECT fingerprint FROM ssh_keys WHERE name = 'spare'")
        fleet = self.conn.scalar("SELECT fingerprint FROM ssh_keys WHERE name = 'fleet'")
        seen = {'unreadable': [], 'keys': [{'user': 'root', 'fingerprint': spare, 'comment': 'x'}, {'user': 'scan', 'fingerprint': fleet, 'comment': 'x'},
                                            {'user': 'admin', 'fingerprint': fleet, 'comment': 'x'}]}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'authkeys': seen})})
        p = {k['key']: k for k in rotation.plan(self.db, self.conn)['keys']}
        self.assertEqual(p['spare']['elsewhere'], ['root@nas'])
        self.assertEqual(p['fleet']['elsewhere'], ['admin@nas'])          # scan@nas is the binding's own account, so that one is rotated
        r = {x['key']: x for x in rotation.apply(self.db, self.conn, 'test')['results']}
        self.assertIn('root@nas', r['spare']['steps'][-1])
        self.assertIn('admin@nas', r['fleet']['steps'][-1])

    def test_only_rotates_the_keys_named(self):
        r = rotation.apply(self.db, self.conn, 'test', only={'spare'})
        self.assertEqual([x['key'] for x in r['results']], ['spare'])
        self.assertEqual(self.fleet.pub('fleet'), self.old['pub'])

    def test_a_new_vault_secret_wraps_everything_again(self):
        r = rotation.apply(self.db, self.conn, 'test', new_vault_secret=b'n' * 40)
        self.assertEqual(r['vault_rewrapped'], 2)
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'n' * 40}):
            with Vault(self.db, self.conn).unlock() as v:
                self.assertEqual(len(v.list_keys()), 2)


class AuthorizedKeysLines(unittest.TestCase):
    """The two lines rotation sends, run under /bin/sh in a temporary HOME."""

    def sh(self, home, command):
        return subprocess.run(['/bin/sh', '-c', command], env={'HOME': str(home), 'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=20)

    def test_add_is_once_and_drop_takes_every_line_of_that_key_and_keeps_the_mode(self):
        home = Path(tempfile.mkdtemp(prefix='sfak-'))
        self.addCleanup(shutil.rmtree, home, True)
        line = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlobOfTheNewKeyxxxxxxxxxxxxxxxxxxxxxxxx storageforge'
        for _ in range(2):
            self.assertIn('added', self.sh(home, rotation.add_line(line)).stdout)
        ak = home / '.ssh' / 'authorized_keys'
        self.assertEqual(ak.read_text().count(line), 1)
        self.assertEqual(oct(ak.stat().st_mode & 0o777), '0o600')
        ak.write_text(ak.read_text() + 'command="x" ' + line + '\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeep you@laptop\n')
        self.assertIn('dropped', self.sh(home, rotation.drop_line(rotation._blob(line))).stdout)
        self.assertEqual(ak.read_text(), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeep you@laptop\n')
        self.assertEqual(oct(ak.stat().st_mode & 0o777), '0o600')

    def test_a_line_with_quotes_or_a_semicolon_in_its_comment_stays_text(self):
        home = Path(tempfile.mkdtemp(prefix='sfak-'))
        self.addCleanup(shutil.rmtree, home, True)
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlobxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx it's; touch $HOME/pwned"
        self.sh(home, rotation.add_line(line))
        self.assertFalse((home / 'pwned').exists())
        self.assertIn(line, (home / '.ssh' / 'authorized_keys').read_text())


if __name__ == '__main__':
    unittest.main()
