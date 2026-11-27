"""The permission guide (apiguide.py) and the routes that add a platform connection (routes_apiconn.py): the guide comes first and
recommends the least that works, never root, an admin key or a full-access role; the token comes in once and goes into the vault; the
certificate is shown for a person to accept."""
import shlex
import unittest

try:
    from test_apiconn import TOKEN, TOKEN_ID, Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import TOKEN, TOKEN_ID, Base
from storageforge_index import apiconn, apiguide, server, users

PW = 'a long enough password'
FULL = ('Administrator', 'PVEAdmin', 'PVEVMAdmin', 'PVESysAdmin', 'DatastoreAdmin', ' Admin ', 'root@pam', '-privsep 0')


class Guide(unittest.TestCase):
    def runs(self, kind, **kw):
        return [cmd for s in apiguide.steps(kind, now=0, **kw) for cmd in s['run']]

    def test_each_platform_recommends_its_read_only_role_and_never_a_full_one(self):
        want = {'pve': 'PVEAuditor', 'pbs': 'DatastoreAudit', 'pdm': 'Auditor'}
        for kind in want:                       # the other platforms have their own test of this (test_apitruenas and the rest)
            with self.subTest(kind):
                cmds = self.runs(kind, scope='store1' if kind == 'pbs' else 'lab' if kind == 'pdm' else None)
                self.assertTrue(any(want[kind] in c for c in cmds))
                for c in cmds:
                    for bad in FULL:
                        self.assertNotIn(bad, f' {c} ')
                    shlex.split(c)                  # each command is one a shell reads as written
                g = apiguide.guide(kind)
                self.assertEqual(g['label'], 'not lab-tested')
                self.assertTrue(g['sources'] and g['fetched'])
                self.assertTrue(any('root@pam' in n for n in g['never']))

    def test_proxmox_ve_separates_the_token_gives_the_user_and_the_token_the_role_and_sets_an_expiry(self):
        cmds = self.runs('pve')
        self.assertEqual(cmds, [
            "pveum user add storageforge@pve -comment 'StorageForge: reads through the API'",
            'pveum acl modify / -user storageforge@pve -role PVEAuditor',
            f'pveum user token add storageforge@pve storageforge -privsep 1 -expire {365 * 86400}',
            "pveum acl modify / -token 'storageforge@pve!storageforge' -role PVEAuditor",
            'pveum user token permissions storageforge@pve storageforge'])
        narrow = self.runs('pve', scope='/vms /storage /nodes')
        self.assertIn("pveum acl modify /storage -token 'storageforge@pve!storageforge' -role PVEAuditor", narrow)
        self.assertNotIn('pveum acl modify / -user storageforge@pve -role PVEAuditor', narrow)

    def test_backup_server_and_datacenter_manager_are_scoped_to_the_named_datastores_and_remotes(self):
        pbs = self.runs('pbs', scope='store1, store2')
        self.assertIn("proxmox-backup-manager acl update /datastore/store2 DatastoreAudit --auth-id 'storageforge@pbs!storageforge'", pbs)
        self.assertIn(f'proxmox-backup-manager user generate-token storageforge@pbs storageforge --expire {365 * 86400}', pbs)
        self.assertFalse([c for c in pbs if ' / ' in c or c.endswith(' /datastore') or '/datastore DatastoreAudit' in c])
        pdm = self.runs('pdm', scope='pve-a pbs-b')
        self.assertIn('proxmox-datacenter-manager-client acl update /resource/pve-a Auditor --auth-id storageforge@pdm', pdm)
        self.assertFalse([c for c in pdm if 'acl update / ' in c])
        self.assertIn('reaches as far as PDM does', apiguide.guide('pdm')['reach'])

    def test_an_action_says_what_it_needs_on_which_object_and_pdm_offers_none(self):
        (step,) = apiguide.action_steps('pve', 'snapshot')
        self.assertIn("pveum role add StorageForgeSnapshot -privs VM.Snapshot", step['run'])
        self.assertIn('/vms/<vmid>', step['say'])
        self.assertTrue(all(' / ' not in f' {c} ' for c in step['run']))
        backup = apiguide.action_steps('pve', 'backup')[0]['run']
        self.assertIn("pveum role add StorageForgeBackup -privs 'VM.Backup Datastore.AllocateSpace'", backup)
        self.assertIn('DatastoreReader', apiguide.action_steps('pbs', 'restore-test')[0]['say'])
        with self.assertRaisesRegex(apiguide.GuideError, 'narrower than Administrator'):
            apiguide.action_steps('pdm', 'migrate')
        self.assertEqual(apiguide.actions('pdm'), [])

    def test_a_name_that_a_shell_would_read_as_syntax_is_refused(self):
        for kw in ({'user': 'a;b'}, {'token': '$(id)'}, {'scope': '/vms;rm'}):
            with self.subTest(kw), self.assertRaises(apiguide.GuideError):
                apiguide.steps('pve', **kw)
        with self.assertRaises(apiguide.GuideError):
            apiguide.steps('pbs', scope="x'y")


class Registry(unittest.TestCase):
    def test_every_platform_has_a_connection_kind_a_guide_and_a_reader_in_one_order(self):
        from storageforge_index import apiread
        self.assertEqual(list(apiguide.READER_MODULES), list(apiguide.GUIDES))
        self.assertEqual(set(apiconn.KINDS), set(apiguide.GUIDES))
        self.assertEqual(list(apiguide.GUIDES)[:3], ['pve', 'pbs', 'pdm'])
        self.assertLessEqual(set(apiconn.REFUSED), set(apiconn.KINDS))
        for kind, name in apiguide.READER_MODULES.items():
            self.assertEqual(apiread.reader(kind).__name__, f'storageforge_index.{name}')
        self.assertIsNone(apiread.reader('apiconn'))


class Web(Base):
    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def test_guide_then_token_then_certificate_then_remove(self):
        c = self.client('admin')
        g = c.get('/api/keys/platforms/guide/pve').get_json()
        self.assertEqual(g['role'], 'PVEAuditor')
        self.assertEqual(c.get('/api/keys/platforms/guide/xen').status_code, 400)
        r = c.post('/api/keys/platforms', json={'kind': 'pve', 'name': 'lab', 'url': self.fake.url, 'token_id': TOKEN_ID, 'token': TOKEN})
        self.assertEqual(r.status_code, 201, r.get_json())
        body = r.get_json()
        self.assertEqual(body['certificate']['sha256'], self.fake.fingerprint)
        self.assertEqual(body['connection']['state'], 'certificate-unaccepted')
        cid = body['connection']['conn_id']
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(c.post(f'/api/keys/platforms/{cid}/certificate', json={'sha256': ':'.join(['00'] * 32)}).status_code, 409)
        r = c.post(f'/api/keys/platforms/{cid}/certificate', json={'sha256': self.fake.fingerprint})
        self.assertEqual(r.get_json()['connection']['state'], 'not-read')
        self.assertEqual(c.put(f'/api/keys/platforms/{cid}/actions', json={'actions': ['format-disks']}).status_code, 400)
        r = c.put(f'/api/keys/platforms/{cid}/actions', json={'actions': ['snapshot']})
        self.assertIn('VM.Snapshot', r.get_json()['needs']['snapshot'][0]['say'])
        listed = c.get('/api/keys/platforms')
        self.assertEqual(listed.get_json()['connections'][0]['actions'], ['snapshot'])
        self.assertEqual(c.delete(f'/api/keys/platforms/{cid}').status_code, 200)
        self.assertEqual(c.delete(f'/api/keys/platforms/{cid}').status_code, 404)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'platform.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['platform.add', 'platform.certificate', 'platform.certificate', 'platform.actions', 'platform.remove'])
        self.no_token_anywhere(listed.get_data(as_text=True), r.get_data(as_text=True))

    def test_a_refused_add_says_why_and_keeps_nothing(self):
        c = self.client('admin')
        r = c.post('/api/keys/platforms', json={'kind': 'pve', 'name': 'lab', 'url': self.fake.url.replace('https', 'http'), 'token_id': TOKEN_ID, 'token': TOKEN})
        self.assertIn('plain HTTP is refused', r.get_json()['error'])
        r = c.post('/api/keys/platforms', json={'kind': 'pve', 'name': 'lab', 'url': self.fake.url, 'token_id': 'root@pam!x', 'token': TOKEN})
        self.assertIn('root@pam is refused', r.get_json()['error'])
        self.assertEqual(apiconn.listing(self.conn), [])
        self.no_token_anywhere(r.get_data(as_text=True))

    def test_a_viewer_reads_the_guide_and_cannot_add_accept_or_remove(self):
        row = self.add()
        c = self.client('viewer')
        self.assertEqual(c.get('/api/keys/platforms').status_code, 200)
        self.assertEqual(c.get('/api/keys/platforms/guide/pbs').status_code, 200)
        self.assertEqual(c.post('/api/keys/platforms', json={'kind': 'pve', 'name': 'b', 'url': self.fake.url, 'token_id': TOKEN_ID, 'token': TOKEN}).status_code, 403)
        self.assertEqual(c.post(f'/api/keys/platforms/{row["conn_id"]}/certificate', json={'sha256': self.fake.fingerprint}).status_code, 403)
        self.assertEqual(c.delete(f'/api/keys/platforms/{row["conn_id"]}').status_code, 403)


if __name__ == '__main__':
    unittest.main()
