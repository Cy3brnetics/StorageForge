"""The log (every source in one list, filters, exports) and the drive and share options reaching their scripts.
Run with: python3 -m unittest discover -s tests -v"""
import csv
import io
import json
import shutil
import tempfile
import unittest

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, logbook, shares
from storageforge_index.vault import AuditLog


class Log(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        AuditLog(self.db, self.conn, None).append('web:gabe', 'shares.save', 'ok', 'nas', None, {'path': '/srv/a'})
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, exit_code, output, actor, started_at)
                             VALUES ('g', 'nas', 'tasks', 'nightly', 'apply', 'failed', 1, '=cmd|boom', 'web:gabe', 2000000000)""")
        self.conn.execute("""INSERT INTO task_runs (host, task, started_at, exit_code, via, received_at)
                             VALUES ('pc', 'nightly', 1000, 0, 'scan', 1000)""")
        self.conn.execute("""INSERT INTO scan_jobs (host, requested_by, status, queued_at) VALUES ('pc', 'web:gabe', 'partial', 500)""")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rows(self, **f):
        return logbook.entries(self.conn, logbook.clean_filter(**f), 50)

    def test_every_source_newest_first_and_filters(self):
        self.assertEqual([e['source'] for e in self.rows()], ['deploy', 'audit', 'task', 'scan'])
        self.assertEqual({e['source'] for e in self.rows(host='pc')}, {'task', 'scan'})
        self.assertEqual([e['source'] for e in self.rows(outcomes='failed')], ['deploy'])
        self.assertEqual([e['source'] for e in self.rows(outcomes='warn')], ['scan'])
        self.assertEqual([e['source'] for e in self.rows(q='/srv/a')], ['audit'])
        self.assertEqual([e['source'] for e in self.rows(q='100%')], [])         # % is text, not a wildcard
        self.assertEqual([e['source'] for e in self.rows(until=1500)], ['task', 'scan'])
        with self.assertRaises(ValueError):
            self.rows(sources='nope')
        p = logbook.page(self.conn, logbook.clean_filter(), 2, 1)
        self.assertEqual(([e['source'] for e in p['entries']], p['more']), (['audit', 'task'], True))

    def test_exports(self):
        f = logbook.clean_filter()
        text, n = logbook.export(self.conn, f, 'csv', output=True)
        self.assertEqual(n, 4)
        row = next(r for r in csv.DictReader(io.StringIO(text)) if r['source'] == 'deploy')
        self.assertEqual(row['output'], "'=cmd|boom")                            # a spreadsheet must not run it
        data = json.loads(logbook.export(self.conn, f, 'json')[0])
        self.assertEqual(data['count'], 4)
        self.assertTrue(next(e for e in data['entries'] if e['source'] == 'audit')['hash'])
        self.assertNotIn('output', data['entries'][0])                           # only when asked for
        self.assertIn('| =cmd|boom', logbook.export(self.conn, f, 'text', output=True)[0])
        with self.assertRaises(ValueError):
            logbook.export(self.conn, f, 'xml')


class Options(unittest.TestCase):
    def test_mkfs_options_become_flags_and_nothing_else_does(self):
        self.assertEqual(changes.mkfs_args('ext4', 'reserved=1,stride=16,stripe_width=64'), '-m 1 -E stride=16,stripe_width=64')
        self.assertEqual(changes.mkfs_args('xfs', 'reflink=1,crc=1,su=64k,sw=4'), '-m reflink=1,crc=1 -d su=64k,sw=4')
        self.assertEqual(changes.mkfs_args('btrfs', 'data=single,checksum=xxhash'), '-d single --csum xxhash')
        self.assertEqual(changes.mkfs_args('ext4', ''), '')
        for fs, bad in (('ext4', 'reflink=1'), ('ext4', 'reserved=99'), ('xfs', 'su=1;id'), ('', 'reserved=1')):
            with self.assertRaises(ValueError):
                changes.mkfs_args(fs, bad)

    def test_new_empty_fields_keep_a_deployed_plans_hash(self):
        old = {'tasks': [{'type': 'format', 'host': 'h', 'params': {'device': '/dev/sdb', 'fstype': 'ext4'}}]}
        new = {'tasks': [{'type': 'format', 'host': 'h', 'params': {'device': '/dev/sdb', 'fstype': 'ext4', 'mkfs': ''}}]}
        set_ = {'tasks': [{'type': 'format', 'host': 'h', 'params': {'device': '/dev/sdb', 'fstype': 'ext4', 'mkfs': 'reserved=1'}}]}
        self.assertEqual(changes.plan_hash(old), changes.plan_hash(new))
        self.assertNotEqual(changes.plan_hash(old), changes.plan_hash(set_))

    def test_smb_settings_reach_the_config_as_checked_text(self):
        lines = shares.smb_lines({'smb': {'browseable': False, 'create_mask': '0664', 'force_group': 'media', 'recycle': True,
                                          'shadow_copy': 'zfs', 'shadow_prefix': 'daily', 'veto': ['*.tmp'], 'encrypt': 'required'}})
        for want in ('browseable = no', 'create mask = 0664', 'force group = media', 'smb encrypt = required', 'veto files = /*.tmp/',
                     'vfs objects = shadow_copy2 recycle', 'shadow:snapdir = .zfs/snapshot', 'shadow:format = daily-%Y-%m-%d_%H%M%S'):
            self.assertIn(want, lines)
        self.assertEqual(shares.smb_lines({}), [])
        for bad in ({'comment': 'x\npath = /etc'}, {'force_user': 'a b'}, {'write_list': 'a;b'}, {'encrypt': 'maybe'}, {'veto': ['a/b']}):
            with self.assertRaises(ValueError):
                shares.smb_lines({'smb': bad})

    def test_client_options(self):
        self.assertEqual(shares.client_options({'options': 'noatime,nconnect=4', 'idle_min': 10, 'automount': False}),
                         ('noatime,nconnect=4,x-systemd.idle-timeout=10min', False))
        self.assertEqual(shares.client_options({}), ('', True))
        for bad in ('a b', 'credentials=/etc/x', 'x-systemd.automount', 'a\nb'):
            with self.assertRaises(ValueError):
                shares.client_options({'options': bad})


if __name__ == '__main__':
    unittest.main()
