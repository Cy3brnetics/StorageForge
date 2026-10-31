"""Host configuration history and the reinstall script: passwords never kept, values never run as code."""
import base64
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import hostconfig, reinstall

CANARY = '$(touch${IFS}/tmp/CANARY)`id`"q;x'


def line(path, text):
    return f'{path}\t{base64.b64encode(text.encode()).decode()}'


def inventory(fstab, **extra):
    return {'collected_at': '2026-10-30T00:00:00+00:00', 'configs': hostconfig.parse_configs(line('/etc/fstab', fstab)),
            'accounts': 'u\tana\t1500\t1500\t/home/ana\t/bin/bash\ng\tana\t1500',
            'lsblk': {'blockdevices': [{'name': 'sdb', 'path': '/dev/sdb', 'type': 'disk', 'children': [
                {'name': 'sdb1', 'path': '/dev/sdb1', 'type': 'part', 'fstype': 'btrfs', 'uuid': 'aaaa-bbbb'}]}]}, **extra}


class Capture(unittest.TestCase):
    def test_passwords_are_removed(self):
        fstab = '//nas/a /mnt/a cifs username=me,password=hunter2,nofail 0 0\n'
        got = hostconfig.parse_configs(line('/etc/fstab', fstab) + '\n' + line('/etc/samba/x.conf', '[a]\\n  ldap admin password = hunter2\\n'.replace('\\n', '\n')))
        self.assertNotIn('hunter2', str(got))
        self.assertEqual(hostconfig.parse_fstab_lines(got['files']['/etc/fstab'])[0]['target'], '/mnt/a')

    def test_only_known_paths_and_unreadable_ones_are_listed(self):
        got = hostconfig.parse_configs(line('/etc/shadow', 'x') + '\n/etc/crypttab\t!')
        self.assertEqual(got, {'files': {}, 'unreadable': ['/etc/crypttab']})

    def test_a_group_with_no_members_on_the_last_line_is_kept(self):
        got = hostconfig.parse_accounts('g\tlab\t1000\tlab\ng\tana\t1500')      # the section is stripped, and with it the last tab
        self.assertEqual([g['name'] for g in got['groups']], ['lab', 'ana'])


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(shutil.rmtree, self.tmp)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")

    def scan(self, fstab, **extra):
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps(inventory(fstab, **extra))})
        return hostconfig.capture(self.conn, 'nas')

    FSTAB = 'UUID=root / ext4 defaults 0 1\nUUID=aaaa-bbbb /data/media btrfs subvol=@media,nofail 0 0\nUUID=root /home ext4 defaults 0 0\n'

    def test_a_version_only_when_something_changed_and_old_ones_go(self):
        first = self.scan(self.FSTAB)
        self.assertTrue(first['new'])
        self.assertFalse(self.scan(self.FSTAB)['new'])
        second = self.scan(self.FSTAB + '/data/media /srv/m none bind 0 0\n')
        self.assertTrue(second['new'])
        changes = hostconfig.diff(hostconfig.get(self.conn, first['config_id'])['body'], hostconfig.get(self.conn, second['config_id'])['body'])
        self.assertIn('/etc/fstab', [c['name'] for c in changes])
        for i in range(hostconfig.KEEP + 3):
            self.scan(self.FSTAB + f'# {i}\n')
        self.assertEqual(len(hostconfig.versions(self.conn, 'nas')), hostconfig.KEEP)

    def test_kinds_and_order(self):
        self.scan(self.FSTAB + '/data/media /srv/m none bind 0 0\n//nas/a /mnt/a cifs password=x 0 0\n')
        body = hostconfig.latest(self.conn, 'nas')['body']
        kinds = {m['target']: m['kind'] for m in body['mounts']}
        self.assertEqual(kinds, {'/': 'system', '/data/media': 'device', '/home': 'rootfs', '/srv/m': 'derived', '/mnt/a': 'network'})
        self.assertLess([m['target'] for m in body['mounts']].index('/data/media'), [m['target'] for m in body['mounts']].index('/srv/m'))
        self.assertTrue(next(m for m in body['mounts'] if m['target'] == '/mnt/a')['blocked'])

    def test_live_exports_stand_in_for_a_file_the_scan_could_not_read(self):
        inv = inventory(self.FSTAB, nfs='/data/media\t10.0.0.0/24(rw,sync)')
        inv['configs']['unreadable'] = ['/etc/exports.d/storageforge.exports']
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps(inv)})
        body = hostconfig.build(self.conn, 'nas')
        self.assertTrue(body['files']['/etc/exports.d/storageforge.exports'].startswith(hostconfig.REBUILT_MARK))
        self.assertEqual(body['unreadable'], [])

    def test_bundle_holds_the_script_and_files_but_no_passwords(self):
        self.scan(self.FSTAB + '//nas/a /mnt/a cifs password=hunter2 0 0\n')
        with tarfile.open(fileobj=io.BytesIO(hostconfig.bundle(self.conn, ['nas']))) as tar:
            names = tar.getnames()
            everything = b''.join(tar.extractfile(n).read() for n in names)
        self.assertIn('nas/reinstall.sh', names)
        self.assertIn('nas/etc/fstab', names)
        self.assertNotIn(b'hunter2', everything)

    def test_no_value_runs_as_code(self):
        fstab = f'UUID=aaaa-bbbb /data/{CANARY.replace(" ", "")} btrfs subvol=@,nofail 0 0\n'
        version = {'host': 'nas', 'config_id': 1, 'captured_at': 1, 'body': {
            **json.loads(json.dumps(hostconfig.build(self.conn, 'nas'))),
            'os': CANARY, 'files': {'/etc/exports': f'/srv/{CANARY} *(rw)\n', '/etc/fstab': fstab},
            'mounts': [{**e, 'kind': k, 'origin': 'fstab', 'blocked': None} for e in hostconfig.parse_fstab_lines(fstab) for k in ('device', 'network', 'derived')],
            'crypt': [{'name': CANARY, 'spec': CANARY, 'key': CANARY, 'line': CANARY, 'in_crypttab': True}],
            'datasets': [{'name': CANARY, 'target': '/' + CANARY}], 'zpools': [CANARY],
            'accounts': {'users': [{'name': 'ana', 'uid': 1500, 'gid': 1500, 'home': '/' + CANARY, 'shell': CANARY}], 'groups': []},
            'exports': [{'protocol': 'NFS', 'path': '/' + CANARY}], 'links': [{'path': '/' + CANARY, 'target': CANARY, 'needs': CANARY}],
            'drives': [{'uuid': CANARY, 'fstype': 'x', 'label': CANARY + '\nrm -rf /', 'dev': CANARY}]}}
        text = reinstall.script(version)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True).returncode, 0)
        bare = re.sub(r"'[^']*'", "''", text)
        self.assertEqual([x for x in bare.splitlines() if 'CANARY' in x and not x.lstrip().startswith('#')], [])
        self.assertNotIn('\nrm -rf /', text)
