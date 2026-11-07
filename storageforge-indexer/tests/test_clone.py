"""Copying a host onto another: the plans clone.build makes, the accounts and share-file steps, the Moves options it
uses, and the API's rule that every risk is accepted by name before anything is saved."""
import base64
import contextlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, clone, hostconfig, moves, pkglist, steps_clone

CANARY = '$(touch${IFS}/tmp/CANARY)`id`"q;x'
HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; PROBLEMS=0; STAMP=20261107-120000
'''
FSTAB = ('UUID=rootid / ext4 defaults 0 1\n'
         'UUID=aaaa-1111 /srv/data ext4 noatime,nofail 0 2\n'
         'UUID=bbbb-2222 /srv/media btrfs subvol=@media,compress=zstd,nofail 0 0\n'
         'UUID=bbbb-2222 /srv/photos btrfs subvol=@photos,nofail 0 0\n'
         'nas:/backups /mnt/backups nfs4 _netdev,nofail 0 0\n')
EXPORTS = '/srv/data 10.0.0.0/24(rw,sync,no_subtree_check)\n'


def line(path, text):
    return f'{path}\t{base64.b64encode(text.encode()).decode()}'


def blk(*disks):
    return {'blockdevices': [{'name': n, 'path': f'/dev/{n}', 'type': 'disk', 'serial': serial, 'size': 10 * 2**30,
                              **({'children': [{'name': n + '1', 'path': f'/dev/{n}1', 'type': 'part', 'fstype': fs}]} if fs else {})}
                             for n, serial, fs in disks]}


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        src = {'collected_at': '2026-11-07T00:00:00+00:00',
               'configs': hostconfig.parse_configs(line('/etc/fstab', FSTAB) + '\n' + line('/etc/exports', EXPORTS)),
               'accounts': 'u\tana\t1500\t1500\t/home/ana\t/bin/bash\nu\tbob\t1501\t1501\t/home/bob\t/bin/zsh\ng\tana\t1500\t\ng\tbob\t1501\t\ng\tmedia\t2000\tana,bob',
               'lsblk': blk(('sda', 'S1', 'ext4'), ('sdb', 'S2', 'btrfs')),
               'pkglist': pkglist.parse('distro\tdebian\t13\npm apt-get\nm\tvim\nm\tnfs-kernel-server\nm\tmydeb\no\tmydeb\ncomplete')}
        self.add('web-01', src, [('/', 'ext4', 'UUID=rootid', 10), ('/srv/data', 'ext4', 'UUID=aaaa-1111', 8), ('/srv/media', 'btrfs', 'UUID=bbbb-2222', 3)])
        tgt = {'lsblk': blk(('vda', 'V0', 'ext4'), ('vdb', 'sf-data1', None), ('vdc', 'sf-data2', None)),
               'accounts': 'u\tana\t1600\t1600\t/home/ana\t/bin/bash\ng\tana\t1600\t', 'configs': hostconfig.parse_configs(line('/etc/exports', '/old *(ro)\n'))}
        self.add('web-copy', tgt, [('/', 'ext4', '/dev/vda1', 2)])

    def add(self, name, inv, mounts):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:n, :n, 'scan', :i)", {'n': name, 'i': json.dumps(inv)})
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :n', {'n': name})
        for target, fs, source, gib in mounts:
            self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                                 VALUES (:h, :m, :s, :f, :t, :u, 'indexed')""", {'h': hid, 'm': target, 's': source, 'f': fs, 't': 100 * 2**30, 'u': gib * 2**30})

    def libvirt(self):
        from storageforge_index import security
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('kvm', 'kvm', 'scan', '{}')")
        security._save_measurement(self.conn, 'kvm', 'infra', int(time.time()), 'test', {'tools': ['virsh'], 'libvirt': [{'name': 'web-copy', 'state': 'running'}]})


class Build(Db):
    def test_the_plan_is_made_of_ordinary_steps(self):
        got = clone.build(self.conn, 'web-01', 'web-copy', files='all')
        tasks = got['plans']['changes']['tasks']
        kinds = [t['type'] for t in tasks]
        self.assertEqual(kinds[:2], ['packages', 'accounts'])
        self.assertEqual(kinds.count('format'), 2)
        fmt = {t['params']['device']: t['params'] for t in tasks if t['type'] == 'format'}
        self.assertEqual((fmt['/dev/vdb']['fstype'], fmt['/dev/vdb']['confirm'], fmt['/dev/vdc']['fstype']), ('ext4', '/dev/vdb', 'btrfs'))
        mounts = {t['params']['target']: t['params'] for t in tasks if t['type'] == 'mount'}
        self.assertEqual(mounts['/srv/data']['options'], 'noatime,nofail')
        self.assertEqual((mounts['/srv/media']['subvol'], mounts['/srv/media']['options']), ('@media', 'compress=zstd,nofail'))
        top = next(t for t in mounts if t.endswith('-top'))
        self.assertEqual(sorted(t['params']['path'] for t in tasks if t['type'] == 'subvolume'), [f'{top}/@media', f'{top}/@photos'])
        self.assertEqual(kinds[-1], 'config-files')
        self.assertTrue(any('/mnt/backups' in n for n in got['not_carried']))
        self.assertTrue(any('mydeb' in n for n in got['not_carried']))
        files = got['plans']['files']['steps']
        self.assertEqual(sorted(s['src']['path'] for s in files), ['/home', '/srv/data', '/srv/media', '/srv/photos'])
        home = next(s for s in files if s['src']['path'] == '/home')
        self.assertIn('.cache/', home['excludes'])
        self.assertTrue(all(s['options']['keep_replaced'] and not s['options']['dirs_only'] for s in files))
        # every plan passes the same checks as one made by hand
        changes.normalize(got['plans']['changes'])
        moves.normalize(got['plans']['files'])

    def test_risks_name_what_they_touch(self):
        got = clone.build(self.conn, 'web-01', 'web-copy', files='structure')
        ids = [r['id'] for r in got['risks']]
        self.assertEqual(got['risks'][0]['id'], 'no-snapshot')        # plain ext4 root, and no VM host known
        self.assertIn('format-/dev/vdb', ids)
        self.assertIn('files-replaced', ids)
        self.assertTrue(all(s['options']['dirs_only'] for s in got['plans']['files']['steps']))

    def test_a_vm_is_snapshotted_through_its_libvirt_host(self):
        self.libvirt()
        got = clone.build(self.conn, 'web-01', 'web-copy')
        first = got['plans']['changes']['tasks'][0]
        self.assertEqual((first['type'], first['host'], first['params']['action']), ('workload-action', 'kvm', 'snapshot'))
        self.assertEqual(got['plans']['after']['tasks'][0]['params']['action'], 'snapshot')
        self.assertNotIn('no-snapshot', [r['id'] for r in got['risks']])

    def test_a_disk_that_holds_something_is_a_critical_risk_and_a_map_wins(self):
        got = clone.build(self.conn, 'web-01', 'web-copy', storage={'/srv/data': '/dev/vda'})
        risk = next(r for r in got['risks'] if r['id'] == 'format-/dev/vda')
        self.assertEqual(risk['level'], 'crit')
        self.assertIn('holds partitions', risk['text'])
        self.assertTrue(any('/srv/media' in n and 'no target disk' in n for n in got['not_carried']))

    def test_bad_requests(self):
        with self.assertRaises(ValueError):
            clone.build(self.conn, 'web-01', 'web-01')
        with self.assertRaises(LookupError):
            clone.build(self.conn, 'web-01', 'nowhere')
        with self.assertRaises(ValueError):
            clone.build(self.conn, 'web-01', 'web-copy', mode='yolo')

    def test_the_checks_of_the_new_steps(self):
        got = clone.build(self.conn, 'web-01', 'web-copy')
        pid = clone.save(self.conn, got, 'test')['changes']
        items = {t['title']: [i['text'] for i in t['items']] for t in changes.check(self.conn, changes.get_plan(self.conn, pid))['tasks']}
        acc = items['Accounts of web-01']
        self.assertTrue(any('ana is 1600 here, 1500 there' in x for x in acc))
        self.assertTrue(any('bob' in x and 'to add' in x for x in acc))
        self.assertTrue(any('replaces /etc/exports' in x for x in items['Share files of web-01']))
        again = clone.save(self.conn, clone.build(self.conn, 'web-01', 'web-copy'), 'test')['changes']      # the same name twice: the second gets a date
        self.assertNotEqual(pid, again)

    def test_the_whole_script_and_playbook(self):
        got = clone.build(self.conn, 'web-01', 'web-copy', files='all')
        script = changes.script(self.conn, got['plans']['changes'])
        sh = Path(self.tmp) / 'c.sh'
        sh.write_text(script)
        self.assertEqual(subprocess.run(['bash', '-n', str(sh)], capture_output=True, text=True).stderr, '')
        for fn in ('t_packages', 't_accounts', 't_config_files', 't_format', 't_mount'):
            self.assertIn(fn, script)
        self.assertIn('t_accounts', changes.ansible(self.conn, got['plans']['changes']))
        mv = moves.script(self.conn, {**moves.normalize(got['plans']['files']), 'id': 1})
        self.assertIn('keepold', mv)


class Steps(Db):
    def run_bash(self, fn, *args, apply=False):
        script = HARNESS + f'APPLY={int(apply)}\n' + steps_clone.ACCOUNTS_BASH + f'\n{fn} ' + ' '.join(shlex.quote(a) for a in args) + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)

    def test_accounts_report_what_they_would_add(self):
        body = steps_clone._accounts_args(self.conn, {'params': {'from_host': 'web-01'}})[0]
        lines = base64.b64decode(body).decode().splitlines()
        self.assertIn('u\tbob\t1501\t1501\t/home/bob\t/bin/zsh', lines)
        self.assertIn('m\tana\tmedia', lines)
        # names no machine has: everything is missing, nothing is added
        mine = base64.b64encode(b'g\tsfclonetestg\t54321\nu\tsfclonetestu\t54321\t54321\t/home/sfclonetestu\t/bin/bash').decode()
        out = self.run_bash('t_accounts', 'web-01', '1', mine)
        self.assertIn('missing: group sfclonetestg (54321)', out.stdout)
        self.assertIn('missing: user sfclonetestu (54321), home /home/sfclonetestu', out.stdout)
        self.assertIn('has no accounts', self.run_bash('t_accounts', 'web-01', '1', '').stdout)

    def test_a_home_or_shell_that_is_not_a_plain_path_is_replaced(self):
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'web-01'",
                          {'i': json.dumps({'accounts': f'u\tana\t1500\t1500\t/home/{CANARY}\t/bin/sh;id', 'configs': {'files': {}}})})
        body = steps_clone._accounts_args(self.conn, {'params': {'from_host': 'web-01'}})[0]
        self.assertEqual(base64.b64decode(body).decode().splitlines(), ['u\tana\t1500\t1500\t/home/ana\t/bin/bash'])

    def test_share_files_are_only_share_files(self):
        body = steps_clone._config_args(self.conn, {'params': {'from_host': 'web-01'}})[0]
        self.assertEqual([l.split('\t')[0] for l in base64.b64decode(body).decode().splitlines()], ['/etc/exports'])
        out = self.run_bash('t_config_files', 'web-01', body)
        self.assertIn('/etc/exports', out.stdout)
        self.assertNotIn('doing', out.stdout)
        bad = base64.b64encode(f'/etc/shadow\t{base64.b64encode(b"x").decode()}'.encode()).decode()
        out = self.run_bash('t_config_files', 'web-01', bad, apply=True)
        self.assertIn('not a file this step writes: /etc/shadow', out.stdout)


class MoveOptions(unittest.TestCase):
    STEP = {'method': 'copy', 'src': {'host': 'a', 'path': '/srv'}, 'dst': {'host': 'b', 'path': '/srv'}}

    def test_only_present_when_on_so_old_plans_keep_their_hash(self):
        plain = moves.normalize({'name': 'p', 'steps': [self.STEP]})['steps'][0]['options']
        self.assertNotIn('dirs_only', plain)
        self.assertNotIn('keep_replaced', plain)
        on = moves.normalize({'name': 'p', 'steps': [{**self.STEP, 'options': {'dirs_only': True, 'keep_replaced': True}}]})['steps'][0]['options']
        self.assertEqual((on['dirs_only'], on['keep_replaced']), (True, True))
        self.assertNotIn('dirs_only', moves.normalize({'name': 'p', 'steps': [{**self.STEP, 'method': 'move', 'options': {'dirs_only': True}}]})['steps'][0]['options'])

    def test_rsync_gets_them(self):
        from storageforge_index import jobscript
        body = Path(moves.__file__).read_text() + Path(jobscript.__file__).read_text()
        self.assertEqual(body.count("RS+=('--include=*/' '--exclude=*')"), 2)
        self.assertEqual(body.count('RS+=(--backup "--suffix=.sf-replaced-$(date +%Y%m%d)")'), 2)


class Api(Db):
    def test_preview_then_save_with_every_risk_accepted(self):
        from storageforge_index import server, users
        users.create(self.conn, 'alice', 'a long enough password')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(client.post('/api/clone/preview', json={}).status_code, 401)
        client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        body = {'source': 'web-01', 'target': 'web-copy', 'files': 'all'}
        pre = client.post('/api/clone/preview', json=body).json
        ids = sorted({r['id'] for r in pre['risks'] if r['level'] in ('crit', 'warn')})
        self.assertIn('format-/dev/vdb', ids)
        r = client.post('/api/clone', json={**body, 'accept': ids[:-1]})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json['open'], ids[-1:])
        self.assertEqual(changes.list_plans(self.conn), [])
        r = client.post('/api/clone', json={**body, 'accept': ids})
        self.assertEqual(r.status_code, 201, r.json)
        self.assertEqual(sorted(r.json['saved']), ['changes', 'files'])
        self.assertEqual(client.post('/api/clone/preview', json={**body, 'target': 'nowhere'}).status_code, 404)
        self.assertEqual(client.post('/api/clone/preview', json={**body, 'map': ['x']}).status_code, 400)

    def test_cli(self):
        from storageforge_index import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(['--db', str(Path(self.tmp) / 'index.db'), 'clone', 'web-01', '--to', 'web-copy', '--files', 'structure', '--map', '/srv/data=/dev/vdc', '--dry-run'])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn('Data at risk:', text)
        self.assertIn('formats /dev/vdc', text)
        self.assertEqual(changes.list_plans(self.conn), [])
        with contextlib.redirect_stdout(io.StringIO()) as o2, contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(['--db', str(Path(self.tmp) / 'index.db'), 'clone', 'web-01', '--to', 'web-copy'])
        self.assertIn('run them in this order: plan script', o2.getvalue())
        self.assertEqual(len(changes.list_plans(self.conn)), 1)


if __name__ == '__main__':
    unittest.main()
