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
    """lsblk JSON: (disk, serial, fstype of its one partition or None, that partition's UUID)."""
    return {'blockdevices': [{'name': n, 'path': f'/dev/{n}', 'type': 'disk', 'serial': serial, 'size': 10 * 2**30, 'pttype': 'gpt',
                              **({'children': [{'name': n + '1', 'path': f'/dev/{n}1', 'type': 'part', 'fstype': fs, 'uuid': uuid,
                                                'size': 10 * 2**30 - 2**20, 'start': 2048}]} if fs else {})}
                             for n, serial, fs, uuid in disks]}


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
               'lsblk': blk(('sda', 'S1', 'ext4', 'rootid'), ('sdb', 'S2', 'ext4', 'aaaa-1111'), ('sdc', 'S3', 'btrfs', 'bbbb-2222')),
               'pkglist': pkglist.parse('distro\tdebian\t13\npm apt-get\nm\tvim\nm\tnfs-kernel-server\nm\tmydeb\no\tmydeb\ncomplete')}
        self.add('web-01', src, [('/', 'ext4', '/dev/sda1', 10, 'rw,relatime'), ('/srv/data', 'ext4', '/dev/sdb1', 8, 'rw,noatime'),
                                 ('/srv/media', 'btrfs', '/dev/sdc1[/@media]', 3, 'rw,compress=zstd:3,subvol=/@media'),
                                 ('/srv/photos', 'btrfs', '/dev/sdc1[/@photos]', 1, 'rw,compress=zstd:3,subvol=/@photos'),
                                 ('/mnt/backups', 'nfs4', 'nas:/backups', 0, 'rw')])
        tgt = {'lsblk': blk(('vda', 'V0', 'ext4', 'vroot'), ('vdb', 'sf-data1', None, None), ('vdc', 'sf-data2', None, None), ('vdd', 'V3', 'xfs', 'old')),
               'accounts': 'u\tana\t1600\t1600\t/home/ana\t/bin/bash\ng\tana\t1600\t', 'configs': hostconfig.parse_configs(line('/etc/exports', '/old *(ro)\n'))}
        self.add('web-copy', tgt, [('/', 'ext4', '/dev/vda1', 2, 'rw')])

    def add(self, name, inv, mounts):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:n, :n, 'scan', :i)", {'n': name, 'i': json.dumps(inv)})
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :n', {'n': name})
        for target, fs, source, gib, opts in mounts:
            self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, mount_options, total_bytes, used_bytes, scan_state)
                                 VALUES (:h, :m, :s, :f, :o, :t, :u, 'indexed')""", {'h': hid, 'm': target, 's': source, 'f': fs, 'o': opts, 't': 100 * 2**30, 'u': gib * 2**30})

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
        self.assertEqual(tasks[0]['params']['also'], 'parted,btrfs-progs,e2fsprogs')     # what the storage steps run
        # sdb (ext4) goes to the first empty sf-data disk, sdc (btrfs with subvolumes) to the second
        part = {t['params']['disk']: t['params'] for t in tasks if t['type'] == 'partition'}
        self.assertEqual((part['/dev/vdb']['fstype'], part['/dev/vdb']['confirm'], part['/dev/vdb']['wipe']), ('ext4', '/dev/vdb', False))
        self.assertEqual(part['/dev/vdc']['fstype'], '')      # the btrfs is made by format, as a pool of one
        fmt = {t['params']['device']: t['params'] for t in tasks if t['type'] == 'format'}
        self.assertEqual((fmt['/dev/vdc1']['fstype'], fmt['/dev/vdc1']['confirm']), ('btrfs', '/dev/vdc1'))
        mounts = {t['params']['target']: t['params'] for t in tasks if t['type'] == 'mount'}
        self.assertEqual(mounts['/srv/data']['options'], 'noatime,nofail')
        self.assertEqual((mounts['/srv/media']['subvol'], mounts['/srv/media']['options']), ('@media', 'compress=zstd:3,nofail'))
        top = next(t for t in mounts if t.endswith('-top'))
        self.assertEqual(sorted(t['params']['path'] for t in tasks if t['type'] == 'subvolume'), [f'{top}/@media', f'{top}/@photos'])
        at = {t['params'].get('target'): i for i, t in enumerate(tasks) if t['type'] == 'mount'}
        self.assertLess(at[top], min(at['/srv/media'], at['/srv/photos']))     # the top level first, where the subvolumes are made
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

    def test_a_test_copy_keeps_the_targets_logins_and_a_migration_says_it_replaces_them(self):
        # the Pi run: /home came across with .ssh/authorized_keys, and the VM's own key, the one StorageForge used, was gone
        test = clone.build(self.conn, 'web-01', 'web-copy', files='all')
        home = next(s for s in test['plans']['files']['steps'] if s['src']['path'] == '/home')
        self.assertIn('/*/.ssh/authorized_keys', home['excludes'])
        self.assertNotIn('logins-replaced', [r['id'] for r in test['risks']])
        mig = clone.build(self.conn, 'web-01', 'web-copy', files='all', mode='migrate')
        home = next(s for s in mig['plans']['files']['steps'] if s['src']['path'] == '/home')
        self.assertNotIn('/*/.ssh/authorized_keys', home['excludes'])
        self.assertIn('logins-replaced', [r['id'] for r in mig['risks']])

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
        got = clone.build(self.conn, 'web-01', 'web-copy', storage={'/srv/data': '/dev/vdd'})
        risk = next(r for r in got['risks'] if r['id'] == 'format-/dev/vdd')
        self.assertEqual(risk['level'], 'crit')
        self.assertIn('what it holds now (xfs) is destroyed', risk['text'])
        part = next(t['params'] for t in got['plans']['changes']['tasks'] if t['type'] == 'partition')
        self.assertEqual((part['disk'], part['wipe']), ('/dev/vdd', True))
        self.assertTrue(any('/srv/media' in n and 'no target disk' in n for n in got['not_carried']))
        # a disk is mapped by its name too, and never onto the target's system disk
        self.assertIn('format-/dev/vdb', [r['id'] for r in clone.build(self.conn, 'web-01', 'web-copy', storage={'/dev/sdc': '/dev/vdb'})['risks']])
        with self.assertRaisesRegex(ValueError, 'running system'):
            clone.build(self.conn, 'web-01', 'web-copy', storage={'/dev/sdb': '/dev/vda'})
        with self.assertRaisesRegex(ValueError, 'two disks'):
            clone.build(self.conn, 'web-01', 'web-copy', storage={'/dev/sdb': '/dev/vdb', '/dev/sdc': '/dev/vdb'})

    def test_a_zfs_mirror_comes_across_whole_disk_with_its_datasets_and_properties(self):
        # the shape a real scan of the lab's ZFS host gave: zpool create on whole disks makes partitions 1 and 9
        def member(n, serial):
            return {'name': n, 'path': f'/dev/{n}', 'type': 'disk', 'serial': serial, 'size': 2 * 2**30, 'children': [
                {'name': n + '1', 'path': f'/dev/{n}1', 'type': 'part', 'fstype': 'zfs_member', 'label': 'vault', 'uuid': '850901', 'size': 2136997888},
                {'name': n + '9', 'path': f'/dev/{n}9', 'type': 'part', 'size': 8 << 20}]}
        lsblk = blk(('sda', 'Z0', 'ext4', 'zroot'))
        lsblk['blockdevices'] += [member('sdb', 'Z1'), member('sdc', 'Z2')]
        zfs = {'collected_at': '2026-11-07T00:00:00+00:00', 'lsblk': lsblk, 'zfs_props': 'vault\tcompression\tlz4\nvault\tatime\toff',
               'zpool_status': 'pool: vault\n state: ONLINE\nconfig:\n\n\tNAME           STATE     READ WRITE CKSUM\n\tvault          ONLINE       0     0     0\n'
                               '\t  mirror-0     ONLINE       0     0     0\n\t    /dev/sdb1  ONLINE       0     0     0\n\t    /dev/sdc1  ONLINE       0     0     0\n\nerrors: No known data errors'}
        self.add('zfs-01', zfs, [('/', 'ext4', '/dev/sda1', 3, 'rw'), ('/vault', 'zfs', 'vault', 0, 'rw,noatime,xattr'),
                                 ('/vault/media', 'zfs', 'vault/media', 1, 'rw,noatime,xattr')])
        got = clone.build(self.conn, 'zfs-01', 'web-copy', files='all', packages=False, accounts=False)
        tasks = [t for t in got['plans']['changes']['tasks'] if t['type'].startswith('zfs')]
        pool = tasks[0]['params']
        self.assertEqual((tasks[0]['type'], pool['pool'], pool['level'], pool['devices'], pool['confirm']),
                         ('zfs-pool', 'vault', 'mirror', '/dev/vdb /dev/vdc', '/dev/vdb /dev/vdc'))     # whole disks, not partitions 1 and 9
        self.assertEqual((pool['mountpoint'], pool['fs_props']), ('/vault', 'atime=off,compression=lz4'))
        self.assertEqual([(t['type'], t['params']['dataset'], t['params']['mountpoint']) for t in tasks[1:]], [('zfs-dataset', 'vault/media', '/vault/media')])
        self.assertFalse([t for t in got['plans']['changes']['tasks'] if t['type'] in ('partition', 'partition-add', 'format')])
        self.assertEqual({s['src']['path'] for s in got['plans']['files']['steps']} & {'/vault', '/vault/media'}, {'/vault', '/vault/media'})
        changes.normalize(got['plans']['changes'])

    def test_a_btrfs_root_is_snapshotted_with_the_subvolumes_the_copy_writes_to(self):
        # Fedora's cloud image: /, /home and /var are subvolumes of one btrfs, and accounts and files go to /home
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'web-copy'")
        self.conn.execute("UPDATE mounts SET filesystem_type = 'btrfs', source = '/dev/vda1[/root]' WHERE host_id = :h", {'h': hid})
        for target, sub in (('/home', 'home'), ('/var', 'var'), ('/boot', 'boot')):
            self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                                 VALUES (:h, :m, :s, 'btrfs', 1, 0, 'indexed')""", {'h': hid, 'm': target, 's': f'/dev/vda1[/{sub}]'})
        got = clone.build(self.conn, 'web-01', 'web-copy')
        snaps = [t['params'] for t in got['plans']['changes']['tasks'] if t['type'] == 'snapshot']
        self.assertEqual([p['source'] for p in snaps], ['/', '/home', '/var'])
        self.assertTrue(snaps[1]['dest'].endswith('-home') and snaps[1]['dest'].startswith('/.snapshots/sf-clone-before-'))
        self.assertRegex(snaps[0]['dest'], r'-\d{8}-\d{4}$')        # the time too: a second copy the same day is not this one
        self.assertEqual([t['params']['source'] for t in got['plans']['after']['tasks']], ['/', '/home', '/var'])
        self.assertNotIn('no-snapshot', [r['id'] for r in got['risks']])

    def test_a_scan_older_than_a_plan_onto_the_same_disks_is_critical(self):
        clone.save(self.conn, clone.build(self.conn, 'web-01', 'web-copy'), 'test')
        self.conn.execute("UPDATE hosts SET last_scanned_at = 1 WHERE hostname = 'web-copy'")
        self.assertIn('scan-older-than-plan', [r['id'] for r in clone.build(self.conn, 'web-01', 'web-copy')['risks']])
        self.conn.execute("UPDATE hosts SET last_scanned_at = :t WHERE hostname = 'web-copy'", {'t': int(time.time()) + 60})
        self.assertNotIn('scan-older-than-plan', [r['id'] for r in clone.build(self.conn, 'web-01', 'web-copy')['risks']])

    def test_the_top_level_of_a_btrfs_stays_mounted(self):
        # an unmount after its mount in the same plan is undone by every rerun: the planner's own check says so
        tasks = clone.build(self.conn, 'web-01', 'web-copy')['plans']['changes']['tasks']
        self.assertNotIn('unmount', [t['type'] for t in tasks])
        self.assertTrue(any(t['type'] == 'mount' and t['params']['target'].endswith('-top') for t in tasks))

    def test_saving_the_same_copy_twice_in_a_minute_gives_two_plans(self):
        built = clone.build(self.conn, 'web-01', 'web-copy')
        ids = {clone.save(self.conn, built, 'test')['changes'] for _ in range(3)}
        self.assertEqual(len(ids), 3)

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
        for fn in ('t_packages', 't_accounts', 't_config_files', 't_partition', 't_format', 't_mount', 't_subvolume'):
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

    def test_a_share_file_of_only_comments_is_not_copied(self):
        self.assertEqual(steps_clone._share_files({'files': {'/etc/exports': '# stock file\n\n#/srv *(ro)\n', '/etc/samba/smb.conf': '; x\n[data]\n'}}),
                         {'/etc/samba/smb.conf': '; x\n[data]\n'})

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
        self.assertIn('/dev/vdc on web-copy takes the layout of /dev/sdb', text)
        self.assertEqual(changes.list_plans(self.conn), [])
        with contextlib.redirect_stdout(io.StringIO()) as o2, contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(['--db', str(Path(self.tmp) / 'index.db'), 'clone', 'web-01', '--to', 'web-copy'])
        self.assertIn('run them in this order: plan script', o2.getvalue())
        self.assertEqual(len(changes.list_plans(self.conn)), 1)


if __name__ == '__main__':
    unittest.main()
