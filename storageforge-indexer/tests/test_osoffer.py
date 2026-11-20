"""What the page for a second system offers and stages (osoffer.py), and the step that keeps a desktop plan out of the wrong
system (`os-running`). The disks are lsblk's own JSON: this machine's, and tables written out as lsblk writes them."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import changes, desktop, osoffer, server, steps_osinstall, users

PW = 'correct horse battery staple'
KEY = 'ssh-ed25519 ' + 'A' * 68 + ' gabe@laptop'
GIB = 1024 ** 3
SECTOR = 512
PRELUDE = ('set -euo pipefail; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }; later() { echo "later: $*"; }\n'
           'act() { echo "changed: $*"; }; try() { "$@"; }; doing() { :; }\n')


def part(name, start_gib, size_gib, fstype='ext4', mountpoint=None, partlabel=None, **more):
    return {'name': name, 'path': f'/dev/{name}', 'size': int(size_gib * GIB), 'type': 'part', 'fstype': fstype, 'mountpoint': mountpoint, 'partlabel': partlabel,
            'start': int(start_gib * GIB) // SECTOR, 'pttype': None} | more


def disk(name, size_gib, *children, pttype='gpt', fstype=None, model='Disk'):
    return {'name': name, 'path': f'/dev/{name}', 'size': int(size_gib * GIB), 'type': 'disk', 'fstype': fstype, 'mountpoint': None, 'model': model,
            'pttype': pttype if (children or pttype != 'gpt') else None, 'start': None} | ({'children': list(children)} if children else {})


NAS = {'scan_user': 'scan', 'lsblk': {'blockdevices': [
    disk('nvme0n1', 500, part('nvme0n1p1', 0.001, 0.5, 'vfat', '/boot/efi'), part('nvme0n1p2', 0.501, 199.499, 'ext4', '/')),      # 300 GiB after the root
    disk('sda', 1000),                                                                                                             # blank
    disk('sdb', 1000, fstype='zfs_member'),                                                                                        # a whole disk in a pool
    disk('sdc', 250, part('sdc1', 0.001, 249.9, 'ntfs'), pttype='dos'),
    disk('sdd', 100, part('sdd1', 0.001, 98.5, 'xfs', '/srv')),                                                                    # 1.5 GiB left
    disk('sde', 200, part('sde1', 0.001, 0.2, 'vfat', None, 'sf-nas-fedora-1'), part('sde2', 0.201, 1, 'ext4', None, 'sf-nas-fedora-2'),
         part('sde3', 1.201, 40, 'btrfs', None, 'sf-nas-fedora-root'), part('sde4', 100, 50, 'ext4', '/data', 'data-old')),          # gaps of 58.8 and 50
    {'name': 'sr0', 'path': '/dev/sr0', 'size': 1 << 30, 'type': 'rom'},
]}}


class TheDisks(unittest.TestCase):
    def test_the_room_on_each_disk_and_why_one_cannot_be_used(self):
        got = {d['path']: d for d in osoffer.disks(NAS)}
        self.assertEqual(list(got), ['/dev/nvme0n1', '/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd', '/dev/sde'], 'disks, and not the drive for discs')
        nvme = got['/dev/nvme0n1']
        self.assertEqual((nvme['usable'], nvme['running'], nvme['partitions'], nvme['blank']), (True, True, 2, False))
        self.assertAlmostEqual(nvme['free'] / GIB, 300, delta=0.01)
        self.assertEqual((got['/dev/sda']['usable'], got['/dev/sda']['blank'], got['/dev/sda']['why']), (True, True, ''))
        self.assertEqual((got['/dev/sdb']['usable'], got['/dev/sdb']['why']), (False, 'the whole disk holds ZFS'))
        self.assertEqual((got['/dev/sdc']['usable'], got['/dev/sdc']['why']), (False, 'its partition table is dos, not GPT'))
        self.assertEqual((got['/dev/sdd']['usable'], got['/dev/sdd']['why']), (False, 'under 3 GiB of unpartitioned space, and nothing is shrunk'))
        self.assertAlmostEqual(got['/dev/sde']['free'] / GIB, 58.799, delta=0.01, msg='the largest stretch, which is what the step uses, and not the sum of them')

    def test_a_scan_that_did_not_read_where_partitions_start_promises_nothing(self):
        old = disk('sda', 100, part('sda1', 0, 10) | {'start': None})
        got = osoffer.disks({'lsblk': {'blockdevices': [old]}})[0]
        self.assertEqual((got['free'], got['usable']), (None, True))
        self.assertIn('the step looks when it runs', got['why'])
        self.assertEqual(osoffer.disks({}), [])
        self.assertEqual(osoffer.disks({'lsblk': None}), [])

    def test_partitions_that_overlap_or_come_out_of_order_do_not_make_room(self):
        d = disk('sda', 100, part('sda2', 50, 50), part('sda1', 0.001, 60))
        self.assertLess(osoffer.largest_gap(d), GIB // 100)

    @unittest.skipUnless(shutil.which('lsblk'), 'needs lsblk')
    def test_what_lsblk_prints_on_this_machine_is_read(self):
        ran = subprocess.run(['lsblk', '-J', '-b', '-o', 'NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,PARTLABEL,SERIAL,MODEL,TRAN,ROTA,PTTYPE,START,LOG-SEC,PHY-SEC'], capture_output=True, text=True)
        if ran.returncode:
            self.skipTest('this lsblk does not know those columns')
        inv = {'lsblk': json.loads(ran.stdout)}
        for d in osoffer.disks(inv):
            with self.subTest(d['path']):
                self.assertTrue(d['free'] is None or 0 <= d['free'] <= d['size'])
                self.assertTrue(d['usable'] or d['why'], 'a disk that is not offered says why')
        self.assertIn(osoffer.started_by(inv), ('uefi', 'unknown'))
        osoffer.systems(inv)

    def test_the_second_systems_already_there_and_how_the_machine_was_started(self):
        self.assertEqual(osoffer.systems(NAS), [{'name': 'nas-fedora', 'disk': '/dev/sde', 'size': int(41.2 * GIB), 'partitions': 3, 'running': False}])
        self.assertEqual(osoffer.started_by(NAS), 'uefi')
        bios = {'lsblk': {'blockdevices': [disk('sda', 100, part('sda1', 0.001, 50, 'ext4', '/'))]}}
        self.assertEqual(osoffer.started_by(bios), 'unknown', 'no EFI partition seen is not proof of BIOS, and a scan does not read the firmware')
        inside = {'lsblk': {'blockdevices': [disk('vda', 50, part('vda1', 0.001, 0.2, 'vfat', '/boot/efi', 'sf-web-1'), part('vda2', 0.3, 40, 'btrfs', '/', 'sf-web-root'))]}}
        self.assertTrue(osoffer.systems(inside)[0]['running'])


def form(**more):
    return {'host': 'nas', 'name': 'nas-fedora', 'image': 'fedora44', 'disk': '/dev/sda', 'confirm': '/dev/sda', 'user': 'gabe', 'ssh_key': KEY} | more


class ThePlans(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute(f"INSERT INTO hosts (hostname, ssh_user, os_info, inventory_json, last_scanned_at) VALUES ('nas', 'scan', 'Debian 13', :i, {self.db.ts(':t')})",
                          {'i': json.dumps(NAS), 't': 1700000000})
        self.conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('new', '{}')")

    def plans(self):
        return {p['name']: changes.get_plan(self.conn, p['id']) for p in changes.list_plans(self.conn)}

    def test_the_offer(self):
        got = osoffer.offer(self.conn)
        nas, new = got['hosts']
        self.assertEqual((nas['host'], nas['user'], nas['os'], nas['scanned_at'], nas['read'], nas['started_by']), ('nas', 'scan', 'Debian 13', 1700000000, True, 'uefi'))
        self.assertEqual([d['path'] for d in nas['disks'] if d['usable']], ['/dev/nvme0n1', '/dev/sda', '/dev/sde'])
        self.assertEqual((new['read'], new['disks'], new['systems']), (False, [], []))
        keys = {i['key'] for i in got['images']}
        self.assertTrue({'fedora44', 'rocky10', 'alma10', 'debian13', 'ubuntu2404', 'leap16'} <= keys)
        self.assertFalse(any(k.startswith('alpine') for k in keys), 'its image has no EFI partition')
        for i in got['images']:
            self.assertTrue(i['url'].startswith('https://') and i['checksums'].startswith('https://'), i)
        self.assertEqual(got['choices']['network'], ['same', 'fixed', 'dhcp'])
        self.assertEqual((got['desktop']['compositors'], got['desktop']['profiles']), (['niri', 'hyprland', 'mango'], []))

    def test_an_install_is_one_plan_with_what_the_form_held(self):
        made = osoffer.stage(self.conn, form(size_gb='40', network='fixed', host_keys='new'), 'gabe')
        self.assertEqual([(p['name'], p['tasks']) for p in made['plans']], [('nas: install nas-fedora', 1)])
        task = self.plans()['nas: install nas-fedora']['tasks'][0]
        self.assertEqual((task['type'], task['host']), ('os-install', 'nas'))
        p = task['params']
        self.assertEqual((p['disk'], p['confirm'], p['size_gb'], p['network'], p['host_keys'], p['carry'], p['user'], p['ssh_key']), ('/dev/sda', '/dev/sda', '40', 'fixed', 'new', 'mount', 'gabe', KEY))

    def test_starting_it_is_a_step_of_the_same_plan_only_where_it_is_asked_for(self):
        osoffer.stage(self.conn, form(start='once'), 'gabe')
        tasks = self.plans()['nas: install nas-fedora']['tasks']
        self.assertEqual([(t['type'], t['params'].get('when'), t['params'].get('restart')) for t in tasks], [('os-install', None, None), ('os-boot', 'once', 'no')])
        osoffer.stage(self.conn, form(name='nas-rocky', image='rocky10', start='restart'), 'gabe')
        self.assertEqual(self.plans()['nas: install nas-rocky']['tasks'][1]['params'], {'name': 'nas-rocky', 'when': 'once', 'restart': 'yes'}, 'never made the default from here')

    def test_a_desktop_is_a_plan_of_its_own_that_stops_in_any_other_system(self):
        desktop.save(self.conn, {'name': 'fleet', 'binds': [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}]}, 'gabe')
        made = osoffer.stage(self.conn, form(desktop={'dux': True, 'compositor': 'niri', 'version': 'v2.1.2', 'installer_sha': 'a' * 64, 'profile': 'fleet'}), 'gabe')
        self.assertEqual([(p['name'], p['tasks']) for p in made['plans']], [('nas: install nas-fedora', 1), ('nas: desktop on nas-fedora', 3)])
        after = self.plans()['nas: desktop on nas-fedora']
        self.assertEqual([t['type'] for t in after['tasks']], ['os-running', 'dux-install', 'desktop-profile'], 'the guard is first')
        self.assertEqual(after['tasks'][0]['params'], {'name': 'nas-fedora'})
        self.assertEqual(after['tasks'][1]['params'], {'user': 'gabe', 'compositor': 'niri', 'terminal': 'ghostty', 'version': 'v2.1.2', 'installer_sha': 'a' * 64})
        self.assertEqual(after['tasks'][2]['params'], {'profile': 'fleet', 'user': 'gabe', 'compositor': 'niri'})
        self.assertIn('after the machine has been started into nas-fedora', after['notes'])
        self.assertEqual({t['host'] for t in after['tasks']}, {'nas-fedora'}, 'a script does the steps of the machine it is on, by its host name: the new system has the name it was given')
        self.assertNotIn('dux-install', [t['type'] for t in self.plans()['nas: install nas-fedora']['tasks']], 'not in the plan that runs in the old system')
        self.assertRegex(changes.script(self.conn, after), r'\nrun 1 nas-fedora os-running ', 'a script is written for a host no scan has seen yet')
        checked = changes.check(self.conn, after)
        self.assertEqual(len(checked['tasks']), 3, 'and the plan can be checked before the new system has been scanned')
        osoffer.stage(self.conn, form(name='nas-alma', image='alma10', desktop={'profile': 'fleet', 'profile_compositor': 'sway'}), 'gabe')
        self.assertEqual([(t['type'], t['params'].get('compositor')) for t in self.plans()['nas: desktop on nas-alma']['tasks']], [('os-running', None), ('desktop-profile', 'sway')])

    def test_what_is_refused_leaves_no_plan_behind(self):
        for why, body in (('the disk not typed again', form(confirm='')), ('another disk typed', form(confirm='/dev/sdb')), ('no key', form(ssh_key='')), ('root', form(user='root; reboot')),
                          ('an image nobody lists', form(image='windows11')), ('a host that is not there', form(host='nowhere; id')), ('a name with a space', form(name='nas fedora')),
                          ('a desktop with a compositor Dux does not set up', form(desktop={'dux': True, 'compositor': 'sway'})),
                          ('a start nobody offers', form(start='always')), ('a kind nobody offers', form(kind='format')), ('a desktop that is not an object', form(desktop='niri'))):
            with self.subTest(why), self.assertRaises((ValueError, LookupError)):
                osoffer.stage(self.conn, body, 'gabe')
        self.assertEqual(self.plans(), {}, 'the install plan is not saved where the desktop plan beside it is refused')
        osoffer.stage(self.conn, form(), 'gabe')
        with self.assertRaisesRegex(ValueError, 'already exists: run it or delete it in Changes first'):
            osoffer.stage(self.conn, form(desktop={'profile': 'fleet'}), 'gabe')
        self.assertEqual(list(self.plans()), ['nas: install nas-fedora'])

    def test_starting_and_removing_one_that_is_there(self):
        made = osoffer.stage(self.conn, {'kind': 'boot', 'host': 'nas', 'name': 'nas-fedora', 'when': 'always'}, 'gabe')
        self.assertEqual(made['plans'][0]['name'], 'nas: start nas-fedora always')
        osoffer.stage(self.conn, {'kind': 'boot', 'host': 'nas', 'name': 'nas-fedora', 'restart': 'yes'}, 'gabe')
        osoffer.stage(self.conn, {'kind': 'remove', 'host': 'nas', 'name': 'nas-fedora'}, 'gabe')
        got = {n: [(t['type'], t['params']) for t in p['tasks']] for n, p in self.plans().items()}
        self.assertEqual(got, {'nas: start nas-fedora always': [('os-boot', {'name': 'nas-fedora', 'when': 'always', 'restart': 'no'})],
                               'nas: start nas-fedora once': [('os-boot', {'name': 'nas-fedora', 'when': 'once', 'restart': 'yes'})],
                               'nas: remove nas-fedora': [('os-remove', {'name': 'nas-fedora'})]})
        with self.assertRaises(ValueError):
            osoffer.stage(self.conn, {'kind': 'boot', 'host': 'nas', 'name': 'nas-fedora', 'when': 'sometimes'}, 'gabe')

    def test_the_routes(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        self.assertEqual([h['host'] for h in viewer.get('/api/os-install/offer').get_json()['hosts']], ['nas', 'new'])
        self.assertEqual(viewer.post('/api/os-install/plan', json=form()).status_code, 403)
        self.assertEqual(admin.post('/api/os-install/plan', json=form(confirm='/dev/sdz')).status_code, 400)
        got = admin.post('/api/os-install/plan', json=form())
        self.assertEqual((got.status_code, [p['name'] for p in got.get_json()['plans']]), (201, ['nas: install nas-fedora']))
        self.assertEqual(admin.post('/api/os-install/plan', json=form()).status_code, 400, 'the same plan twice')
        row = self.conn.all("SELECT target_host, detail_json FROM audit_log WHERE action = 'osinstall.plan'")
        self.assertEqual(len(row), 1)
        self.assertEqual((row[0][0], json.loads(row[0][1]) if isinstance(row[0][1], str) else row[0][1]), ('nas', {'kind': 'install', 'system': 'nas-fedora', 'plans': [got.get_json()['plans'][0]['plan_id']]}))
        self.assertNotIn(KEY, str(row), 'the audit row names the system, not what the form held')
        profile = {'name': 'draft', 'binds': [{'keys': 'mod+q', 'action': 'close'}], 'hosts': {'nas': [{'output': 'DP-9', 'scale': '2'}]}}
        self.assertEqual(viewer.post('/api/desktop/render', json={'profile': profile, 'compositor': 'sway'}).status_code, 403, 'an account that only reads sends nothing: it reads a saved profile')
        text = admin.post('/api/desktop/render', json={'profile': profile, 'compositor': 'sway', 'host': 'nas'})
        self.assertEqual((text.status_code, text.mimetype, text.get_data(as_text=True)), (200, 'text/plain', desktop.render(profile, 'sway', 'nas')))
        self.assertIn('DP-9', text.get_data(as_text=True))
        self.assertEqual(admin.post('/api/desktop/render', json={'profile': profile | {'binds': [{'keys': 'mod+q', 'action': 'spawn', 'arg': 'a"; rm'}]}, 'compositor': 'sway'}).status_code, 400)
        self.assertEqual(admin.post('/api/desktop/render', json={'profile': profile, 'compositor': 'kwin'}).status_code, 400)
        self.assertEqual(desktop.profiles(self.conn), {}, 'a preview saves nothing')


class OnlyInThatSystem(unittest.TestCase):
    """`os-running`. Which system is running is read from the partition the root is on: lsblk and findmnt are stood in for,
    as in test_osinstall, since a partition table of its own needs a disk."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'T': str(self.tmp)}
        self.tool('lsblk', '''case "$*" in
  "-rno PATH,PARTLABEL") printf '/dev/vda1 \\n/dev/vda2 \\n/dev/vdb1 sf-fedora-2\\n/dev/vdb2 sf-fedora-root\\n/dev/vdb3 sf-fedora-old-root\\n';;
esac''')

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
        (self.bin / name).chmod(0o755)

    def running(self, root):
        self.tool('findmnt', f'echo "{root}"')

    def step(self, name):
        ran = subprocess.run(['bash', '-c', PRELUDE + steps_osinstall.bash() + f'\nt_os_running {name}'], capture_output=True, text=True, env=self.env)
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def test_it_goes_on_in_that_system_and_in_no_other(self):
        self.running('/dev/vdb2[/root]')
        self.assertEqual(self.step('fedora'), 'ok: fedora is the system that is running\n')
        self.assertIn('conflict: fedora-old is installed and is not the system that is running', self.step('fedora-old'), 'a name that begins the same is another system')
        self.running('/dev/vda2')
        out = self.step('fedora')
        self.assertIn('conflict: fedora is installed and is not the system that is running: start it first (os-boot, then a restart)', out)
        self.assertIn('Nothing was changed', out)
        self.assertIn('conflict: there is no system named arch on this machine', self.step('arch'))

    @unittest.skipUnless(shutil.which('unshare') and subprocess.run(['unshare', '-Urm', 'mount', '-t', 'tmpfs', 'none', '/run/lock'], capture_output=True).returncode == 0, 'needs a user who may make namespaces of its own (unshare -Urm)')
    def test_in_a_plan_the_steps_after_it_are_not_run_in_the_old_system(self):
        db = dbfactory.make(self, f'{self.tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname) VALUES ('nas')")
        plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'os-running', 'host': 'nas', 'params': {'name': 'fedora'}},
                                                         {'type': 'dux-install', 'host': 'nas', 'params': {'user': 'gabe', 'compositor': 'niri', 'version': 'v2.1.2', 'installer_sha': 'a' * 64}}]})
        text = changes.script(conn, plan).replace('ME=$(host_slug "$(uname -n)")', 'ME=nas')
        self.assertIn('ME=nas', text)
        (self.tmp / 'p.sh').write_text(text)
        for tool in ('curl', 'sudo', 'gzip', 'runuser', 'su'):
            self.tool(tool, f'echo "{tool} $*" >> $T/ran')
        self.running('/dev/vda2')
        # --apply wants root and a lock in /run/lock: this user is root in namespaces of its own, with an empty folder mounted there, and can change nothing outside
        ran = subprocess.run(['unshare', '-Urm', 'bash', '-c', 'mount -t tmpfs none /run/lock && exec bash "$0" --apply', str(self.tmp / 'p.sh')], capture_output=True, text=True, timeout=120, env=self.env)
        out = ran.stdout + ran.stderr
        self.assertNotIn('unbound variable', out)
        self.assertIn('fedora is installed and is not the system that is running', out)
        self.assertIn('skipped: an earlier task failed', out)
        self.assertIn('stopped at the first one', out)
        self.assertNotEqual(ran.returncode, 0)
        self.assertFalse((self.tmp / 'ran').exists(), 'the installer of the desktop was not fetched, let alone run')


if __name__ == '__main__':
    unittest.main()
