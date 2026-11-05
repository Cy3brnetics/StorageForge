"""btrfs, ZFS and LVM operations: forms and checks, the generated scripts, and send/receive on one host run against stand-ins for
btrfs and zfs (nothing here needs a real pool or root). Alerts from what scans and the server already know. A send between two hosts: test_sends.py."""
import datetime as dt
import json
import os
import subprocess
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

import yaml

from storageforge_index import alerts, changes, tasks
from storageforge_index.cli import scans_here

from test_tasks import Fleet

BTRFS = r"""#!/bin/bash
echo "btrfs $*" >>"$STUB_LOG"
case "$1 $2" in
  "--version "*) exit 0 ;;
  "subvolume show") p=${@: -1}; [ -d "$p" ] || exit 1
    if [ -e "$p/.partial" ]; then echo 'Received UUID: -'; else echo 'Received UUID: 1234abcd'; fi ;;
  "subvolume delete") rm -rf "${@: -1}" ;;
  "property get") [ -e "$STUB_RW" ] && echo ro=false || echo ro=true ;;
  send*) basename "${@: -1}" ;;
  receive*) read -r n; mkdir -p "${@: -1}/$n" ;;
esac
"""
ZFS = r"""#!/bin/bash
echo "zfs $*" >>"$STUB_LOG"
case $1 in
  version) exit 0 ;;
  list) t=${@: -1}
    if [[ " $* " == *" -t snapshot "* && $t != *@* ]]; then grep "^$t@" "$STUB_ZFS"; exit 0; fi
    grep -q "^$t\(@\|$\)" "$STUB_ZFS" && { echo "$t"; exit 0; }; exit 1 ;;
  get) t=${@: -1}; grep -q "^$t$" "$STUB_ZFS" || exit 1; echo "${t#*@}" | cksum | cut -d' ' -f1 ;;
  send) echo "${@: -1}" | cut -d@ -f2 ;;
  receive) read -r n; echo "${@: -1}@$n" >>"$STUB_ZFS" ;;
  destroy) sed -i "\|^${@: -1}\$|d" "$STUB_ZFS" ;;
esac
"""


class Stubbed(Fleet):
    def setUp(self):
        super().setUp()
        self.t = Path(self.tmp)
        self.bin = self.t / 'bin'
        self.bin.mkdir()
        for name, body in (('btrfs', BTRFS), ('zfs', ZFS)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.log, self.zstate = self.t / 'log', self.t / 'zfs'
        self.log.write_text('')
        self.zstate.write_text('')

    def run_task(self, blocks, *args):
        text = tasks.script(self.conn, {'name': 'T', 'host': 'nas', 'blocks': blocks}).replace('PATH=/usr/local/sbin', f'PATH={self.bin}:/usr/local/sbin')
        sh = self.t / 'task.sh'
        sh.write_text(text)
        self.log.write_text('')
        return subprocess.run(['bash', str(sh), *args], capture_output=True, text=True, timeout=60, env={
            **os.environ, 'STUB_LOG': str(self.log), 'STUB_ZFS': str(self.zstate), 'STORAGEFORGE_TASK_STATE': f'{self.tmp}/state'})


class Types(Fleet):
    def plan(self, kind, **params):
        return {'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params}]}

    def samples(self):
        return [('btrfs-reclaim', dict(target='/mnt/pool', dusage='40')), ('btrfs-replace', dict(target='/mnt/pool', old='2', device='/dev/sdx', confirm='/dev/sdx')),
                ('btrfs-remove', dict(target='/mnt/pool', device='missing', confirm='missing')), ('btrfs-resize', dict(target='/mnt/pool', devid='2')),
                ('subvolume-restore', dict(source='/mnt/pool/.snap/a', path='/mnt/pool/my data')), ('btrfs-quota', dict(target='/mnt/pool')),
                ('btrfs-send', dict(source='/mnt/pool/.snap/a', parent='/mnt/pool/.snap/b', dest_host='pc', dest='/mnt/x')),
                ('zfs-pool', dict(pool='tank', level='mirror', devices='/dev/sdx /dev/sdy', confirm='/dev/sdx  /dev/sdy')),
                ('zfs-dataset', dict(dataset='tank/a', mountpoint='/srv/my data', options='compression=zstd')),
                ('zfs-snapshot', dict(dataset='tank/a', name='s1', recursive=True)),
                ('zfs-send', dict(dataset='tank/a', name='s2', base='s1', dest_host='root@10.0.0.9', dest='back/a', raw=True)),
                ('zfs-scrub', dict(pool='tank')), ('lvm-vg', dict(vg='vg0', devices='/dev/sdx', confirm='/dev/sdx')),
                ('lvm-vg-extend', dict(vg='vg0', device='/dev/sdy', confirm='/dev/sdy')),
                ('lvm-lv', dict(vg='vg0', lv='data', size='100G', fstype='xfs')), ('lvm-extend', dict(vg='vg0', lv='data', size='200G')),
                ('lvm-snapshot', dict(vg='vg0', lv='data', name='snap', size='10G'))]

    def test_every_new_type_writes_valid_bash_and_ansible(self):
        for kind, params in self.samples():
            with self.subTest(kind):
                plan = self.plan(kind, **params)
                r = subprocess.run(['bash', '-n'], input=changes.script(self.conn, plan), capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(yaml.safe_load(changes.ansible(self.conn, plan))[0]['tasks'])

    def test_creating_pools_needs_the_devices_typed_again_and_the_destructive_flag(self):
        with self.assertRaisesRegex(ValueError, 'again'):
            changes.normalize(self.plan('zfs-pool', pool='t', level='stripe', devices='/dev/sdx', confirm='/dev/sdy'))
        text = changes.script(self.conn, self.plan('lvm-vg', vg='v', devices='/dev/sdx', confirm='/dev/sdx'))
        self.assertIn('zfs-pool|lvm-vg|lvm-vg-extend) CUR_DESTRUCTIVE=1', text)
        self.assertTrue(yaml.safe_load(changes.ansible(self.conn, self.plan('lvm-vg', vg='v', devices='/dev/sdx', confirm='/dev/sdx')))[0]['tasks'][0]['when'])

    def test_values_that_could_be_options_are_refused(self):
        for kind, params in (('zfs-dataset', dict(dataset='-o/x')), ('lvm-lv', dict(vg='-x', lv='a', size='1G')),
                             ('lvm-lv', dict(vg='v', lv='a', size='100%FREE')), ('btrfs-send', dict(source='/a', dest='/b', dest_host='-oProxyCommand=x'))):
            with self.subTest(kind), self.assertRaises(ValueError):
                changes.normalize(self.plan(kind, **params))

    def levels(self, kind, **params):
        return [(i['level'], i['text']) for i in changes.check(self.conn, changes.normalize(self.plan(kind, **params)))['tasks'][0]['items']]

    def test_checks(self):
        crit = lambda items: [t for l, t in items if l == 'crit']   # noqa: E731
        self.assertIn('/mnt/backup/x is on ext4', crit(self.levels('btrfs-send', source='/mnt/pool/s', dest='/mnt/backup/x'))[0])
        self.assertIn('whole pool', crit(self.levels('zfs-send', dataset='t/a', name='s', dest='back'))[0])
        self.assertIn('at least 2', ' '.join(crit(self.levels('zfs-pool', pool='t', level='mirror', devices='/dev/sdx', confirm='/dev/sdx'))))
        self.assertIn('/dev/sdx was not seen', ' '.join(crit(self.levels('lvm-vg', vg='v', devices='/dev/sdx', confirm='/dev/sdx'))))
        self.assertIn('stops working', ' '.join(t for _, t in self.levels('lvm-snapshot', vg='v', lv='a', name='s', size='1G')))

    def test_loopback_with_its_own_port_is_ssh_not_this_machine(self):
        a = lambda **k: Namespace(**{'local': False, 'user': None, 'key': None, 'port': 22, **k})   # noqa: E731
        self.assertTrue(scans_here(a(), '127.0.0.1'))
        self.assertFalse(scans_here(a(port=2222), '127.0.0.1'))
        self.assertFalse(scans_here(a(), 'nas'))


class LvmScript(Stubbed):
    def test_growing_a_volume_with_a_snapshot_says_why_and_never_calls_lvextend(self):
        (self.bin / 'lvs').write_text('#!/bin/bash\ncase "$*" in *lv_attr*) echo "  owi-aos---" ;; *lv_size*) echo "  1048576" ;; esac\n')
        (self.bin / 'lvextend').write_text('#!/bin/bash\necho "lvextend $*" >>"$STUB_LOG"\n')
        for name in ('lvs', 'lvextend'):
            (self.bin / name).chmod(0o755)
        me = os.uname().nodename.split('.')[0]
        plan = {'name': 'p', 'tasks': [{'type': 'lvm-extend', 'host': me, 'params': {'vg': 'v', 'lv': 'a', 'size': '2M'}}]}
        sh = self.t / 'c.sh'
        sh.write_text(changes.script(self.conn, plan))
        r = subprocess.run(['bash', str(sh)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_LOG': str(self.log)})
        self.assertIn('has a snapshot', r.stdout)
        self.assertEqual(self.log.read_text(), '')


class Sends(Stubbed):
    def btrfs_block(self, keep=0):
        return [{'type': 'btrfs_send', 'params': {'into': f'{self.tmp}/here', 'prefix': 'd', 'dst_host': '', 'dst': f'{self.tmp}/there', 'keep': keep}}]

    def snap(self, *names):
        for n in names:
            (self.t / 'here' / n).mkdir(parents=True)

    def test_btrfs_full_then_changes_only_then_nothing(self):
        self.snap('d-1')
        r = self.run_task(self.btrfs_block(), '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('no shared snapshot', r.stdout)
        self.assertNotIn(' -p ', self.log.read_text())
        self.assertTrue((self.t / 'there/d-1').is_dir())
        self.snap('d-2')
        r = self.run_task(self.btrfs_block(), '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f'btrfs send -p {self.tmp}/here/d-1', self.log.read_text())
        r = self.run_task(self.btrfs_block(), '--run')
        self.assertIn('d-2 is already there', r.stdout)
        self.assertNotIn('btrfs send', self.log.read_text())

    def test_btrfs_balance_block(self):
        r = self.run_task([{'type': 'btrfs_balance', 'params': {'path': '/mnt/pool', 'dusage': 40, 'musage': 20}}], '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('balance start -dusage=40 -musage=20 -- /mnt/pool', self.log.read_text())

    def test_btrfs_report_changes_nothing(self):
        self.snap('d-1')
        r = self.run_task(self.btrfs_block())
        self.assertIn('would run: btrfs send', r.stdout)
        self.assertFalse((self.t / 'there').exists())

    def test_btrfs_removes_an_interrupted_receive_and_uses_the_last_finished_one(self):
        self.snap('d-1', 'd-2')
        (self.t / 'there/d-1').mkdir(parents=True)
        (self.t / 'there/d-2').mkdir()
        (self.t / 'there/d-2/.partial').write_text('')
        r = self.run_task(self.btrfs_block(), '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('unfinished', r.stdout)
        self.assertIn(f'-p {self.tmp}/here/d-1', self.log.read_text())
        self.assertFalse((self.t / 'there/d-2/.partial').exists())

    def test_btrfs_prunes_the_other_side_and_keeps_the_newest(self):
        self.snap('d-3')
        for n in ('d-1', 'd-2', 'd-3'):
            (self.t / 'there' / n).mkdir(parents=True)
        self.assertEqual(self.run_task(self.btrfs_block(keep=1), '--run').returncode, 0)
        self.assertEqual(sorted(p.name for p in (self.t / 'there').iterdir()), ['d-3'])

    def test_a_failed_receive_fails_the_task(self):
        self.snap('d-1')
        (self.bin / 'btrfs').write_text(BTRFS.replace('receive*) read -r n; mkdir -p "${@: -1}/$n" ;;', 'receive*) exit 1 ;;'))
        r = self.run_task(self.btrfs_block(), '--run')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('send failed', r.stdout)

    def zfs_block(self, keep=0, dst_host=''):
        return [{'type': 'zfs_send', 'params': {'dataset': 'tank/a', 'prefix': 'd', 'dst_host': dst_host, 'dst': 'back/a', 'keep': keep}}]

    def test_zfs_report_before_any_snapshot_exists(self):
        r = self.run_task(self.zfs_block())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('bad array subscript', r.stderr)
        self.assertIn('no tank/a@d-* yet', r.stdout)

    def test_zfs_full_then_changes_only_then_prunes(self):
        self.zstate.write_text('tank/a@d-1\n')
        r = self.run_task(self.zfs_block(), '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('back/a@d-1', self.zstate.read_text())
        self.assertIn('zfs receive -u -x mountpoint -- back/a', self.log.read_text())
        with self.zstate.open('a') as f:
            f.write('tank/a@d-2\n')
        r = self.run_task(self.zfs_block(keep=1), '--run')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('zfs send -i @d-1 -- tank/a@d-2', self.log.read_text())
        state = self.zstate.read_text()
        self.assertIn('back/a@d-2', state)
        self.assertNotIn('back/a@d-1', state)

    def test_zfs_never_overwrites_a_dataset_it_shares_nothing_with(self):
        self.zstate.write_text('tank/a@d-1\nback/a\n')
        r = self.run_task(self.zfs_block(), '--run')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not overwriting', r.stdout)
        self.assertNotIn('zfs send', self.log.read_text())

    def test_new_blocks_in_a_host_local_send_use_no_ssh(self):
        self.snap('d-1')
        self.assertEqual(self.run_task(self.btrfs_block(), '--run').returncode, 0)
        self.assertNotIn('ssh', self.log.read_text())

    def test_change_plan_reports_send_and_refuses_a_writable_snapshot(self):
        self.snap('d-1')
        plan = {'name': 'p', 'tasks': [{'type': 'btrfs-send', 'host': 'nas', 'params': {'source': f'{self.tmp}/here/d-1', 'dest_host': '', 'dest': f'{self.tmp}/there'}}]}
        text = changes.script(self.conn, plan)
        text = text.replace('ME=$(host_slug "$(uname -n)")', 'ME=nas')
        sh = self.t / 'c.sh'
        sh.write_text(f'PATH={self.bin}:$PATH\n' + text)
        env = {**os.environ, 'STUB_LOG': str(self.log), 'STUB_RW': str(self.t / 'rw')}
        r = subprocess.run(['bash', str(sh)], capture_output=True, text=True, env=env, timeout=60)
        self.assertIn('would: btrfs send', r.stdout + r.stderr)
        (self.t / 'rw').write_text('')
        r = subprocess.run(['bash', str(sh)], capture_output=True, text=True, env=env, timeout=60)
        self.assertIn('is not read-only', r.stdout)
        self.assertNotEqual(r.returncode, 0)


class Alerts(Fleet):
    def host(self, name='nas'):
        return self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': name})

    def use(self, mp, used, total=1000 * 2**30):
        self.conn.execute('UPDATE mounts SET used_bytes = :u, total_bytes = :t WHERE mount_point = :m', {'u': used * 2**30, 't': total, 'm': mp})

    def test_full_disks_warn_then_go_critical(self):
        self.use('/mnt/backup', 500)
        self.assertNotIn('disk-warn:nas:/mnt/backup', alerts.scan_problems(self.conn))
        self.use('/mnt/backup', 920)
        self.assertEqual(alerts.scan_problems(self.conn)['disk-warn:nas:/mnt/backup'][4], 'warn')
        self.use('/mnt/backup', 970)
        now = alerts.scan_problems(self.conn)
        self.assertEqual(now['disk-crit:nas:/mnt/backup'][4], 'crit')
        self.assertNotIn('disk-warn:nas:/mnt/backup', now)

    def test_another_hosts_share_and_ram_disks_never_count_as_full(self):
        self.use('/mnt/media', 999)
        self.assertFalse([k for k in alerts.scan_problems(self.conn) if '/mnt/media' in k])

    def test_a_gone_mount_alerts_until_it_is_old_news(self):
        ts = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc) if self.db.dialect != 'sqlite' else t   # noqa: E731
        self.conn.execute("INSERT INTO scans (host_id, started_at, finished_at, status) VALUES (:h, :t, :t, 'ok')", {'h': self.host(), 't': ts(int(time.time()))})
        self.conn.execute("UPDATE mounts SET scan_state = 'gone', seen_at = :s WHERE mount_point = '/mnt/backup'", {'s': ts(int(time.time()) - 3600)})
        self.assertIn('mount-gone:nas:/mnt/backup', alerts.scan_problems(self.conn))
        self.conn.execute("UPDATE mounts SET seen_at = :s WHERE mount_point = '/mnt/backup'", {'s': ts(int(time.time()) - 40 * 86400)})
        self.assertNotIn('mount-gone:nas:/mnt/backup', alerts.scan_problems(self.conn))

    def test_failed_scan_alerts_and_a_later_good_one_resolves_it(self):
        add = lambda st, r: self.conn.execute('INSERT INTO scan_jobs (host, status, result_json, requested_by, queued_at) VALUES (:h, :s, :r, :a, :q)', {'h': 'nas', 's': st, 'r': json.dumps(r), 'a': 't', 'q': int(time.time())})   # noqa: E731
        add('failed', {'error': 'no route to host'})
        self.assertIn('no route', alerts.scan_problems(self.conn)['scan-failed:nas'][3])
        add('ok', {})
        self.assertNotIn('scan-failed:nas', alerts.scan_problems(self.conn))

    def test_degraded_pool_alerts(self):
        status = ('  pool: tank\n state: DEGRADED\nstatus: One or more devices could not be used.\nconfig:\n\n\tNAME        STATE     READ WRITE CKSUM\n'
                  '\ttank        DEGRADED     0     0     0\n\t  mirror-0  DEGRADED     0     0     0\n\t    sdb     ONLINE       0     0     0\n'
                  '\t    sdc     UNAVAIL      0     0     0\n\nerrors: No known data errors\n')
        lsblk = {'blockdevices': [{'name': 'sdb', 'type': 'disk', 'size': 1000, 'fstype': 'zfs_member', 'label': 'tank'}]}
        self.conn.execute('UPDATE hosts SET inventory_json = :i WHERE hostname = :h', {'i': json.dumps({'lsblk': lsblk, 'zpool_status': status}), 'h': 'nas'})
        now = alerts.scan_problems(self.conn)
        self.assertEqual(now['pool:nas:tank'][4], 'crit')
        self.assertIn('DEGRADED', now['pool:nas:tank'][2])

    def test_failed_nightly_backup_alerts_until_one_succeeds(self):
        from storageforge_index.vault import AuditLog
        log = AuditLog(self.db, self.conn, None)
        log.append('system', 'backup.create', 'failed', None, None, {'error': 'disk full'})
        with mock.patch('storageforge_index.backup.listing', return_value=[]):
            self.assertIn('disk full', alerts.backup_problems(self.conn)['backup-failed'][3])
            log.append('system', 'backup.create', 'ok', None, None, {})
            self.assertEqual(alerts.backup_problems(self.conn), {})
        with mock.patch('storageforge_index.backup.listing', return_value=[{'kind': 'essentials', 'created': time.time() - 5 * 86400}]):
            self.assertIn('backup-stale', alerts.backup_problems(self.conn))

    def test_certificate_expiry(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'sf')])

        def cert(days):
            now = dt.datetime.now(dt.timezone.utc)
            c = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(
                now - dt.timedelta(days=1000)).not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256())
            p = Path(self.tmp) / 'c.pem'
            p.write_bytes(c.public_bytes(serialization.Encoding.PEM))
            return str(p)
        for days, want in ((100, []), (20, ['cert-warn']), (3, ['cert-crit'])):
            with mock.patch.dict(os.environ, {'STORAGEFORGE_REPORT_CA_FILE': cert(days)}):
                self.assertEqual(list(alerts.cert_problems()), want)
        with mock.patch.dict(os.environ, {'STORAGEFORGE_REPORT_CA_FILE': '/nonexistent'}):
            self.assertEqual(alerts.cert_problems(), {})


del Fleet, Stubbed
if __name__ == '__main__':
    unittest.main()
