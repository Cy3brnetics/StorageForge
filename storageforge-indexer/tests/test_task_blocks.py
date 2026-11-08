"""Every block of a storage task (tasks.py), run: the script a task makes is run in report mode and with --run, against
real rsync on temporary folders and stand-ins for btrfs, zfs, systemctl, docker, df, mountpoint and sleep that log
what they were asked. Guards, conditions, Try and Stop, rotating backups, verifying, snapshots and their pruning,
services and the rest. Nothing here needs root, a pool or a network."""
import os
import socket
import subprocess
import threading
import unittest
from pathlib import Path

from storageforge_index import tasks

from test_tasks import Fleet

STUBS = {
    'mountpoint': 'echo "mountpoint $*" >>"$STUB_LOG"; p=${@: -1}; [[ ":$STUB_MOUNTED:" == *":$p:"* ]]',
    'df': 'echo "df $*" >>"$STUB_LOG"; echo "Filesystem 1G-blocks Used Available Capacity Mounted on"; echo "/dev/x 100 1 ${STUB_FREE:-50} 1% /"',
    'systemctl': 'echo "systemctl $*" >>"$STUB_LOG"',
    'docker': 'echo "docker $*" >>"$STUB_LOG"',
    'sleep': 'echo "sleep $*" >>"$STUB_LOG"',
    'logger': 'echo "logger $*" >>"$STUB_LOG"',
    'btrfs': r'''echo "btrfs $*" >>"$STUB_LOG"
case "$1 $2" in
  "subvolume snapshot") mkdir -p "${@: -1}" ;;
  "subvolume delete") rm -rf "${@: -1}" ;;
  "scrub start"|"balance start") exit "${STUB_BTRFS_RC:-0}" ;;
esac''',
    'zfs': r'''echo "zfs $*" >>"$STUB_LOG"
case $1 in
  snapshot) echo "${@: -1}" >>"$STUB_ZFS" ;;
  list) t=${@: -1}; grep "^$t@" "$STUB_ZFS" || true ;;
  destroy) sed -i "\|^${@: -1}\$|d" "$STUB_ZFS" ;;
esac''',
}


def b(type_, slots=None, **params):
    return tasks._b(type_, slots, **params)


class Blocks(Fleet):
    def setUp(self):
        super().setUp()
        self.t = Path(self.tmp)
        self.bin = self.t / 'bin'
        self.bin.mkdir()
        for name, body in STUBS.items():
            (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
            (self.bin / name).chmod(0o755)
        self.log = self.t / 'log'
        self.zfs = self.t / 'zfs'
        self.zfs.write_text('')
        self.stamp = '2026-11-08_120000'

    def run_task(self, blocks, *, run=False, on_fail=(), env=None):
        task = {'name': 'T', 'host': 'nas', 'blocks': list(blocks), 'on_fail': list(on_fail)}
        text = (tasks.script(self.conn, task).replace('PATH=/usr/local/sbin', f'PATH={self.bin}:/usr/local/sbin')
                .replace('STAMP=$(date +%Y-%m-%d_%H%M%S)', f'STAMP={self.stamp}'))
        sh = self.t / 'task.sh'
        sh.write_text(text)
        self.log.write_text('')
        r = subprocess.run(['bash', str(sh), *(['--run'] if run else [])], capture_output=True, text=True, timeout=60,
                           env={**os.environ, 'STUB_LOG': str(self.log), 'STUB_ZFS': str(self.zfs),
                                'STORAGEFORGE_TASK_STATE': f'{self.tmp}/state', **(env or {})})
        r.calls = self.log.read_text().splitlines()
        return r

    def folder(self, *parts):
        p = self.t.joinpath(*parts)
        p.mkdir(parents=True, exist_ok=True)
        return str(p)


class Guards(Blocks):
    def test_require_mounted_stops_a_run_and_a_report_goes_on(self):
        blocks = [b('require_mounted', path='/mnt/backup'), b('log', message='AFTER')]
        run = self.run_task(blocks, run=True, env={'STUB_MOUNTED': '/mnt/other'})
        self.assertEqual(run.returncode, 1)
        self.assertIn('not met: /mnt/backup is mounted', run.stdout)
        self.assertNotIn('AFTER', run.stdout)
        report = self.run_task(blocks, env={'STUB_MOUNTED': '/mnt/other'})
        self.assertIn('a real run stops here', report.stdout)
        self.assertIn('AFTER', report.stdout)
        ok = self.run_task(blocks, run=True, env={'STUB_MOUNTED': '/mnt/backup'})
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn('AFTER', ok.stdout)

    def test_require_free_reads_df(self):
        blocks = [b('require_free', path='/mnt/backup', gib=40), b('log', message='AFTER')]
        self.assertEqual(self.run_task(blocks, run=True, env={'STUB_FREE': '41'}).returncode, 0)
        self.assertEqual(self.run_task(blocks, run=True, env={'STUB_FREE': '40'}).returncode, 0)        # at least: equal is enough
        low = self.run_task(blocks, run=True, env={'STUB_FREE': '39'})
        self.assertEqual(low.returncode, 1)
        self.assertIn('not met: 40 GiB free on /mnt/backup', low.stdout)

    def listening(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        s.listen(5)
        self.addCleanup(s.close)
        threading.Thread(target=lambda: [s.accept() for _ in range(5)], daemon=True).start()
        return s.getsockname()[1]

    def test_require_reachable_tries_the_ssh_port(self):
        port = self.listening()
        for name, p in (('up', port), ('down', 1)):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port, inventory_json) VALUES (:h, '127.0.0.1', 'scan', :p, '{}')",
                              {'h': name, 'p': p})
        self.assertEqual(self.run_task([b('require_reachable', host='up')], run=True).returncode, 0)
        down = self.run_task([b('require_reachable', host='down')], run=True)
        self.assertEqual(down.returncode, 1)
        self.assertIn('down answers SSH', down.stdout)


class Control(Blocks):
    def branch(self, cond, arg='', value=None, negate=False, env=None):
        p = {'cond': cond, 'arg': arg, 'negate': negate, **({'value': value} if value is not None else {})}
        r = self.run_task([b('if', {'then': [b('log', message='THEN')], 'else': [b('log', message='ELSE')]}, **p)], run=True, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return 'THEN' if 'THEN' in r.stdout else 'ELSE'

    def test_every_condition_of_if(self):
        import datetime as dt
        now = dt.datetime.now()
        here = self.folder('exists')
        self.assertEqual(self.branch('mounted', '/mnt/backup', env={'STUB_MOUNTED': '/mnt/backup'}), 'THEN')
        self.assertEqual(self.branch('mounted', '/mnt/backup', env={'STUB_MOUNTED': ''}), 'ELSE')
        self.assertEqual(self.branch('exists', here), 'THEN')
        self.assertEqual(self.branch('exists', here + '/nope'), 'ELSE')
        self.assertEqual(self.branch('free below', '/mnt/backup', value=50, env={'STUB_FREE': '10'}), 'THEN')
        self.assertEqual(self.branch('free below', '/mnt/backup', value=50, env={'STUB_FREE': '90'}), 'ELSE')
        self.assertEqual(self.branch('weekday', f'Mon, {now.strftime("%a")}'), 'THEN')       # spaces in the list are fine
        other = 'Sun' if now.strftime('%a') != 'Sun' else 'Mon'
        self.assertEqual(self.branch('weekday', other), 'ELSE')
        self.assertEqual(self.branch('day of month', f'{now.day},31'), 'THEN')
        self.assertEqual(self.branch('day of month', '99'), 'ELSE')
        self.assertEqual(self.branch('command succeeds', 'true'), 'THEN')
        self.assertEqual(self.branch('command succeeds', 'exit 3'), 'ELSE')
        self.assertEqual(self.branch('exists', here, negate=True), 'ELSE')                   # not
        self.assertEqual(self.branch('command succeeds', 'false', negate=True), 'THEN')

    def test_try_runs_the_fallback_and_carries_on(self):
        r = self.run_task([b('try', {'do': [b('command', cmd='exit 7'), b('log', message='NEVER')], 'fallback': [b('log', message='FALLBACK')]}),
                           b('log', message='AFTER')], run=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        for word in ('FALLBACK', 'AFTER'):
            self.assertIn(word, r.stdout)
        self.assertNotIn('NEVER', r.stdout)
        clean = self.run_task([b('try', {'do': [b('log', message='DO')], 'fallback': [b('log', message='FALLBACK')]})], run=True)
        self.assertNotIn('FALLBACK', clean.stdout)

    def test_stop_ok_inside_a_try_stops_the_task_as_ok(self):
        r = self.run_task([b('try', {'do': [b('stop', outcome='ok', message='nothing to do')], 'fallback': [b('log', message='FALLBACK')]}),
                           b('log', message='AFTER')], run=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('stopping: nothing to do', r.stdout)
        self.assertNotIn('FALLBACK', r.stdout)
        self.assertNotIn('AFTER', r.stdout)

    def test_stop_failed_fails_and_runs_what_runs_on_failure(self):
        r = self.run_task([b('stop', outcome='failed', message='broken'), b('log', message='AFTER')], run=True,
                          on_fail=[b('log', message='ON-FAILURE')])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('broken', r.stdout)
        self.assertIn('ON-FAILURE', r.stdout)
        self.assertNotIn('AFTER', r.stdout)

    def test_a_block_turned_off_does_nothing(self):
        off = b('command', cmd='touch ' + str(self.t / 'made'))
        off['off'] = True
        r = self.run_task([off, b('log', message='AFTER')], run=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('turned off', r.stdout)
        self.assertFalse((self.t / 'made').exists())


class Copies(Blocks):
    def test_rotate_keeps_hard_linked_dated_copies_and_cleans_up_a_failed_run(self):
        src = Path(self.folder('src'))
        (src / 'big.bin').write_bytes(os.urandom(4096))
        into = self.t / 'backups'
        blocks = [b('rotate', src=str(src), dst=str(into), keep=2, one_fs=False)]
        for i, stamp in enumerate(('2026-11-08_010000', '2026-11-08_020000', '2026-11-08_030000')):
            self.stamp = stamp
            if i == 2:
                (into / '2026-11-08_025959.partial').mkdir()           # left by a run that failed
            r = self.run_task(blocks, run=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(p.name for p in into.iterdir()), ['2026-11-08_020000', '2026-11-08_030000'])   # newest 2, no partial
        a, c = (into / '2026-11-08_020000' / 'big.bin').stat(), (into / '2026-11-08_030000' / 'big.bin').stat()
        self.assertEqual(a.st_ino, c.st_ino)                           # unchanged: a hard link to the run before

    def test_rotate_in_a_report_writes_nothing(self):
        src = self.folder('src')
        into = self.t / 'backups'
        r = self.run_task([b('rotate', src=src, dst=str(into), keep=2, one_fs=False)])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(into.exists())

    def test_verify_fails_on_a_difference_only_when_asked(self):
        src, dst = Path(self.folder('a')), Path(self.folder('b'))
        (src / 'f').write_text('one')
        (dst / 'f').write_text('one')
        self.assertEqual(self.run_task([b('verify', src=str(src), dst=str(dst))], run=True).returncode, 0)
        (dst / 'f').write_text('two')
        strict = self.run_task([b('verify', src=str(src), dst=str(dst), fail=True)], run=True)
        self.assertEqual(strict.returncode, 1)
        self.assertIn('entries differ', strict.stdout)
        loose = self.run_task([b('verify', src=str(src), dst=str(dst), fail=False)], run=True)
        self.assertEqual(loose.returncode, 0)
        self.assertIn('entries differ', loose.stdout)

    def test_rsync_mirror_deletes_and_copy_keeps(self):
        src, dst = Path(self.folder('s')), Path(self.folder('d'))
        (src / 'keep').write_text('x')
        (dst / 'extra').write_text('y')
        self.run_task([b('rsync', src=str(src), dst=str(dst), mode='copy', one_fs=False)], run=True)
        self.assertTrue((dst / 'extra').exists())
        self.run_task([b('rsync', src=str(src), dst=str(dst), mode='mirror', one_fs=False)], run=True)
        self.assertFalse((dst / 'extra').exists())
        self.assertEqual((dst / 'keep').read_text(), 'x')


class Snapshots(Blocks):
    def test_btrfs_snapshot_then_prune_keeps_the_newest(self):
        into = self.t / 'snaps'
        for stamp in ('2026-11-01_000000', '2026-11-02_000000', '2026-11-03_000000'):
            self.stamp = stamp
            r = self.run_task([b('btrfs_snapshot', subvol=self.folder('pool'), into=str(into), prefix='daily')], run=True)
            self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(f'btrfs subvolume snapshot -r -- {self.t}/pool {into}/daily-2026-11-03_000000', r.calls)
        self.run_task([b('btrfs_prune', into=str(into), prefix='daily', keep=2)], run=True)
        self.assertEqual(sorted(p.name for p in into.iterdir()), ['daily-2026-11-02_000000', 'daily-2026-11-03_000000'])

    def test_a_prune_never_takes_another_prefix_that_starts_the_same(self):
        into = self.t / 'snaps'
        for name in ('daily-2026-11-01_000000', 'daily-2026-11-02_000000', 'daily-db-2026-10-01_000000', 'daily-db-2026-10-02_000000', 'daily-notes'):
            (into / name).mkdir(parents=True)
        self.run_task([b('btrfs_prune', into=str(into), prefix='daily', keep=1)], run=True)
        self.assertEqual(sorted(p.name for p in into.iterdir()),
                         ['daily-2026-11-02_000000', 'daily-db-2026-10-01_000000', 'daily-db-2026-10-02_000000', 'daily-notes'])

    def test_zfs_snapshot_then_prune_and_its_prefix(self):
        for stamp in ('2026-11-01_000000', '2026-11-02_000000', '2026-11-03_000000'):
            self.stamp = stamp
            self.run_task([b('zfs_snapshot', dataset='tank/media', prefix='daily', recursive=True)], run=True)
        self.assertIn('zfs snapshot -r -- tank/media@daily-2026-11-03_000000', self.log.read_text())
        with self.zfs.open('a') as f:                                  # another task's snapshots on the same dataset
            f.write('tank/media@daily-db-2026-10-01_000000\ntank/media@daily-db-2026-10-02_000000\n')
        r = self.run_task([b('zfs_prune', dataset='tank/media', prefix='daily', keep=1, recursive=True)], run=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.zfs.read_text().split(), ['tank/media@daily-2026-11-03_000000', 'tank/media@daily-db-2026-10-01_000000',
                                                         'tank/media@daily-db-2026-10-02_000000'])
        self.assertIn('zfs destroy -r -- tank/media@daily-2026-11-01_000000', r.calls)

    def test_a_report_deletes_nothing(self):
        into = self.t / 'snaps'
        for name in ('daily-2026-11-01_000000', 'daily-2026-11-02_000000'):
            (into / name).mkdir(parents=True)
        self.run_task([b('btrfs_prune', into=str(into), prefix='daily', keep=1)])
        self.assertEqual(len(list(into.iterdir())), 2)


class Actions(Blocks):
    def test_each_action_runs_what_it_says_and_a_report_runs_none(self):
        made = self.t / 'made folder'
        blocks = [b('compose', project='immich', action='stop'), b('service', unit='smbd.service', action='restart'),
                  b('scrub', path='/mnt/pool'), b('btrfs_balance', path='/mnt/pool', dusage=40, musage=20),
                  b('mkdir', path=str(made)), b('wait', seconds=30), b('log', message='hello there'),
                  b('command', cmd=f'echo ran >{self.t}/cmd')]
        report = self.run_task(blocks)
        self.assertEqual(report.returncode, 0, report.stdout)
        self.assertEqual([c for c in report.calls if not c.startswith(('df', 'mountpoint'))], [])
        self.assertFalse(made.exists())
        self.assertFalse((self.t / 'cmd').exists())
        run = self.run_task(blocks, run=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        for want in ('docker compose -p immich stop', 'systemctl restart -- smbd.service', 'btrfs scrub start -B -- /mnt/pool',
                     'btrfs balance start -dusage=40 -musage=20 -- /mnt/pool', 'sleep 30', 'logger -t sf-task-t -- hello there'):
            self.assertIn(want, run.calls)
        self.assertTrue(made.is_dir())
        self.assertEqual((self.t / 'cmd').read_text(), 'ran\n')

    def test_a_failed_action_fails_the_task(self):
        r = self.run_task([b('scrub', path='/mnt/pool'), b('log', message='AFTER')], run=True, env={'STUB_BTRFS_RC': '3'})
        self.assertEqual(r.returncode, 1)
        self.assertIn('scrub failed or found errors', r.stdout)
        self.assertNotIn('AFTER', r.stdout)



class Checks(Fleet):
    """What the check says about a task before it is saved or run: every finding that warns of lost data or a wasted run."""
    def setUp(self):
        super().setUp()
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        for mp, src, fs in (('/mnt/usb', '/dev/sdd1', 'vfat'), ('/tank/media', 'tank/media', 'zfs'), ('/mnt/pool2', '/dev/sde1', 'btrfs')):
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options) "
                              "VALUES (:h, :m, :s, :f, :t, 1, 'indexed', 'rw')", {'h': hid, 'm': mp, 's': src, 'f': fs, 't': 10 * 2**40})

    def found(self, blocks, host='nas'):
        got = tasks.check(self.conn, tasks.normalize({'name': 't', 'host': host, 'blocks': blocks}))
        return [(x['level'], x['text']) for x in got['general']] + [(x['level'], x['text']) for bl in got['blocks'] for x in bl['items']]

    def has(self, blocks, level, words, host='nas'):
        got = self.found(blocks, host)
        self.assertTrue(any(lv == level and words in t for lv, t in got), f'no {level} with "{words}" in {got}')

    def lacks(self, blocks, words, host='nas'):
        got = self.found(blocks, host)
        self.assertFalse(any(words in t for _, t in got), f'"{words}" should not be in {got}')

    def test_the_task_itself(self):
        self.has([b('log', message='x')], 'crit', 'pick the host the task runs on', host='')
        self.has([b('log', message='x')], 'warn', 'ghost has not been scanned: paths cannot be checked', host='ghost')
        self.has([], 'warn', 'the task has no blocks yet')

    def test_an_empty_field(self):
        self.has([b('mkdir', path='')], 'crit', 'Folder is empty')

    def test_guards_against_the_last_scan(self):
        self.has([b('require_mounted', path='/mnt/pool/photos')], 'warn', 'is not a mount point in the last scan (it is inside /mnt/pool)')
        self.has([b('require_mounted', path='/mnt/backup')], 'ok', '/mnt/backup is mounted now (ext4)')
        self.has([b('require_free', path='/mnt/backup', gib=10)], 'ok', 'GiB free at the last scan')
        self.has([b('require_free', path='/mnt/backup', gib=999_999)], 'warn', 'GiB free at the last scan')

    def test_a_copy_onto_a_disk_that_may_not_be_mounted(self):
        copy = b('rsync', src='/mnt/pool/photos', dst='/mnt/backup/photos')
        self.has([copy], 'warn', 'if that disk is not mounted, the copy lands on the system disk')
        self.lacks([b('require_mounted', path='/mnt/backup'), copy], 'lands on the system disk')
        guarded = b('if', {'then': [copy], 'else': []}, cond='mounted', arg='/mnt/backup')
        self.lacks([guarded], 'lands on the system disk')                      # inside "if mounted" it is guarded too

    def test_a_mirror_whose_source_disk_may_be_gone(self):
        mirror = b('rsync', src='/mnt/pool/photos', dst='/mnt/backup/photos', mode='mirror')
        self.has([b('require_mounted', path='/mnt/backup'), mirror], 'warn', 'the copy gets emptied')
        self.lacks([b('require_mounted', path='/mnt/backup'), b('require_mounted', path='/mnt/pool'), mirror], 'gets emptied')

    def test_sources_hosts_and_overlap(self):
        self.has([b('rsync', src='/mnt/pool/photos', dst='/mnt/pool/photos/copy')], 'crit', 'From and To overlap')
        self.has([b('rsync', src_host='ghost', src='/x', dst='/mnt/backup/x')], 'warn', 'ghost has not been scanned: give it as user@address')
        self.lacks([b('rsync', src_host='me@10.0.0.40', src='/x', dst='/mnt/backup/x')], 'has not been scanned')
        self.has([b('rsync', src='/mnt/pool/photos', dst='/mnt/backup/p')], 'ok', '/mnt/pool/photos: 1 files')
        self.has([b('rsync', src='/mnt/pool/nothing', dst='/mnt/backup/p')], 'warn', 'is not in the index of nas (or is empty)')

    def test_a_rotating_backup_needs_hard_links(self):
        self.has([b('rotate', src='/mnt/pool/photos', dst='/mnt/usb/rot')], 'crit', '/mnt/usb is vfat: it has no hard links')
        self.lacks([b('rotate', src='/mnt/pool/photos', dst='/mnt/backup/rot')], 'no hard links')

    def test_snapshots_need_btrfs_and_one_filesystem(self):
        self.has([b('btrfs_snapshot', subvol='/mnt/backup')], 'crit', '/mnt/backup is on ext4, not btrfs')
        self.has([b('btrfs_snapshot', subvol='/mnt/pool', into='/mnt/pool2/snaps')], 'crit', 'is on another filesystem')
        self.has([b('btrfs_snapshot', subvol='/mnt/pool', prefix='daily')], 'ok', 'go to /mnt/pool/.snapshots/daily-<date>')
        self.has([b('zfs_snapshot', dataset='tank/other')], 'warn', 'tank/other is not a mounted dataset on nas')
        self.lacks([b('zfs_snapshot', dataset='tank/media')], 'not a mounted dataset')
        self.has([b('scrub', path='/mnt/backup')], 'crit', 'scrub is for btrfs')
        self.has([b('btrfs_balance', path='/mnt/backup')], 'crit', 'balance is for btrfs')

    def test_sends_land_on_the_right_kind_of_place(self):
        self.has([b('btrfs_send', into='/mnt/pool/.snapshots', dst_host='pc', dst='/mnt/media/in')], 'crit', 'not btrfs')
        self.has([b('zfs_send', dataset='tank/media', dst_host='pc', dst='backup')], 'crit', 'is a whole pool')

    def test_a_command_that_removes_the_root_in_any_spelling(self):
        for cmd in ('rm -rf /', 'rm -fr /', 'rm -rf /*', 'rm -r -f /', 'rm --no-preserve-root -rf /', 'sudo rm -Rf / ', 'cd /tmp && rm -rf /;'):
            with self.subTest(cmd):
                self.has([b('command', cmd=cmd)], 'crit', 'this removes the root of the filesystem')
        for cmd in ('rm -rf /tmp/x', 'rm -rf /mnt/backup/old', 'echo rm -rf'):
            with self.subTest(cmd):
                self.lacks([b('command', cmd=cmd)], 'removes the root')

    def test_if_needs_an_absolute_path(self):
        self.has([b('if', {'then': [], 'else': []}, cond='exists', arg='relative/path')], 'crit', '"exists" needs an absolute path')
        self.has([b('if', {'then': [], 'else': []}, cond='mounted', arg='/mnt/backup')], 'note', 'holds no blocks yet')


if __name__ == '__main__':
    unittest.main()
