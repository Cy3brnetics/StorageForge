"""Run with: python3 -m unittest discover -s tests -v"""
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index.capacity import TiB, parse_size, pool_capacity
from storageforge_index.db import Database, MassDeleteRefused
from storageforge_index.payloads import (apply_df, apply_fstab, apply_lvs, apply_zpool_status, load_structured, lvm_level,
                                         node_from_blueprint, node_from_lsblk, parse_df, parse_fstab, parse_zpool_status)
from storageforge_index.remote import MountInfo, Transport, find_command
from storageforge_index.report import render_report
from storageforge_index.scanner import ScanOptions, build_jobs, plan_mounts, scan_host
from storageforge_index.search import SearchQuery, classify, glob_to_like, glob_to_regex, run_search
from storageforge_index.stream import TruncatedStream, extension, iter_rows, split_path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples' / 'atlas'


class Units(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(parse_size('100MB'), 100_000_000)
        self.assertEqual(parse_size('100MiB'), 100 * 2**20)
        self.assertEqual(parse_size('1.9T'), int(1.9 * 2**40))
        self.assertEqual(parse_size('4096'), 4096)
        with self.assertRaises(ValueError):
            parse_size('lots')

    def test_split_and_extension(self):
        self.assertEqual(split_path('/'), ('', '/'))
        self.assertEqual(split_path('/etc'), ('/', 'etc'))
        self.assertEqual(split_path('/etc/fstab'), ('/etc', 'fstab'))
        self.assertEqual(extension('IMG_1.CR2', False), 'cr2')
        self.assertEqual(extension('.bashrc', False), '')
        self.assertEqual(extension('dir.d', True), '')


class Stream(unittest.TestCase):
    def rec(self, path, t='f', size=10, target=''):
        return b'\0'.join([t.encode(), str(size).encode(), b'-rw-r--r--', b'1000', b'1000', b'1700000000.75',
                           target.encode(), path.encode()]) + b'\0'

    def test_newlines_and_spaces_in_names(self):
        data = self.rec('/srv/a b/new\nline.txt') + self.rec('/srv/l', 'l', 3, '../x')
        rows = list(iter_rows(io.BytesIO(data)))
        self.assertEqual(rows[0][:4], ('/srv/a b', 'new\nline.txt', 'txt', 10))
        self.assertEqual(rows[0][-1], 1700000000)
        self.assertTrue(rows[1][5])
        self.assertEqual(rows[1][6], '../x')

    def test_truncated_stream_is_an_error(self):
        data = self.rec('/a')[:-7]
        with self.assertRaises(TruncatedStream):
            list(iter_rows(io.BytesIO(data)))

    def test_small_reads_span_record_boundaries(self):
        class Trickle(io.BytesIO):
            def read1(self, n=-1):
                return super().read(3)
        rows = list(iter_rows(Trickle(self.rec('/x/y') * 50)))
        self.assertEqual(len(rows), 50)


class Patterns(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify('*.cr2'), ('ext', 'cr2'))
        self.assertEqual(classify('report.pdf'), ('exact', 'report.pdf'))
        self.assertEqual(classify('IMG_*'), ('prefix', 'IMG_'))
        self.assertEqual(classify('*2019*raw*')[0], 'glob')

    def test_translations(self):
        self.assertEqual(glob_to_like('IMG_?[0-9]*.cr2'), 'IMG___%.cr2')
        self.assertEqual(glob_to_regex('a?[!x]*.c'), '^a.[^x].*\\.c$')


class Capacity(unittest.TestCase):
    def test_tank_matches_dashboard(self):
        r = pool_capacity('zfs', 'raidz2', [20000588955648] * 6)
        self.assertAlmostEqual(r['usable'] / TiB, 72.64, places=2)
        self.assertEqual(r['tolerance'], 2)

    def test_md_raid1_ext4(self):
        r = pool_capacity('md', 'raid1', [8001563222016 - 2**20] * 2, fs='ext4')
        self.assertAlmostEqual(r['usable'] / TiB, 6.80, places=2)

    def test_too_few_devices_and_btrfs_parity(self):
        """GM-23: one device in raid1 left usable at -512 MiB (data 0 minus metadata); btrfs raid5/6 counted no parity."""
        for kind, level, sizes in (('btrfs', 'raid1', [4e12]), ('btrfs', 'raid10', [4e12, 4e12]), ('md', 'raid5', [4e12]),
                                   ('btrfs', 'raid6', [4e12, 4e12])):
            self.assertGreaterEqual(pool_capacity(kind, level, sizes)['usable'], 0, (kind, level))
        r = pool_capacity('btrfs', 'raid5', [4e12] * 4)
        self.assertEqual((r['parity'], r['tolerance']), (4e12, 1))
        self.assertAlmostEqual(r['usable'] / 1e12, 12 * 0.99, delta=0.01)
        self.assertEqual(pool_capacity('btrfs', 'raid6', [4e12] * 4)['tolerance'], 2)

    def test_btrfs_raid1_mixed(self):
        r = pool_capacity('btrfs', 'raid1', [16e12, 4e12])
        self.assertAlmostEqual(r['usable'] / 1e12, 4.0, delta=0.1)   # limited by the small device
        self.assertGreater(r['waste'], 11e12)


class Planning(unittest.TestCase):
    def test_plan_skips_and_bind_alias(self):
        mounts = [MountInfo('/', '/dev/sda2', 'ext4', majmin='8:2', fsroot='/'),
                  MountInfo('/proc', 'proc', 'proc'),
                  MountInfo('/mnt/data', '/dev/sdb1', 'xfs', majmin='8:17', fsroot='/'),
                  MountInfo('/srv/data', '/dev/sdb1', 'xfs', majmin='8:17', fsroot='/shares'),
                  MountInfo('/mnt/nas', 'nas:/x', 'nfs4', majmin='0:55'),
                  MountInfo('/home', '/dev/sdc1', 'btrfs', majmin='0:40', fsroot='/@home'),
                  MountInfo('/var', '/dev/sdc1', 'btrfs', majmin='0:40', fsroot='/@var')]
        plans = {p.info.target: p for p in plan_mounts(mounts, ScanOptions())}
        self.assertEqual(plans['/proc'].action, 'skip')
        self.assertEqual(plans['/mnt/nas'].action, 'skip')
        self.assertEqual(plans['/srv/data'].action, 'alias')
        self.assertIs(plans['/srv/data'].alias_of, plans['/mnt/data'])
        self.assertEqual(plans['/home'].action, 'scan')   # sibling btrfs subvolumes are distinct trees
        self.assertEqual(plans['/var'].action, 'scan')
        jobs = {j.root: j for j in build_jobs(list(plans.values()), ScanOptions())}
        self.assertIn('/mnt/data', jobs['/'].prune)       # nested mounts are pruned from the parent walk
        self.assertIn('/proc', jobs['/'].prune)
        self.assertNotIn('/srv/data', jobs)

    def test_nested_btrfs_subvolumes_get_their_own_scan(self):
        """GM-14: openSUSE nests subvolumes under /@. /home (subvol /@/home) shares /'s maj:min and sits under its
        fsroot, but the walk of / prunes /home and never crosses into another subvolume: it was skipped entirely."""
        opts = 'rw,relatime,compress=zstd:1,subvolid={},subvol={}'
        mounts = [MountInfo('/', '/dev/sda2', 'btrfs', opts.format(256, '/@'), majmin='0:25', fsroot='/@'),
                  MountInfo('/home', '/dev/sda2', 'btrfs', opts.format(263, '/@/home'), majmin='0:25', fsroot='/@/home'),
                  MountInfo('/mnt/logs', '/dev/sda2', 'btrfs', opts.format(264, '/@/var/log'), majmin='0:25', fsroot='/@/var/log'),
                  MountInfo('/srv/share', '/dev/sda2', 'btrfs', opts.format(256, '/@'), majmin='0:25', fsroot='/@/data/share'),
                  # mountinfo fallback: no subvolid, but mounted where its files would appear in /
                  MountInfo('/opt', '/dev/sda2', 'btrfs', 'rw,relatime', majmin='0:25', fsroot='/@/opt')]
        plans = {p.info.target: p for p in plan_mounts(mounts, ScanOptions())}
        self.assertEqual({t: p.action for t, p in plans.items()},
                         {'/': 'scan', '/home': 'scan', '/mnt/logs': 'scan', '/srv/share': 'alias', '/opt': 'scan'})
        jobs = {j.root: j for j in build_jobs(list(plans.values()), ScanOptions())}
        self.assertEqual(set(jobs), {'/', '/home', '/mnt/logs', '/opt'})
        self.assertIn('/home', jobs['/'].prune)                  # still pruned from /, but now walked on its own

    def test_root_on_skipped_mount_is_refused(self):
        mounts = [MountInfo('/', '/dev/sda2', 'ext4', majmin='8:2'), MountInfo('/mnt/nas', 'nas:/x', 'nfs4')]
        with self.assertRaises(ValueError):
            build_jobs(plan_mounts(mounts, ScanOptions()), ScanOptions(roots=['/mnt/nas/photos']))

    def test_denied_lines_and_readonly_tools(self):
        from storageforge_index.remote import DENIED
        self.assertEqual(DENIED.match("find: '/srv/it's': Permission denied").group(1), "/srv/it's")
        self.assertEqual(DENIED.match('find: ‘/root’: Permission denied').group(1), '/root')
        self.assertIsNone(DENIED.match("find: '/x': No such file or directory"))
        cmd = find_command('/srv', [], [], nice=False)
        self.assertIn('/usr/local/lib/storageforge/find / -maxdepth 0', cmd)   # used only when it actually runs
        self.assertIn('|| echo find', cmd)

    def test_access_scripts(self):
        from storageforge_index import access
        s = access.setup_script('scan')
        self.assertIn('setcap cap_dac_read_search+ep', s)
        self.assertIn('-m 0750', s)
        self.assertIn('runuser -u "$U"', s)
        self.assertIn('rm -rf "$D"', s)                                      # a setup that cannot work leaves nothing
        with self.assertRaises(ValueError):
            access.setup_script('x; rm -rf /')
        self.assertIn('groupdel storageforge-scan', access.remove_script('scan'))

    def test_inventory_sections_land_in_their_fields(self):
        from storageforge_index import remote
        out = '\n'.join(['@@hostname', 'h', '@@ip', '10.0.0.1', '@@os', 'Linux', '@@lsblk', '{"blockdevices": []}',
                          '@@findmnt', '{"filesystems": [{"target": "/", "source": "/dev/sda1", "fstype": "ext4"}]}',
                          '@@lvs', 'LVS', '@@btrfs', 'BTRFS', '@@nfs', 'NFS', '@@smb', 'SMB', '@@access', 'capability', 'scan', '@@end'])

        class T:
            host, local = 'h', False

            def run(self, script, timeout=0):
                return out
        inv = remote.collect_inventory(T())
        self.assertEqual((inv.lvs, inv.btrfs, inv.nfs, inv.smb, inv.access, inv.user), ('LVS', 'BTRFS', 'NFS', 'SMB', 'capability', 'scan'))

    def test_inventory_sections_and_mountinfo_options(self):
        """GM-23: a line of a file the inventory shows (fstab, exports) starting with @@ started a section of its own;
        the /proc/self/mountinfo fallback dropped the filesystem's own options (subvol=, compress=)."""
        from storageforge_index.remote import parse_mountinfo, parse_sections
        sec = parse_sections('@@hostname\nnas\n@@nfs\n/srv x(rw)\n@@note from the admin\n@@end\n')
        self.assertEqual(sec, {'hostname': 'nas', 'nfs': '/srv x(rw)\n@@note from the admin'})
        line = '36 25 0:31 /@/home /home rw,relatime shared:1 - btrfs /dev/sda2 rw,compress=zstd:3,subvolid=257,subvol=/@/home'
        m = parse_mountinfo(line)[0]
        self.assertEqual(m.options, 'rw,relatime,compress=zstd:3,subvolid=257,subvol=/@/home')

    def test_find_command_quotes_and_prunes(self):
        cmd = find_command("/srv/it's here", ['/srv/it\'s here/[x]'], ['.git'], nice=False)
        self.assertIn("'/srv/it'\"'\"'s here'", cmd)
        self.assertIn('\\[x\\]', cmd)
        self.assertIn('-xdev', cmd)



def bash_fn(source: str, name: str) -> str:
    """One function of a generated script, to run on its own with the rest stubbed out."""
    import re
    m = re.search(rf'^{name}\(\) \{{.*?^\}}\n', source, re.M | re.S)
    assert m, name
    return m.group(0)


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class GeneratedBash(unittest.TestCase):
    """Helpers of the root scripts StorageForge writes, run for real with their surroundings stubbed."""

    def bash(self, code: str) -> str:
        import subprocess
        p = subprocess.run(['bash', '-c', code], capture_output=True, text=True, timeout=30)
        return p.stdout + p.stderr

    def test_move_verify_fails_when_rsync_fails(self):
        """A failed rsync lists no differences: verify must not call that a match, since cutover trusts it (GM-21)."""
        from storageforge_index import moves
        from storageforge_index.scriptkit import HELPERS

        def verify(rs):
            return self.bash(f"""set -euo pipefail
{HELPERS}has() {{ return 1; }}; dst_guard() {{ return 0; }}; CHECKSUM=0; S_METHOD=(move)
rsync_args() {{ RS=({rs}); }}
{bash_fn(moves.SCRIPT_BODY, 'verify_step')}
if verify_step 0; then echo VERDICT=match; else echo VERDICT=differ; fi""")
        out = verify("bash -c 'echo \"rsync: change_dir failed\" >&2; exit 23'")
        self.assertIn('VERDICT=differ', out)
        self.assertIn('exit 23', out)
        self.assertIn('VERDICT=match', verify("printf '%s\\n' '.d..t...... ./'"))
        self.assertIn('VERDICT=differ', verify("printf '%s\\n' '>f+++++++++ new.txt'"))

    def job(self, code: str, **env) -> str:
        """Runs code after the job program's helpers (without its command dispatch) and env as shell variables."""
        import shlex
        from storageforge_index.jobscript import JOB_SCRIPT
        helpers = JOB_SCRIPT[:JOB_SCRIPT.index('\ncase ${1:-} in')]
        helpers = helpers[helpers.index('\nsubvol_of() {'):]          # skip the config loading at the top
        return self.bash('\n'.join(f'{k}={shlex.quote(str(v))}' for k, v in env.items()) + f'\n{helpers}\n{code}')

    def test_job_paths_when_the_subvolume_or_root_is_slash(self):
        """GM-10: snap_path lost the / between the snapshot and the path; under x / matched nothing."""
        for sv, root, want in (('/', '/var/lib/data', '/.storageforge-snap/p1-s1/var/lib/data'),
                               ('/srv', '/srv/x', '/srv/.storageforge-snap/p1-s1/x'),
                               ('/srv', '/srv', '/srv/.storageforge-snap/p1-s1')):
            out = self.job(f'subvol_of() {{ echo {sv}; }}\nsnap_path', ROOT=root, SID='p1-s1')
            self.assertEqual(out.strip(), want, (sv, root))
        out = self.job('for c in "/srv/f /" "/ /" "/etc /srv" "/srv2 /srv" "/srv/a /x /srv"; do '
                       'under $c && echo "$c yes" || echo "$c no"; done')
        self.assertEqual(out.splitlines(), ['/srv/f / yes', '/ / yes', '/etc /srv no', '/srv2 /srv no', '/srv/a /x /srv yes'])

    def test_snapshot_first_git_job_may_clone_its_snapshot(self):
        """GM-10: the runner clones from the snapshot of the root, which serve used to refuse."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'git-upload-pack').write_text('#!/bin/sh\necho "UPLOAD $*"\n')
        (tmp / 'git-upload-pack').chmod(0o755)
        snap = '/srv/.storageforge-snap/p1-s1/repo.git'

        def serve(path, flag):
            return self.job(f"serve_load() {{ :; }}; die() {{ echo \"DIE $*\"; exit 1; }}\n"
                            f"subvol_of() {{ echo /srv; }}\nPATH={tmp}:$PATH\nserve p1-s1 \"git-upload-pack '{path}'\"",
                            ROOT='/srv/repo.git', SID='p1-s1', SNAP=flag, VAR=tmp)
        self.assertIn(f'UPLOAD --strict {snap}', serve(snap, 1))
        self.assertIn('UPLOAD --strict /srv/repo.git', serve('/srv/repo.git', 1))
        self.assertIn('DIE', serve(snap, 0))                                       # no snapshot, no snapshot path
        self.assertIn('DIE', serve('/srv/other.git', 1))

    def test_remote_rsnapshot_source_is_an_rsync_url(self):
        """GM-10: rsnapshot takes a daemon source only as rsync://… (is_anon_rsync_path); host::module fails its
        config check. RSYNC_CONNECT_PROG still carries either form over SSH."""
        out = self.job('src_spec /srv/data; echo; src_spec /srv/.storageforge-snap/p1-s1/data; echo; SRC_LOCAL=1 src_spec /srv/data',
                       SRC_LOCAL=0, SRC='/srv/data', SRC_HOST='nas')
        self.assertEqual(out.splitlines(), ['rsync://storageforge-deploy@nas/src/', 'rsync://storageforge-deploy@nas/snap/',
                                            '/srv/data/'])

    def test_restore_drops_devices_and_setuid_and_stays_private_while_it_runs(self):
        """GM-01: a restore archive comes from the backup host. Device nodes, pipes and setuid bits never survive, and
        the target is 0700 while tar writes, so nothing in it is reachable before the cleanup."""
        import io
        import stat
        import tarfile
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            for name, kind, mode, data in (('d', tarfile.DIRTYPE, 0o755, b''), ('d/su', tarfile.REGTYPE, 0o4755, b'x'),
                                           ('d/ok', tarfile.REGTYPE, 0o644, b'y'), ('d/mem', tarfile.CHRTYPE, 0o666, b''),
                                           ('d/fifo', tarfile.FIFOTYPE, 0o666, b'')):
                ti = tarfile.TarInfo(name)
                ti.type, ti.mode, ti.size = kind, mode, len(data)
                ti.devmajor, ti.devminor = (1, 1) if kind == tarfile.CHRTYPE else (0, 0)
                tf.addfile(ti, io.BytesIO(data))
        (tmp / 'in.tar').write_bytes(buf.getvalue())
        target = tmp / 'root' / 'restored'
        (tmp / 'root').mkdir()
        out = self.job(f'serve_load() {{ :; }}; die() {{ echo "DIE $*"; exit 1; }}\n'
                       f'tar() {{ stat -c %a "$2" >{tmp}/mode-during; command tar "$@"; }}\n'
                       f'unpack p1-s1 {target} <{tmp}/in.tar', ROOT=tmp / 'root')
        self.assertEqual((tmp / 'mode-during').read_text().strip(), '700', out)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
        self.assertEqual(sorted(p.name for p in (target / 'd').iterdir()), ['ok', 'su'], out)
        self.assertFalse((target / 'd' / 'su').stat().st_mode & 0o6000)
        self.assertEqual((target / 'd' / 'ok').read_text(), 'y')

    def test_owner_change_touches_only_what_was_asked(self):
        """GM-09: an owner with no group used to chown -R owner:<the top folder's group>, flattening every group
        inside; and a link at the path handed its target to the new owner."""
        import grp
        import pwd
        from storageforge_index import changes
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'tree' / 'sub').mkdir(parents=True)
        (tmp / 'link').symlink_to(tmp / 'tree')
        other = next(u.pw_name for u in pwd.getpwall() if u.pw_uid != os.geteuid())
        mine = grp.getgrgid(os.getegid()).gr_name

        def run(*args):
            return self.bash('ok() { echo "OK $*"; }; conflict() { echo "CONFLICT $*"; }; act() { return 0; }\n'
                             'try() { echo "RUN $*"; }\n' + bash_fn(changes.CHANGE_BODY_3, 'owner_mode')
                             + 'owner_mode ' + ' '.join(f"'{a}'" for a in args))
        self.assertIn(f'RUN chown -R -- {other} {tmp}/tree', run(f'{tmp}/tree', other, '', '', 1))
        out = run(f'{tmp}/tree', '', mine, '', 1)                             # every group already is the one asked
        self.assertIn(f'OK owner :{mine}', out)
        self.assertNotIn('RUN', out)
        out = run(f'{tmp}/link', other, '', '0700', 1)
        self.assertIn('CONFLICT', out)
        self.assertNotIn('RUN', out)
        self.assertIn('no user', run(f'{tmp}/tree', 'no-such-user-sf', '', '', 1))

    def test_share_records_the_fstab_line_it_keeps(self):
        """GM-21: when fstab already mounts the share with its own options, those stay, and the line recorded for drift
        checks must be that one: recording ours made every later scan report the line as gone."""
        from storageforge_index import shares
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        fn = bash_fn(Path(shares.__file__).read_text(), 'client_mount').replace('/etc/fstab', f'{tmp}/fstab')

        def run(fstab):
            (tmp / 'fstab').write_text(fstab)
            return self.bash(f"""ok() {{ echo "OK $*"; }}; conflict() {{ echo "CONFLICT $*"; }}; missing() {{ :; }}; section() {{ :; }}
need_cmd() {{ return 0; }}; mountpoint() {{ return 0; }}; APPLY=1; WANT_LINES=()
C_TARGET=(/mnt/media); C_SOURCE=(nas:/srv/media); C_PROTO=(NFS)
{fn}client_mount 0; printf 'WANT %s\\n' "${{WANT_LINES[@]}}" """)
        own = 'nas:/srv/media /mnt/media nfs4 rw,hard,vers=4.2 0 0'
        out = run(own + '\n')
        self.assertIn('its own options kept', out)
        self.assertIn(f'WANT {own}', out)
        out = run('other:/x /mnt/media nfs4 defaults 0 0\n')                 # a conflict: nothing of ours is there
        self.assertIn('CONFLICT', out)
        self.assertNotIn('WANT nas:', out)

    def test_restore_says_why_pack_failed_and_leaves_no_empty_folder(self):
        """GM-22: pack's errors went to /dev/null (same host) or only into another run's log (runner elsewhere), and a
        restore that got nothing left an empty .restored-<time> folder."""
        import contextlib
        import io
        import types
        from unittest import mock
        from storageforge_index import deploy, jobs
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'root').mkdir()
        out = self.job(f'serve_load() {{ :; }}; die() {{ echo "DIE $*"; exit 1; }}\nunpack p1-s1 {tmp}/root/x.restored </dev/null',
                       ROOT=tmp / 'root')
        self.assertNotIn('restored into', out)
        self.assertEqual(list((tmp / 'root').iterdir()), [])
        fake = tmp / 'storageforge-job'
        fake.write_text('#!/bin/bash\ncase $1 in pack) echo 4096 >&2; echo "storageforge-job: a.txt is not in daily.0" >&2; exit 1 ;;\n'
                        '  unpack) cat >/dev/null; echo "tar: This does not look like a tar archive" >&2; exit 2 ;; esac\n')
        fake.chmod(0o755)
        job = {'runner': 'nas', 'source': 'nas', 'spec': {'src': '/srv'}}
        scripts = []
        with mock.patch.object(jobs, 'get', lambda *a: job), \
             mock.patch.object(deploy, 'run', lambda db, h, script, **k: scripts.append(script) or {'status': 'failed'}):
            jobs.restore(None, None, 'p1-s1', 'daily.0', 'a.txt', 't')
        out = self.bash(scripts[0].replace(deploy.JOBBIN, str(fake)))
        self.assertIn('a.txt is not in daily.0', out)
        self.assertNotIn('4096', out)

        @contextlib.contextmanager
        def raw(*a, **k):
            yield types.SimpleNamespace(stdout=io.BytesIO(b''), returncode=1,
                                        errors=[b'4096\nstorageforge-job: a.txt is not in daily.0\n'])
        job['runner'] = 'backup'
        with mock.patch.object(jobs, 'get', lambda *a: job), mock.patch.object(deploy, 'raw', raw), \
             mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'failed', 'output': 'tar: not a tar archive'}):
            r = jobs.restore(None, None, 'p1-s1', 'daily.0', 'a.txt', 't')
        self.assertEqual(r['status'], 'failed')
        self.assertIn('on backup: storageforge-job: a.txt is not in daily.0', r['output'])
        self.assertNotIn('4096', r['output'])

    def test_host_relay_passes_arguments_intact(self):
        """GM-02: --host joined the arguments unquoted into the remote command line, so the remote shell split them
        again and ran what they held; a host starting with - reached ssh as an option. GM-08: tasks refuse those too."""
        from storageforge_index import tasks
        from storageforge_index.scriptkit import REMOTE
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'bin').mkdir()
        for name, body in (('ssh', f'for a; do last=$a; done\ncase $* in *mktemp*) cat "{tmp}/where" ;; *" -O "*) ;; '
                                   f'*) printf %s "$last" >"{tmp}/cmd" ;; esac\n'),
                           ('scp', ':\n'), ('sudo', 'shift; exec "$@"\n')):
            (tmp / 'bin' / name).write_text('#!/bin/bash\n' + body)
            (tmp / 'bin' / name).chmod(0o755)

        def run(host):
            return self.bash(f"""set -euo pipefail; PATH={tmp}/bin:$PATH
ARGS=(--step '1; touch {tmp}/PWNED' --host {host} --apply); HOST={host}
{REMOTE}""")
        for where in (tmp / 'plain', tmp / 'with space'):   # the remote command removes it at the end
            where.mkdir()
            (where / 'move.sh').write_text('for a; do printf "ARG<%s>\\n" "$a"; done\n')
            (tmp / 'where').write_text(str(where))
            run('nas')
            out = self.bash(f'PATH={tmp}/bin:$PATH; sh -c "$(cat \'{tmp}/cmd\')"')
            self.assertEqual(out.splitlines(), ['ARG<--step>', f'ARG<1; touch {tmp}/PWNED>', 'ARG<--apply>'], where)
            self.assertFalse((tmp / 'PWNED').exists())
            self.assertFalse(where.exists())
        self.assertIn('not a host name', run('-oProxyCommand=x'))
        for bad in ('-e.', '-oX@nas', 'scan@-e.'):
            with self.assertRaisesRegex(ValueError, 'host name'):
                tasks.normalize({'name': 't', 'host': bad, 'blocks': []})
        self.assertEqual(tasks.normalize({'name': 't', 'host': 'scan@nas-2', 'blocks': []})['host'], 'scan@nas-2')

class Payloads(unittest.TestCase):
    def test_zpool_status(self):
        st = parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text())[0]
        self.assertEqual((st['name'], st['state'], st['level'], st['width']), ('tank', 'ONLINE', 'raidz2', 6))
        self.assertEqual(len(st['log']), 1)
        self.assertEqual(len(st['cache']), 1)
        self.assertEqual(st['device_errors'][0]['cksum'], 2)
        self.assertIn('unrecoverable error', st['status'])

    def test_df_wrapped_lines(self):
        rows = {r['target']: r for r in parse_df((EXAMPLES / 'df-h.txt').read_text())}
        self.assertEqual(rows['/mnt/remote_nfs']['source'], 'nas-02.tail4c2e.ts.net:/export/archive')
        self.assertEqual(rows['/mnt/legacy']['avail'], parse_size('191G'))

    def test_fstab(self):
        e = {x['target']: x for x in parse_fstab((EXAMPLES / 'fstab').read_text())}
        self.assertIn('subvol=@home', e['/home']['options'])
        self.assertIn('bind', e['/var/lib/docker']['options'])

    def test_atlas_report(self):
        node = node_from_blueprint(load_structured(str(EXAMPLES / 'blueprint.json')))
        apply_zpool_status(node, parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text()))
        apply_fstab(node, parse_fstab((EXAMPLES / 'fstab').read_text()))
        apply_df(node, parse_df((EXAMPLES / 'df-h.txt').read_text()))
        import datetime as dt
        md = render_report([node], as_of=dt.date(2026, 10, 26))
        for heading in ('## 1. Executive Summary', '## 2. Node & Disk Inventory', '## 3. Symbolic Link',
                        '## 4. Resilience', '## 5. Storage Economics'):
            self.assertIn(heading, md)
        self.assertIn('Circular symlink', md)
        self.assertIn('protection: {protected: 4, local_only: 2, critical: 3, excluded: 1}', md)
        self.assertIn('72.64 TiB', md)


class Shares(unittest.TestCase):
    def test_nfs_exports_and_etab(self):
        from storageforge_index.payloads import parse_nfs_exports
        e = parse_nfs_exports('# comment\n/srv/media  10.42.0.0/24(rw,sync) 100.64.0.0/10(ro)\n'
                              '"/srv/with space" *(ro)\n/srv/long \\\n    host1(rw)\n')
        self.assertEqual([(x['path'], x['clients'], x['options']) for x in e],
                         [('/srv/media', '10.42.0.0/24 100.64.0.0/10', 'rw,sync'), ('/srv/with space', '*', 'ro'),
                          ('/srv/long', 'host1', 'rw')])
        etab = parse_nfs_exports('/mnt/ssd/shared\t10.42.0.11(rw,sync,wdelay)\n/mnt/ssd/shared\t10.42.0.12(rw,sync)\n')
        self.assertEqual([(x['path'], x['clients']) for x in etab], [('/mnt/ssd/shared', '10.42.0.11 10.42.0.12')])

    def test_smb_conf(self):
        from storageforge_index.payloads import parse_smb_conf
        s = parse_smb_conf('[global]\n  workgroup = HOME\n[homes]\n  browseable = no\n'
                           '[Photos]\n  path = /mnt/photos/\n  read only = yes\n  valid users = @family\n'
                           '; [old]\n[printers]\n  path = /var/spool\n[nopath]\n  comment = x\n')
        self.assertEqual(s, [{'protocol': 'SMB', 'name': 'Photos', 'path': '/mnt/photos', 'clients': '@family', 'options': 'ro'}])


class Cli(unittest.TestCase):
    def test_parser_builds(self):
        """argparse refuses duplicate subcommands only when the parser is built, which is at container start-up"""
        from storageforge_index import cli
        parser = cli.build_parser()
        for argv in (['plan', 'list'], ['changes', '--host', 'h'], ['docker'], ['backup', 'list'], ['moves', 'list']):
            self.assertTrue(parser.parse_args(argv))
        # two handlers with one name: the later def silently replaces the earlier one
        handlers = [c._defaults['fn'] for c in parser._subparsers._group_actions[0].choices.values() if 'fn' in c._defaults]
        self.assertEqual(len(handlers), len({f.__name__ for f in handlers}))
        self.assertIs(parser.parse_args(['changes', '--host', 'h']).fn, cli.cmd_changes)


class BtrfsProfiles(unittest.TestCase):
    def test_multi_device_pool_gets_its_real_profile(self):
        from storageforge_index.payloads import apply_btrfs
        disk = lambda n: {'name': n, 'type': 'disk', 'size': 4 * 10**12, 'children': [
            {'name': n + '1', 'type': 'part', 'size': 4 * 10**12, 'fstype': 'btrfs', 'uuid': 'a90e'}]}
        node = node_from_lsblk({'blockdevices': [disk('sda'), disk('sdb'), disk('sdc'), disk('sdd'),
                                                 {'name': 'nvme0n1', 'type': 'disk', 'size': 10**12, 'fstype': 'btrfs', 'uuid': '719d'}]}, 'h')
        [pool] = node['pools']
        self.assertEqual(pool['level'], 'multi-device')
        apply_btrfs(node, 'a90e\traid1\traid1\t\n719d\tsingle\tdup\t\n')
        self.assertEqual((pool['level'], pool['meta_level'], pool['level_source']), ('raid1', 'raid1', '/sys/fs/btrfs'))
        self.assertAlmostEqual(pool['cap']['usable'], 8 * 10**12, delta=0.02 * 8 * 10**12)        # raid1 keeps two copies
        self.assertEqual(node['disks'][4]['parts'][0]['btrfs_profile'], 'single/dup')


class LvmRaid(unittest.TestCase):
    """thinkingrock01: an LVM raid5 LV across three whole disks, plus plain LVs on the boot NVMe."""
    G = 931.5 * 2**30

    def lsblk(self):
        lv = {'name': 'vg_data-lv_data01', 'type': 'lvm', 'size': int(2 * self.G), 'fstype': 'ext4', 'mountpoint': '/mnt/data01'}
        def leg(disk, i):
            return {'name': disk, 'type': 'disk', 'size': int(self.G + 4 * 2**20), 'rota': True, 'children': [
                {'name': f'vg_data-lv_data01_rmeta_{i}', 'type': 'lvm', 'size': 4 * 2**20, 'children': [lv]},
                {'name': f'vg_data-lv_data01_rimage_{i}', 'type': 'lvm', 'size': int(self.G), 'children': [lv]}]}
        nvme = {'name': 'nvme0n1', 'type': 'disk', 'tran': 'nvme', 'size': 500 * 10**9, 'children': [
            {'name': 'nvme0n1p3', 'type': 'part', 'size': 498 * 10**9, 'fstype': 'LVM2_member', 'children': [
                {'name': 'rl-root', 'type': 'lvm', 'size': 70 * 2**30, 'fstype': 'xfs', 'mountpoint': '/'},
                {'name': 'rl-swap', 'type': 'lvm', 'size': 16 * 2**30, 'fstype': 'swap', 'mountpoint': '[SWAP]'},
                {'name': 'rl-home', 'type': 'lvm', 'size': 378 * 2**30, 'fstype': 'xfs', 'mountpoint': '/home'}]}]}
        return {'blockdevices': [leg('sdd', 0), leg('sde', 1), leg('sdf', 2), nvme]}

    def test_lsblk_legs_become_a_raid5_pool(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        pool = node['pools'][0]
        self.assertEqual((pool['name'], pool['type'], pool['level'], pool['vg'], pool['lv']),
                         ('vg_data-lv_data01', 'lvm', 'raid5', 'vg_data', 'lv_data01'))
        self.assertEqual(pool['members'], ['sdd', 'sde', 'sdf'])
        self.assertEqual((pool['mount'], pool['fs']), ('/mnt/data01', 'ext4'))
        self.assertIn('mapper/vg_data-lv_data01', pool['aliases'])
        self.assertEqual(pool['cap']['tolerance'], 1)
        self.assertAlmostEqual(pool['cap']['usable'] + pool['cap']['fs_reserve'], 2 * self.G, delta=2**20)
        self.assertEqual({d['dev']: d['member'] for d in node['disks']},
                         {'sdd': 'vg_data-lv_data01', 'sde': 'vg_data-lv_data01', 'sdf': 'vg_data-lv_data01', 'nvme0n1': None})

    def test_plain_lvs_group_into_their_volume_group(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        vg = next(p for p in node['pools'] if p['name'] == 'rl')
        self.assertEqual((vg['type'], vg['level'], vg['lv'], vg['members']), ('lvm', 'linear', None, ['nvme0n1p3']))
        self.assertEqual([(d['name'], d['mount'], d['props']['fs']) for d in vg['datasets']],
                         [('rl/root', '/', 'xfs'), ('rl/home', '/home', 'xfs'), ('rl/swap', None, 'swap')])
        self.assertIn('mapper/rl-home', vg['aliases'])
        self.assertEqual(node['disks'][3]['parts'][0]['member'], 'rl')
        self.assertEqual(len(node['pools']), 2)                     # the raid LV is not counted again as a plain LV

    def test_level_from_leg_count(self):
        G = self.G
        self.assertEqual(lvm_level(2, G, G)[0], 'raid1')
        self.assertEqual(lvm_level(3, G, 3 * G)[0], 'raid0')
        self.assertEqual(lvm_level(5, G, 3 * G)[0], 'raid6')
        self.assertEqual(lvm_level(6, G, 3 * G)[0], 'raid10')
        self.assertIn('raid6', lvm_level(4, G, 2 * G)[1])          # ambiguous, and it says so

    def test_lvs_overrides_the_guess(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        apply_lvs(node, '{"report": [{"lv": [{"vg_name": "vg_data", "lv_name": "lv_data01", "segtype": "raid4", '
                        '"lv_health_status": "partial", "copy_percent": "41.50"}]}]}')
        pool = node['pools'][0]
        self.assertEqual((pool['level'], pool['health'], pool['scan']), ('raid4', 'partial', 'resyncing 41.50%'))


class EndToEnd(unittest.TestCase):
    """Real local scans into a temporary SQLite index."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfidx-test-'))
        self.tree = self.tmp / 'tree'
        (self.tree / 'a').mkdir(parents=True)
        (self.tree / 'b').mkdir()
        for i in range(1200):
            (self.tree / 'a' / f'IMG_{i:04d}.CR2').write_text(str(i))
        (self.tree / 'b' / 'notes.txt').write_text('hi')
        (self.tree / 'b' / '.git').mkdir()
        (self.tree / 'b' / '.git' / 'HEAD').write_text('x')
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, root=None, **kw):
        opts = ScanOptions(roots=[str(root or self.tree)], include_tmpfs=True, include_fstypes=['overlay'], **kw)
        return scan_host(self.db, Transport('localhost', local=True), opts, log=lambda m: None)

    def search(self, **kw):
        conn = self.db.connect()
        try:
            return run_search(self.db, conn, SearchQuery(limit=5000, **kw))
        finally:
            conn.close()

    @unittest.skipIf(os.geteuid() == 0, 'root reads every folder')
    @unittest.skipIf(os.access('/usr/local/lib/storageforge/find', os.X_OK),
                     "this machine has StorageForge's read-everything find (scan access was set up here)")
    def test_unreadable_folders_and_duplicate_folders(self):
        from storageforge_index import access
        from storageforge_index.folders import duplicate_folders
        locked = self.tree / 'locked'
        (locked / 'inner').mkdir(parents=True)
        for root in (self.tree / 'photos' / '2019', self.tree / 'backup' / '2019 copy'):   # a renamed copy
            (root / 'raw').mkdir(parents=True)
            for i, n in enumerate(('a.jpg', 'b.jpg', 'c.jpg')):
                (root / n).write_bytes(b'x' * (1000 + i))
            (root / 'raw' / 'a.cr2').write_bytes(b'y' * 5000)
        (self.tree / 'photos' / '2020').mkdir()
        (self.tree / 'photos' / '2020' / 'a.jpg').write_bytes(b'x' * 1000)          # same name, different set
        locked.chmod(0)
        try:
            r = self.scan()
        finally:
            locked.chmod(0o755)
        self.assertEqual(r['status'], 'ok')                                       # unreadable is partial, not failed
        conn = self.db.connect()
        try:
            [st] = access.status(conn)
            self.assertEqual([d['path'] for d in st['denied']], [str(locked)])
            self.assertEqual((st['denied_total'], st['access']), (1, 'user'))
            dup = duplicate_folders(conn, min_files=3, min_bytes=0, include_system=True)   # the tree is under /tmp
        finally:
            conn.close()
        [g] = dup['groups']                                                       # raw/ is not listed again
        self.assertEqual(sorted(c['path'] for c in g['copies']),
                         [str(self.tree / 'backup' / '2019 copy'), str(self.tree / 'photos' / '2019')])
        self.assertEqual((g['files'], g['bytes'], g['same_name'], g['scope']), (4, 3003 + 5000, False, 'same host'))

    def test_second_scan_of_a_host_is_refused_while_one_runs(self):
        from storageforge_index.db import ScanBusy
        self.scan()
        conn = self.db.connect()
        try:
            host_id = conn.scalar('SELECT host_id FROM hosts')
            self.db.begin_scan(conn, host_id)                         # a scan left "running"
            with self.assertRaises(ScanBusy):
                self.scan()
            self.assertIsInstance(self.db.begin_scan(conn, host_id, stale_after=-1), int)   # a dead run expires
        finally:
            conn.close()

    def test_move_plan_check_and_script(self):
        import subprocess
        from storageforge_index import moves
        self.scan()
        conn = self.db.connect()
        try:
            host = conn.scalar('SELECT hostname FROM hosts')
            br = moves.browse(conn, host, str(self.tree))
            self.assertEqual({d['name'] for d in br['dirs']}, {'a', 'b'})
            self.assertEqual(next(d for d in br['dirs'] if d['name'] == 'a')['entries'], 1200)
            plan = moves.normalize({'name': 'Test plan', 'steps': [
                {'method': 'copy', 'src': {'host': host, 'path': str(self.tree / 'a')}, 'dst': {'host': host, 'path': str(self.tree / 'c')}},
                {'method': 'copy', 'src': {'host': host, 'path': str(self.tree)}, 'dst': {'host': host, 'path': str(self.tree / 'inside')}},
                {'method': 'move', 'src': {'host': 'nowhere', 'path': '/x'}, 'dst': {'host': host, 'path': '/y'}}]})
            c = moves.check(conn, plan)
            texts = [[(it['level'], it['text']) for it in st['items']] for st in c['steps']]
            self.assertIn(('ok', '1,200 files, 3.6 KiB to transfer'), texts[0])
            self.assertTrue(any(l == 'crit' and 'overlap' in t for l, t in texts[1]))
            self.assertTrue(any(l == 'crit' and 'nowhere' in t for l, t in texts[2]))
            sh = self.tmp / 'plan.sh'
            sh.write_text(moves.script(conn, plan))
            self.assertEqual(subprocess.run(['bash', '-n', str(sh)]).returncode, 0)
            pid = moves.save_plan(conn, plan, 'test')
            self.assertEqual(moves.get_plan(conn, pid)['steps'][0]['src']['path'], str(self.tree / 'a'))
            with self.assertRaises(ValueError):
                moves.save_plan(conn, {'name': 'test PLAN', 'steps': []}, 'test')        # names are unique
        finally:
            conn.close()
        for bad in ({'name': ''}, {'name': 'x', 'steps': [{'src': {'host': 'h', 'path': 'rel/path'}, 'dst': {'host': 'h', 'path': '/d'}}]},
                    {'name': 'x', 'steps': [{'src': {'host': 'h', 'path': '/a/../b'}, 'dst': {'host': 'h', 'path': '/d'}}]},
                    {'name': 'x', 'steps': [{'method': 'wipe', 'src': {'host': 'h', 'path': '/a'}, 'dst': {'host': 'h', 'path': '/d'}}]}):
            with self.assertRaises(ValueError):
                moves.normalize(bad)

    @unittest.skipUnless(shutil.which('git'), 'needs git')
    def test_git_repositories_and_copies(self):
        import subprocess
        from storageforge_index import gitrepos
        g = lambda *a, cwd=None, when='2026-10-01T10:00:00': subprocess.run(
            ['git', *a], cwd=cwd, check=True, capture_output=True,
            env={**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't',
                 'GIT_COMMITTER_EMAIL': 't@x', 'GIT_COMMITTER_DATE': when, 'GIT_AUTHOR_DATE': when})
        shutil.rmtree(self.tree / 'b' / '.git')
        work = self.tree / 'proj'
        work.mkdir()
        g('init', '-q', '-b', 'main', cwd=work)
        (work / 'x.txt').write_text('1')
        g('add', '.', cwd=work); g('commit', '-qm', 'first', cwd=work)
        g('clone', '-q', '--mirror', str(work), str(self.tree / 'archive' / 'proj.git'))
        (work / 'x.txt').write_text('2')
        g('commit', '-qam', 'second', cwd=work, when='2026-10-02T10:00:00')   # the archive is now a commit behind
        (work / 'x.txt').write_text('3')                            # and there is an uncommitted change
        other = self.tree / 'other'
        other.mkdir(); g('init', '-q', cwd=other)                   # no commits: no root, a single copy
        r = self.scan()
        self.assertEqual(r['status'], 'ok')
        conn = self.db.connect()
        try:
            repos = {x['path'].replace(str(self.tree), ''): x for x in gitrepos.listing(conn)['repos']}
        finally:
            conn.close()
        self.assertEqual(set(repos), {'/proj', '/archive/proj.git', '/other'})
        w, a = repos['/proj'], repos['/archive/proj.git']
        self.assertEqual((w['bare'], w['branch'], w['dirty'], w['head_subject']), (False, 'main', 1, 'second'))
        self.assertEqual((a['bare'], a['head_subject'], a['name']), (True, 'first', 'proj'))
        self.assertEqual(w['root_commit'], a['root_commit'])
        self.assertEqual([c['path'] for c in w['copies']], [str(self.tree / 'archive' / 'proj.git')])
        self.assertEqual((w['state'], a['state']), ('uncommitted', 'behind'))
        self.assertEqual(repos['/other']['state'], 'single copy')

    def test_cold_folders(self):
        import time
        from storageforge_index.folders import cold_folders
        old = time.time() - 3 * 365 * 86400
        (self.tree / 'archive' / 'inner').mkdir(parents=True)
        for i in range(3):
            f = self.tree / 'archive' / 'inner' / f'f{i}.bin'
            f.write_bytes(b'x' * 1000)
            os.utime(f, (old, old))
        self.scan()
        conn = self.db.connect()
        try:
            r = cold_folders(conn, min_bytes=0, include_system=True)   # the tree is under /tmp
        finally:
            conn.close()
        self.assertEqual([f['path'] for f in r['folders']], [str(self.tree / 'archive')])   # outermost cold folder only
        self.assertEqual((r['folders'][0]['files'], r['folders'][0]['bytes']), (3, 3000))

    def test_scan_search_and_incremental_diff(self):
        first = self.scan()
        self.assertEqual(first['status'], 'ok')
        self.assertEqual(first['entries'], 1 + 2 + 1200 + 1 + 1)   # root, a, b, images, notes, b/.git (its contents pruned)
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)
        self.assertEqual(len(self.search(pattern='*_00?5.CR2')), 10)
        self.assertEqual(len(self.search(pattern='notes.TXT')), 1)
        self.assertEqual(self.search(pattern='HEAD'), [])

        (self.tree / 'a' / 'IMG_0000.CR2').unlink()
        (self.tree / 'b' / 'notes.txt').write_text('longer text')
        (self.tree / 'b' / 'new.md').write_text('n')
        second = self.scan()
        self.assertEqual((second['added'], second['deleted']), (1, 1))
        self.assertGreaterEqual(second['modified'], 1)
        self.assertEqual(self.search(pattern='IMG_0000.CR2'), [])
        self.assertEqual(len(self.search(pattern='*0000*')), 0)       # FTS row removed too
        self.assertEqual(self.search(pattern='notes.txt')[0]['size'], 11)

    def test_subtree_scan_does_not_delete_siblings(self):
        self.scan()
        result = self.scan(self.tree / 'b')
        self.assertEqual(result['deleted'], 0)
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)

    def test_symlinks_resolve_through_symlinked_parents(self):
        from storageforge_index.db import Database as _D
        from storageforge_index.payloads import node_from_index
        t = self.tree
        (t / 'usr' / 'lib').mkdir(parents=True)
        (t / 'usr' / 'lib' / 'thing.so').write_text('x')
        os.symlink('usr/lib', t / 'lib')                                 # usr-merge style parent link
        os.symlink(str(t / 'lib' / 'thing.so'), t / 'via-parent')        # resolves only through /lib → usr/lib
        os.symlink(str(t / 'lib' / 'missing.so'), t / 'dead')
        os.symlink('loop-b', t / 'loop-a')
        os.symlink('loop-a', t / 'loop-b')
        res = self.scan()
        conn = self.db.connect()
        try:
            node = node_from_index(conn, res['host'])
        finally:
            conn.close()
        listed = {l['path']: l for l in node['links'] if l.get('from_index')}
        self.assertNotIn(str(t / 'via-parent'), listed)                 # healthy, same mount: not reported
        self.assertNotIn(str(t / 'lib'), listed)
        self.assertIs(listed[str(t / 'dead')]['exists'], False)
        self.assertEqual(listed[str(t / 'loop-a')].get('note'), 'ELOOP')

    def test_canonical_and_system_links(self):
        from storageforge_index.payloads import canonical, is_system_link
        links = {'/lib': ('usr/lib', '/'), '/etc/alternatives/editor': ('/usr/bin/vim', '/'), '/a': ('b', '/'), '/b': ('/a', '/')}
        self.assertEqual(canonical('/lib/systemd/system/x.service', links), ('/usr/lib/systemd/system/x.service', False))
        self.assertEqual(canonical('/etc/alternatives/editor', links), ('/usr/bin/vim', False))
        self.assertEqual(canonical('/usr/lib/../share', links), ('/usr/share', False))
        self.assertTrue(canonical('/a', links)[1])
        for p in ('/etc/alternatives/editor', '/etc/systemd/system/multi-user.target.wants/ssh.service',
                  '/lib', '/usr/bin/python3', '/etc/localtime'):
            self.assertTrue(is_system_link(p), p)
        for p in ('/var/media', '/home/ops/Archive', '/srv/vm-images', '/etc-data/x'):
            self.assertFalse(is_system_link(p), p)

    def test_mass_delete_guard(self):
        self.scan()
        for f in (self.tree / 'a').iterdir():
            f.unlink()
        result = self.scan()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)     # index left untouched
        result = self.scan(max_delete_ratio=1.0)
        self.assertEqual(result['deleted'], 1200)


if __name__ == '__main__':
    unittest.main()
