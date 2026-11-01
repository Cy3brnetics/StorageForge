"""The sync engine in storageforge-job: routes, pre-transfer dedup, the volume lock, state events, snapshot streams,
duperemove and the room check. The real program runs; ssh, btrfs and duperemove are stand-ins, since they need root, a
second host or a real pool (the KVM lab is where those get proven)."""
import ast
import fcntl
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import jobs, moves, permissions, server
from storageforge_index.jobscript import JOB_SCRIPT
from storageforge_index.syncindex import SYNC_PY

MB = 1 << 20
FAKE_SSH = r"""#!/bin/bash
# sshd plus the job key's forced command. An address listed in $T/down does not answer.
args=("$@"); n=${#args[@]}; cmd=${args[n-1]}; dest=${args[n-2]}; addr=${dest#*@}
printf '%s\n' "$*" >>"$T/ssh.log"
grep -qxF -- "$addr" "$T/down" 2>/dev/null && exit 255
exec bash "$T/job" --serve "$JOB" "$cmd"
"""
FAKE_RSYNC = r"""#!/bin/bash
# the source's chrooted daemon is a local folder here. $T/drop: fail like a lost connection, once per line in it
printf '%s\n' "$*" >>"$T/rsync.log"
out=()
for a in "$@"; do
  case $a in
    -e) skip=1; continue ;;
    rsync://*) a=$T/src/ ;;
  esac
  [[ -n ${skip:-} ]] && { skip=; continue; }
  out+=("$a")
done
if [[ -s $T/drop && " $* " != *" -n "* ]]; then sed -i 1d "$T/drop"; exit 255; fi
exec "$REAL_RSYNC" "${out[@]}"
"""
FAKE_STAT = r"""#!/bin/bash
# everything is btrfs, and $T/src and $T/dst are subvolume roots
if [[ "$*" == "-f -c %T "* ]]; then echo "${FAKE_FS:-btrfs}"; exit 0; fi
if [[ $1 == -c && $2 == %i && ( $3 == "$T/src" || $3 == / ) ]]; then echo 256; exit 0; fi
exec "$REAL_STAT" "$@"
"""
FAKE_BTRFS = r"""#!/bin/bash
# subvolumes are folders; a stream is a tar of one; the id of a snapshot is its name, kept with its copy on receive
printf '%s\n' "$*" >>"$T/btrfs.log"
case "$1 $2" in
  "subvolume snapshot") mkdir -p "$5"; tar -C "$4" --exclude=.storageforge-snap -cf - . | tar -C "$5" -xf - ;;   # stops at subvolumes
  "subvolume delete") rm -rf "$3" ;;
  "subvolume show")
    if [[ -f $3/.received ]]; then echo "UUID: other"; echo "Received UUID: $(cat "$3/.received")"
    else echo "UUID: $(basename "$3")"; echo "Received UUID: -"; fi ;;
  "filesystem sync") ;;
  "filesystem usage") cat "$T/usage" ;;
  "filesystem du") printf '     Total   Exclusive  Set shared  Filename\n 100 %s 40 %s\n' "$(cat "$T/exclusive")" "$3" ;;
  send*)
    shift; [[ $1 == -q ]] && shift
    if [[ $1 == -p ]]; then shift 2; fi
    tar -C "$(dirname "$1")" -cf - "$(basename "$1")"; [[ -s $T/send_fails ]] && { sed -i 1d "$T/send_fails"; exit 1; }; exit 0 ;;
  receive*)
    shift; [[ $1 == -C ]] && shift; dir=$1; before=$(ls "$dir")
    tar -C "$dir" -xf - || exit 1
    for d in "$dir"/sf-*; do grep -qxF "$(basename "$d")" <<<"$before" || echo "$(basename "$d")" >"$d/.received"; done ;;
  *) echo "fake btrfs: $*" >&2; exit 9 ;;
esac
"""


def helper(*args, stdin=None):
    return subprocess.run(['python3', '-I', '-c', SYNC_PY, *map(str, args)], capture_output=True, text=True, timeout=60,
                          pass_fds=(), input=stdin)


@unittest.skipIf(os.geteuid() == 0, 'root ignores the test paths')
@unittest.skipUnless(shutil.which('rsync') and shutil.which('python3') and shutil.which('flock'), 'needs rsync, python3, flock')
class Engine(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.t, ignore_errors=True)
        self.src, self.dst, self.etc, self.var, self.bin = (self.t / x for x in ('src', 'dst', 'etc', 'var', 'bin'))
        for d in (self.src, self.dst, self.etc / 'jobs', self.etc / 'serve', self.var, self.bin):
            d.mkdir(parents=True)
        (self.t / 'job').write_text(JOB_SCRIPT.replace('PATH=/usr/local/sbin', f'PATH={self.bin}:/usr/local/sbin', 1))
        (self.t / 'job').chmod(0o755)
        self.env = {**os.environ, 'STORAGEFORGE_JOB_ETC': str(self.etc), 'STORAGEFORGE_JOB_VAR': str(self.var), 'T': str(self.t),
                    'JOB': 'p1-a', 'REAL_RSYNC': shutil.which('rsync'), 'REAL_STAT': shutil.which('stat')}

    def need_no_reflinks(self):
        """Same-host jobs reflink first, on a filesystem that can, and that counts as dedup too."""
        (self.t / 'r1').write_bytes(b'x')
        with open(self.t / 'r1', 'rb') as a, open(self.t / 'r2', 'wb') as b:
            try:
                fcntl.ioctl(b, 0x40049409, a.fileno())       # FICLONE
            except OSError:
                return
        self.skipTest('this filesystem has reflinks, so hashes are not what dedups here')

    def fake(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(0o755)

    def conf(self, *, local=True, routes=(), transport='rsync', **kw):
        spec = {'id': 'p1-a', 'name': 'test', 'method': kw.pop('method', 'mirror'), 'local': local, 'src_host': 'nas', 'src_port': 22,
                'src': str(self.src), 'dst': str(self.dst), 'dst_mount': '/', 'flags': kw.pop('flags', ''), 'keep': '', 'lowest': 'daily',
                'window': None, 'bw_day': kw.pop('bw', None), 'bw_night': None, 'night': None, 'snapshot': False, 'pre': [], 'post': [],
                'excludes': [], 'routes': list(routes), 'transport': transport, **kw}
        (self.etc / 'jobs' / 'p1-a.conf').write_text(jobs.conf_text(spec, None))
        (self.etc / 'serve' / 'p1-a.conf').write_text(jobs.serve_text(spec))
        if not local:
            self.fake('ssh', FAKE_SSH)
            self.fake('rsync', FAKE_RSYNC)

    def job(self, *args, **env):
        return subprocess.run(['bash', str(self.t / 'job'), *args], capture_output=True, text=True, timeout=120,
                              env={**self.env, **env}, stdin=subprocess.DEVNULL)

    def last_run(self):
        return json.loads((self.var / 'jobs' / 'p1-a' / 'runs.jsonl').read_text().splitlines()[-1])

    def events(self, out):
        return [json.loads(x) for x in out.splitlines() if x.startswith('{"event"')]

    # ── dedup ──
    def test_a_renamed_file_is_not_sent_again(self):
        self.need_no_reflinks()
        data = os.urandom(2 * MB)
        (self.dst / 'old-name.bin').write_bytes(data)
        (self.src / 'sub').mkdir()
        (self.src / 'sub' / 'new-name.bin').write_bytes(data)
        (self.src / 'other.bin').write_bytes(os.urandom(2 * MB))
        self.conf(dedup=True)
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual((self.dst / 'sub' / 'new-name.bin').read_bytes(), data)
        self.assertEqual((self.dst / 'old-name.bin').read_bytes(), data)
        r = self.last_run()
        self.assertEqual(r['dedup_bytes'], 2 * MB)
        self.assertEqual(r['bytes'], 2 * MB)                # only other.bin went through rsync
        self.assertEqual(self.events(p.stdout)[-1]['dedup_ratio'], 0.5)
        self.assertEqual(stat.S_IMODE((self.dst / 'sub').stat().st_mode), stat.S_IMODE((self.src / 'sub').stat().st_mode))
        self.assertEqual(self.job('verify', 'p1-a').returncode, 0)

    def test_nothing_is_hashed_when_nothing_changed(self):
        self.need_no_reflinks()
        (self.src / 'a.bin').write_bytes(os.urandom(2 * MB))
        self.conf(dedup=True)
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        self.assertFalse((self.var / 'index' / 'p1-a.source.db').exists())   # no file that size at the destination: the source read nothing
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        self.assertEqual(self.last_run()['dedup_bytes'], 0)

    def test_dedup_failure_leaves_it_to_rsync(self):
        self.need_no_reflinks()
        data = os.urandom(2 * MB)
        (self.dst / 'x.bin').write_bytes(data)
        (self.src / 'y.bin').write_bytes(data)
        self.conf(dedup=True)
        (self.etc / 'serve' / 'p1-a.conf').write_text(f'ROOT={self.src}\nDEDUP=0\n')     # the source refuses hashes
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual((self.dst / 'y.bin').read_bytes(), data)
        self.assertEqual(self.last_run()['dedup_bytes'], 0)

    def apply(self, entries, hardlink=0):
        (self.t / 'manifest').write_text(''.join(json.dumps(e) + '\n' for e in entries))
        db = self.t / 'dst.db'
        (self.t / 'want').write_text(''.join(f"{e['size']} {bytes.fromhex(e['p']).decode()}\n" for e in entries))
        helper('candidates', db, self.dst, self.t / 'want', 1)
        return helper('apply', db, self.dst, self.t / 'manifest', 'sha256', 1, hardlink)

    def entry(self, rel, data, **kw):
        import hashlib
        return {'p': rel.encode().hex(), 'size': len(data), 'mtime_ns': 1_600_000_000_000_000_000, 'mode': 0o100644, 'uid': os.getuid(),
                'gid': os.getgid(), 'algo': 'sha256', 'hash': hashlib.sha256(data).hexdigest(), **kw}

    def test_a_hostile_manifest_stays_in_the_destination(self):
        """The paths and hashes come from the source, which may have been taken over."""
        data = b'x' * 4096
        (self.dst / 'pool.bin').write_bytes(data)
        outside = self.t / 'outside'
        outside.mkdir()
        (self.dst / 'link').symlink_to(outside)
        p = self.apply([self.entry(r, data) for r in ('../outside/a', '/etc/x', 'link/b', 'a/../../outside/c', './d')])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(sorted(x.name for x in self.dst.iterdir()), ['link', 'pool.bin'])

    def test_a_wrong_hash_makes_nothing(self):
        data = b'x' * 4096
        (self.dst / 'pool.bin').write_bytes(data)
        p = self.apply([self.entry('new.bin', data, hash='0' * 64)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.dst / 'new.bin').exists())

    def test_the_candidate_is_read_again_before_it_is_used(self):
        data = b'x' * 4096
        pool = self.dst / 'pool.bin'
        pool.write_bytes(data)
        e = self.entry('new.bin', data)
        self.apply([])
        pool.write_bytes(b'y' * 4096)                      # changed since any index saw it
        self.apply([e])
        self.assertFalse((self.dst / 'new.bin').exists())

    def test_hard_links_only_when_opted_in_and_everything_on_the_inode_agrees(self):
        data = b'x' * 4096
        pool = self.dst / 'pool.bin'
        pool.write_bytes(data)
        os.utime(pool, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
        self.apply([self.entry('off.bin', data)])
        self.assertEqual(pool.stat().st_nlink, 1)
        self.apply([self.entry('other-time.bin', data, mtime_ns=1_500_000_000_000_000_000)], hardlink=1)
        self.assertEqual(pool.stat().st_nlink, 1)          # rsync setting its time would change pool.bin as well
        self.assertEqual((self.dst / 'other-time.bin').read_bytes(), data)
        self.apply([self.entry('same.bin', data, mode=pool.stat().st_mode)], hardlink=1)
        # a filesystem with reflinks clones instead: then the inodes stay apart and that is better
        self.assertEqual((self.dst / 'same.bin').read_bytes(), data)

    def test_reflinks_on_a_filesystem_that_has_them(self):
        base = Path(__file__).resolve().parent
        d = Path(tempfile.mkdtemp(dir=base))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        a = d / 'a'
        a.write_bytes(b'z' * 65536)
        if subprocess.run(['cp', '--reflink=always', a, d / 'b'], capture_output=True).returncode:
            self.skipTest('no reflinks here')
        (d / 'b').unlink()
        (d / 'src').mkdir()
        (d / 'dst').mkdir()
        (d / 'src' / 'f').write_bytes(b'q' * 65536)
        os.utime(d / 'src' / 'f', ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
        (d / 'want').write_text('65536 f\n')
        p = helper('clone', d / 'src', d / 'dst', d / 'want')
        self.assertEqual(p.stdout.split(), ['1', '65536'], p.stderr)
        self.assertEqual((d / 'dst' / 'f').read_bytes(), b'q' * 65536)
        self.assertEqual((d / 'dst' / 'f').stat().st_mtime_ns, 1_600_000_000_000_000_000)
        self.assertNotEqual((d / 'dst' / 'f').stat().st_ino, (d / 'src' / 'f').stat().st_ino)

    def test_source_hashes_stay_under_the_root_and_are_cached(self):
        (self.src / 'a').write_bytes(b'a' * 100)
        secret = self.t / 'secret'
        secret.write_bytes(b's')
        (self.src / 'l').symlink_to(secret)
        self.conf(dedup=True)
        paths = [b'a', b'../secret', b'l', str(secret).encode()]
        p = subprocess.run(['bash', str(self.t / 'job'), '--serve', 'p1-a', 'hashes'], input=''.join(x.hex() + '\n' for x in paths),
                           capture_output=True, text=True, env=self.env, timeout=60)
        rows = [json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual([bytes.fromhex(r['p']) for r in rows], [b'a'], p.stderr)
        db = sqlite3.connect(self.var / 'index' / 'p1-a.source.db')
        self.assertEqual(db.execute('SELECT path, size, algo, hash FROM files').fetchall(), [(b'a', 100, 'sha256', rows[0]['hash'])])
        self.assertIsNotNone(db.execute('SELECT inode, mtime_ns FROM files').fetchone()[0])

    def test_hashes_need_the_jobs_own_setting(self):
        self.conf()
        p = self.job('--serve', 'p1-a', 'hashes')
        self.assertIn('does not deduplicate', p.stderr)

    # ── routes ──
    LAN, MESH = {'via': 'lan', 'address': '192.0.2.1', 'iface': None}, {'via': 'mesh', 'address': '100.64.0.1', 'iface': 'lo'}

    def test_lan_first_unthrottled_then_mesh_with_the_limit_and_its_interface(self):
        (self.src / 'f').write_text('hello')
        self.conf(local=False, routes=[self.LAN, self.MESH], bw=500)
        (self.etc / 'jobs' / 'p1-a.key').write_text('x')
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        log = (self.t / 'rsync.log').read_text()
        self.assertNotIn('--bwlimit', log)
        self.assertIn('HostKeyAlias=storageforge-source', log)
        self.assertEqual(self.events(p.stdout)[-1]['route'], 'lan')
        (self.t / 'down').write_text('192.0.2.1\n')
        (self.t / 'rsync.log').unlink()
        (self.src / 'g').write_text('again')
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual((self.dst / 'g').read_text(), 'again')
        log = (self.t / 'rsync.log').read_text()
        self.assertIn('--bwlimit=500', log)
        self.assertIn('BindInterface=lo', log)
        last = self.events(p.stdout)[-1]
        self.assertEqual((last['route'], last['node']), ('mesh', '100.64.0.1'))

    def test_a_route_lost_mid_run_moves_to_the_next_and_resumes(self):
        (self.src / 'f').write_text('hello')
        self.conf(local=False, routes=[self.LAN, self.MESH])
        # the fake drops the first real transfer, and the LAN is gone from then on
        (self.t / 'drop').write_text('1\n')
        wrapper = FAKE_RSYNC.replace('sed -i 1d "$T/drop"; exit 255', 'sed -i 1d "$T/drop"; echo 192.0.2.1 >"$T/down"; exit 255')
        self.fake('rsync', wrapper)
        self.fake('sleep', '#!/bin/bash\nexit 0\n')
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual((self.dst / 'f').read_text(), 'hello')
        states = [(e['state'], e['route']) for e in self.events(p.stdout)]
        self.assertIn(('failover', 'mesh'), states)
        self.assertEqual(states[-1], ('finished', 'mesh'))

    def test_a_route_with_no_interface_is_skipped_and_none_left_is_a_clear_failure(self):
        self.conf(local=False, routes=[{'via': 'mesh', 'address': '100.64.0.1', 'iface': 'nosuch0'}])
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 8)
        self.assertIn('no route', self.last_run()['message'])
        self.assertIn('no interface nosuch0', p.stderr)

    def test_a_pinned_key_is_required_on_every_route(self):
        (self.src / 'f').write_text('x')
        self.conf(local=False, routes=[self.LAN])
        (self.etc / 'jobs' / 'p1-a.hostkey').write_text('storageforge-source ssh-ed25519 AAAA\n')
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        self.assertIn('StrictHostKeyChecking=yes', (self.t / 'ssh.log').read_text())

    def test_jobs_without_routes_connect_as_before(self):
        (self.src / 'f').write_text('x')
        self.conf(local=False)
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        log = (self.t / 'rsync.log').read_text()
        self.assertIn('StrictHostKeyChecking=accept-new', log)
        self.assertNotIn('HostKeyAlias', log)

    # ── lock, events ──
    def hold(self, mode):
        lock = self.var / 'locks' / '.storage.lock'
        lock.parent.mkdir(exist_ok=True)
        f = open(lock, 'a')
        self.addCleanup(f.close)
        fcntl.flock(f, mode)
        return f

    def test_a_rotation_waits_for_a_sync_stream_and_streams_share(self):
        self.hold(fcntl.LOCK_SH)
        p = subprocess.run(['bash', '-c', 'exec 8>&-; bash "$T/job" with-lock / -- echo ran'], capture_output=True, text=True,
                           env={**self.env, 'LOCK_WAIT': '0'}, timeout=30)
        self.assertEqual(p.returncode, 75, p.stderr)
        self.assertNotIn('ran', p.stdout)
        self.assertEqual(self.job('with-lock', '/', '--shared', '--', 'echo', 'ran', LOCK_WAIT='0').stdout.strip(), 'ran')

    def test_a_job_does_not_start_under_an_exclusive_holder(self):
        (self.src / 'f').write_text('x')
        self.conf()
        conf = self.etc / 'jobs' / 'p1-a.conf'
        conf.write_text(conf.read_text() + 'LOCK_WAIT=0\n')
        self.hold(fcntl.LOCK_EX)
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 75)
        self.assertFalse((self.dst / 'f').exists())
        self.assertIn('busy', self.last_run()['message'])

    def test_mirror_delete_keeps_the_lock_file(self):
        (self.src / 'f').write_text('x')
        (self.dst / '.storage.lock').write_text('')
        (self.dst / 'gone').write_text('')
        self.conf(flags='delete')
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        self.assertTrue((self.dst / '.storage.lock').exists())
        self.assertFalse((self.dst / 'gone').exists())

    def test_events_are_json_on_stdout_and_in_the_state_file(self):
        (self.src / 'f').write_bytes(os.urandom(MB))
        self.conf()
        p = self.job('run', 'p1-a')
        ev = self.events(p.stdout)
        self.assertEqual((ev[0]['state'], ev[-1]['state'], ev[-1]['percent']), ('starting', 'finished', 100))
        self.assertEqual(set(ev[0]), {'event', 'job', 'run', 'state', 'percent', 'speed', 'dedup_ratio', 'route', 'node', 'at'})
        self.assertEqual(json.loads((self.var / 'jobs/p1-a/state.json').read_text()), ev[-1])
        self.assertEqual(self.last_run()['files'], 1)    # the stats still come through the progress filter

    def test_a_verify_is_not_the_state_of_the_sync(self):
        self.conf()
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        before = (self.var / 'jobs/p1-a/state.json').read_text()
        self.job('verify', 'p1-a')
        self.assertEqual((self.var / 'jobs/p1-a/state.json').read_text(), before)

    # ── room to receive ──
    def test_no_room_stops_before_anything_is_copied(self):
        (self.src / 'f').write_text('x')
        self.conf(preflight=True, reserve_gb=90000000)
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 6, p.stdout + p.stderr)
        self.assertFalse((self.dst / 'f').exists())
        self.assertIn('not enough room', self.last_run()['message'])

    USAGE = ('Overall:\n    Device size:\t\t 100\n    Device unallocated:\t\t %d\n    Free (estimated):\t\t %d\t(min: 1)\n'
             'Data,single: Size:1000, Used:1 (0.1%%)\nMetadata,DUP: Size:%d, Used:%d (50.00%%)\n')

    def test_btrfs_metadata_room_counts_even_with_data_free(self):
        (self.src / 'f').write_text('x')
        self.fake('stat', FAKE_STAT)
        self.fake('btrfs', FAKE_BTRFS)
        self.conf(preflight=True, reserve_gb=0)
        (self.t / 'usage').write_text(self.USAGE % (0, 10 ** 12, 1 << 28, (1 << 28) - 4096))
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 6, p.stdout + p.stderr)
        self.assertIn('metadata room', self.last_run()['message'])
        (self.t / 'usage').write_text(self.USAGE % (1 << 32, 10 ** 12, 1 << 28, 4096))
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    # ── snapshot streams ──
    def stream(self):
        self.fake('stat', FAKE_STAT)
        self.fake('btrfs', FAKE_BTRFS)
        self.conf(transport='btrfs')

    def received(self):
        return sorted(x.name for x in (self.dst / '.storageforge-stream').iterdir())

    def test_a_stream_sends_in_full_then_incrementally_and_cleans_up_after_verifying(self):
        (self.src / 'f').write_text('one')
        self.stream()
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        first = self.received()
        self.assertEqual(len(first), 1)
        self.assertEqual((self.dst / 'latest' / 'f').read_text(), 'one')
        self.assertNotIn('-p ', (self.t / 'btrfs.log').read_text())
        self.assertIn(f'receive -C {self.dst}/.storageforge-stream', (self.t / 'btrfs.log').read_text())
        (self.src / 'f').write_text('two')
        time.sleep(1.1)                                    # names have one-second resolution
        p = self.job('run', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f'-p {self.src}/.storageforge-snap/stream-p1-a/{first[0]}', (self.t / 'btrfs.log').read_text())
        self.assertEqual(len(self.received()), 1)
        self.assertNotEqual(self.received(), first)
        self.assertEqual((self.dst / 'latest' / 'f').read_text(), 'two')
        self.assertEqual([x.name for x in (self.src / '.storageforge-snap/stream-p1-a').iterdir()], self.received())
        self.assertEqual(self.job('verify', 'p1-a').returncode, 0)

    def test_a_failed_stream_keeps_the_last_good_copy(self):
        (self.src / 'f').write_text('one')
        self.stream()
        self.assertEqual(self.job('run', 'p1-a').returncode, 0)
        good = self.received()
        (self.src / 'f').write_text('two')
        time.sleep(1.1)
        (self.t / 'send_fails').write_text('1\n')
        p = self.job('run', 'p1-a')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.received(), good)
        self.assertEqual((self.dst / 'latest' / 'f').read_text(), 'one')

    def test_a_stream_of_a_folder_inside_a_subvolume_is_refused(self):
        """It would send the whole subvolume to a key that may read one folder of it."""
        self.fake('stat', FAKE_STAT)
        self.fake('btrfs', FAKE_BTRFS)
        (self.src / 'inner').mkdir()
        self.conf(transport='btrfs')
        (self.etc / 'serve' / 'p1-a.conf').write_text(f'ROOT={self.src}/inner\nSTREAM=btrfs\n')
        p = self.job('--serve', 'p1-a', 'stream-snap')
        self.assertIn('not the root of a btrfs subvolume', p.stderr)

    def test_stream_verbs_take_only_their_own_names(self):
        self.stream()
        for cmd in ('stream-send ../../etc -', 'stream-send sf-20260101T000000 ../x', 'stream-keep $(id)', 'stream-nope sf-20260101T000000'):
            p = self.job('--serve', 'p1-a', cmd)
            self.assertNotEqual(p.returncode, 0, cmd)
        self.assertNotIn('send', (self.t / 'btrfs.log').read_text() if (self.t / 'btrfs.log').exists() else '')

    def test_a_job_without_the_setting_cannot_stream(self):
        self.conf()
        self.assertIn('does not stream', self.job('--serve', 'p1-a', 'stream-snap').stderr)

    # ── duperemove ──
    def test_dedupe_logs_what_it_freed(self):
        self.fake('stat', FAKE_STAT)
        self.fake('btrfs', FAKE_BTRFS)
        (self.t / 'exclusive').write_text('80')
        self.fake('duperemove', '#!/bin/bash\nprintf "%s\\n" "$*" >"$T/dupe.log"\necho 50 >"$T/exclusive"\n')
        self.conf(extent_dedup='weekly')
        p = self.job('dedupe', 'p1-a')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f'--hashfile={self.var}/index/p1-a.dupehash', (self.t / 'dupe.log').read_text())
        r = self.last_run()
        self.assertEqual((r['kind'], r['bytes']), ('dedupe', 30))
        db = sqlite3.connect(self.var / 'index' / 'p1-a.db')
        self.assertEqual(db.execute('SELECT kind, total, exclusive, shared, saved FROM space_metrics').fetchall(), [('dedupe', 100, 50, 40, 30)])

    def test_dedupe_does_not_run_during_a_sync(self):
        self.fake('duperemove', '#!/bin/bash\ntouch "$T/ran"\n')
        self.conf()
        conf = self.etc / 'jobs' / 'p1-a.conf'
        conf.write_text(conf.read_text() + 'LOCK_WAIT=0\n')
        self.hold(fcntl.LOCK_SH)
        self.assertEqual(self.job('dedupe', 'p1-a').returncode, 75)
        self.assertFalse((self.t / 'ran').exists())


class Portable(unittest.TestCase):
    def test_the_helper_runs_on_python_3_6(self):
        """openSUSE Leap 15 and RHEL 8 ship it: anything newer and dedup is quietly skipped on them."""
        ast.parse(SYNC_PY, feature_version=(3, 6))
        self.assertNotIn('capture_output', SYNC_PY)


class Plans(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.db = dbfactory.make(self, Path(d) / 'x.db')

    def plan(self, method='mirror', **o):
        return {'name': 'p', 'steps': [{'method': method, 'src': {'host': 'a', 'path': '/s'}, 'dst': {'host': 'b', 'path': '/d'}, 'options': o}]}

    def test_a_plan_that_uses_none_of_it_keeps_its_fingerprint(self):
        keys = set(moves.normalize(self.plan())['steps'][0]['options'])
        self.assertFalse(keys & {'routes', 'dedup', 'transport', 'preflight', 'extent_dedup', 'hash'})

    def test_bad_values_are_refused(self):
        lan = {'via': 'lan', 'address': '10.0.0.1'}
        for o, method in (({'routes': [{'via': 'wan', 'address': '10.0.0.1'}]}, 'mirror'),
                          ({'routes': [{'via': 'lan', 'address': '-oProxyCommand=x'}]}, 'mirror'),
                          ({'routes': [{'via': 'lan', 'address': 'a b'}]}, 'mirror'),
                          ({'routes': [{**lan, 'iface': '$(id)'}]}, 'mirror'),
                          ({'routes': [{**lan, 'iface': 'a|b'}]}, 'mirror'),
                          ({'routes': [lan] * 5}, 'mirror'),
                          ({'transport': 'btrfs'}, 'copy'),
                          ({'transport': 'tar'}, 'mirror'),
                          ({'transport': 'btrfs', 'dedup': True}, 'mirror'),
                          ({'transport': 'zfs', 'snapshot': True}, 'mirror'),
                          ({'dedup': True}, 'rsnapshot'),
                          ({'dedup': True, 'hash': 'md5'}, 'mirror'),
                          ({'extent_dedup': 'daily'}, 'mirror'),
                          ({'extent_dedup': 'weekly'}, 'git')):
            with self.assertRaises(ValueError, msg=str(o)):
                moves.normalize(self.plan(method, **o))
        for o in ({'preflight': True, 'reserve_gb': 'lots'}, {'dedup': True, 'dedup_min_kb': 'x'}):
            with self.assertRaisesRegex(ValueError, 'whole number'):
                moves.normalize(self.plan(**o))

    def test_no_reserve_given_means_the_default_and_zero_means_zero(self):
        norm = lambda **o: moves.normalize(self.plan(preflight=True, **o))['steps'][0]['options']['reserve_gb']   # noqa: E731
        self.assertEqual((norm(), norm(reserve_gb=''), norm(reserve_gb='0')), (1, 1, 0))

    def test_ipv6_routes_and_interfaces_are_kept(self):
        o = moves.normalize(self.plan(routes=[{'via': 'mesh', 'address': 'fd7a:115c:a1e0::1', 'iface': 'tailscale0'}]))['steps'][0]['options']
        self.assertEqual(o['routes'], [{'via': 'mesh', 'address': 'fd7a:115c:a1e0::1', 'iface': 'tailscale0'}])

    def spec(self, **kw):
        return {'id': 'p1-a', 'plan_id': 1, 'step': 'a', 'name': 'x', 'method': 'mirror', 'runner': 'b', 'source': 'a', 'local': False,
                'src_host': 'a', 'src_port': 22, 'src': '/s', 'dst': '/d', 'dst_mount': '/', 'flags': '', 'excludes': [], 'schedule': 'daily',
                'window': None, 'bw_day': None, 'bw_night': None, 'night': None, 'pre': [], 'post': [], 'snapshot': False, 'verify': None,
                'keep': '', 'lowest': 'daily', 'paused': False, **kw}

    def test_the_deploy_script_carries_it(self):
        s = self.spec(routes=[{'via': 'mesh', 'address': '100.64.0.1', 'iface': 'tailscale0'}], dedup=True, hash='blake3', transport='rsync',
                      extent_dedup='monthly', hostkey='storageforge-source ssh-ed25519 AAAA\n', preflight=True, reserve_gb=2)
        run = jobs.host_script({'id': 1, 'name': 'p'}, 'b', [s], [], None)
        for want in ('ROUTES=(', 'mesh|100.64.0.1|tailscale0', 'DEDUP=1', 'HASH=blake3', 'RESERVE_GB=2', 'p1-a.hostkey', 'BindInterface=lo',
                     'sf-job-p1-a-dedupe.timer', 'need_cmd python3', 'need_cmd duperemove', 'need b3sum'):
            self.assertIn(want, run)
        self.assertEqual(subprocess.run(['bash', '-n'], input=run, text=True, capture_output=True).returncode, 0)
        src = jobs.host_script({'id': 1, 'name': 'p'}, 'a', [], [self.spec(transport='btrfs')], None)
        self.assertIn('STREAM=btrfs', src)
        self.assertIn('need_cmd btrfs', src)

    def test_old_specs_still_write_a_config(self):
        self.assertIn('TRANSPORT=rsync', jobs.conf_text(self.spec(), None))

    def test_the_state_route_takes_the_jobs_own_token(self):
        c = self.db.connect()
        self.addCleanup(c.close)
        self.db.migrate(c)
        c.execute("""INSERT INTO jobs (job_id, plan_id, step_id, name, method, runner_host, source_host, spec_json, token_hash, paused, deployed_at)
                     VALUES ('p1-a', 1, 'a', 'n', 'mirror', 'b', 'a', '{}', :t, 0, 1)""", {'t': jobs.token_hash('tok')})
        web = server.create_app(server.App(self.db), 's' * 48).test_client()
        body = {'job': 'p1-a', 'run': '12345678-1234-1234-1234-123456789012', 'state': 'transferring', 'percent': 4, 'at': 1}
        self.assertEqual(web.post('/api/jobs/state', json=body).status_code, 401)
        self.assertEqual(web.post('/api/jobs/state', json=body, headers={'Authorization': 'Bearer nope'}).status_code, 401)
        ok = {'Authorization': 'Bearer tok'}
        self.assertEqual(web.post('/api/jobs/state', json={**body, 'job': 'p2-b'}, headers=ok).status_code, 403)
        self.assertEqual(web.post('/api/jobs/state', json=body, headers=ok).status_code, 200)
        self.assertEqual(c.scalar("SELECT percent FROM job_state WHERE job_id = 'p1-a'"), 4)
        self.assertEqual(jobs.overview(c)[0]['live']['state'], 'transferring')

    def test_running_duperemove_is_not_a_read(self):
        self.assertEqual(permissions.required('POST', '/api/deploy/jobs/p1-a/dedupe'), 'deploy.apply')

    def test_state_events_are_kept_per_job_and_checked(self):
        run = '12345678-1234-1234-1234-123456789012'
        c = self.db.connect()
        self.addCleanup(c.close)
        self.db.migrate(c)
        jobs.ingest_state(c, {'job': 'p1-a', 'run': run, 'state': 'transferring', 'percent': 400, 'speed': '1MB/s', 'dedup_ratio': 0.5, 'route': 'lan', 'node': '10.0.0.1', 'at': 5})
        jobs.ingest_state(c, {'job': 'p1-a', 'run': run, 'state': 'finished', 'percent': 100, 'at': 6})
        self.assertEqual([tuple(r) for r in c.all('SELECT state, percent FROM job_state')], [('finished', 100)])
        for bad in ({'job': '../x', 'run': run}, {'job': 'p1-a', 'run': 'x'}, {'job': 'p1-a', 'run': run, 'percent': 'lots'},
                    {'job': 'p1-a', 'run': run, 'at': time.time() + 9999}):
            with self.assertRaises(ValueError):
                jobs.ingest_state(c, bad)


if __name__ == '__main__':
    unittest.main()
