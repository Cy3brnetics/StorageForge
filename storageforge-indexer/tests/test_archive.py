"""Tests for lossless ultra-compression archiving, safe extraction, wire compression, and sender/receiver/worker CPU offload."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:
    from tests import dbfactory

from storageforge_index import changes, cli, jobs, jobscript, moves, steps_archive

ME = moves.host_slug(socket.gethostname())


def _seed_hosts(conn):
    now = 1700000000
    for name, addr, pkgs in (
        (ME, '127.0.0.1', 'tar\nzstd\nxz-utils\nrsync\n'),
        ('weaknas', '10.0.0.21', 'tar\nrsync\n'),
        ('beefybox', '10.0.0.99', 'tar\nzstd\nxz-utils\nrsync\n'),
    ):
        conn.execute(
            """INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port, ip_address, created_at, last_scanned_at,
                                  inventory_json)
               VALUES (:n, :a, 'root', 22, :a, """ + conn.ts(':t') + ', ' + conn.ts(':t') + """, :inv)""",
            {'n': name, 'a': addr, 't': now, 'inv': json.dumps({'os_release': 'ID=debian', 'packages': 'pm apt-get\n' + ''.join('have ' + tool + '\n' for tool in pkgs.replace('xz-utils', 'xz').splitlines())})},
        )
        conn.execute(
            """INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options)
               SELECT host_id, '/', '/dev/sda1', 'ext4', 1099511627776, 10737418240, 'skipped', 'rw' FROM hosts WHERE hostname = :n""",
            {'n': name},
        )


def _make_sample_tree(root: Path) -> Path:
    src = root / 'dataset'
    (src / 'nested').mkdir(parents=True)
    # Highly compressible, realistic structured text + binary data
    (src / 'alpha.txt').write_text(('StorageForge lossless archive line 0123456789\n' * 800))
    (src / 'nested' / 'beta.bin').write_bytes((b'\x00\x01\x02\x03storageforge-block-' * 1200))
    return src


@unittest.skipUnless(shutil.which('zstd') and shutil.which('xz') and shutil.which('tar'), 'needs tar, zstd and xz')
class ArchiveStepsAndOffloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-arc-'))
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        _seed_hosts(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_change_script(self, script_text: str, *args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
        # Allow running --apply unprivileged in tests by stripping only the EUID==0 guard on temp paths
        patched = script_text.replace('if ((APPLY)) && [[ $EUID -ne 0 ]]; then', 'if false; then')
        patched = patched.replace('/run/lock/sf-changes-', str(self.tmp / 'lock-'))
        # the script makes its log folder under /var/log, which a non-root user (CI's runner) cannot, and `set -e` ends the run silently
        patched = patched.replace('/var/log/storageforge', str(self.tmp / 'log'))
        sfile = self.tmp / 'change.sh'
        sfile.write_text(patched)
        sfile.chmod(0o755)
        env = {**os.environ, 'SF_TRASH_HOME': str(self.tmp / 'trash-disk')}
        if env_extra:
            env.update(env_extra)
        (self.tmp / 'trash-disk').mkdir(exist_ok=True)
        return subprocess.run(['bash', str(sfile), *args], capture_output=True, text=True, env=env, timeout=60)

    def test_change_archive_and_extract_roundtrip_zstd_and_xz(self):
        src = _make_sample_tree(self.tmp)
        raw_bytes = sum(p.stat().st_size for p in src.rglob('*') if p.is_file())
        for codec, ext in (('zstd-ultra', '.tar.zst'), ('xz-extreme', '.tar.xz'), ('zstd-high', '.tar.zst')):
            arc = self.tmp / f'out-{codec}{ext}'
            restored = self.tmp / f'restored-{codec}'
            plan = {
                'name': f'Archive {codec}',
                'tasks': [
                    {'type': 'archive', 'host': ME, 'params': {'path': str(src), 'dest': str(arc), 'codec': codec, 'verify': True}},
                    {'type': 'archive-extract', 'host': ME, 'params': {'archive': str(arc), 'dest': str(restored), 'verify_checksum': True}},
                ],
            }
            ansible_yaml = changes.ansible(self.conn, plan)
            self.assertIn(codec.split('-')[0], ansible_yaml)
            script_text = changes.script(self.conn, plan)
            chk = self._run_change_script(script_text, '--check')
            self.assertEqual(chk.returncode, 0, chk.stdout + chk.stderr)
            res = self._run_change_script(script_text, '--apply')
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue(arc.is_file())
            self.assertTrue(Path(f'{arc}.sha256').is_file())
            self.assertLess(arc.stat().st_size, raw_bytes // 5, f'{codec} should strongly compress repetitive input')
            self.assertEqual((restored / 'dataset' / 'alpha.txt').read_text(), (src / 'alpha.txt').read_text())
            self.assertEqual((restored / 'dataset' / 'nested' / 'beta.bin').read_bytes(), (src / 'nested' / 'beta.bin').read_bytes())
            # Idempotent rerun reports ok
            res2 = self._run_change_script(script_text, '--apply')
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)

    def test_change_archive_trash_source_and_tamper_guards(self):
        src = _make_sample_tree(self.tmp)
        arc = self.tmp / 'trashed.tar.zst'
        plan = {
            'name': 'Archive and trash',
            'tasks': [{'type': 'archive', 'host': ME, 'params': {
                'path': str(src), 'dest': str(arc), 'codec': 'zstd-ultra', 'verify': True, 'trash_source': True,
            }}],
        }
        res = self._run_change_script(changes.script(self.conn, plan), '--apply')
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse(src.exists(), 'source should be moved to .storageforge-trash after verified archive')
        self.assertTrue(list((self.tmp / 'trash-disk' / '.storageforge-trash').rglob('alpha.txt')))

        # Tampered .sha256 sidecar must block extraction
        Path(f'{arc}.sha256').write_text('0' * 64 + f'  {arc.name}\n')
        bad_extract = changes.script(self.conn, {
            'name': 'Tampered checksum',
            'tasks': [{'type': 'archive-extract', 'host': ME, 'params': {
                'archive': str(arc), 'dest': str(self.tmp / 'bad-out'), 'verify_checksum': True,
            }}],
        })
        r_bad = self._run_change_script(bad_extract, '--apply')
        self.assertNotEqual(r_bad.returncode, 0)
        self.assertIn('checksum mismatch', r_bad.stdout + r_bad.stderr)

        # Path traversal ../ member inside tar.zst must be rejected before extraction
        evil_tar = io.BytesIO()
        with tarfile.open(fileobj=evil_tar, mode='w') as tf:
            ti = tarfile.TarInfo('../escaped.txt')
            ti.size = 4
            tf.addfile(ti, io.BytesIO(b'evil'))
        evil_arc = self.tmp / 'evil.tar.zst'
        subprocess.run(['zstd', '-q', '-o', str(evil_arc)], input=evil_tar.getvalue(), check=True)
        r_evil = self._run_change_script(changes.script(self.conn, {
            'name': 'Traversal test',
            'tasks': [{'type': 'archive-extract', 'host': ME, 'params': {
                'archive': str(evil_arc), 'dest': str(self.tmp / 'safe-out'), 'verify_checksum': False,
            }}],
        }), '--apply')
        self.assertNotEqual(r_evil.returncode, 0)
        self.assertIn('unsafe member paths', r_evil.stdout + r_evil.stderr)
        self.assertFalse((self.tmp / 'escaped.txt').exists())

    def test_change_archive_remote_compression_host_spares_local_cpu(self):
        src = _make_sample_tree(self.tmp)
        arc = self.tmp / 'offloaded.tar.zst'
        ssh_log = self.tmp / 'ssh-calls.log'
        bin_dir = self.tmp / 'mockbin'
        bin_dir.mkdir()
        # Mock ssh executes the remote command locally in a clean PATH that has zstd, while hiding zstd from the caller PATH!
        real_path = os.environ['PATH']
        (bin_dir / 'ssh').write_text(
            f'#!/bin/bash\n'
            f'while [[ $# -gt 0 ]]; do\n'
            f'  case $1 in -o|-p|-i) shift 2 ;; -*) shift ;; *) host=$1; shift; break ;; esac\n'
            f'done\n'
            f'printf "%s\\t%s\\n" "$host" "$*" >>{str(ssh_log)!r}\n'
            f'PATH={real_path!r} exec bash -c "$*"\n'
        )
        (bin_dir / 'ssh').chmod(0o755)
        # Build a restricted local PATH WITHOUT zstd or xz to prove the storage host never invokes zstd/xz locally!
        no_comp_dir = self.tmp / 'nocomp'
        no_comp_dir.mkdir()
        for tool in ('bash', 'sh', 'tar', 'ln', 'mkdir', 'rm', 'mv', 'cp', 'cat', 'tee', 'awk', 'sed', 'grep', 'sha256sum',
                     'stat', 'du', 'df', 'dirname', 'basename', 'realpath', 'pwd', 'chmod', 'date', 'uname', 'tr',
                     'head', 'tail', 'wc', 'find', 'sort', 'cut', 'mountpoint', 'mktemp', 'mkfifo', 'nice', 'ionice', 'flock'):
            found = shutil.which(tool)
            if found:
                os.symlink(found, no_comp_dir / tool)
        os.symlink(bin_dir / 'ssh', no_comp_dir / 'ssh')

        plan = {
            'name': 'Same-host archive offloaded to beefybox',
            'tasks': [{'type': 'archive', 'host': ME, 'params': {
                'path': str(src), 'dest': str(arc), 'codec': 'zstd-ultra', 'verify': True, 'compress_host': 'beefybox',
            }}],
        }
        chk_meta = changes.check(self.conn, changes.normalize(plan))
        self.assertEqual(chk_meta['crit'], 0, chk_meta)
        self.assertTrue(any('CPU-offloaded compression' in it['text'] for it in chk_meta['tasks'][0]['items']))

        res = self._run_change_script(changes.script(self.conn, plan), '--apply', env_extra={'PATH': str(no_comp_dir)})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertTrue(arc.is_file())
        self.assertIn('root@10.0.0.99', ssh_log.read_text())
        # Verify the resulting archive decompresses cleanly and matches sha256
        want_sha = Path(f'{arc}.sha256').read_text().split()[0]
        self.assertEqual(want_sha, hashlib.sha256(arc.read_bytes()).hexdigest())
        dec = subprocess.run(['zstd', '-dc', '--long=31', str(arc)], capture_output=True, check=True)
        with tarfile.open(fileobj=io.BytesIO(dec.stdout), mode='r:') as tf:
            names = tf.getnames()
            self.assertIn('dataset/alpha.txt', names)

    def test_moves_sender_receiver_and_worker_compression_plus_wire_compress(self):
        # 1. Wire compression keeps existing plan_hash unchanged when unset
        base_plan = {'name': 'Wire check', 'steps': [{'method': 'copy', 'src': {'host': 'weaknas', 'path': '/data'}, 'dst': {'host': ME, 'path': '/dst'}}]}
        h_plain = jobs.plan_hash(base_plan)
        zstd_plan = {'name': 'Wire check', 'steps': [{'method': 'copy', 'src': {'host': 'weaknas', 'path': '/data'}, 'dst': {'host': ME, 'path': '/dst'}, 'options': {'compress': 'max'}}]}
        self.assertNotEqual(h_plain, jobs.plan_hash(zstd_plan))
        ms_wire = moves.script(self.conn, zstd_plan)
        self.assertIn('compress=max', ms_wire)
        self.assertIn('--compress-choice=zstd', ms_wire)

        # 2. Check package rules: weaknas lacks zstd!
        #    - sender compression (source=weaknas) flags missing zstd on weaknas
        #    - receiver compression (destination=ME) does NOT need zstd on weaknas!
        #    - worker compression (worker=beefybox) needs zstd ONLY on beefybox!
        p_sender = moves.normalize({'name': 'Sender', 'steps': [{'method': 'archive', 'src': {'host': 'weaknas', 'path': '/data'}, 'dst': {'host': ME, 'path': '/arc.tar.zst'}, 'options': {'compress_on': 'source'}}]})
        chk_sender = moves.check(self.conn, p_sender)
        self.assertTrue(any('weaknas' in it['text'] and 'zstd' in it['text'] and 'installed' in it['text'] for it in chk_sender['steps'][0]['items']))

        p_recv = moves.normalize({'name': 'Receiver', 'steps': [{'method': 'archive', 'src': {'host': 'weaknas', 'path': '/data'}, 'dst': {'host': ME, 'path': '/arc.tar.zst'}, 'options': {'compress_on': 'destination'}}]})
        chk_recv = moves.check(self.conn, p_recv)
        self.assertFalse(any('weaknas' in it['text'] and 'zstd' in it['text'] and 'installed' in it['text'] for it in chk_recv['steps'][0]['items']), chk_recv)

        p_worker = moves.normalize({'name': 'Worker', 'steps': [{'method': 'archive', 'src': {'host': 'weaknas', 'path': '/data'}, 'dst': {'host': 'weaknas', 'path': '/arc.tar.zst'}, 'options': {'compress_on': 'worker', 'compress_host': 'beefybox'}}]})
        chk_worker = moves.check(self.conn, p_worker)
        self.assertFalse(any('weaknas' in it['text'] and 'zstd' in it['text'] and 'installed' in it['text'] for it in chk_worker['steps'][0]['items']), chk_worker)
        self.assertTrue(any('beefybox' in it['text'] and 'zstd' in it['text'] for it in chk_worker['steps'][0]['items']), chk_worker)

    def test_jobscript_end_to_end_sender_receiver_and_remote_worker(self):
        src = _make_sample_tree(self.tmp)
        etc = self.tmp / 'etc'
        var = self.tmp / 'var'
        (etc / 'jobs').mkdir(parents=True)
        (etc / 'serve').mkdir(parents=True)
        var.mkdir(parents=True)
        jbin = self.tmp / 'storageforge-job'
        jbin.write_text(jobscript.JOB_SCRIPT.replace('export LC_ALL=C PATH=', 'export LC_ALL=C PATH="$PATH":'))
        jbin.chmod(0o755)

        # Mock ssh routes storageforge-deploy@10.0.0.21 -> --serve p1-s1 "<cmd>" and storageforge-deploy@10.0.0.99 -> --serve p1-s1-compress "<cmd>"
        mock_bin = self.tmp / 'jbin'
        mock_bin.mkdir()
        ssh_calls = self.tmp / 'job-ssh.log'
        (mock_bin / 'ssh').write_text(
            f'#!/bin/bash\n'
            f'while [[ $# -gt 0 ]]; do\n'
            f'  case $1 in -o|-p|-i) shift 2 ;; -*) shift ;; *) target=$1; shift; break ;; esac\n'
            f'done\n'
            f'printf "%s\\t%s\\n" "$target" "$*" >>{str(ssh_calls)!r}\n'
            f'if [[ $target == *10.0.0.99 ]]; then exec {str(jbin)!r} --serve p1-s1-compress "$*";\n'
            f'else exec {str(jbin)!r} --serve p1-s1 "$*"; fi\n'
        )
        (mock_bin / 'ssh').chmod(0o755)
        env = {
            **os.environ,
            'PATH': f'{mock_bin}:{os.environ["PATH"]}',
            'STORAGEFORGE_JOB_ETC': str(etc),
            'STORAGEFORGE_JOB_VAR': str(var),
        }

        # Deploy-generated configs for a 3-role job: source=weaknas, runner=ME, compressor=beefybox!
        plan = {
            'id': 1,
            'name': 'Remote worker archive',
            'steps': [{
                'id': 's1', 'method': 'archive',
                'src': {'host': 'weaknas', 'path': str(src)},
                'dst': {'host': ME, 'path': str(self.tmp / 'vault-out')},
                'options': {'archive_codec': 'xz-extreme', 'compress_on': 'worker', 'compress_host': 'beefybox'},
            }],
        }
        sp = jobs.specs(self.conn, plan)[0]
        self.assertEqual(sp['compressor'], 'beefybox')
        (etc / 'jobs' / 'p1-s1.conf').write_text(jobs.conf_text(sp, None))
        (etc / 'jobs' / 'p1-s1.key').write_text('dummy')
        (etc / 'jobs' / 'p1-s1.compress.key').write_text('dummy')
        (etc / 'serve' / 'p1-s1.conf').write_text(jobs.serve_text(sp))
        (etc / 'serve' / 'p1-s1-compress.conf').write_text(jobs.compress_serve_text(sp))

        # Security invariant: COMPRESS_ONLY=1 key must refuse filesystem commands!
        refused = subprocess.run([str(jbin), '--serve', 'p1-s1-compress', 'rsync --server --daemon .'], env=env, capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('no filesystem access', refused.stderr)

        # Test connectivity, dryrun, run, and verify!
        for subcmd in ('test', 'dryrun', 'run', 'verify'):
            r = subprocess.run([str(jbin), subcmd, 'p1-s1'], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, f'{subcmd} failed: {r.stdout}\n{r.stderr}')

        arc_out = Path(sp['dst'])
        self.assertTrue(arc_out.name.endswith('.tar.xz'))
        self.assertTrue(arc_out.is_file())
        self.assertTrue(Path(f'{arc_out}.sha256').is_file())
        calls_txt = ssh_calls.read_text()
        self.assertIn('storageforge-deploy@10.0.0.21\tarchive-raw', calls_txt)
        self.assertIn('storageforge-deploy@10.0.0.99\tcompress', calls_txt)

    @unittest.skipIf(dbfactory.PG, 'this drives a SQLite file through --db; the archive plans on PostgreSQL are covered by the other tests here')
    def test_cli_archive_subcommands(self):
        parser = cli.build_parser()
        # Same-host with --compress-host creates a Moves plan with worker offload
        a1 = parser.parse_args(['--db', str(self.tmp / 'index.db'), 'archive', 'create', 'weaknas:/srv/cold', '--compress-host', 'beefybox'])
        self.assertEqual(a1.fn(a1), 0)
        mplans = moves.list_plans(self.conn)
        self.assertEqual(len(mplans), 1)
        mp = moves.get_plan(self.conn, mplans[0]['id'])
        self.assertEqual(mp['steps'][0]['options']['compress_on'], 'worker')
        self.assertEqual(mp['steps'][0]['options']['compress_host'], 'beefybox')

        # Cross-host with --compress-on destination spares weaknas CPU
        a2 = parser.parse_args(['--db', str(self.tmp / 'index.db'), 'archive', 'create', 'weaknas:/srv/cold', f'{ME}:/srv/backups', '--compress-on', 'destination'])
        self.assertEqual(a2.fn(a2), 0)
        mp2 = moves.get_plan(self.conn, max(p['id'] for p in moves.list_plans(self.conn)))
        self.assertEqual(mp2['steps'][0]['options']['compress_on'], 'destination')

        # Extract subcommand saves a change plan
        a3 = parser.parse_args(['--db', str(self.tmp / 'index.db'), 'archive', 'extract', f'{ME}:/srv/backups/cold.tar.zst', '/srv/restored'])
        # /srv/backups/cold.tar.zst is not in index so check reports crit (1), plan is still saved
        self.assertIn(a3.fn(a3), (0, 1))
        cplans = changes.list_plans(self.conn)
        self.assertEqual(len(cplans), 1)


if __name__ == '__main__':
    unittest.main()
