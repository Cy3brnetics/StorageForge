"""Restore tests (steps_restoretest.py) run through Bash: the latest snapshot restored into a scratch folder and the SHA-256 of every
unchanged file compared with the source, for real (sha256sum on real files). The backup programs are stand-ins that restore what they are
told to, or a damaged copy, or fail, since restic and Borg are not installed here; with restic installed, a real repository is made,
backed up, restored and compared too, and then damaged. The key is read from a file and never seen on a command line, the scratch folder
is removed after each run, the result line is what the adapter of restic and Borg shows, and a scheduled test writes a script that runs
on its own."""
import os
import shutil
import subprocess
import time
import unittest
from pathlib import Path

try:
    import test_toolbox_steps as tts
except ImportError:      # run as tests.test_x from the project folder
    from tests import test_toolbox_steps as tts
from storageforge_index import changes, steps_restoretest, steps_runtime, steps_toolbox, steps_workloads, tbadapters_c, toolbox

RESTIC = r'''key=${RESTIC_PASSWORD_FILE:-}; [[ -r $key && $(cat "$key") == "s3cret-key" ]] || { echo "wrong password" >&2; exit 1; }
case $1 in
  snapshots) printf "[{\"time\":\"%s\",\"paths\":[\"/x\"]}]\n" "$SNAPTIME" ;;
  restore) t= p=; while (($#)); do case $1 in --target) t=$2; shift ;; --path) p=$2; shift ;; esac; shift; done
    [[ ${FAILRESTORE:-} == 1 ]] && { echo "Fatal: pack 3f2a: ciphertext verification failed" >&2; exit 1; }
    mkdir -p "$t$p"; cp -a "$p/." "$t$p/"
    [[ -n ${DAMAGE:-} ]] && printf "flipped" >"$t$p/$DAMAGE"
    [[ -n ${DROP:-} ]] && rm -f "$t$p/$DROP"
    rm -f "$t$p/after.txt" ;;
esac'''
BORG = r'''[[ $BORG_PASSCOMMAND == "cat "* ]] && [[ $(${BORG_PASSCOMMAND}) == "s3cret-key" ]] || { echo "passphrase supplied is incorrect" >&2; exit 1; }
case $1 in
  list) printf "host-2026-11-20\t%s\n" "$SNAPTIME" ;;
  extract) src=/${3}; mkdir -p "./$3"; cp -a "$src/." "./$3/"; rm -f "./$3/after.txt" ;;
esac'''


class RestoreTest(tts.Steps):
    def setUp(self):
        super().setUp()
        for name in ('shuf', 'find', 'date', 'base64', 'tail', 'xargs'):
            if shutil.which(name) and not (self.real / name).exists():
                (self.real / name).symlink_to(shutil.which(name))
        for name, body in (('restic', RESTIC), ('borg', BORG)):
            (self.bin / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
            (self.bin / name).chmod(0o755)
        self.paths[steps_restoretest.RT_LIB] = str(self.root / 'usr/local/lib/storageforge')
        self.src = self.root / 'srv/photos'
        (self.src / 'album').mkdir(parents=True)
        for i in range(12):
            (self.src / 'album' / f'p{i}.jpg').write_bytes(os.urandom(2048) + bytes([i]))
        (self.src / 'notes.txt').write_text('first\n')
        old = time.time() - 3600
        for p in self.src.rglob('*'):
            os.utime(p, (old, old))
        self.snaptime = time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(time.time() - 60))
        (self.src / 'after.txt').write_text('written after the snapshot\n')       # newer than the snapshot: not compared
        self.secrets = self.tmp / 'secrets'
        self.secrets.mkdir()
        (self.secrets / 'restic-photos').write_text('s3cret-key')
        self.scratch = self.root / 'srv/restore-test'
        self.rtdir = self.tmp / 'home/restore-tests'

    def bash(self):
        text = steps_runtime.BASH + steps_workloads.BASH + steps_toolbox.BASH + steps_restoretest.BASH
        for a, b in self.paths.items():
            text = text.replace(a, b)
        return text

    def run_rt(self, apply, tool='restic', schedule='none', name='photos', **env):
        words = [name, tool, str(self.root / 'srv/backup/repo'), 'restic-photos', str(self.src), str(self.scratch), '100', schedule]
        call = 't_restore_test ' + ' '.join(f"'{w}'" for w in words)
        e = {'PATH': f'{self.bin}:{self.real}', 'FAKE': str(self.fake), 'LOG': str(self.fake / 'log'), 'HOME': str(self.tmp), 'SF_SECRET_DIR': str(self.secrets),
             'SNAPTIME': self.snaptime if tool == 'restic' else time.strftime('%a, %Y-%m-%d %H:%M:%S', time.localtime(time.time() - 60)), **env}
        p = subprocess.run([str(self.real / 'bash'), '-c', tts.HARNESS + f'APPLY={int(apply)}\n' + self.bash() + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                           capture_output=True, text=True, timeout=60, env=e)
        return p.stdout + p.stderr

    def last(self, name='photos'):
        return (self.rtdir / f'{name}.last').read_text().rstrip('\n').split('\t')

    def test_a_report_restores_nothing(self):
        out = self.run_rt(False)
        self.assertIn('would: restore the latest snapshot', out)
        self.assertFalse(self.scratch.exists())
        self.assertNotIn('restore', self.log())

    def test_a_good_restore_matches_by_sha256_and_leaves_no_scratch(self):
        out = self.run_rt(True)
        self.assertIn('ok: restore test photos: 13 files compared, their SHA-256 match', out)
        f = self.last()
        self.assertEqual(f[1:7], ['photos', 'restic', 'ok', '13', '0', '0'])
        self.assertEqual(list(self.scratch.iterdir()), [], 'the scratch folder of the run is removed')
        key = self.rtdir / 'photos.key'
        self.assertEqual(key.read_text(), 's3cret-key')
        self.assertEqual(oct(key.stat().st_mode & 0o777), '0o600')
        self.assertNotIn('s3cret-key', self.log(), 'the key is on no command line')
        self.assertNotIn('s3cret-key', out)

    def test_a_damaged_file_fails_the_test_loudly(self):
        out = self.run_rt(True, DAMAGE='album/p3.jpg')
        self.assertIn('conflict: restore test photos FAILED: 1 of 13 files differ', out)
        self.assertIn('album/p3.jpg', out)
        f = self.last()
        self.assertEqual((f[3], f[5]), ('failed', '1'))
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_a_failed_restore_fails_and_a_missing_file_is_counted_apart(self):
        out = self.run_rt(True, FAILRESTORE='1')
        self.assertIn('FAILED: the restore failed (exit 1): Fatal: pack 3f2a: ciphertext verification failed', out)
        out = self.run_rt(True, DROP='notes.txt')
        self.assertIn('12 files compared, their SHA-256 match; 1 older files are not in the backup', out)

    def test_a_wrong_key_fails(self):
        (self.secrets / 'restic-photos').write_text('another key')
        out = self.run_rt(True)
        self.assertIn('FAILED: no snapshot of', out)

    def test_borg_too(self):
        out = self.run_rt(True, tool='borg')
        self.assertIn('ok: restore test photos: 13 files compared', out)
        self.assertIn('borg extract ::host-2026-11-20', self.log())

    def test_a_scheduled_test_writes_a_script_that_runs_alone(self):
        out = self.run_rt(True, schedule='weekly')
        self.assertIn('restore test photos runs weekly', out)
        timer = (self.root / 'etc/systemd/system/sf-restore-test-photos.timer').read_text()
        self.assertIn('OnCalendar=weekly', timer)
        script = self.root / 'usr/local/lib/storageforge/restore-test-photos.sh'
        self.assertIn('ExecStart=' + str(script), (self.root / 'etc/systemd/system/sf-restore-test-photos.service').read_text())
        (self.rtdir / 'photos.last').unlink()
        e = {'PATH': f'{self.bin}:{self.real}', 'LOG': str(self.fake / 'log'), 'SNAPTIME': self.snaptime, 'DAMAGE': 'album/p1.jpg'}
        p = subprocess.run([str(self.real / 'bash'), str(script)], capture_output=True, text=True, timeout=60, env=e)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('FAILED: 1 of 13 files differ', p.stdout)
        self.assertEqual(self.last()[3], 'failed')
        self.assertIn('systemctl enable --now sf-restore-test-photos.timer', self.log())
        out = self.run_rt(True, schedule='none')
        self.assertFalse((self.root / 'etc/systemd/system/sf-restore-test-photos.timer').exists())

    def test_the_adapter_shows_the_last_verified_restore(self):
        self.run_rt(True)
        self.run_rt(True, name='docs', DAMAGE='notes.txt')
        lines = ['r\t' + (self.rtdir / f'{n}.last').read_text().rstrip('\n') for n in ('photos', 'docs')]
        reading = {'toolbox': {'c': {**tbadapters_c.read_c(lines + ['v\trestic\trestic 0.18.1 compiled with go1.24'])}}}
        a = tbadapters_c.ADAPTERS[0]
        found = a.detect(reading, {})
        self.assertEqual(found['version'], 'restic 0.18.1 compiled with go1.24')
        st = a.status(reading, {}, found)
        self.assertEqual(st['health'], 'down')
        tiles = {t['label']: t for t in st['tiles']}
        self.assertEqual(tiles['Restore test photos']['level'], 'ok')
        self.assertIn('FAILED', tiles['Restore test docs']['value'])
        tasks = a.tasks('restore-test', {'name': 'photos', 'repo': '/srv/backup/repo', 'secret': 'restic-photos', 'source': '/srv/photos', 'scratch': '/srv/restore-test'}, 'box', reading)
        self.assertEqual(tasks[0]['type'], 'restore-test')
        self.assertEqual(tasks[0]['params']['schedule'], 'none')

    def test_the_check_refuses_a_scratch_folder_that_is_not_its_own(self):
        def says(**p):
            got = []
            base = {'name': 'photos', 'tool': 'restic', 'repo': '/srv/backup/repo', 'secret': 'k', 'source': '/srv/photos', 'scratch': '/srv/restore-test', 'schedule': 'none'}
            steps_restoretest._check(self.conn, None, {'name': 'box'}, base | p, lambda level, text: got.append((level, text)))
            return ' '.join(t for lv, t in got if lv == 'crit')
        self.assertEqual(says(), '')
        self.assertIn('inside the folder it is compared with', says(scratch='/srv/photos/tmp'))
        self.assertIn('system folder', says(scratch='/etc/restore'))
        self.assertIn('repository', says(repo='-o x'))
        plan = changes.normalize({'name': 'r', 'tasks': [{'host': 'box', 'type': 'restore-test', 'params': {
            'name': 'photos', 'tool': 'restic', 'repo': '/srv/backup/repo', 'secret': 'restic-photos', 'source': '/srv/photos', 'scratch': '/srv/restore-test',
            'sample': '50', 'schedule': 'weekly'}}]})
        text = changes.script(self.conn, plan)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True).returncode, 0)
        from storageforge_index import secretstore
        self.assertEqual(secretstore.plan_secrets(self.conn, plan), {'box': [('restic-photos', 'restore-test')]}, 'the key is brought with the apply')


@unittest.skipUnless(shutil.which('restic'), 'restic is not installed here')
class RealRestic(RestoreTest):
    """With the real restic: a repository made, backed up, restored and compared, then a pack damaged on disk."""
    def setUp(self):
        super().setUp()
        (self.bin / 'restic').unlink()
        (self.real / 'restic').symlink_to(shutil.which('restic'))

    def test_real_backup_restore_and_damage(self):
        repo = self.root / 'srv/backup/repo'
        env = dict(os.environ, RESTIC_REPOSITORY=str(repo), RESTIC_PASSWORD_FILE=str(self.secrets / 'restic-photos'))
        (self.secrets / 'restic-photos').write_text('s3cret-key')
        (self.src / 'after.txt').unlink()
        subprocess.run(['restic', 'init', '-q'], env=env, check=True, capture_output=True)
        subprocess.run(['restic', 'backup', '-q', str(self.src)], env=env, check=True, capture_output=True)
        out = self.run_rt(True)
        self.assertIn('13 files compared, their SHA-256 match', out)
        for pack in (repo / 'data').rglob('*'):
            if pack.is_file():
                data = bytearray(pack.read_bytes())
                data[len(data) // 2] ^= 0xFF
                pack.chmod(0o600)
                pack.write_bytes(bytes(data))
        out = self.run_rt(True)
        self.assertIn('FAILED', out)


for _n in [n for n in dir(tts.Steps) if n.startswith('test_')]:
    setattr(RestoreTest, _n, None)          # the harness of test_toolbox_steps, without running its tests again here
for _n in [n for n in vars(RestoreTest) if n.startswith('test_')]:
    setattr(RealRestic, _n, None)           # the stand-in tests stay with the stand-ins


if __name__ == '__main__':
    unittest.main()
