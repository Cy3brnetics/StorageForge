"""ClamAV on hosts: the generated scripts against stand-ins, reading results back, alerts, quarantine and restore.
Run with: python3 -m unittest discover -s tests -v"""
import base64
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import alerts, clamav, deploy, jobs

SIG = 'Win.Test.EICAR_HDB-1'


def report(found=(), rc=1, scanned=100, run=None, end=None, version='ClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026'):
    end = end or int(time.time())
    lines = [f'run\t{run or uuid.uuid4()}\t{end - 5}\t{end}\t{rc}\t{scanned}\t{version}']
    lines += [f'found\t{base64.b64encode(p.encode()).decode()}\t{s}' for p, s in found]
    return '\n'.join(lines)


class Results(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname) VALUES ('nas')")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def states(self):
        return {d['path']: d['state'] for d in clamav.detections(self.conn, 'nas', True)}

    def test_a_finished_run_closes_what_it_no_longer_reports_and_a_broken_one_does_not(self):
        self.assertTrue(clamav.ingest(self.conn, 'nas', report([('/srv/a', SIG), ('/srv/b', SIG)])))
        self.assertEqual(self.states(), {'/srv/a': 'open', '/srv/b': 'open'})
        for broken in (report(rc=137, scanned=0), report(rc=2, scanned=50), report(rc=0, scanned=0)):
            clamav.ingest(self.conn, 'nas', broken)
            self.assertEqual(self.states(), {'/srv/a': 'open', '/srv/b': 'open'})
        clamav.ingest(self.conn, 'nas', report([('/srv/a', SIG)]))
        self.assertEqual(self.states(), {'/srv/a': 'open', '/srv/b': 'gone'})
        clamav.ingest(self.conn, 'nas', report([('/srv/a', SIG), ('/srv/b', SIG)]))
        self.assertEqual(self.states()['/srv/b'], 'open')

    def test_the_same_run_counts_once_and_bad_reports_are_refused(self):
        rid = str(uuid.uuid4())
        self.assertTrue(clamav.ingest(self.conn, 'nas', report(run=rid)))
        self.assertFalse(clamav.ingest(self.conn, 'nas', report(run=rid)))
        self.assertFalse(clamav.ingest(self.conn, 'nas', 'nonsense'))
        self.assertFalse(clamav.ingest(self.conn, 'nas', report(end=int(time.time()) + 100000)))     # dated ahead

    def test_hostile_lines_are_dropped(self):
        bad = report([('relative/path', SIG), ('/ok', 'bad sig;$(x)')]) + '\nfound\t!!!\tSig\nfound\tonly-two'
        clamav.ingest(self.conn, 'nas', bad)
        self.assertEqual(self.states(), {})

    def test_alerts_group_by_signature_and_stay_quiet_when_ignored(self):
        clamav.ingest(self.conn, 'nas', report([('/srv/a', SIG), ('/srv/b', SIG)]))
        key = f'clamav:nas:{SIG}'
        self.assertEqual(list(clamav.problems(self.conn)), [key])
        self.assertIn(key, alerts.problems(self.conn))
        self.assertIn('/srv/b', clamav.problems(self.conn)[key][3])
        for d in clamav.detections(self.conn, 'nas'):
            clamav.set_ignored(self.conn, d['id'], True, 'ours', 'me')
        self.assertEqual(clamav.problems(self.conn), {})
        clamav.ingest(self.conn, 'nas', report([('/srv/a', SIG)]))      # still ignored when seen again
        self.assertEqual(clamav.problems(self.conn), {})

    def test_failed_stale_and_old_signature_alerts(self):
        now = int(time.time())
        deploy.mark_deployed(self.conn, 'nas', 'clamav', 'clamav', 'x', {'schedule': 'weekly'}, 'me')
        clamav.ingest(self.conn, 'nas', report(rc=137, scanned=0, end=now, version='ClamAV 1.0.7/27000/Sat Jan  3 08:30:00 2026'))
        p = clamav.problems(self.conn, now)
        self.assertIn('clamav-failed:nas', p)
        self.assertIn('clamav-signatures:nas', p)
        self.assertNotIn('clamav-stale:nas', p)
        self.assertIn('clamav-stale:nas', clamav.problems(self.conn, now + 2 * jobs.period('weekly') + 86401))

    def test_config_refuses_bad_values_and_defaults_to_indexed_mounts(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:i, '/srv', 'ext4', 'indexed')", {'i': hid})
        self.assertEqual(clamav.get_config(self.conn, 'nas')['paths'], ['/srv'])
        for bad in ({'schedule': 'hourly; rm'}, {'paths': ['relative']}, {'paths': ['/a/../b']}, {'paths': ['/a\nb']}):
            with self.assertRaises(ValueError):
                clamav.save_config(self.conn, 'nas', bad, 'me')
        self.assertEqual(clamav.save_config(self.conn, 'nas', {'schedule': 'daily', 'paths': ['/x']}, 'me')['paths'], ['/x'])

    def test_deploy_items_follow_the_mode(self):
        deploy_args = lambda **k: clamav.deploy_items(self.db, self.conn, 'nas', k.pop('mode', 'apply'), 'me', **k)[0]['args']   # noqa: E731
        self.assertEqual(deploy_args(mode='report'), [])
        self.assertEqual(deploy_args(), ['--apply'])
        self.assertEqual(deploy_args(remove=True), ['--uninstall'])
        self.assertEqual(deploy_args(run_now=True), ['--run'])
        with self.assertRaises(ValueError):
            clamav.deploy_items(self.db, self.conn, 'unknown', 'report', 'me')


class Scripts(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        self.bin = self.t / 'bin'
        self.bin.mkdir()
        self.log = self.t / 'calls'
        self.stub('systemctl', 'echo "systemctl $*" >>"$STUB_LOG"; [ "$1" != cat ] && [ "$1" != is-active ]')
        for name in ('useradd', 'chown', 'freshclam'):
            self.stub(name, f'echo "{name} $*" >>"$STUB_LOG"')
        self.data = self.t / 'data'
        self.data.mkdir()

    def tearDown(self):
        shutil.rmtree(self.t)

    def stub(self, name, body):
        f = self.bin / name
        f.write_text(f'#!/bin/bash\n{body}\n')
        f.chmod(0o755)

    def localize(self, text):
        for old, new in (('/var/lib/storageforge', self.t / 'var'), ('/etc/systemd/system', self.t / 'units'), ('/etc/storageforge', self.t / 'etc'),
                         ('/usr/local/sbin', self.t / 'sbin')):
            text = text.replace(old, str(new))
        return text

    def run_script(self, text, *args):
        sh = self.t / 's.sh'
        sh.write_text(self.localize(text))
        return subprocess.run(['bash', str(sh), *args], capture_output=True, text=True, timeout=60, cwd=self.t,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_LOG': str(self.log)})

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def clam(self, rc):
        self.stub('clamscan', f'[ "$1" = --version ] && {{ echo "ClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026"; exit 0; }}\nexit {rc}')

    def test_no_flags_changes_nothing(self):
        self.clam(0)
        r = self.run_script(clamav.install_script({'schedule': 'weekly', 'paths': ['/srv']}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('--apply installs it', r.stdout)
        self.assertFalse((self.t / 'sbin').exists())
        self.assertNotIn('enable', self.calls())
        self.assertFalse((self.t / 'var').exists())

    def install(self):
        for d in ('sbin', 'units', 'etc'):
            (self.t / d).mkdir(exist_ok=True)
        r = self.run_script(clamav.install_script({'schedule': 'weekly', 'paths': [str(self.data)]}), '--apply')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_apply_installs_a_locked_down_scan_and_removing_keeps_quarantine(self):
        self.clam(0)
        self.install()
        self.install()                                      # reruns are safe
        service = (self.t / 'units/sf-clamav.service').read_text()
        for line in ('User=storageforge-clamav', 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH', 'NoNewPrivileges=yes', 'PrivateNetwork=yes', 'ProtectSystem=strict'):
            self.assertIn(line, service)
        self.assertIn('enable --now sf-clamav.timer', self.calls())
        sums = subprocess.run(['sha256sum', '-c', str(self.t / 'var/managed/clamav.sha256')], capture_output=True, text=True)
        self.assertEqual(sums.returncode, 0, sums.stdout)
        (self.t / 'var/quarantine/x').mkdir(parents=True)
        r = self.run_script(clamav.install_script({'schedule': 'weekly', 'paths': ['/srv']}), '--uninstall')
        self.assertIn('1 file(s) stay in quarantine', r.stdout)
        self.assertFalse((self.t / 'units/sf-clamav.timer').exists())
        self.assertTrue((self.t / 'var/quarantine/x').exists())

    def scan_with(self, output, rc):
        (self.t / 'out.txt').write_text(output)
        self.stub('clamscan', f'[ "$1" = --version ] && {{ echo "ClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026"; exit 0; }}\ncat {self.t}/out.txt\nexit {rc}')
        r = subprocess.run([str(self.t / 'sbin/storageforge-clamscan')], capture_output=True, text=True, timeout=30,
                           env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}'})
        self.assertEqual(r.returncode, 0, r.stderr)
        return clamav.parse_report((self.t / 'var/clamav/last.tsv').read_text())

    def test_the_scan_writes_a_report_ingest_can_read(self):
        self.clam(0)
        self.install()
        run, found = self.scan_with(f'/srv/a b: c.exe: {SIG} FOUND\nnoise\n/srv/ok\n\n----------- SCAN SUMMARY -----------\nScanned files: 42\n', 1)
        self.assertEqual((run['rc'], run['scanned'], run['version']), (1, 42, 'ClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026'))
        self.assertEqual([(p, s) for _, p, s in found], [('/srv/a b: c.exe', SIG)])
        run, found = self.scan_with('', 137)
        self.assertEqual((run['rc'], run['scanned'], found), (137, 0, []))

    def detection(self, name='bad file'):
        f = self.data / name
        f.write_text('x')
        f.chmod(0o640)
        return f, {'b64': base64.b64encode(str(f).encode()).decode(), 'signature': SIG, 'qid': 'a' * 32}

    def test_quarantine_and_restore(self):
        self.clam(1)
        f, d = self.detection()
        r = self.run_script(clamav.quarantine_script(d, 'a' * 32))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(f.exists(), 'no flags: nothing moved')
        self.assertNotIn('QUARANTINED', r.stdout)
        r = self.run_script(clamav.quarantine_script(d, 'a' * 32), '--apply')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r'QUARANTINED a{32} [0-9a-f]{64}')
        q = self.t / 'var/quarantine' / ('a' * 32)
        self.assertFalse(f.exists())
        self.assertEqual((q / 'file').stat().st_mode & 0o777, 0)
        self.assertEqual(q.stat().st_mode & 0o777, 0o700)
        again = self.run_script(clamav.quarantine_script(d, 'a' * 32), '--apply')          # a rerun reports the same
        self.assertIn('QUARANTINED', again.stdout)
        r = self.run_script(clamav.restore_script(d))
        self.assertFalse(f.exists(), 'no flags: nothing moved')
        f.write_text('new')                                 # never overwrites
        r = self.run_script(clamav.restore_script(d), '--apply')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(f.read_text(), 'new')
        f.unlink()
        r = self.run_script(clamav.restore_script(d), '--apply')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('RESTORED', r.stdout)
        self.assertEqual((f.read_text(), f.stat().st_mode & 0o777), ('x', 0o640))
        self.assertFalse(q.exists())

    def test_quarantine_refuses_what_clamav_does_not_confirm(self):
        f, d = self.detection()
        for rc, says in ((0, 'no longer detects'), (2, 'could not check')):
            self.clam(rc)
            r = self.run_script(clamav.quarantine_script(d, 'a' * 32), '--apply')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(says, r.stdout)
            self.assertTrue(f.exists())

    def test_quarantine_refuses_symlinks_and_system_paths(self):
        self.clam(1)
        f, d = self.detection()
        link = self.data / 'link'
        link.symlink_to(f)
        as_link = {**d, 'b64': base64.b64encode(str(link).encode()).decode()}
        self.assertNotEqual(self.run_script(clamav.quarantine_script(as_link, 'a' * 32), '--apply').returncode, 0)
        self.assertTrue(f.exists())
        system = {**d, 'b64': base64.b64encode(b'/etc/passwd').decode()}
        r = self.run_script(clamav.quarantine_script(system, 'a' * 32), '--apply')
        self.assertIn('system path', r.stdout)
        self.assertNotEqual(r.returncode, 0)

    def test_a_hostile_path_stays_data(self):
        self.clam(1)
        canary = self.t / 'CANARY'
        f, d = self.detection('$(touch CANARY)`touch CANARY`;"q')
        self.assertEqual(self.run_script(clamav.quarantine_script(d, 'a' * 32), '--apply').returncode, 0)
        self.assertFalse(f.exists())
        self.assertFalse(canary.exists())
        self.assertEqual(self.run_script(clamav.restore_script(d), '--apply').returncode, 0)
        self.assertTrue(f.exists())
        self.assertFalse(canary.exists())


if __name__ == '__main__':
    unittest.main()
