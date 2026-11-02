"""System updates: the script against stand-in package managers, and how a fleet of hosts goes through the engine.
Run with: python3 -m unittest discover -s tests -v"""
import json
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:
    from tests import dbfactory
from storageforge_index import deploy, engine, preflight, updates

TOOLS = ('awk', 'bash', 'cat', 'df', 'grep', 'head', 'id', 'ls', 'mktemp', 'printf', 'rm', 'sed', 'setsid', 'sleep', 'sort', 'tail', 'tr', 'uname')


class Script(unittest.TestCase):
    def setUp(self):
        self.bin = Path(tempfile.mkdtemp(prefix='sf-updates-'))
        self.addCleanup(shutil.rmtree, self.bin, True)
        for tool in TOOLS:       # nothing else on PATH: the machine running the tests may have a package manager of its own
            (self.bin / tool).symlink_to(shutil.which(tool))

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f'#!/bin/bash\necho "{name} $*" >>"{self.bin}/calls"\n{body}\n')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def calls(self):
        path = self.bin / 'calls'
        return path.read_text() if path.exists() else ''

    def run_it(self, *args):
        return subprocess.run(['bash', '-c', updates.SCRIPT, 'updates', *args], capture_output=True, text=True, timeout=60,
                              env={'PATH': str(self.bin), 'SF_DONE': str(self.bin / 'done')})

    def apt(self, simulate='[ -e "$SF_DONE" ] || echo "Inst openssl [3.0] (3.1 Debian)"'):
        self.stub('apt-get', f"""case " $* " in
  *" update "*) ;;
  *" -s "*) {simulate} ;;
  *) echo unpacking; touch "$SF_DONE" ;;
esac""")
        self.stub('dpkg', ':')
        self.stub('touch', 'for f; do : >"$f"; done')

    def test_a_report_changes_nothing(self):
        self.apt()
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('1 update(s) with apt-get', p.stdout)
        self.assertIn('openssl', p.stdout)
        self.assertEqual(updates.parse(p.stdout)['pending'], 1)
        self.assertNotIn('--force-confold', self.calls())
        self.assertFalse((self.bin / 'done').exists())

    def test_apply_installs_keeps_config_files_and_ends_with_nothing_left(self):
        self.apt()
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('unpacking', p.stdout)       # the package manager's own lines reach the run's output
        self.assertIn('--force-confold', self.calls())
        self.assertIn('upgrade --with-new-pkgs', self.calls())
        self.assertNotIn('dist-upgrade', self.calls())
        got = updates.parse(p.stdout)
        self.assertEqual((got['manager'], got['pending']), ('apt-get', 0))

    def test_apply_with_nothing_to_do_runs_no_upgrade(self):
        self.apt(simulate=':')
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('already up to date', p.stdout)
        self.assertNotIn('-y', self.calls())

    def test_a_failed_upgrade_fails_the_run_and_says_so(self):
        self.apt()
        self.stub('apt-get', """case " $* " in
  *" update "*) ;;
  *" -s "*) echo "Inst openssl [3.0] (3.1 Debian)" ;;
  *) echo "E: dpkg was interrupted"; exit 100 ;;
esac""")
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 1)
        self.assertIn('E: dpkg was interrupted', p.stdout)
        self.assertIn('stopped with an error', p.stdout)
        self.assertEqual(updates.parse(p.stdout)['pending'], 1)

    def test_lists_that_cannot_refresh_stop_before_anything_changes(self):
        self.stub('apt-get', 'echo "E: 401 Unauthorized"; exit 100')
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 1)
        self.assertIn('401 Unauthorized', p.stdout)
        self.assertNotIn('-y', self.calls())

    def test_what_is_held_back_leaves_the_run_incomplete(self):
        self.apt(simulate='echo "Inst linux [1] (2 Debian)"')
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(deploy.run_status(0, 'apply', p.stdout), 'incomplete')

    def test_dnf_counts_exit_100_as_updates(self):
        self.stub('dnf', """case " $* " in
  *check-update*) [ -e "$SF_DONE" ] && exit 0; echo "kernel.x86_64 6.1 baseos"; echo "curl.x86_64 8.0 baseos"; exit 100 ;;
  *) : >"$SF_DONE" ;;
esac""")
        report = self.run_it()
        self.assertEqual(updates.parse(report.stdout)['pending'], 2, report.stdout + report.stderr)
        applied = self.run_it('--apply')
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn('dnf -y upgrade', self.calls())
        self.assertEqual(updates.parse(applied.stdout)['pending'], 0)

    def test_zypper_exit_codes_that_mean_it_worked(self):
        self.stub('zypper', """case " $* " in
  *needs-rebooting*) exit 102 ;;
  *refresh*) ;;
  *list-updates*) [ -e "$SF_DONE" ] || echo "v | repo | curl | 1 | 2 | x86_64" ;;
  *) : >"$SF_DONE"; exit 102 ;;
esac""")
        self.assertEqual(updates.parse(self.run_it().stdout)['pending'], 1)
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        got = updates.parse(p.stdout)
        self.assertEqual(got['pending'], 0)
        self.assertTrue(got['reboot'])

    def test_a_pacman_report_never_refreshes_its_lists(self):      # -Sy without -u is a partial upgrade
        self.stub('pacman', ': >"$SF_DONE"')
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.calls(), '')
        self.assertIn('pacman-contrib', p.stdout)
        self.assertIsNone(updates.parse(p.stdout)['pending'])
        self.stub('checkupdates', 'echo "linux 6.1-1 -> 6.2-1"')
        self.assertEqual(updates.parse(self.run_it().stdout)['pending'], 1)
        self.assertNotIn('pacman', self.calls())

    def test_pacman_applies_a_full_upgrade(self):
        self.stub('pacman', ':')
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('pacman -Syu --noconfirm', self.calls())
        self.assertEqual(updates.parse(p.stdout)['pending'], 0)

    def test_losing_the_connection_leaves_the_package_manager_running(self):
        self.apt()
        self.stub('apt-get', """case " $* " in
  *" update "*) ;;
  *" -s "*) [ -e "$SF_DONE" ] || echo "Inst openssl [3.0] (3.1 Debian)" ;;
  *) echo unpacking; sleep 1.5; : >"$SF_DONE" ;;
esac""")
        p = subprocess.Popen(['bash', '-c', updates.SCRIPT, 'updates', '--apply'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             env={'PATH': str(self.bin), 'SF_DONE': str(self.bin / 'done')})
        self.addCleanup(p.wait)
        for line in p.stdout:
            if 'unpacking' in line:
                break
        self.assertFalse((self.bin / 'done').exists())
        p.kill()                # as a force stop, or the network going away
        p.stdout.close()
        for _ in range(100):
            if (self.bin / 'done').exists():
                break
            time.sleep(0.05)
        self.assertTrue((self.bin / 'done').exists(), 'the upgrade died with the connection')

    def test_no_package_manager(self):
        p = self.run_it('--apply')
        self.assertEqual(p.returncode, 1)
        self.assertIn('no package manager', p.stdout)

    def test_refuses_an_appliance(self):
        self.assertTrue(updates.SCRIPT.startswith(updates.REFUSE_APPLIANCE))


class Fleet(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-updates-db-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def host(self, name, state='ready', facts=None):
        now = int(time.time())
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port) VALUES (:h, :h, 'scan', 22)", {'h': name})
        self.conn.execute('INSERT INTO deploy_access (host, state, updated_at) VALUES (:h, :s, :t)', {'h': name, 's': state, 't': now})
        if facts:
            preflight.save(self.conn, name, 'probe', facts, [], 'test')

    def test_all_means_the_ready_hosts_that_can_take_it(self):
        self.host('debian')
        self.host('openrc', facts={'init': 'other'})      # updates need no systemd
        self.host('truenas', facts={'platform': 'truenas 25.10'})
        self.host('new', state='none')
        items = updates.deploy_items(self.conn, 'all', 'apply')
        self.assertEqual(sorted(i['host'] for i in items), ['debian', 'openrc'])
        self.assertTrue(all(i['args'] == ['--apply'] and i['phase'] == 0 and i['mode'] == 'apply' for i in items))
        self.assertTrue(all(i['args'] == [] for i in updates.deploy_items(self.conn, 'all', 'report')))

    def test_one_host_keeps_its_name_and_a_bad_one_is_refused(self):
        self.host('debian')
        self.assertEqual([i['host'] for i in updates.deploy_items(self.conn, 'DEBIAN', 'report')], ['debian'])
        with self.assertRaises(ValueError):
            updates.deploy_items(self.conn, '-oProxyCommand=x', 'report')

    def test_one_host_failing_stops_none_of_the_others(self):
        for h in ('a', 'b', 'c', 'd', 'e', 'f'):
            self.host(h)
        seen = []

        def fake_run(db, host, script, args=(), **kw):
            seen.append(host)
            status = 'failed' if host == 'a' else 'ok'
            conn = db.connect()
            conn.execute('UPDATE deploy_runs SET status = :s, finished_at = 1 WHERE run_id = :r', {'s': status, 'r': kw['run_id']})
            conn.close()
            return {'status': status}
        items = updates.deploy_items(self.conn, 'all', 'apply')
        rescanned = []
        with mock.patch.object(deploy, 'run', fake_run):
            gid = engine.start(self.db, items, 'test', after=rescanned.append, kind='updates', ref='all', mode='apply',
                               **updates.group_options('updates', 'apply'))
            for _ in range(200):
                if not engine.running(gid):
                    break
                time.sleep(0.02)
        self.assertEqual(sorted(seen), ['a', 'b', 'c', 'd', 'e', 'f'])
        self.assertEqual(sorted(rescanned), ['a', 'b', 'c', 'd', 'e', 'f'])
        self.assertEqual(engine.get(self.conn, gid)['state'], 'failed')
        self.assertEqual(engine.unfinished_hosts(self.conn, gid), ['a'])

    def test_other_deploys_still_stop_at_the_first_failure(self):
        self.assertEqual(updates.group_options('changes', 'apply'), {'stop_on_failure': True})
        self.assertEqual(updates.group_options('changes', 'report'), {'stop_on_failure': False})

    def test_overview_reads_the_last_run_of_each_host(self):
        self.host('fresh')
        self.host('old')
        self.host('truenas', facts={'platform': 'truenas 25.10'})
        self.host('new', state='none')
        for mode, status, out, at in (('apply', 'ok', 'sf-updates manager=apt-get pending=0 reboot=yes\n', 100),
                                      ('report', 'ok', 'sf-updates manager=apt-get pending=3 reboot=no\n', 200)):
            self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, output, started_at, finished_at)
                                 VALUES ('g', 'old', 'updates', 'all', :m, :s, :o, :t, :t)""", {'m': mode, 's': status, 'o': out, 't': at})
        rows = {r['host']: r for r in updates.overview(self.conn)}
        self.assertEqual(sorted(rows), ['fresh', 'old', 'truenas'])
        self.assertEqual((rows['old']['pending'], rows['old']['reboot'], rows['old']['updated_at'], rows['old']['checked_at']), (3, False, 100, 200))
        self.assertEqual(rows['fresh']['status'], None)
        self.assertIn('TrueNAS', rows['truenas']['blocked'])
        json.dumps(rows)


class Parsing(unittest.TestCase):
    def test_the_last_result_wins_and_only_a_whole_line_counts(self):
        text = 'sf-updates manager=dnf pending=2 reboot=no\n  say sf-updates manager=x pending=9 reboot=yes\nsf-updates manager=dnf pending=0 reboot=yes\n'
        self.assertEqual(updates.parse(text), {'manager': 'dnf', 'pending': 0, 'reboot': True})

    def test_nothing_known(self):
        self.assertEqual(updates.parse(None)['pending'], None)
        self.assertIsNone(updates.parse('sf-updates manager=pacman pending=unknown reboot=no\n')['pending'])


if __name__ == '__main__':
    unittest.main()
