"""The unit-state plan step (steps_services.py): one systemd service started, restarted or stopped. Its Bash runs for real against a
stand-in systemctl that keeps each unit's state in a file, so what it does and what it says are both checked."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import changes, steps_services

HEAD = ('APPLY=${APPLY:-1}; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; }\n'
        'act() { if ((!APPLY)); then missing "would: $*"; return 1; fi; echo "doing: $*"; }\nsleep() { :; }\n')
SYSTEMCTL = r'''#!/bin/bash
# a stand-in: a unit is a file under $UNITS holding active, inactive or failed. A unit named stubborn.service never starts.
verb=$1; shift; args=(); for a in "$@"; do [[ $a == -- || $a == -p || $a == --value || $a == LoadState ]] || args+=("$a"); done
unit=${args[0]:-}; f=$UNITS/$unit
echo "$verb $unit" >> "$UNITS/calls"
case $verb in
  show) if [[ -e $f ]]; then echo loaded; else echo not-found; fi ;;
  is-active) [[ -e $f ]] && cat "$f"; [[ -e $f && $(cat "$f") == active ]] ;;
  start|restart) [[ $unit == stubborn.service ]] && { echo failed > "$f"; exit 1; }; echo active > "$f" ;;
  stop) echo inactive > "$f" ;;
  reset-failed) : ;;
esac
'''


class TheStep(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'units').mkdir()
        for name, text in (('systemctl', SYSTEMCTL), ('journalctl', '#!/bin/bash\necho "it said why"\n')):
            (self.tmp / 'bin' / name).write_text(text)
            (self.tmp / 'bin' / name).chmod(0o755)

    def unit(self, name, state):
        (self.tmp / 'units' / name).write_text(state + '\n')

    def state(self, name):
        return (self.tmp / 'units' / name).read_text().strip()

    def run_step(self, unit, want, apply=True, systemd=True):
        script = HEAD + steps_services.UNIT_BASH.replace('[[ -d /run/systemd/system ]]', '[[ -n $HAS_SYSTEMD ]]') + f'\nt_unit_state "$1" "$2"\n'
        env = {'PATH': f'{self.tmp}/bin:{os.environ["PATH"]}', 'UNITS': str(self.tmp / 'units'), 'APPLY': '1' if apply else '0', 'HAS_SYSTEMD': '1' if systemd else ''}
        p = subprocess.run(['bash', '-c', script, 'x', unit, want], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def calls(self):
        f = self.tmp / 'units' / 'calls'
        return [c for c in f.read_text().splitlines() if not c.startswith(('show', 'is-active'))] if f.exists() else []

    def test_a_failed_unit_is_restarted_and_said_to_be_running(self):
        self.unit('nginx.service', 'failed')
        out = self.run_step('nginx.service', 'restarted')
        self.assertIn('doing: systemctl restart nginx.service (it is failed)', out)
        self.assertIn('ok: nginx.service is running', out)
        self.assertEqual(self.state('nginx.service'), 'active')
        self.assertEqual(self.calls(), ['reset-failed nginx.service', 'restart nginx.service'], 'nothing is enabled or disabled')

    def test_the_way_back_stops_it_and_stopping_what_is_stopped_does_nothing(self):
        self.unit('nginx.service', 'active')
        self.assertIn('ok: nginx.service is stopped', self.run_step('nginx.service', 'stopped'))
        self.assertEqual(self.state('nginx.service'), 'inactive')
        (self.tmp / 'units' / 'calls').unlink()
        self.assertIn('ok: nginx.service is not running (inactive)', self.run_step('nginx.service', 'stopped'))
        self.assertEqual(self.calls(), [])

    def test_started_leaves_a_running_unit_alone(self):
        self.unit('nginx.service', 'active')
        self.assertIn('ok: nginx.service is running', self.run_step('nginx.service', 'started'))
        self.assertEqual(self.calls(), [])

    def test_a_report_changes_nothing_and_says_what_it_would_do(self):
        self.unit('nginx.service', 'failed')
        out = self.run_step('nginx.service', 'restarted', apply=False)
        self.assertIn('missing: would: systemctl restart nginx.service (it is failed)', out)
        self.assertEqual((self.state('nginx.service'), self.calls()), ('failed', []))

    def test_a_unit_that_does_not_stay_up_is_a_conflict_with_what_it_logged(self):
        self.unit('stubborn.service', 'failed')
        out = self.run_step('stubborn.service', 'restarted')
        self.assertIn('conflict: stubborn.service did not stay up, it is failed: it said why', out)

    def test_what_the_host_is_reached_through_is_never_touched(self):
        for unit in ('sshd.service', 'ssh.service', 'NetworkManager.service', 'systemd-networkd.service', 'firewalld.service', 'nftables.service', 'dbus.service'):
            self.unit(unit, 'active')
            for want in steps_services.UNIT_STATES:
                with self.subTest(unit=unit, want=want):
                    self.assertIn('do this one by hand', self.run_step(unit, want))
        self.assertEqual(self.calls(), [])

    def test_a_unit_that_is_not_there_and_a_host_without_systemd_are_conflicts(self):
        self.assertIn('conflict: ghost.service is not a unit on this host (not-found)', self.run_step('ghost.service', 'restarted'))
        self.unit('nginx.service', 'failed')
        self.assertIn('no systemd', self.run_step('nginx.service', 'restarted', systemd=False))
        self.assertEqual(self.calls(), [])


class InAPlan(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute(f"INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES ('nas', 'nas', 'scan', '{{}}', {self.db.ts(':t')})", {'t': 1600000000})

    def plan(self, **params):
        return changes.normalize({'name': 'p', 'tasks': [{'type': 'unit-state', 'host': 'nas', 'params': {'unit': 'nginx.service', 'state': 'restarted', **params}}]})

    def test_only_a_service_name_and_one_of_three_states_get_into_a_plan(self):
        self.assertEqual(self.plan()['tasks'][0]['params'], {'unit': 'nginx.service', 'state': 'restarted'})
        for bad in ({'unit': 'nginx'}, {'unit': 'a b.service'}, {'unit': 'x.service; reboot #.service'}, {'unit': '$(reboot).service'}, {'unit': 'x.timer'}, {'state': 'enabled'}, {'state': ''}):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.plan(**bad)

    def test_the_script_calls_the_step_with_the_unit_as_one_word_and_parses(self):
        text = changes.script(self.conn, self.plan(unit='my-app@blue.service'))
        self.assertIn('unit-state', text)
        self.assertIn('my-app@blue.service restarted', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text.encode()).returncode, 0)

    def test_the_check_refuses_what_the_host_is_reached_through(self):
        got = changes.check(self.conn, self.plan(unit='sshd.service'))
        self.assertIn('not restarted or stopped from here', str(got))
        self.assertNotIn('not restarted or stopped from here', str(changes.check(self.conn, self.plan())))


if __name__ == '__main__':
    unittest.main()
