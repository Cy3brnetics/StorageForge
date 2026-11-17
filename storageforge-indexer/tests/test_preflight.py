"""The check before a deploy (preflight.py): what each fact about a host means, read from a signed probe or the last scan, and which hosts a
deploy of each kind can't run on. The probe's output is the host's to write, so odd values are read as unknown, never as a crash: a clock of
'x' took the host check, and every deploy's check of its blockers, down with it."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import deploy, preflight


def texts(items, level=None):
    return [i['text'] for i in items if level is None or i['level'] == level]


class Findings(unittest.TestCase):
    def test_each_fact_says_what_it_means_for_a_deploy(self):
        cases = [
            ({'bash': ''}, 'crit', 'no bash'), ({'sudo': ''}, 'crit', 'no sudo'), ({'init': 'openrc'}, 'crit', 'no systemd'),
            ({'platform': 'truenas 24.10'}, 'crit', 'TrueNAS manages this system'), ({'openssh': 'OpenSSH_7.4p1'}, 'crit', 'too old'),
            ({'pve_enterprise': 'yes'}, 'warn', "Proxmox's paid repository"), ({'pm': 'none'}, 'warn', 'no package manager'),
            ({'clock': '1000400'}, 'crit', '400 s off'), ({'clock': '1000090'}, 'warn', '90 s off'), ({'modules': 'no', 'kernel': '6.1'}, 'warn', 'no modules on disk'),
            ({'mod_nfsd': 'no'}, 'warn', 'no nfsd module'), ({'mod_cifs': 'no'}, 'warn', 'no cifs module'), ({'reboot': 'yes'}, 'note', 'waiting for a reboot'),
            ({'free_var': '50'}, 'warn', 'only 50 MiB free in /var'), ({'free_tmp': '10'}, 'warn', 'in /run'), ({'selinux': 'enforcing'}, 'note', 'SELinux is enforcing'),
            ({'firewall': 'ufw'}, 'note', 'ufw is active'),
        ]
        for facts, level, words in cases:
            with self.subTest(facts):
                said = preflight.findings(facts, now=1000000)
                self.assertTrue(any(words in t for t in texts(said, level)), said)

    def test_a_host_with_nothing_wrong_says_nothing(self):
        good = {'bash': 'yes', 'sudo': 'yes', 'init': 'systemd', 'openssh': 'OpenSSH_9.6p1', 'pm': 'apt-get', 'clock': '1000010', 'modules': 'yes',
                'free_var': '5000', 'free_tmp': '900', 'selinux': 'none', 'firewall': 'none', 'reboot': 'no'}
        self.assertEqual(preflight.findings(good, now=1000000), [])

    def test_what_a_source_could_not_tell_is_left_out(self):
        self.assertEqual(preflight.findings({}), [])
        self.assertEqual(preflight.findings({'bash': 'yes', 'sudo': 'yes'}), [])

    def test_a_number_the_host_printed_is_plain_digits_or_unknown(self):
        """Found under stress-testing the routes: int() threw on 'x' and took '١٢٣' as 123."""
        for clock in ('x', '1.7e9', '١٢٣', '12-', '--5'):
            with self.subTest(clock):
                said = preflight.findings({'clock': clock}, now=1000)
                self.assertEqual([i['level'] for i in said], ['warn'])
                self.assertIn('could not be read', said[0]['text'])
        self.assertEqual(preflight.findings({'free_var': '١٠'}), [], 'not a number: not a warning about room')
        self.assertIn('988 s off', texts(preflight.findings({'clock': ' 12 '}, now=1000))[0])
        self.assertEqual(preflight._number('-5'), -5)

    def test_probe_output_is_read_line_by_line_and_nothing_else_is_taken(self):
        facts = preflight.parse_probe('os=Debian 13\nclock=1700000000\nhave=rsync git  btrfs\nevil=1\nbash=yes\n')
        self.assertEqual(facts['have'], ['rsync', 'git', 'btrfs'])
        self.assertEqual((facts['os'], facts['clock'], facts['bash']), ('Debian 13', '1700000000', 'yes'))
        self.assertNotIn('evil', facts)
        self.assertEqual(preflight.parse_probe('')['have'], [])

    def test_keyboard_interactive_counts_as_a_password_and_not_knowing_does_too(self):
        self.assertTrue(preflight.takes_password(['publickey', 'keyboard-interactive']))
        self.assertTrue(preflight.takes_password(None))
        self.assertFalse(preflight.takes_password(['publickey']))


class AuthMethods(unittest.TestCase):
    def ssh(self, stderr, code=255):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / 'ssh').write_text(f'#!/bin/bash\nprintf %s "$*" > {d}/argv\necho {stderr!r} >&2\nexit {code}\n')
        (d / 'ssh').chmod(0o755)
        p = mock.patch.dict(os.environ, {'PATH': f'{d}:{os.environ["PATH"]}'})
        p.start()
        self.addCleanup(p.stop)
        return d

    def test_the_methods_come_from_the_servers_refusal_of_a_login_that_tries_nothing(self):
        d = self.ssh('storageforge-probe@nas: Permission denied (publickey,password).')
        self.assertEqual(preflight.auth_methods('nas', 2222), ['publickey', 'password'])
        argv = (d / 'argv').read_text()
        self.assertIn('PreferredAuthentications=none', argv)
        self.assertIn('-p 2222', argv)
        self.assertIn('storageforge-probe@nas', argv)

    def test_an_answer_it_cannot_read_is_none(self):
        self.ssh('ssh: connect to host nas port 22: Connection refused')
        self.assertIsNone(preflight.auth_methods('nas'))


class FromTheDatabase(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def host(self, name, packages, os_line='Debian GNU/Linux 13'):
        self.conn.execute('INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES (:h, :h, :i)',
                          {'h': name, 'i': json.dumps({'os': os_line, 'packages': packages})})

    def test_a_scan_says_enough_to_tell_whether_a_host_can_be_set_up(self):
        self.host('nas', 'pm apt-get\nopenssh OpenSSH_9.6p1\nplatform truenas\ninit systemd\nprobed 1\nhave bash\n')
        facts = preflight.facts_from_scan(self.conn, 'NAS')
        self.assertEqual((facts['pm'], facts['openssh'], facts['platform'], facts['init'], facts['bash'], facts['sudo']),
                         ('apt-get', 'OpenSSH_9.6p1', 'truenas', 'systemd', 'yes', ''))
        self.assertEqual(preflight.facts_from_scan(self.conn, 'nobody'), {'os': '', 'have': [], 'pm': None})

    def test_an_older_scan_that_did_not_look_for_bash_does_not_say_it_is_missing(self):
        self.host('old', 'pm dnf\n')
        self.assertNotIn('bash', preflight.facts_from_scan(self.conn, 'old'))

    def test_what_blocks_a_deploy_depends_on_its_kind(self):
        self.host('rc', 'pm apk\ninit openrc\n')
        self.assertTrue(preflight.blockers(self.conn, ['rc'], 'shares'), 'shares are systemd units')
        self.assertEqual(preflight.blockers(self.conn, ['rc', 'rc'], 'changes'), [], 'a change plan needs no units')
        self.assertEqual(preflight.blockers(self.conn, ['rc'], 'console'), [], 'a kind with no deploy step')

    def test_a_saved_check_is_used_and_its_clock_is_compared_with_when_it_was_read(self):
        self.host('nas', 'pm apt-get\n')
        preflight.save(self.conn, 'nas', 'probe', {'clock': '1000', 'sudo': ''}, [], 'test')
        self.conn.execute('UPDATE host_checks SET checked_at = 1000')
        said = preflight.blockers(self.conn, ['nas'], 'jobs')
        self.assertEqual([b['text'][:7] for b in said], ['no sudo'])
        self.assertEqual(preflight.stored(self.conn)['nas']['facts'], {'clock': '1000', 'sudo': ''})
        preflight.save(self.conn, 'nas', 'probe', {'clock': 'x'}, [], 'test')          # an odd clock saved before 0.5.3 still checks
        self.assertEqual(preflight.blockers(self.conn, ['nas'], 'jobs'), [])

    def test_a_host_not_set_up_is_checked_from_its_scan_and_its_ssh_server(self):
        self.host('nas', 'pm apt-get\nprobed 1\nhave bash\nhave sudo\n')    # one tool a line, as the scan writes them
        with mock.patch.object(preflight, 'auth_methods', return_value=['publickey']):
            r = preflight.host_report(self.db, self.conn, 'nas', 'test')
        self.assertEqual((r['source'], r['ssh_logins'], r['deployable']), ('scan', ['publickey'], True))
        self.assertIn('takes no SSH passwords', texts(r['items'], 'note')[0])
        self.assertEqual(preflight.stored(self.conn)['nas']['source'], 'scan')

    def test_a_host_set_up_is_asked_by_a_signed_probe(self):
        self.host('nas', 'pm apt-get\n')
        deploy.set_access(self.conn, 'nas', 'ready', '', 'test')
        out = 'os=Debian 13\nbash=yes\nsudo=yes\ninit=systemd\nopenssh=OpenSSH_9.6\npm=apt-get\nclock=x\n'
        with mock.patch.object(deploy, 'run', return_value={'status': 'ok', 'output': out}) as run:
            r = preflight.host_report(self.db, self.conn, 'nas', 'test')
        self.assertEqual(run.call_args.kwargs['kind'], 'doctor')
        self.assertEqual((r['source'], r['deployable']), ('probe', True))
        self.assertIn('could not be read', texts(r['items'], 'warn')[0])
        with mock.patch.object(deploy, 'run', return_value={'status': 'failed', 'output': 'sudo: a password is required\n'}):
            r = preflight.host_report(self.db, self.conn, 'nas', 'test')
        self.assertFalse(r['deployable'])
        self.assertIn('the signed probe failed: sudo: a password is required', r['items'][0]['text'])


if __name__ == '__main__':
    unittest.main()
