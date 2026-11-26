"""Decided fixes from the bug hunt, group G4: deploy run time limits, wg-forward restore, the hub forwarding reading,
netconsole's claim about what is loaded, and the Pomerium deny wording."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:
    from tests import dbfactory
from storageforge_index import accessproxies, confirm, inframeasure, sfnetwork, steps_infra


class DeployRunTimeout(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-g4-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def add(self, nonce, started, timeout):
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at, timeout_s)
                             VALUES ('g', 'h1', 'changes', '1', 'apply', 'running', :n, :t, :to)""", {'n': nonce, 't': started, 'to': timeout})

    def status(self, nonce):
        return self.conn.scalar('SELECT status FROM deploy_runs WHERE nonce = :n', {'n': nonce})

    def test_a_run_is_absent_only_after_its_own_limit_and_a_margin(self):
        now = int(time.time())
        self.add('a' * 32, now - 2000, 1800)      # 33 minutes in, allowed 30 plus the margin of 10: still working
        self.add('b' * 32, now - 3000, None)      # no limit stored: the old 10 minutes
        self.add('c' * 32, now - 2500, 1800)      # past 30 + 10 minutes
        confirm.ingest_runs(self.conn, 'h1', '')
        self.assertEqual(self.status('a' * 32), 'running')
        self.assertEqual(self.status('b' * 32), 'failed')
        self.assertEqual(self.status('c' * 32), 'failed')
        self.add('d' * 32, now - 2300, 1800)
        confirm.ingest_runs(self.conn, 'h1', '')
        self.assertEqual(self.status('d' * 32), 'running')


class WgForward(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-g4-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        self.log = self.tmp / 'log'
        self.state = self.tmp / 'state'
        (self.tmp / 'bin' / 'sysctl').write_text(f'#!/bin/bash\nif [ "$1" = -n ]; then cat {self.state}; exit 0; fi\necho "$*" >> {self.log}\n')
        (self.tmp / 'bin' / 'sysctl').chmod(0o755)
        self.fn = re.search(r'^t_wg_forward\(\) \{.*?^\}$', steps_infra.BASH, re.M | re.S)[0]

    def run_step(self, state, running):
        self.state.write_text(f'{running}\n')
        stubs = ('fw_tool() { :; }; FW=true; ok() { echo "ok: $*"; }; act() { echo "act: $*"; }; conflict() { echo "conflict: $*"; }; '
                 'durable() { :; }; try() { "$@"; }\n')
        script = f'export SF_SYSCTL_DIR={self.tmp}/sysctl.d PATH={self.tmp}/bin:$PATH APPLY=1\n' + stubs + self.fn + f'\nt_wg_forward sf0 10.1.0.0/24 {state}\n'
        p = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        self.assertEqual(p.stderr, '')
        return p.stdout

    def drop_in(self):
        return self.tmp / 'sysctl.d' / '90-storageforge-sf0.conf'

    def test_removal_restores_what_the_host_had_before(self):
        self.run_step('present', 1)
        self.assertEqual(self.drop_in().read_text(), '# before: 1\nnet.ipv4.ip_forward = 1\n')
        self.run_step('absent', 1)
        self.assertFalse(self.drop_in().exists())
        self.assertEqual(self.log.read_text().splitlines()[-1], '-w net.ipv4.ip_forward=1', 'a host that forwarded before keeps forwarding')

    def test_removal_turns_forwarding_off_when_it_was_off_before(self):
        self.run_step('present', 0)
        self.assertTrue(self.drop_in().read_text().startswith('# before: 0\n'))
        self.run_step('present', 1)      # a second run keeps the recorded value
        self.assertTrue(self.drop_in().read_text().startswith('# before: 0\n'))
        self.run_step('absent', 1)
        self.assertEqual(self.log.read_text().splitlines()[-1], '-w net.ipv4.ip_forward=0')

    def test_an_older_drop_in_is_removed_and_the_running_value_is_left_alone(self):
        self.drop_in().parent.mkdir()
        self.drop_in().write_text('net.ipv4.ip_forward = 1\n')
        self.run_step('absent', 1)
        self.assertFalse(self.drop_in().exists())
        self.assertFalse(self.log.exists())


class ForwardReading(unittest.TestCase):
    def test_the_collector_reads_it_and_the_parser_keeps_it(self):
        self.assertIn('ip_forward', inframeasure.SECTIONS)
        self.assertIn('sec ip_forward', inframeasure.BODY)
        for text, want in (('1\n', 1), ('0\n', 0), ('', None), ('x\n', None)):
            self.assertEqual(inframeasure.parse_access({'ip_forward': text.splitlines()}, [])['ip_forward'], want)

    def test_a_hub_plans_wg_forward_only_where_forwarding_is_off_or_unknown(self):
        from test_sfnet_roaming import RoamingAndHub as R
        t = R('test_hub_topology_emits_and_runs_wg_forward_step')
        t.setUp()
        self.addCleanup(t.doCleanups)
        sfnetwork.create(t.conn, 'gabe', topology='hub')
        sfnetwork.join(t.conn, 'hub', 'gabe', endpoint='[2001:db8::10]', hub=True)
        sfnetwork.join(t.conn, 'pi', 'gabe', reachable=False)
        import json
        from test_sfnet_roaming import key

        def read(forward):
            t.conn.execute("DELETE FROM security_measurements WHERE kind = 'infra'")
            for i, h in enumerate(('hub', 'pi'), 1):
                access = {'wireguard': [{'name': 'sf0', 'public_key': key(i), 'listen_port': 51903, 'peers': []}]}
                if forward is not None and h == 'hub':
                    access['ip_forward'] = forward
                t.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                               {'h': h, 't': int(time.time()), 'd': json.dumps({'access': access})})
            sfnetwork.observe(t.conn)
            return [x for x in sfnetwork.tasks(t.conn) if x['type'] == 'wg-forward']
        self.assertEqual(len(read(None)), 1)
        self.assertEqual(len(read(0)), 1)
        self.assertEqual(read(1), [])


class NetconsoleClaim(unittest.TestCase):
    def setUp(self):
        import test_netconsole
        h = test_netconsole.TheStep('test_through_a_gateway_it_sends_to_the_gateways_mac')     # its stand-ins for ip, modprobe and the rest
        h.setUp()
        self.addCleanup(h.doCleanups)
        self.root, self.run_step = h.root, h.run_step
        (self.root / 'sys/module/netconsole').mkdir(parents=True)
        self.step_files()

    def step_files(self):
        mp = self.root / 'etc/modprobe.d'
        mp.mkdir(parents=True)
        (mp / 'storageforge-netconsole.conf').write_text('options netconsole netconsole=+6665@10.42.0.7/enp3s0,6666@10.42.0.10/52:54:00:aa:bb:cc\n')
        ml = self.root / 'etc/modules-load.d'
        ml.mkdir(parents=True)
        (ml / 'storageforge-netconsole.conf').write_text('netconsole\n')

    def test_a_module_nobody_here_loaded_this_boot_is_not_claimed(self):
        out = self.run_step()
        self.assertNotIn('is loaded with these settings', out)
        self.assertIn('conflict: netconsole is loaded already, with other settings', out)

    def test_a_marker_from_this_boot_lets_it_say_so(self):
        (self.root / 'run/storageforge').mkdir(parents=True)
        (self.root / 'run/storageforge/netconsole-loaded').write_text('')
        self.assertIn('ok: netconsole is loaded with these settings', self.run_step())

    def test_a_matching_configfs_target_lets_it_say_so(self):
        cfs = self.root / 'sys/kernel/config/netconsole/storageforge'
        cfs.mkdir(parents=True)
        for k, v in (('enabled', '1'), ('dev_name', 'enp3s0'), ('remote_ip', '10.42.0.10'), ('remote_port', '6666'), ('local_port', '6665'),
                     ('local_ip', '10.42.0.7'), ('remote_mac', '52:54:00:aa:bb:cc')):
            (cfs / k).write_text(v + '\n')
        self.assertIn('ok: netconsole is loaded with these settings', self.run_step())

    def test_loading_it_writes_the_marker(self):
        shutil.rmtree(self.root / 'sys/module/netconsole')
        self.run_step()
        self.assertTrue((self.root / 'run/storageforge/netconsole-loaded').exists())


class Pomerium(unittest.TestCase):
    def test_allow_everyone_with_a_deny_rule_is_said_plainly(self):
        out = accessproxies.pomerium('routes:\n  - from: https://x.example.com\n    to: http://10.0.0.1\n    policy:\n      - allow:\n          or:\n            - accept: true\n'
                                     '      - deny:\n          or:\n            - domain: {is: evil.example}\n')
        t = out['targets'][0]
        self.assertFalse(t['public'])
        self.assertIn('everyone is allowed, except what the deny rules exclude', str(t))


if __name__ == '__main__':
    unittest.main()
