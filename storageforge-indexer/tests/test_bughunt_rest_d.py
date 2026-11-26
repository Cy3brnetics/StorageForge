"""Fixes from the last bug hunt, in the files of group D: each test fails on the code as it was and passes now."""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
import test_agent_receiver as tar
import test_rotation as tr
from storageforge_index import agentaction, alerts, cli, enclave, gitrepos, reset, rotation, secplus, security
from storageforge_index import agenttunnel as t
from storageforge_index.vault import Vault, VaultError


class Db(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = tmp
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)


class Alerts(Db):
    def test_a_bare_timer_line_does_not_stop_alerting(self):
        self.conn.execute('INSERT INTO hosts (hostname, inventory_json) VALUES (:h, :i)',
                          {'h': 'evil', 'i': json.dumps({'managed': '## timers\nTIMER \nTIMER\nTIMER x.timer\n'})})
        alerts.drift(self.conn)

    def test_a_route_matches_the_host_and_not_the_whole_reference(self):
        cfg = {'routes': [{'level': 'crit', 'host': '*', 'channels': ['pagerduty']}, {'level': 'warn', 'host': 'nas01', 'channels': ['ntfy']}]}
        self.assertEqual(alerts.routed(cfg, 'warn', 'nas01:/data'), {'ntfy'})
        self.assertEqual(alerts.routed(cfg, 'warn', '7', host='nas01'), {'ntfy'}, 'a job id: the host is given')
        self.assertIsNone(alerts.routed(cfg, 'warn', 'web01:/data'))


class HostsRemove(Db):
    def test_a_different_case_still_meets_the_running_scan(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host) VALUES ('Nas', 'nas')")
        self.conn.execute("INSERT INTO scan_jobs (host, status, requested_by, queued_at) VALUES ('Nas', 'running', 'a', 1)")
        args = argparse.Namespace(db=str(self.tmp / 'index.db'), hosts_cmd='remove', name='NAS', keep_design=False)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.cmd_hosts(args)
        self.assertEqual(code, 1)
        self.assertIn('scan', err.getvalue())
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM hosts"), 1)


class Rotation(unittest.TestCase):
    setUp = tr.Rotation.setUp

    def test_a_host_that_refuses_keeps_its_binding_and_the_old_key_stays(self):
        self.fleet.refuse = {'pc'}
        r = rotation.apply(self.db, self.conn, 'test')
        fleet = next(x for x in r['results'] if x['key'] == 'fleet')
        self.assertFalse(fleet['ok'])
        self.assertEqual(fleet['left'], ['pc'])
        with Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.resolve('pc', 'scan').fingerprint, self.old['fp'], 'pc was never given the new key')
            self.assertNotEqual(v.resolve('nas', 'scan').fingerprint, self.old['fp'], 'nas took it')
            names = [k['name'] for k in v.list_keys()]
        self.assertIn('fleet', names)
        self.assertEqual(self.fleet.pub('fleet'), self.old['pub'])
        nas, pc = self.fleet.keys[('nas', 'scan')], self.fleet.keys[('pc', 'scan')]
        self.assertFalse(any(rotation._blob(self.old['pub']) in x for x in nas), 'the old line is out where the new key works')
        self.assertEqual(sum(rotation._blob(self.old['pub']) in x for x in pc), 1)
        self.assertEqual(len(pc), 2, 'no line of the new key was left on pc')

    def test_a_binding_that_covers_no_scanned_host_keeps_the_old_key(self):
        with Vault(self.db, self.conn).unlock() as v:
            v.bind('fleet', 'elsewhere.example', 'scan')
        r = rotation.apply(self.db, self.conn, 'test', only={'fleet'})
        fleet = r['results'][0]
        self.assertFalse(fleet['ok'])
        with Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.resolve('elsewhere.example').fingerprint, self.old['fp'])

    def test_a_short_new_vault_secret_is_refused_before_anything_changes(self):
        with self.assertRaises(VaultError):
            rotation.apply(self.db, self.conn, 'test', new_vault_secret=b'short')
        self.assertEqual(self.fleet.pub('fleet'), self.old['pub'], 'no key was rotated')


class Security(Db):
    def test_a_line_with_an_epoch_int_refuses_is_skipped(self):
        u = '12345678-1234-1234-1234-123456789abc'
        good = f'ev\t{u}\tcanary_tripped\t1700000000\tYQ==\tYg=='
        self.assertIsNotNone(security.parse_event_line(good))
        for bad in ('²', '①', '9' * 5000, ''):
            self.assertIsNone(security.parse_event_line(f'ev\t{u}\tcanary_tripped\t{bad}\tYQ==\tYg=='))

    def test_an_avc_line_with_a_huge_stamp_does_not_raise(self):
        line = 'type=AVC msg=audit(' + '1' * 5000 + ':1): avc: denied { read } for comm="smbd" path="/x"'
        security._parse_avc(line)

    def test_decoy_folders_do_not_follow_like_wildcards_or_case(self):
        self.conn.execute("INSERT INTO hosts (hostname) VALUES ('nas')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/', 'ext4', 'indexed')", {'h': hid})
        mid = self.conn.scalar('SELECT mount_id FROM mounts WHERE host_id = :h', {'h': hid})
        for p in ('/srv/data_1/a', '/srv/dataX1/b', '/SRV/data_1/c'):
            self.conn.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p)', {'m': mid, 'p': p})
        got = security.spread_folders(self.conn, 'nas', ['/srv/data_1'], 'top')
        self.assertEqual(got, ['/srv/data_1', '/srv/data_1/a'])


class Git(Db):
    def test_a_tag_called_error_is_a_tag(self):
        out = '@@tags\nerror\tabc123\t1700000000\tthe release\n@@commits\n' + '\t'.join(['a' * 40, 'aaaaaaa', 'me', 'me@x', '1700000000', 'subject', '']) + '\n'
        t_ = mock.MagicMock()
        t_.__enter__.return_value.run.return_value = out
        with mock.patch.object(gitrepos, '_known_repo'), mock.patch.object(gitrepos, 'open_host_transport', return_value=t_):
            res = gitrepos.repo_history(self.db, 'nas', '/srv/repo')
        self.assertNotIn('error', res)
        self.assertEqual([x['name'] for x in res['tags']], ['error'])
        self.assertEqual(len(res['commits']), 1)

    def test_the_scripts_own_error_still_counts_before_any_section(self):
        t_ = mock.MagicMock()
        t_.__enter__.return_value.run.return_value = 'error\tnot a git repository\n'
        with mock.patch.object(gitrepos, '_known_repo'), mock.patch.object(gitrepos, 'open_host_transport', return_value=t_):
            self.assertEqual(gitrepos.repo_history(self.db, 'nas', '/srv/repo')['error'], 'not a git repository')


class Reset(unittest.TestCase):
    def test_the_new_secret_is_written_before_it_is_moved_into_place(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        f = d / 'vault_secret'
        f.write_text('old')
        staged = reset._stage_secret(f, 'new-secret')
        self.assertEqual(f.read_text(), 'old', 'staging changes nothing yet')
        self.assertEqual(staged.read_text(), 'new-secret')
        reset._install_secret(f, staged)
        self.assertEqual(f.read_text(), 'new-secret')
        self.assertTrue((d / 'reset_at').exists())

    def test_a_folder_that_refuses_the_write_stops_staging_with_nothing_replaced(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        f = d / 'vault_secret'
        f.write_text('old')
        with mock.patch('os.open', side_effect=OSError(28, 'No space left on device')):
            with self.assertRaises(OSError):
                reset._stage_secret(f, 'new-secret')
        self.assertEqual(f.read_text(), 'old')


class Witness(unittest.TestCase):
    def test_an_address_is_found_whole_not_inside_a_longer_one(self):
        self.assertTrue(agentaction._names('client=10.0.0.1 touched decoy', '10.0.0.1'))
        self.assertTrue(agentaction._names('from 10.0.0.1.', '10.0.0.1'))
        self.assertFalse(agentaction._names('client=10.0.0.11 touched decoy', '10.0.0.1'))
        self.assertFalse(agentaction._names('client=110.0.0.1', '10.0.0.1'))
        self.assertFalse(agentaction._names('anything', ''))


class Delivery(tar.Base):
    def test_a_plugin_program_the_receiver_cannot_read_is_logged_and_recorded(self):
        a = tar.Agent(self, 'nas')
        a.open()
        with mock.patch.object(t, 'delivery_frames', side_effect=t.TunnelError('no plugin folder')):
            try:
                a.hello()
            except Exception:
                pass                    # the session ends
            for _ in range(50):
                if self.events('delivery-failed'):
                    break
                time.sleep(0.1)
        self.assertEqual(len(self.events('delivery-failed')), 1)
        self.assertTrue(any('no plugin folder' in line for line in self.lines))

    def test_dropped_records_are_one_loss_not_two(self):
        a = tar.Agent(self, 'nas')
        a.open()
        a.hello()
        a.send(a.body())
        a.seq += 100
        a.send(a.body(dropped=100))
        self.assertEqual(self.peer(a.fp)['lost'], 100)


class Playbooks(Db):
    def save(self, **extra):
        return secplus.save_playbook(self.conn, {'name': 'Brake', 'trigger': 'canary_tripped', 'actions': ['notify'], **extra}, 'a')

    def dry(self):
        return self.conn.scalar("SELECT dry_run FROM security_playbooks WHERE name = 'Brake'")

    def test_a_missing_mode_is_a_dry_run(self):
        self.save()
        self.assertEqual(self.dry(), 1)

    def test_null_and_unknown_modes_are_refused_or_safe(self):
        for bad in ('Confirm', 'dryrun', 'x', 5, ['live']):
            with self.assertRaises(ValueError):
                self.save(mode=bad)
        self.save(mode=None)
        self.assertEqual(self.dry(), 1, 'null is a missing mode')

    def test_the_known_modes(self):
        self.save(mode='live')
        self.assertEqual(self.dry(), 0)
        self.save(mode='confirm')
        self.assertEqual(self.dry(), 0)
        self.assertIn('confirm', self.conn.scalar("SELECT conditions_json FROM security_playbooks WHERE name = 'Brake'"))


class SambaNetworks(unittest.TestCase):
    def nets(self, *addresses):
        script = secplus.SESSIONS_SCRIPT
        fn = script[script.index('function net('):script.index('$1 >= t {')]
        prog = fn + ' { print net($1) }'
        r = subprocess.run(['awk', prog], input='\n'.join(addresses) + '\n', capture_output=True, text=True, timeout=20)
        return r.stdout.split()

    def test_networks(self):
        self.assertEqual(self.nets('192.168.1.20', 'ipv4:192.168.1.7', '::ffff:192.168.1.9'), ['192.168.1', '192.168.1', '192.168.1'])
        got = self.nets('fd00::20', 'fd00::21', 'FD00:0:0:1::5', 'fd00:0:0:1:2:3:4:5')
        self.assertEqual(got[0], got[1], 'two addresses of one /64 are one network')
        self.assertEqual(got[2], got[3])
        self.assertNotEqual(got[0], got[2])


class Enclave(unittest.TestCase):
    def test_values_the_enclave_would_count_as_bad_requests_stay_here(self):
        e = enclave.Enclave('127.0.0.1:1')
        with mock.patch.object(e, 'raw') as raw:
            for call in (lambda: e._proof('u', {'uuid': 'x', 'dek_nonce': b'', 'wrapped_dek': b'', 'nonce': b'', 'ciphertext': b''}, password='p' * 1100),
                         lambda: e.generate('u' * 32, 'ed25519', 'c' * 201),
                         lambda: e.generate('u' * 32, 'ed25519', 'bad\ncomment')):
                with self.assertRaises(enclave.EnclaveError) as cm:
                    call()
                self.assertEqual(cm.exception.code, 'bad-request')
            raw.assert_not_called()


class Watcher(unittest.TestCase):
    def test_an_oserror_while_restarting_does_not_end_the_watcher(self):
        from storageforge_index import enclave_vm
        sup = enclave_vm.Supervisor.__new__(enclave_vm.Supervisor)
        import threading
        sup._stop, sup._lock = threading.Event(), threading.Lock()
        sup.proc, sup.vmm, sup.cid, sup.digest, sup.image, sup.signers = None, 'qemu', 5, 'd', 'img', None
        sup.restarts = 0
        events = []
        sup.on_event = lambda kind, info: (events.append(kind), sup._stop.set() if kind == 'failed' else None)
        with mock.patch.object(enclave_vm, 'image_digest', side_effect=FileNotFoundError('gone')):
            th = threading.Thread(target=sup._watch, daemon=True)
            th.start()
            th.join(10)
        self.assertFalse(th.is_alive())
        self.assertEqual(events[:2], ['down', 'failed'])


if __name__ == '__main__':
    unittest.main()
