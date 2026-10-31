"""Unit tests for the StorageForge Unified Scheduler and Client Runner."""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import tempfile
import time
import unittest

try:
    import dbfactory
except ImportError:
    from tests import dbfactory

from storageforge_index import changes, moves, scheduler, schedscript, tasks
from storageforge_index.db import Database, dir_id


class SchedulerBaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sfsched-')
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

        # Seed test hosts and mounts
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', '10.0.0.5', 'scan', '{}')")
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('backup-box', '10.0.0.6', 'scan', '{}')")
        self.hid_nas = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")

        self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options) "
                          "VALUES (:h, '/mnt/data', '/dev/sdb1', 'ext4', :t, :u, 'indexed', 'rw')",
                          {'h': self.hid_nas, 't': 500 * (1024 ** 3), 'u': 100 * (1024 ** 3)})
        self.mid = self.conn.scalar("SELECT mount_id FROM mounts WHERE mount_point = '/mnt/data'")

        # Seed files
        p_dir = dir_id(self.conn, self.mid, '/mnt/data')
        self.conn.execute("INSERT INTO file_records (mount_id, dir_id, filename, is_directory, file_size_bytes, modified_at) "
                          f"VALUES (:m, :d, 'archive.tar.gz', 0, 1024, {self.db.ts('0')})",
                          {'m': self.mid, 'd': p_dir})

        # Seed a storage task
        self.task_id = tasks.save_task(self.conn, {
            'name': 'daily-sync',
            'host': 'nas',
            'blocks': [
                {'type': 'require_mounted', 'params': {'path': '/mnt/data'}},
                {'type': 'log', 'params': {'message': 'sync complete'}},
            ],
        }, 'test')

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class CronEngineTests(unittest.TestCase):
    def test_parse_cron_valid(self):
        m, h, dom, mon, dow = scheduler.parse_cron('*/15 2-4 1,15 * 1-5')
        self.assertEqual(m, {0, 15, 30, 45})
        self.assertEqual(h, {2, 3, 4})
        self.assertEqual(dom, {1, 15})
        self.assertEqual(mon, set(range(1, 13)))
        self.assertEqual(dow, {1, 2, 3, 4, 5})

    def test_cron_aliases(self):
        m, h, dom, mon, dow = scheduler.parse_cron('@daily')
        self.assertEqual(m, {0})
        self.assertEqual(h, {0})
        self.assertTrue(scheduler.validate_cron('@hourly'))
        self.assertTrue(scheduler.validate_cron('@weekly'))
        self.assertTrue(scheduler.validate_cron('@monthly'))
        self.assertTrue(scheduler.validate_cron('@yearly'))

    def test_validate_cron_invalid(self):
        self.assertFalse(scheduler.validate_cron('bad cron'))
        self.assertFalse(scheduler.validate_cron('60 * * * *'))
        self.assertFalse(scheduler.validate_cron('* 25 * * *'))
        self.assertFalse(scheduler.validate_cron('* * 32 * *'))
        self.assertFalse(scheduler.validate_cron('* * * 13 *'))
        self.assertFalse(scheduler.validate_cron('* * * * 8'))

    def test_next_run(self):
        # Jan 1 2026, 00:00 UTC
        base_ts = 1767225600
        nxt = scheduler.next_run('30 2 * * *', base_ts, tz_name='UTC')
        dt_nxt = dt.datetime.fromtimestamp(nxt, dt.timezone.utc)
        self.assertEqual(dt_nxt.hour, 2)
        self.assertEqual(dt_nxt.minute, 30)
        self.assertTrue(nxt > base_ts)


class ConfigNormalizationTests(unittest.TestCase):
    def test_valid_config(self):
        cfg = scheduler.normalize_config({
            'config': {
                'window': '02:00-06:00',
                'timeout_sec': 1800,
                'concurrency_policy': 'queue',
                'retry_count': 3,
                'retry_delay_sec': 60,
                'retry_backoff': 2.0,
                'nice': 5,
                'ionice_class': 'best-effort',
                'ionice_priority': 4,
                'user': 'backup_user',
                'env': {'FOO': 'BAR'},
                'verify_policy': 'comprehensive',
                'verify_rules': {
                    'require_exit_zero': True,
                    'check_mounts': ['/mnt/data'],
                    'min_free_gib': {'/mnt/data': 50},
                    'output_must_match': 'SUCCESS',
                },
            }
        })
        self.assertEqual(cfg['window'], '02:00-06:00')
        self.assertEqual(cfg['timeout_sec'], 1800)
        self.assertEqual(cfg['concurrency_policy'], 'queue')
        self.assertEqual(cfg['retry_count'], 3)
        self.assertEqual(cfg['verify_rules']['check_mounts'], ['/mnt/data'])
        self.assertEqual(cfg['verify_rules']['min_free_gib']['/mnt/data'], 50)

    def test_invalid_config_raises(self):
        with self.assertRaises(ValueError):
            scheduler.normalize_config({'config': {'window': 'invalid'}})
        with self.assertRaises(ValueError):
            scheduler.normalize_config({'config': {'timeout_sec': -1}})
        with self.assertRaises(ValueError):
            scheduler.normalize_config({'config': {'concurrency_policy': 'parallel_unknown'}})
        with self.assertRaises(ValueError):
            scheduler.normalize_config({'config': {'retry_count': 20}})


class ScheduleCrudTests(SchedulerBaseTest):
    def test_create_and_get_schedule(self):
        body = {
            'name': 'nightly-backup',
            'host': 'nas',
            'cron_expr': '0 3 * * *',
            'task_type': 'task',
            'task_ref': str(self.task_id),
            'config': {
                'window': '03:00-05:00',
                'timeout_sec': 3600,
            },
        }
        sched, token = scheduler.create_schedule(self.conn, body, 'admin')
        self.assertEqual(sched['name'], 'nightly-backup')
        self.assertEqual(sched['host'], 'nas')
        self.assertTrue(len(token) >= 32)
        self.assertIsNotNone(sched['next_run_at'])

        # Fetch
        fetched = scheduler.get_schedule(self.conn, sched['schedule_id'])
        self.assertEqual(fetched['name'], 'nightly-backup')

        # Authentication via token
        matched = scheduler.schedule_for_token(self.conn, token)
        self.assertIsNotNone(matched)
        self.assertEqual(matched['schedule_id'], sched['schedule_id'])

    def test_update_and_pause_schedule(self):
        body = {
            'name': 'hourly-scan',
            'host': 'nas',
            'cron_expr': '0 * * * *',
            'task_type': 'scan',
            'task_ref': 'nas',
        }
        sched, _ = scheduler.create_schedule(self.conn, body, 'admin')
        sid = sched['schedule_id']

        # Pause
        paused = scheduler.pause_schedule(self.conn, sid, True, 'admin')
        self.assertTrue(paused['paused'])
        self.assertIsNone(paused['next_run_at'])

        # Resume
        resumed = scheduler.pause_schedule(self.conn, sid, False, 'admin')
        self.assertFalse(resumed['paused'])
        self.assertIsNotNone(resumed['next_run_at'])

        # Update
        updated = scheduler.update_schedule(self.conn, sid, {'cron_expr': '*/30 * * * *'}, 'admin')
        self.assertEqual(updated['cron_expr'], '*/30 * * * *')

        # Delete
        scheduler.delete_schedule(self.conn, sid, 'admin')
        with self.assertRaises(LookupError):
            scheduler.get_schedule(self.conn, sid)


class ScriptGenerationTests(SchedulerBaseTest):
    def test_generate_scripts(self):
        # 1. Storage task
        s_task = {
            'schedule_id': 1,
            'name': 's-task',
            'host': 'nas',
            'task_type': 'task',
            'task_ref': str(self.task_id),
            'config': {},
        }
        scr, args = scheduler.generate_task_script(self.conn, s_task)
        self.assertIn('#!/usr/bin/env bash', scr)
        self.assertEqual(args, ['--run'])

        # 2. Command
        s_cmd = {
            'schedule_id': 2,
            'name': 's-cmd',
            'host': 'nas',
            'task_type': 'command',
            'task_ref': 'echo "hello from cron"',
            'config': {},
        }
        scr2, args2 = scheduler.generate_task_script(self.conn, s_cmd)
        self.assertIn('echo "hello from cron"', scr2)
        self.assertEqual(args2, [])

    def test_generate_cron_and_install_bundle(self):
        s = {
            'schedule_id': 42,
            'name': 'archive-run',
            'host': 'nas',
            'cron_expr': '15 4 * * *',
            'task_type': 'command',
            'task_ref': 'echo test',
            'config': {'user': 'root'},
        }
        cron = scheduler.generate_cron_entry(s)
        self.assertIn('15 4 * * * root /usr/local/sbin/storageforge-scheduler run 42', cron)

        cfg_json = scheduler.generate_client_config(s, 'http://server:8080', 'secret_token')
        parsed = json.loads(cfg_json)
        self.assertEqual(parsed['schedule_id'], 42)
        self.assertEqual(parsed['token'], 'secret_token')

        bundle = scheduler.generate_install_script(self.conn, s, 'http://server:8080', 'secret_token')
        self.assertIn('/etc/cron.d/sf-sched-42', bundle)


class ServerVerificationTests(SchedulerBaseTest):
    def test_comprehensive_verification_success(self):
        body = {
            'name': 'data-check',
            'host': 'nas',
            'cron_expr': '0 1 * * *',
            'task_type': 'task',
            'task_ref': str(self.task_id),
            'config': {
                'verify_policy': 'comprehensive',
                'verify_rules': {
                    'require_exit_zero': True,
                    'check_mounts': ['/mnt/data'],
                    'min_free_gib': {'/mnt/data': 50},  # 400 GiB free in setup
                    'paths_must_exist': ['/mnt/data/archive.tar.gz'],
                    'output_must_match': 'completed successfully',
                },
            },
        }
        sched, token = scheduler.create_schedule(self.conn, body, 'admin')
        sid = sched['schedule_id']

        report = {
            'schedule_id': sid,
            'started_at': int(time.time()) - 10,
            'finished_at': int(time.time()),
            'exit_code': 0,
            'output': 'Starting job...\nOperation completed successfully.\nDone.',
        }

        res = scheduler.ingest_report(self.conn, report, '10.0.0.5')
        self.assertEqual(res['status'], 'verified')
        self.assertEqual(res['verified'], 1)
        self.assertTrue(res['verify_result']['passed'])

        # Check recorded in DB
        runs = scheduler.get_schedule_runs(self.conn, schedule_id=sid)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]['status'], 'verified')
        self.assertEqual(runs[0]['verified'], 1)

    def test_verification_failure_exit_code(self):
        body = {
            'name': 'failing-task',
            'host': 'nas',
            'cron_expr': '0 1 * * *',
            'task_type': 'command',
            'task_ref': 'exit 2',
            'config': {
                'verify_rules': {'require_exit_zero': True},
            },
        }
        sched, token = scheduler.create_schedule(self.conn, body, 'admin')
        res = scheduler.ingest_report(self.conn, {
            'schedule_id': sched['schedule_id'],
            'exit_code': 2,
            'output': 'fatal error encountered',
        }, '10.0.0.5')

        self.assertEqual(res['status'], 'failed')
        self.assertEqual(res['verified'], -1)
        self.assertFalse(res['verify_result']['passed'])


class ClientRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sfrun-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_in_window(self):
        self.assertTrue(schedscript.in_window(''))
        dt1 = dt.datetime(2026, 1, 1, 3, 30)
        self.assertTrue(schedscript.in_window('02:00-05:00', dt1))
        self.assertFalse(schedscript.in_window('04:00-05:00', dt1))
        # Crossing midnight (22:00 to 04:00)
        self.assertTrue(schedscript.in_window('22:00-04:00', dt1))

    def test_run_schedule_execution_and_retries(self):
        script_file = os.path.join(self.tmp, 'test.sh')
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\necho 'hello from runner'\nexit 0\n")
        os.chmod(script_file, 0o755)

        conf = {
            'schedule_id': 99,
            'script_path': script_file,
            'config': {
                'timeout_sec': 10,
                'retry_count': 0,
                'env': {'TEST_VAR': '123'},
            },
        }

        var_dir = os.path.join(self.tmp, 'var')
        lock_dir = os.path.join(self.tmp, 'locks')
        rc = schedscript.run_schedule(conf, var_dir=var_dir, locks_dir=lock_dir)
        self.assertEqual(rc, 0)

        # Verify last.json and runs.jsonl
        last_file = os.path.join(var_dir, '99', 'last.json')
        self.assertTrue(os.path.isfile(last_file))
        with open(last_file) as f:
            rec = json.load(f)
            self.assertEqual(rec['exit_code'], 0)
            self.assertIn('hello from runner', rec['output'])


class SchedulerApiTests(SchedulerBaseTest):
    def test_api_endpoints(self):
        from storageforge_index import server, users
        app = server.create_app(server.App(self.db), 's' * 48)
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        client = app.test_client()

        # Sign in
        users.create(self.conn, 'admin', 'a long enough password')
        client.post('/api/login', json={'username': 'admin', 'password': 'a long enough password'})

        # 1. Create schedule
        resp = client.post('/api/scheduler/schedules', json={
            'name': 'api-schedule',
            'host': 'nas',
            'cron_expr': '*/10 * * * *',
            'task_type': 'task',
            'task_ref': str(self.task_id),
            'config': {'timeout_sec': 600},
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        sid = data['schedule']['schedule_id']
        token = data['token']

        # 2. List schedules
        resp = client.get('/api/scheduler/schedules')
        self.assertEqual(resp.status_code, 200)
        schedules = resp.get_json()['schedules']
        self.assertTrue(any(s['schedule_id'] == sid for s in schedules))

        # 3. Get single schedule
        resp = client.get(f'/api/scheduler/schedules/{sid}')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['name'], 'api-schedule')

        # 4. Get cron entry
        resp = client.get(f'/api/scheduler/schedules/{sid}/cron')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(f'/usr/local/sbin/storageforge-scheduler run {sid}', resp.get_data(as_text=True))

        # 5. Ingest client report with bearer token
        rep_resp = client.post('/api/scheduler/report',
                               headers={'Authorization': f'Bearer {token}'},
                               json={
                                   'schedule_id': sid,
                                   'started_at': int(time.time()) - 5,
                                   'finished_at': int(time.time()),
                                   'exit_code': 0,
                                   'output': 'job output success',
                               })
        self.assertEqual(rep_resp.status_code, 200)
        self.assertTrue(rep_resp.get_json()['ok'])

        # 6. Check runs endpoint
        resp = client.get(f'/api/scheduler/schedules/{sid}/runs')
        self.assertEqual(resp.status_code, 200)
        runs = resp.get_json()['runs']
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]['schedule_id'], sid)

        # 7. On-demand verify endpoint
        v_resp = client.post(f'/api/scheduler/schedules/{sid}/verify', json={'run_id': runs[0]['run_id']})
        self.assertEqual(v_resp.status_code, 200)
        self.assertEqual(v_resp.get_json()['status'], 'verified')

        # 8. On-demand local run endpoint
        cmd_sched = client.post('/api/scheduler/schedules', json={
            'name': 'echo-schedule',
            'host': 'nas',
            'cron_expr': '0 * * * *',
            'task_type': 'command',
            'task_ref': 'echo "manual local run ok"',
        }).get_json()['schedule']
        run_resp = client.post(f'/api/scheduler/schedules/{cmd_sched["schedule_id"]}/run', json={'local': True})
        self.assertEqual(run_resp.status_code, 200)
        self.assertEqual(run_resp.get_json()['status'], 'verified')

    def test_scan_ingest_alerts_drift_and_logbook(self):
        from storageforge_index import alerts, deploy, logbook
        sched, _ = scheduler.create_schedule(self.conn, {
            'name': 'scan-fallback-sched',
            'host': 'nas',
            'cron_expr': '0 * * * *',
            'task_type': 'command',
            'task_ref': 'echo ok',
        }, 'admin')
        sid = sched['schedule_id']

        # Deploy items & mark deployed
        items = scheduler.deploy_items(self.db, self.conn, sched, 'report', 'http://localhost:8080', 'admin')
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'schedules')
        deploy.mark_deployed(self.conn, 'nas', 'schedules', str(sid), scheduler.schedule_hash(sched),
                             {'name': sched['name']}, 'admin')
        inst = scheduler.installed(self.conn)
        self.assertIn(str(sid), inst)

        # Scan fallback ingestion
        now = int(time.time())
        scan_jsonl = json.dumps({
            'schedule_id': sid,
            'started_at': now - 30,
            'finished_at': now - 25,
            'exit_code': 1,
            'output': 'simulated failure from scan jsonl',
            'nonce': 'nonce-scan-1',
        })
        added = scheduler.ingest_scan_schedules(self.conn, 'nas', scan_jsonl)
        self.assertEqual(added, 1)
        # Deduplication check
        self.assertEqual(scheduler.ingest_scan_schedules(self.conn, 'nas', scan_jsonl), 0)

        # Alerts problems should flag schedule-failed:<sid>
        probs = alerts.problems(self.conn)
        self.assertIn(f'schedule-failed:{sid}', probs)

        # Update schedule -> drift should report pending
        scheduler.update_schedule(self.conn, sid, {'cron_expr': '*/15 * * * *'}, 'admin')
        dr = alerts.drift(self.conn)
        self.assertTrue(any(d['ref'] == f'sched-{sid}' and d['kind'] == 'pending' for d in dr))

        # Unified logbook integration
        flt = logbook.clean_filter(sources='schedule')
        entries = logbook.entries(self.conn, flt)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['source'], 'schedule')
        self.assertIn('simulated failure from scan jsonl', logbook.output_of(self.conn, entries[0]['id']))


if __name__ == '__main__':
    unittest.main()
