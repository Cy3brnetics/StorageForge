"""Unit tests for the StorageForge Unified Scheduler and Client Runner."""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import zoneinfo
from pathlib import Path

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
            'task_type': 'command',
            'task_ref': 'true',
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
        self.assertIn('* * * * * root /usr/local/sbin/storageforge-scheduler run 42 --if-due', cron)
        self.assertIn('15 4 * * *', cron)

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
        deploy.mark_deployed(self.conn, 'nas', 'schedules', str(sid), scheduler.schedule_hash(self.conn, sched),
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


class SafetyCase(SchedulerBaseTest):
    """A server with an admin, an operator and a viewer signed in."""
    PW = 'a long enough password'

    def setUp(self):
        super().setUp()
        from storageforge_index import server, users
        self.users = users
        self.web = server.create_app(server.App(self.db), 's' * 48)
        users.create(self.conn, 'boss', self.PW, 'admin')
        users.create(self.conn, 'op', self.PW, 'operator')
        users.create(self.conn, 'view', self.PW, 'viewer')
        self.boss, self.op, self.view = self.client('boss'), self.client('op'), self.client('view')

    def client(self, name):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': self.PW}).status_code, 200)
        return c

    def schedule(self, c=None, **kw):
        r = (c or self.boss).post('/api/scheduler/schedules', json={
            'name': 'sched', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true', **kw})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        return r.get_json()['schedule']['schedule_id']

    def stale(self, c):
        with c.session_transaction() as s:
            s['auth_at'] = 0

    def mark_deployed(self, sid, host='nas'):
        from storageforge_index import deploy
        deploy.mark_deployed(self.conn, host, 'schedules', str(sid), 'h', {}, 'test')


class SchedulerSafetyTests(SafetyCase):
    """From the 2026-10-31 audit: SF-23, SF-25, SF-26, PF-19, SF-28 and SF-30."""

    def test_a_schedule_never_runs_on_the_server(self):      # SF-23
        marker = Path(self.tmp) / 'RAN'
        sid = self.schedule(task_ref=f'touch {marker}')
        r = self.boss.post(f'/api/scheduler/schedules/{sid}/run', json={'local': True})
        self.assertFalse(marker.exists())
        self.assertEqual(r.status_code, 409)                 # the deploy path: this host has no deploy access
        self.assertIn('deploy access', r.get_json()['error'])

    def test_scheduler_writes_need_a_fresh_password(self):   # SF-25
        sid = self.schedule()
        self.stale(self.boss)
        for method, path, body in (('post', '/api/scheduler/schedules', {}),
                                   ('put', f'/api/scheduler/schedules/{sid}', {}),
                                   ('delete', f'/api/scheduler/schedules/{sid}', None),
                                   ('post', f'/api/scheduler/schedules/{sid}/pause', {}),
                                   ('post', f'/api/scheduler/schedules/{sid}/token', None),
                                   ('post', f'/api/scheduler/schedules/{sid}/run', {})):
            r = getattr(self.boss, method)(path, json=body)
            self.assertEqual((path, method, r.status_code, r.get_json().get('reauth')), (path, method, 403, True))
        self.assertEqual(self.boss.get(f'/api/scheduler/schedules/{sid}').status_code, 200)   # reading needs none

    def test_running_a_schedule_applies_preflight(self):     # SF-25
        from unittest import mock
        from storageforge_index import deploy, preflight
        sid = self.schedule()
        with mock.patch.object(deploy, 'ready', return_value=True), mock.patch.object(deploy, 'start_group') as start, \
                mock.patch.object(preflight, 'blockers', return_value=[{'host': 'nas', 'text': 'no bash'}]):
            r = self.boss.post(f'/api/scheduler/schedules/{sid}/run', json={})
        self.assertEqual(r.status_code, 409)
        start.assert_not_called()

    def test_a_schedule_cannot_be_destructive(self):         # SF-26
        self.users.save_role(self.conn, 'nodestroy', '', ['plans.edit', 'plans.view', 'deploy.apply'], 'boss', True)
        self.users.create(self.conn, 'nd', self.PW, 'nodestroy')
        nd = self.client('nd')
        plan = nd.post('/api/changes', json={'name': 'p', 'tasks': []}).get_json()['id']
        body = {'name': 'd', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'change', 'task_ref': str(plan)}
        for c in (nd, self.boss):                            # nobody: it is not a permission question
            self.assertEqual(c.post('/api/scheduler/schedules', json={**body, 'config': {'destructive': True}}).status_code, 400)
        sid = self.schedule(nd, **{k: body[k] for k in ('task_type', 'task_ref')})
        self.assertEqual(nd.put(f'/api/scheduler/schedules/{sid}', json={'config': {'destructive': True}}).status_code, 400)
        # a row saved by an older version
        cfg = scheduler.get_schedule(self.conn, sid)['config']
        self.conn.execute('UPDATE schedules SET config_json = :c WHERE schedule_id = :i', {'c': json.dumps({**cfg, 'destructive': True}), 'i': sid})
        self.assertEqual(scheduler.generate_task_script(self.conn, scheduler.get_schedule(self.conn, sid))[1], ['--apply'])

    def test_a_deployed_schedule_cannot_be_deleted(self):    # PF-19
        sid = self.schedule()
        self.mark_deployed(sid)
        r = self.boss.delete(f'/api/scheduler/schedules/{sid}')
        self.assertEqual(r.status_code, 409)
        self.assertIn('uninstall', r.get_json()['error'])
        self.assertEqual(scheduler.get_schedule(self.conn, sid)['schedule_id'], sid)
        self.conn.execute("DELETE FROM deployed WHERE kind = 'schedules'")
        self.assertEqual(self.boss.delete(f'/api/scheduler/schedules/{sid}').status_code, 200)

    def test_a_schedule_already_deleted_can_be_uninstalled(self):   # PF-19
        from unittest import mock
        from storageforge_index import alerts, deploy
        sid = self.schedule()
        self.mark_deployed(sid)
        self.conn.execute('DELETE FROM schedules WHERE schedule_id = :i', {'i': sid})
        self.assertTrue(any(d.get('schedule') == sid and d['deleted'] for d in alerts.drift(self.conn)))
        self.assertEqual(self.boss.post('/api/deploy/start', json={'kind': 'schedules', 'ref': sid, 'mode': 'apply'}).status_code, 400)
        with mock.patch.object(deploy, 'ready', return_value=True), mock.patch.object(deploy, 'start_group', return_value='g') as start:
            r = self.boss.post('/api/deploy/start', json={'kind': 'schedules', 'ref': sid, 'mode': 'apply', 'remove': True})
        self.assertEqual((r.status_code, r.get_json()['hosts']), (200, ['nas']))
        item = start.call_args.args[1][0]
        self.assertEqual(item['args'], ['--uninstall'])
        self.assertEqual(subprocess.run(['bash', '-n'], input=item['script'], text=True).returncode, 0)
        self.assertIn(f'/etc/cron.d/sf-sched-{sid}', item['script'])
        item['on_ok']({'status': 'ok'})
        self.assertEqual(deploy.deployed(self.conn, kind='schedules'), [])

    def test_git_routes_do_not_reach_the_server(self):       # SF-28
        repo = Path(self.tmp) / 'repo'
        marker = Path(self.tmp) / 'HOOK-RAN'
        hook = Path(self.tmp) / 'hook.sh'
        hook.write_text(f'#!/bin/sh\ntouch {marker}\n')
        hook.chmod(0o755)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'config', 'core.fsmonitor', str(hook)], check=True)
        for name in ('local', 'localhost', 'LOCALHOST', '127.0.0.1', '::1'):
            q = {'host': name, 'path': str(repo)}
            self.assertEqual(self.op.post('/api/git/status', json=q).status_code, 404, name)
            self.assertEqual(self.op.post('/api/git/history', json=q).status_code, 404, name)
            self.assertEqual(self.op.post('/api/git/commit', json={**q, 'sha': 'abcd'}).status_code, 404, name)
            self.assertEqual(self.op.post('/api/git/sync', json={**q, 'action': 'fetch'}).status_code, 404, name)
        self.assertFalse(marker.exists())

    def test_read_only_accounts_do_not_see_secrets(self):    # SF-30
        from storageforge_index import alerts
        secret = 'curl -H "X: tok-in-command" x'
        sid = self.schedule(task_ref=secret, config={'env': {'API_KEY': 'hunter2'}})
        tid = self.boss.post('/api/tasks', json={'name': 'nightly', 'host': 'nas', 'blocks': []}).get_json()['id']
        task = self.schedule(name='plain', task_type='task', task_ref=str(tid))
        alerts.set_setting(self.conn, 'alerts', {**alerts.get_setting(self.conn, 'alerts'),
                                                 'webhook': {'url': 'https://hooks.example.test/services/SECRET-PATH'},
                                                 'ntfy': {'url': 'https://ntfy.example.test', 'topic': 'secret-topic', 'token': 't'}}, 'boss')
        report = {'schedule_id': sid, 'exit_code': 0, 'output': 'printed-secret'}
        scheduler.ingest_report(self.conn, report, 'test')

        for r in (self.view.get('/api/scheduler/schedules'), self.view.get(f'/api/scheduler/schedules/{sid}')):
            text = r.get_data(as_text=True)
            self.assertEqual(r.status_code, 200)
            self.assertNotIn('hunter2', text)
            self.assertNotIn('tok-in-command', text)
        self.assertIn('API_KEY', self.view.get(f'/api/scheduler/schedules/{sid}').get_data(as_text=True))
        self.assertEqual(self.view.get(f'/api/scheduler/schedules/{task}').get_json()['task_ref'], str(tid))
        got = self.boss.get(f'/api/scheduler/schedules/{sid}').get_json()    # who may edit reads what they edit
        self.assertEqual((got['task_ref'], got['config']['env']), (secret, {'API_KEY': 'hunter2'}))

        shown = self.view.get('/api/deploy').get_json()['settings']['alerts']
        self.assertEqual(shown['webhook']['url'], 'https://hooks.example.test')
        self.assertEqual(shown['ntfy']['topic'], '••••••')
        self.assertNotIn('SECRET-PATH', self.view.get('/api/deploy').get_data(as_text=True))
        self.assertIn('SECRET-PATH', self.boss.get('/api/deploy').get_data(as_text=True))

        self.users.save_role(self.conn, 'plansonly', '', ['plans.view'], 'boss', True)
        self.users.create(self.conn, 'po', self.PW, 'plansonly')
        po = self.client('po')
        self.assertEqual(po.get(f'/api/scheduler/schedules/{sid}/runs').status_code, 403)
        self.assertEqual(po.get('/api/scheduler/runs').status_code, 403)
        self.assertEqual(po.get(f'/api/scheduler/schedules/{sid}').status_code, 200)
        self.assertIn('printed-secret', self.view.get(f'/api/scheduler/schedules/{sid}/runs').get_data(as_text=True))  # viewers hold logs.view

    def report(self, sid, token, **kw):
        return self.web.test_client().post('/api/scheduler/report', headers={'Authorization': f'Bearer {token}'},
                                           json={'schedule_id': sid, 'exit_code': 0, 'output': '', **kw})

    def created(self, **kw):
        r = self.boss.post('/api/scheduler/schedules', json={'name': 'made', 'host': 'nas', 'cron_expr': '0 3 * * *',
                                                             'task_type': 'command', 'task_ref': 'true', **kw})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        return r.get_json()['schedule']['schedule_id'], r.get_json()['token']

    def test_large_reports_are_stored(self):                 # PF-18
        sid, token = self.created()
        self.assertEqual(self.report(sid, token, output='x' * (200 << 10)).status_code, 200)
        self.assertEqual(len(self.conn.scalar('SELECT output FROM schedule_runs WHERE schedule_id = :s', {'s': sid})), 200 << 10)
        self.assertEqual(self.web.test_client().post('/api/enroll', data='x' * 8192, content_type='application/json').status_code, 413)   # others keep 4 KiB
        data = schedscript.fit_report({'schedule_id': sid, 'output': 'a' * 100 + '\\n' * (1 << 20) + 'the end'})
        self.assertLessEqual(len(data), schedscript.REPORT_MAX)
        self.assertTrue(json.loads(data)['output'].endswith('the end'))

    def test_patterns_are_checked_and_cannot_lose_a_report(self):   # SF-32
        for pattern in ('output_must_match', 'output_must_not_match'):
            r = self.boss.post('/api/scheduler/schedules', json={'name': 'bad', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command',
                                                                 'task_ref': 'true', 'config': {'verify_rules': {pattern: '('}}})
            self.assertEqual(r.status_code, 400)
        sid, token = self.created()
        cfg = scheduler.get_schedule(self.conn, sid)['config']       # a row saved by an older version
        cfg['verify_rules']['output_must_match'] = '('
        self.conn.execute('UPDATE schedules SET config_json = :c WHERE schedule_id = :i', {'c': json.dumps(cfg), 'i': sid})
        self.assertEqual(self.report(sid, token, exit_code=1, output='failed').status_code, 200)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM schedule_runs WHERE schedule_id = :s', {'s': sid}), 1)

    def test_a_slow_pattern_is_stopped(self):                # SF-32
        from unittest import mock
        with mock.patch.object(scheduler, 'REGEX_SECONDS', 0.5):
            started = time.time()
            self.assertIsNone(scheduler._search('(a+)+$', 'a' * 40 + 'b'))
            self.assertLess(time.time() - started, 5)
        self.assertTrue(scheduler._search('o+k', 'ok'))
        self.assertFalse(scheduler._search('nope', 'ok'))

    def test_the_hash_covers_what_a_schedule_runs(self):     # PF-21
        block = {'type': 'btrfs_snapshot', 'params': {'subvol': '/mnt/data'}}
        task = self.boss.post('/api/tasks', json={'name': 'digest', 'host': 'nas', 'blocks': [block]}).get_json()['id']
        sid = self.schedule(task_type='task', task_ref=str(task))
        before = scheduler.schedule_hash(self.conn, scheduler.get_schedule(self.conn, sid))
        changed = {**block, 'params': {'subvol': '/mnt/other'}}
        r = self.boss.put(f'/api/tasks/{task}', json={'name': 'digest', 'host': 'nas', 'blocks': [changed]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotEqual(before, scheduler.schedule_hash(self.conn, scheduler.get_schedule(self.conn, sid)))

    def test_tokens_change_only_when_a_host_gets_the_new_one(self):   # SF-31
        from storageforge_index import alerts
        sid, token = self.created()
        r = self.boss.get(f'/api/scheduler/schedules/{sid}/install-script', headers={'Host': 'attacker.test'})
        self.assertEqual(self.report(sid, token, nonce='a').status_code, 200)    # a GET changed nothing
        self.assertNotIn('attacker.test', r.get_data(as_text=True))
        self.assertEqual(self.report(sid, token, nonce='a').get_json().get('duplicate'), True)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM schedule_runs WHERE schedule_id = :s', {'s': sid}), 1)
        self.assertEqual(self.report(sid, token, started_at=int(time.time()) + 86400).status_code, 400)
        alerts.set_setting(self.conn, 'report_url', 'https://sf.example.test', 'boss')
        items = scheduler.deploy_items(self.db, self.conn, scheduler.get_schedule(self.conn, sid), 'apply', 'https://sf.example.test', 'boss')
        self.assertEqual(self.report(sid, token, nonce='b').status_code, 200)    # still the old one: nothing has been installed
        items[0]['on_ok']({'status': 'failed'})
        self.assertEqual(self.report(sid, token, nonce='c').status_code, 200)
        items[0]['on_ok']({'status': 'ok'})
        self.assertEqual(self.report(sid, token, nonce='d').status_code, 401)
        new = json.loads(items[0]['script'].split("EOF_CFG' > \"$CFG_JSON\"\n")[1].split('\nEOF_CFG')[0])['token']
        self.assertEqual(self.report(sid, new, nonce='e').status_code, 200)

    def test_pausing_reaches_the_host(self):                 # PF-20
        from unittest import mock
        from storageforge_index import alerts, deploy
        sid = self.schedule()
        self.assertNotIn('group', self.boss.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).get_json())   # nothing deployed
        self.boss.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': False})
        sched = scheduler.get_schedule(self.conn, sid)
        deploy.mark_deployed(self.conn, 'nas', 'schedules', str(sid), scheduler.schedule_hash(self.conn, sched), {}, 'test')

        r = self.boss.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).get_json()    # no deploy access
        self.assertEqual(r['host_pending'], ['nas'])
        paused = scheduler.get_schedule(self.conn, sid)
        self.assertTrue(scheduler.pause_pending(self.conn, paused))   # alerts keep watching
        self.assertTrue([d for d in alerts.drift(self.conn) if d.get('schedule') == sid])

        with mock.patch.object(deploy, 'ready', return_value=True), mock.patch.object(deploy, 'start_group', return_value='g') as start:
            r = self.boss.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).get_json()
        self.assertEqual(r['group'], 'g')
        item = start.call_args.args[1][0]
        self.assertEqual(item['args'], ['--install'])
        self.assertIn('PAUSED=1', item['script'])
        item['on_ok']({'status': 'ok'})
        self.assertFalse(scheduler.pause_pending(self.conn, scheduler.get_schedule(self.conn, sid)))

    def test_commands_need_their_own_permission(self):       # SF-24
        body = {'name': 'c', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'id'}
        self.assertEqual(self.op.post('/api/scheduler/schedules', json=body).status_code, 403)
        sid = self.schedule()
        self.assertEqual(self.op.put(f'/api/scheduler/schedules/{sid}', json={'task_ref': 'id'}).status_code, 403)
        self.assertEqual(self.op.post(f'/api/scheduler/schedules/{sid}/run', json={}).status_code, 403)
        self.assertEqual(self.op.post('/api/deploy/start', json={'kind': 'schedules', 'ref': sid, 'mode': 'apply'}).status_code, 403)
        plan = self.op.post('/api/changes', json={'name': 'mine', 'tasks': []}).get_json()['id']
        other = self.schedule(self.op, name='ok', task_type='change', task_ref=str(plan))
        self.assertEqual(self.op.put(f'/api/scheduler/schedules/{other}', json={'task_type': 'command', 'task_ref': 'id'}).status_code, 403)
        items = scheduler.deploy_items(self.db, self.conn, scheduler.get_schedule(self.conn, sid), 'report', None, 'boss')
        self.assertIn('runs: true', items[0]['script'])     # the dry run shows it

    def test_env_cannot_change_what_runs(self):              # SF-24
        for name in ('BASH_ENV', 'LD_PRELOAD', 'PATH', 'ld_library_path', 'GIT_SSH', 'PYTHONPATH', 'ENV'):
            r = self.boss.post('/api/scheduler/schedules', json={'name': 'e', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command',
                                                                 'task_ref': 'true', 'config': {'env': {name: '/tmp/x'}}})
            self.assertEqual((name, r.status_code), (name, 400))
        sid = self.schedule(config={'env': {'RETENTION': '7'}})
        cfg = scheduler.get_schedule(self.conn, sid)['config']       # a row saved by an older version
        cfg['env']['BASH_ENV'] = '/tmp/x'
        self.conn.execute('UPDATE schedules SET config_json = :c WHERE schedule_id = :i', {'c': json.dumps(cfg), 'i': sid})
        out = json.loads(scheduler.generate_client_config(scheduler.get_schedule(self.conn, sid), None, ''))
        self.assertEqual(out['config']['env'], {'RETENTION': '7'})

    def test_settings_reach_the_runner(self):                # PF-22
        from unittest import mock
        cmd = schedscript.task_command({'nice': 5, 'ionice_class': 'best-effort', 'ionice_priority': 4}, '/t.sh', ['--run'])
        if schedscript.shutil.which('nice'):
            self.assertEqual(cmd[:3], ['nice', '-n', '5'])
        self.assertEqual(cmd[-2:], ['/t.sh', '--run'])
        conf = {'cron_expr': '0 3 * * *', 'config': {'timezone': 'Asia/Tokyo'}}
        self.assertTrue(schedscript.is_due(conf, dt.datetime(2026, 1, 1, 18, 0, tzinfo=dt.timezone.utc).astimezone(zoneinfo.ZoneInfo('Asia/Tokyo'))))
        self.assertFalse(schedscript.is_due(conf, dt.datetime(2026, 1, 1, 3, 0, tzinfo=dt.timezone.utc).astimezone(zoneinfo.ZoneInfo('Asia/Tokyo'))))
        sched = {'schedule_id': 1, 'name': 'n', 'cron_expr': '0 3 * * *', 'config': {'jitter_sec': 30, 'user': 'backup'}}
        cron = scheduler.generate_cron_entry(sched)
        self.assertIn('* * * * * root ', cron)               # root reads the token; the runner drops to the user
        self.assertIn('--if-due --jitter', cron)
        with mock.patch.object(os, 'geteuid', return_value=0), self.assertRaises(KeyError):
            schedscript.as_user('no-such-user-here')
        self.assertEqual(schedscript.as_user('root'), {})

    def test_an_unknown_user_is_a_failed_run(self):          # PF-22
        from unittest import mock
        script = Path(self.tmp) / 't.sh'
        script.write_text('echo ran\n')
        with mock.patch.object(schedscript, 'as_user', side_effect=KeyError('nobody-here')):
            rc = schedscript.run_schedule({'schedule_id': 9, 'script_path': str(script), 'config': {'user': 'nobody-here'}},
                                          var_dir=self.tmp, locks_dir=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn('nobody-here', (Path(self.tmp) / '9' / 'last.json').read_text())

    def test_a_schedule_stays_on_its_own_host(self):         # PF-23
        task = self.boss.post('/api/tasks', json={'name': 'elsewhere', 'host': 'backup-box', 'blocks': []}).get_json()['id']
        base = {'name': 'x', 'host': 'nas', 'cron_expr': '0 3 * * *'}
        for kw in ({'task_type': 'task', 'task_ref': str(task)}, {'task_type': 'shares', 'task_ref': 'backup-box'},
                   {'task_type': 'task', 'task_ref': 'no such task'}, {'task_type': 'scan', 'task_ref': 'nas'},
                   {'task_type': 'task', 'task_ref': str(task), 'host': 'backup-box', 'config': {'user': 'backup'}}):
            r = self.boss.post('/api/scheduler/schedules', json={**base, **kw})
            self.assertEqual((kw['task_type'], r.status_code), (kw['task_type'], 400), r.get_data(as_text=True))
        ok = self.schedule(task_type='task', task_ref=str(task), host='backup-box')
        self.boss.put(f'/api/tasks/{task}', json={'name': 'elsewhere', 'host': 'nas', 'blocks': []})   # moved after it was scheduled
        with self.assertRaises(ValueError):
            scheduler.deploy_items(self.db, self.conn, scheduler.get_schedule(self.conn, ok), 'apply', None, 'boss')


class HostSideSafetyTests(SafetyCase):
    """From the 2026-10-31 audit: SF-27, SF-29, SF-33, SF-34 and PF-25."""

    def planted(self):
        """A repository whose own config and attributes name programs, and a marker each one touches."""
        repo = Path(tempfile.mkdtemp(dir=self.tmp)) / 'repo'
        self.mark = repo.parent / 'RAN'
        hook = repo.parent / 'hook.sh'
        hook.write_text(f'#!/bin/sh\ntouch {self.mark}\ncat\n')
        hook.chmod(0o755)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        for key, val in (('user.email', 't@t'), ('user.name', 'T')):
            subprocess.run(['git', '-C', str(repo), 'config', key, val], check=True)
        (repo / 'f.txt').write_text('one\n')
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'first'], check=True)
        for key, val in (('core.fsmonitor', str(hook)), ('core.hooksPath', str(repo.parent)), ('gpg.program', str(hook)),
                         ('log.showSignature', 'true'), ('core.pager', str(hook)), ('filter.evil.clean', str(hook))):
            subprocess.run(['git', '-C', str(repo), 'config', key, val], check=True)
        (repo / '.gitattributes').write_text('*.txt filter=evil\n')
        (repo / 'f.txt').write_text('two\n')
        return repo

    def bash(self, script, *args, stdin=None):
        return subprocess.run(['bash', '-c', script, *args], capture_output=True, text=True, input=stdin or '', timeout=60)

    def foreign(self, script):
        from storageforge_index import gitrepos
        self.assertIn(gitrepos.OWNED, script)
        return script.replace(gitrepos.OWNED, 'owned() { false; }')

    def test_a_repository_cannot_run_code_during_status(self):      # SF-27
        from storageforge_index import gitrepos
        repo = self.planted()
        r = self.bash(f'R={repo}\n' + self.foreign(gitrepos._STATUS_BASH))
        self.assertFalse(self.mark.exists(), r.stdout)
        self.assertIn('foreign\t1', r.stdout)
        self.assertNotIn('@@porcelain', r.stdout)
        self.assertIn('first', r.stdout)                  # what needs no worktree still reads
        r = self.bash(f'R={repo}\n' + gitrepos._HISTORY_BASH.replace('$MAX', '5'))
        self.assertFalse(self.mark.exists(), r.stdout)
        self.assertIn('first', r.stdout)

    def test_a_repository_cannot_run_code_during_a_scan(self):      # SF-27
        from storageforge_index import gitrepos
        repo = self.planted()
        r = subprocess.run(['bash', '-c', self.foreign(gitrepos._SURVEY_BASH)], input=f'{repo}\0', capture_output=True, text=True, timeout=60)
        self.assertIn(f'@@repo\t{repo}', r.stdout)
        self.assertNotIn('dirty', r.stdout)
        self.assertFalse(self.mark.exists(), r.stdout)

    def test_an_owned_repository_is_still_read_without_its_monitor(self):   # SF-27
        from storageforge_index import gitrepos
        repo = self.planted()
        subprocess.run(['git', '-C', str(repo), 'config', '--unset', 'filter.evil.clean'], check=True)
        r = self.bash(f'R={repo}\n' + gitrepos._STATUS_BASH)
        self.assertIn('@@porcelain', r.stdout)
        self.assertIn('f.txt', r.stdout)
        self.assertFalse(self.mark.exists(), r.stdout)

    def seed_repo(self, path='/srv/repo'):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute('INSERT INTO git_repos (host_id, path, remotes_json, scan_id) VALUES (:h, :p, :r, 0)', {'h': hid, 'p': path, 'r': '[]'})

    def test_only_found_repositories_are_touched(self):      # SF-27
        for route, extra in (('status', {}), ('history', {}), ('commit', {'sha': 'abcd'}), ('sync', {'action': 'fetch'})):
            r = self.boss.post(f'/api/git/{route}', json={'host': 'nas', 'path': '/etc', **extra})
            self.assertEqual((route, r.status_code), (route, 404))

    def test_git_routes_follow_the_rules(self):              # SF-29
        from unittest import mock
        from storageforge_index import deploy, gitrepos
        self.seed_repo()
        for route in ('status', 'history', 'commit'):        # POST only
            self.assertEqual(self.boss.get(f'/api/git/{route}', query_string={'host': 'nas', 'path': '/srv/repo'}).status_code, 405)
        body = {'host': 'nas', 'path': '/srv/repo'}
        self.assertEqual(self.boss.post('/api/git/sync', json={**body, 'action': 'fetch'}).status_code, 409)     # no deploy access
        with mock.patch.object(deploy, 'ready', return_value=True), mock.patch.object(gitrepos, 'repo_status', side_effect=RuntimeError), \
                mock.patch.object(deploy, 'run', return_value={'status': 'ok', 'output': 'Done.'}) as run:
            r = self.boss.post('/api/git/sync', json={**body, 'action': 'pull'})
        self.assertEqual((r.status_code, r.get_json()['ok']), (200, True))
        self.assertEqual(run.call_args.kwargs['kind'], 'git_sync')
        self.assertIn('ACT=pull', run.call_args.args[2])
        with mock.patch.object(gitrepos, 'repo_status', return_value={'ok': True}):
            self.boss.post('/api/git/status', json=body)
        with mock.patch.object(gitrepos, 'repo_history', return_value={}) as hist:
            self.boss.post('/api/git/history', json={**body, 'max': -1})
            self.assertEqual(hist.call_args.args[3], 1)
            self.boss.post('/api/git/history', json={**body, 'max': 100000})
            self.assertEqual(hist.call_args.args[3], 200)
        seen = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'git.%'")]
        self.assertGreaterEqual(seen.count('git.sync'), 2)
        self.assertIn('git.status', seen)
        self.assertIn('git.history', seen)
        self.stale(self.boss)
        for action in ('fetch', 'pull', 'sync', 'push'):
            r = self.boss.post('/api/git/sync', json={**body, 'action': action})
            self.assertEqual((action, r.status_code, r.get_json().get('reauth')), (action, 403, True))

    def test_sync_runs_no_hooks(self):                       # SF-29
        from storageforge_index import gitrepos
        repo = self.planted()
        fired = repo.parent / 'HOOK-FIRED'
        (repo / '.git' / 'hooks' / 'post-merge').write_text(f'#!/bin/sh\ntouch {fired}\n')
        (repo / '.git' / 'hooks' / 'post-merge').chmod(0o755)
        for key in ('core.hooksPath', 'filter.evil.clean', 'core.fsmonitor'):
            subprocess.run(['git', '-C', str(repo), 'config', '--unset', key], check=True)
        (repo / '.gitattributes').unlink()
        subprocess.run(['git', '-C', str(repo), 'checkout', '-q', '.'], check=True)
        up = repo.parent / 'up.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(repo), str(up)], check=True)
        subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', str(up)], check=True)
        subprocess.run(['git', '-C', str(repo), 'fetch', '-q', 'origin'], check=True)
        branch = subprocess.run(['git', '-C', str(repo), 'symbolic-ref', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
        subprocess.run(['git', '-C', str(repo), 'branch', '-q', f'--set-upstream-to=origin/{branch}'], check=True)
        other = repo.parent / 'other'
        subprocess.run(['git', 'clone', '-q', str(up), str(other)], check=True)
        subprocess.run(['git', '-C', str(other), '-c', 'user.name=T', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'second'], check=True)
        subprocess.run(['git', '-C', str(other), 'push', '-q'], check=True)
        r = self.bash(f'R={repo}\nACT=pull\n' + gitrepos._SYNC_BASH)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('second', subprocess.run(['git', '-C', str(repo), 'log', '-1', '--format=%s'], capture_output=True, text=True).stdout)
        self.assertFalse(fired.exists())
        self.assertNotEqual(self.bash(f'R={repo.parent}\nACT=pull\n' + gitrepos._SYNC_BASH).returncode, 0)

    def test_the_log_fetch_keeps_host_text_as_data(self):    # SF-33
        from unittest import mock
        from storageforge_index import confirm, deploy
        now = int(time.time())
        lines = [json.dumps({'task': 'nightly', 'started': now, 'rc': 1}),
                 json.dumps({'task': 'x; touch /tmp/CANARY', 'started': now, 'rc': 1}),
                 json.dumps({'task': 'bad-time', 'started': 'soon', 'rc': 1})]
        self.assertEqual(confirm.ingest_tasks(self.conn, 'nas', '\n'.join(lines)), 2)   # the bad line is skipped, nothing raises
        long = 'x' * (confirm.MAX_LOG + 100)
        with mock.patch.object(deploy, 'ready', return_value=True), \
                mock.patch.object(deploy, 'run', return_value={'output': long, 'run_id': None}) as run:
            confirm.fetch_problem_logs(self.db, self.conn, 'nas', [])
        scripts = [c.args[2] for c in run.call_args_list]
        self.assertEqual(len(scripts), 1)
        self.assertIn('sf-task-nightly', scripts[0])
        self.assertNotIn('messages', scripts[0])
        self.assertEqual(len(self.conn.scalar('SELECT output FROM host_logs')), confirm.MAX_LOG)

    def test_an_installed_copy_leaves_the_runner_alone(self):       # SF-34
        from storageforge_index import deploy
        runner = Path(self.tmp) / 'storageforge-run'
        runner.write_text('newer runner\n')
        script = deploy.RUNNER_UPDATE.replace('((EUID == 0))', 'true').replace('-o root -g root ', '').replace(deploy.RUNNER, str(runner))
        r = self.bash(script, '/usr/local/lib/storageforge/tasks/nightly.sh')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(runner.read_text(), 'newer runner\n')
        self.bash(script, '/run/sf-run.abc/script')          # a deploy still brings it up to date
        self.assertEqual(runner.read_text(), deploy.RUNNER_SCRIPT)

    def test_a_backup_copy_is_a_signed_run(self):            # PF-25
        from unittest import mock
        from storageforge_index import backup, deploy
        src = Path(self.tmp) / 'storageforge-essentials-1.db'
        src.write_bytes(b'backup bytes' * 10000)
        dst = Path(self.tmp) / "off box's"
        dst.mkdir()
        (dst / 'notes.txt').write_text('mine')
        got = {}

        def run(db, host, script, *a, **kw):
            got.update(host=host, kw=kw)
            done = subprocess.run(['bash', '-c', script], input=b''.join(kw['data']), capture_output=True, timeout=30)
            return {'status': 'ok' if done.returncode == 0 else 'failed', 'output': done.stderr.decode()}
        target = {'host': 'backup-box', 'path': str(dst)}
        with mock.patch.object(deploy, 'run', run):
            backup.copy_off(self.db, self.conn, str(src), target, 2)
        self.assertEqual((got['host'], got['kw']['kind']), ('backup-box', 'backup_copy'))
        self.assertEqual((dst / src.name).read_bytes(), src.read_bytes())
        self.assertEqual((dst / 'notes.txt').read_text(), 'mine')
        with mock.patch.object(deploy, 'run', return_value={'status': 'refused', 'output': 'signature'}), self.assertRaises(RuntimeError):
            backup.copy_off(self.db, self.conn, str(src), target, 2)
