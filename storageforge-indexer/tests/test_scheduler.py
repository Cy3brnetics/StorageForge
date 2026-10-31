"""Unit tests for the StorageForge Unified Scheduler and Client Runner."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import sqlite3
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
                          f"VALUES (:m, :d, 'archive.tar.gz', FALSE, 1024, {self.db.ts('0')})",
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
        self.assertIn('* * * * * root /usr/local/lib/storageforge/scheduler/run-42.sh --if-due', cron)
        self.assertIn('15 4 * * *', cron)

        bundle = scheduler.generate_install_script(self.conn, s, 'http://server:8080', 'secret_token')
        self.assertIn('/etc/cron.d/sf-sched-42', bundle)
        self.assertIn('/etc/systemd/system/$UNIT.timer', bundle)
        self.assertIn('secret_token', bundle)


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

        self.conn.execute(f"INSERT INTO scans (host_id, started_at, finished_at, status) VALUES (:h, {self.db.ts(':t')}, {self.db.ts(':t')}, 'ok')",
                          {'h': self.hid_nas, 't': int(time.time()) + 1})     # a scan newer than the run
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
        self.assertIn(f'/usr/local/lib/storageforge/scheduler/run-{sid}.sh', resp.get_data(as_text=True))

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
        self.assertEqual(v_resp.get_json()['status'], 'reported')      # no scan is newer than this run

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
        new = re.search(r"printf '%s\\n' (\w+) >/etc/storageforge", items[0]['script'])[1]
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
        self.assertIn('rm -f /etc/systemd/system/sf-sched', item['script'])    # a reinstall starts by taking the timer away
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
        script = scheduler.generate_install_script(self.conn, scheduler.get_schedule(self.conn, sid), None, '')
        self.assertIn('RETENTION=7', script)
        self.assertNotIn('BASH_ENV', script)

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
        with mock.patch.object(deploy, 'run', run), mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'v' * 40}):
            backup.copy_off(self.db, self.conn, str(src), target, 2)
        self.assertEqual((got['host'], got['kw']['kind']), ('backup-box', 'backup_copy'))
        self.assertTrue((dst / (src.name + '.enc')).exists())
        self.assertEqual((dst / 'notes.txt').read_text(), 'mine')
        with mock.patch.object(deploy, 'run', return_value={'status': 'refused', 'output': 'signature'}), \
                mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'v' * 40}), self.assertRaises(RuntimeError):
            backup.copy_off(self.db, self.conn, str(src), target, 2)


class RunnerTests(unittest.TestCase):
    """The runner a schedule installs, run for real by bash with a stand-in curl (PF-26)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfrunner-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.tmp / 'etc' / 'scheduler').mkdir(parents=True)
        (self.tmp / 'etc' / 'scheduler' / '5.token').write_text('tok-123\n')
        curl = self.bin / 'curl'
        curl.write_text(f"""#!/bin/bash
while (($#)); do
  case $1 in -H) [[ $2 == @* ]] && cp "${{2#@}}" {self.tmp}/sent-header; shift ;;
    --data-binary) cp "${{2#@}}" {self.tmp}/sent-body; shift ;;
    -m) shift ;;
    http*) echo "$1" >{self.tmp}/sent-url ;;
  esac; shift
done
""")
        curl.chmod(0o755)

    def run_it(self, task, *args, cfg=None, times=None, script_args=('--go',), url='https://sf.test'):
        task_sh = self.tmp / 'task.sh'
        task_sh.write_text(task)
        sched = {'schedule_id': 5, 'name': "it's", 'config': {'timezone': 'UTC', **(cfg or {})}}
        every = (set(range(60)), set(range(24)), set(range(1, 32)), set(range(1, 13)), set(range(7)))
        runner = self.tmp / 'run.sh'
        runner.write_text(schedscript.runner_script(sched, list(script_args), times or every, url, (cfg or {}).get('env') or {}, str(task_sh)))
        return subprocess.run(['bash', str(runner), *args], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              env={**os.environ, 'STORAGEFORGE_SCHED_ROOT': str(self.tmp)})

    def lines(self):
        return [json.loads(x) for x in (self.tmp / 'var' / 'runs.jsonl').read_text().splitlines()]

    def test_no_flags_do_nothing(self):
        r = self.run_it(f'touch {self.tmp}/RAN\n')
        self.assertEqual(r.returncode, 0)
        self.assertFalse((self.tmp / 'RAN').exists())

    def test_a_run_reports_any_output_as_json(self):
        r = self.run_it("""printf 'quote " back\\\\slash\ttab\n'; printf 'bin \\377\\001 end\n'; echo "args $*"\n""", '--run')
        self.assertEqual(r.returncode, 0, r.stderr)
        body = json.loads((self.tmp / 'sent-body').read_bytes())
        self.assertEqual(body['schedule_id'], 5)
        self.assertEqual(body['exit_code'], 0)
        self.assertIn('quote " back\\slash\ttab', body['output'])
        self.assertIn('args --go', body['output'])
        self.assertNotIn('no_output', body)
        self.assertEqual((self.tmp / 'sent-header').read_text(), 'Authorization: Bearer tok-123\n')
        self.assertEqual((self.tmp / 'sent-url').read_text().strip(), 'https://sf.test/api/scheduler/report')

    def test_what_a_scan_can_read_holds_no_output(self):
        self.run_it('echo secret-output\n', '--run')
        var = self.tmp / 'var'
        self.assertEqual(oct((var / 'runs.jsonl').stat().st_mode & 0o777), '0o644')
        self.assertEqual(oct((var / 'last.out').stat().st_mode & 0o777), '0o600')
        self.assertNotIn('secret-output', (var / 'runs.jsonl').read_text())
        self.assertTrue(self.lines()[0]['no_output'])

    def test_a_long_run_fits_the_server_and_keeps_its_end(self):
        self.run_it('head -c 2000000 /dev/zero | tr "\\0" \\"; echo the-end\n', '--run')
        data = (self.tmp / 'sent-body').read_bytes()
        self.assertLessEqual(len(data), 512 << 10)
        self.assertTrue(json.loads(data)['output'].endswith('the-end\n'))

    def test_failures_retry_and_are_reported(self):
        count = self.tmp / 'n'
        r = self.run_it(f'echo x >>{count}; [[ $(wc -l <{count}) == 3 ]]\n', '--run', cfg={'retry_count': 5, 'retry_delay_sec': 1, 'retry_backoff': 1.0})
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.lines()[-1]['attempts'], 3)
        r = self.run_it('exit 7\n', '--run')
        self.assertEqual(r.returncode, 7)
        self.assertEqual(self.lines()[-1]['exit_code'], 7)

    def test_a_timeout_stops_the_task(self):
        r = self.run_it('sleep 30\n', '--run', cfg={'timeout_sec': 1})
        self.assertEqual(r.returncode, 124)

    def test_an_unknown_user_is_a_failed_run(self):          # PF-22
        r = self.run_it(f'touch {self.tmp}/RAN\n', '--run', cfg={'user': 'no-such-user-here'})
        self.assertEqual(r.returncode, 1)
        self.assertFalse((self.tmp / 'RAN').exists())
        self.assertIn('no user no-such-user-here', json.loads((self.tmp / 'sent-body').read_bytes())['output'])

    def test_settings_reach_the_task(self):                  # PF-22
        base = os.nice(0)
        r = self.run_it('nice; echo "v=$RETENTION"; [[ $(pwd) == / ]] && echo at-root\n', '--run', cfg={'nice': 5, 'env': {'RETENTION': '7'}})
        out = json.loads((self.tmp / 'sent-body').read_bytes())['output']
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(str(base + 5), out.split())
        self.assertIn('v=7', out)
        self.assertIn('at-root', out)

    def test_the_schedule_keeps_its_own_timezone(self):      # PF-22
        tokyo = dt.datetime.now(zoneinfo.ZoneInfo('Asia/Tokyo'))
        every = (set(range(60)), {tokyo.hour}, set(range(1, 32)), set(range(1, 13)), set(range(7)))
        other = (set(range(60)), {(tokyo.hour + 5) % 24}, set(range(1, 32)), set(range(1, 13)), set(range(7)))
        mark = self.tmp / 'RAN'
        self.run_it(f'touch {mark}\n', '--if-due', cfg={'timezone': 'Asia/Tokyo'}, times=other)
        self.assertFalse(mark.exists())
        self.run_it(f'touch {mark}\n', '--if-due', cfg={'timezone': 'Asia/Tokyo'}, times=every)
        self.assertTrue(mark.exists())

    def test_the_window_holds_back_a_run(self):
        now = dt.datetime.now(dt.timezone.utc)
        hour = lambda h: f'{h % 24:02d}:00'   # noqa: E731
        mark = self.tmp / 'RAN'
        self.run_it(f'touch {mark}\n', '--timer', cfg={'window': f'{hour(now.hour + 2)}-{hour(now.hour + 3)}'})
        self.assertFalse(mark.exists())
        self.run_it(f'touch {mark}\n', '--timer', cfg={'window': f'{hour(now.hour - 1)}-{hour(now.hour + 2)}'})
        self.assertTrue(mark.exists())

    def test_policies(self):
        (self.tmp / 'run').mkdir()
        task = self.tmp / 'task.sh'
        task.write_text('sleep 20\n')
        every = (set(range(60)), set(range(24)), set(range(1, 32)), set(range(1, 13)), set(range(7)))
        runner = self.tmp / 'first.sh'
        sched = {'schedule_id': 5, 'name': 'n', 'config': {'concurrency_policy': 'skip'}}
        runner.write_text(schedscript.runner_script(sched, [], every, None, {}, str(task)))
        first = subprocess.Popen(['bash', str(runner), '--run'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                 env={**os.environ, 'STORAGEFORGE_SCHED_ROOT': str(self.tmp)})
        self.addCleanup(first.kill)
        for _ in range(100):
            if (self.tmp / 'run' / 'sched-5.pid').exists():
                break
            time.sleep(0.05)
        r = self.run_it('echo second\n', '--run', url='')
        self.assertIn('already running', r.stdout)
        r = self.run_it('echo second\n', '--run', url='', cfg={'concurrency_policy': 'replace'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(first.wait(30), 143)

    def test_a_token_is_never_on_a_command_line(self):
        text = schedscript.RUNNER
        self.assertNotIn('Bearer $', text.replace('Bearer %s', ''))
        self.assertIn('-H @"$hdr"', text)


class InstallScriptTests(SchedulerBaseTest):
    """PF-26: one bash script, no Python on the host, and no flags means no change."""

    def sched(self, **kw):
        return {'schedule_id': 8, 'name': 'nightly', 'host': 'nas', 'cron_expr': '30 2 * * 1-5', 'task_type': 'command', 'task_ref': 'true',
                'paused': False, 'config': {'timezone': 'Asia/Tokyo', **kw.pop('config', {})}, **kw}

    def test_times_for_systemd(self):
        self.assertEqual(scheduler.on_calendar(self.sched()), 'Mon,Tue,Wed,Thu,Fri *-*-* 2:30:00 Asia/Tokyo')
        s = self.sched(cron_expr='*/15 * 1 1,7 *')
        self.assertEqual(scheduler.on_calendar(s), '*-1,7-1 *:0,15,30,45:00 Asia/Tokyo')
        s = self.sched(cron_expr='0 0 * * 0')
        self.assertEqual(scheduler.on_calendar(s), 'Sun *-*-* 0:0:00 Asia/Tokyo')
        if shutil.which('systemd-analyze'):
            for expr in ('30 2 * * 1-5', '*/15 * 1 1,7 *', '0 0 * * 0', '@daily'):
                cal = scheduler.on_calendar(self.sched(cron_expr=expr))
                self.assertEqual(subprocess.run(['systemd-analyze', 'calendar', cal], capture_output=True).returncode, 0, cal)

    def test_no_flags_only_report(self):
        text = scheduler.generate_install_script(self.conn, self.sched(), 'https://sf.test', 'tok')
        self.assertIn('\nMODE=report\n', text)
        r = subprocess.run(['bash', '-c', text], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('needs to be installed', r.stdout)
        self.assertNotIn('python', text.lower().replace('# the python runner of older versions', ''))

    def test_scripts_are_valid_bash(self):
        for s in (self.sched(), self.sched(paused=True), self.sched(config={'env': {'A': "it's"}, 'jitter_sec': 5, 'window': '01:00-02:00'})):
            text = scheduler.generate_install_script(self.conn, s, 'https://sf.test', 'tok')
            self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(['bash', '-n'], input=schedscript.runner_script(s, [], scheduler.parse_cron(s['cron_expr']), None, {}, '/t'),
                                            text=True, capture_output=True).returncode, 0)

    def test_a_value_cannot_end_a_heredoc(self):             # EQ-04
        canary = Path(tempfile.mkdtemp()) / 'CANARY'
        self.addCleanup(shutil.rmtree, canary.parent, True)
        tasks_body = f'true\nSF_ffff\nEOF_TASK\ntouch {canary}\n'
        wrapped = scheduler._heredoc(f'{canary.parent}/out', tasks_body)
        self.assertEqual(subprocess.run(['bash', '-c', wrapped], capture_output=True).returncode, 0)
        self.assertFalse(canary.exists())
        self.assertIn(f'touch {canary}', (canary.parent / 'out').read_text())

    def test_a_downloaded_script_keeps_the_token_a_reinstall_needs(self):
        with_none = scheduler.generate_install_script(self.conn, self.sched(), None, '')
        install = with_none[with_none.index('section "Installing'):]
        self.assertNotIn('8.token', install)
        self.assertIn('8.token', with_none[:with_none.index('section "Installing')])


class VerifiedMeansCheckedTests(SchedulerBaseTest):
    """PF-24: verified is only ever said from a scan newer than the run."""

    def setUp(self):
        super().setUp()
        self.sched, _ = scheduler.create_schedule(self.conn, {
            'name': 'v', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true',
            'config': {'verify_rules': {'paths_must_not_exist': ['/mnt/data/old']}}}, 'test')
        self.sid = self.sched['schedule_id']
        self.conn.execute('DELETE FROM scans')

    def scan_finished(self, at):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        ts = self.db.ts(':t')
        self.conn.execute(f"INSERT INTO scans (host_id, started_at, finished_at, status) VALUES (:h, {ts}, {ts}, 'ok')", {'h': hid, 't': at})

    def report(self, **kw):
        now = int(time.time())
        return scheduler.ingest_report(self.conn, {'schedule_id': self.sid, 'exit_code': 0, 'output': 'fine', 'started_at': now - 60, 'finished_at': now - 30, **kw}, 'test')

    def test_an_exit_code_alone_is_only_reported(self):
        self.scan_finished(int(time.time()) - 3600)          # the index predates the run
        res = self.report()
        self.assertEqual((res['status'], res['verified']), ('reported', 0))
        self.assertFalse(any(c['name'].startswith('path_absent') for c in res['verify_result']['checks']))

    def test_the_next_scan_decides(self):
        res = self.report()
        self.assertEqual(res['status'], 'reported')
        self.scan_finished(int(time.time()))
        self.assertEqual(scheduler.verify_pending(self.conn, 'nas'), 1)
        row = self.conn.all('SELECT status, verified FROM schedule_runs WHERE run_id = :r', {'r': res['run_id']})[0]
        self.assertEqual(tuple(row), ('verified', 1))
        self.assertEqual(scheduler.verify_pending(self.conn, 'nas'), 0)

    def test_a_missing_path_fails_once_the_index_is_new_enough(self):
        cfg = {**self.sched['config']}
        cfg['verify_rules'] = {**cfg['verify_rules'], 'paths_must_exist': ['/nope'], 'paths_must_not_exist': []}
        scheduler.update_schedule(self.conn, self.sid, {'config': cfg}, 'test')
        self.scan_finished(int(time.time()))
        res = self.report()
        self.assertEqual((res['status'], res['verified']), ('verify_failed', -1))

    def test_other_policies_never_say_verified(self):
        scheduler.update_schedule(self.conn, self.sid, {'config': {'verify_policy': 'report_only'}}, 'test')
        self.scan_finished(int(time.time()))
        self.assertEqual(self.report()['status'], 'reported')

    def test_a_run_from_a_scan_is_not_failed_for_its_missing_output(self):
        cfg = {'verify_rules': {'output_must_match': 'fine'}}
        scheduler.update_schedule(self.conn, self.sid, {'config': cfg}, 'test')
        line = json.dumps({'schedule_id': self.sid, 'nonce': 'n1', 'started_at': int(time.time()) - 60, 'exit_code': 0, 'no_output': True})
        self.assertEqual(scheduler.ingest_scan_schedules(self.conn, 'nas', line), 1)
        self.assertEqual(self.conn.scalar('SELECT status FROM schedule_runs WHERE schedule_id = :s', {'s': self.sid}), 'reported')


class RawCommandTests(SafetyCase):
    """SF-39: however raw commands reach a host, it takes hosts.command."""
    CMD = {'type': 'command', 'params': {'cmd': 'id'}}

    def setUp(self):
        super().setUp()
        self.users.save_role(self.conn, 'editor', '', ['plans.edit', 'plans.view', 'deploy.apply', 'deploy.report', 'deploy.view'], 'boss', True)
        self.users.create(self.conn, 'ed', self.PW, 'editor')
        self.ed = self.client('ed')

    def task(self, *blocks, on_fail=()):
        return {'name': 't', 'host': 'nas', 'blocks': list(blocks), 'on_fail': list(on_fail)}

    def test_task_command_blocks(self):
        nested = {'type': 'try', 'slots': {'do': [self.CMD]}}
        off = {**self.CMD, 'off': True}
        condition = {'type': 'if', 'params': {'cond': 'command succeeds', 'arg': 'id'}}
        for body in (self.task(self.CMD), self.task(nested), self.task(off), self.task(on_fail=[self.CMD]), self.task(condition)):
            self.assertEqual(self.ed.post('/api/tasks', json=body).status_code, 403, body)
            self.assertEqual(self.op.post('/api/tasks', json=body).status_code, 403, body)
        plain = {'type': 'mkdir', 'params': {'path': '/srv/x'}}
        tid = self.ed.post('/api/tasks', json=self.task(plain)).get_json()['id']
        self.assertEqual(self.ed.put(f'/api/tasks/{tid}', json=self.task(self.CMD)).status_code, 403)
        admin = self.boss.post('/api/tasks', json={**self.task(self.CMD), 'name': 'written by an admin'}).get_json()['id']
        self.assertEqual(self.ed.put(f'/api/tasks/{admin}', json={**self.task(plain), 'name': 'written by an admin'}).status_code, 403)
        self.assertEqual(self.ed.post('/api/deploy/start', json={'kind': 'tasks', 'ref': admin, 'mode': 'apply'}).status_code, 403)
        self.assertEqual(self.boss.post('/api/deploy/start', json={'kind': 'tasks', 'ref': admin, 'mode': 'apply'}).status_code, 409)   # past the check: no deploy access
        self.assertEqual(self.ed.post('/api/deploy/start', json={'kind': 'tasks', 'ref': admin, 'mode': 'apply', 'remove': True}).status_code, 409)

    def test_a_schedule_cannot_carry_a_command_block_past_the_check(self):
        from unittest import mock
        from storageforge_index import deploy, engine
        admin = self.boss.post('/api/tasks', json=self.task(self.CMD)).get_json()['id']
        sid = self.schedule(self.ed, task_type='task', task_ref=str(admin))
        self.assertEqual(self.ed.post('/api/deploy/start', json={'kind': 'schedules', 'ref': sid, 'mode': 'apply'}).status_code, 403)
        self.assertEqual(self.ed.post(f'/api/scheduler/schedules/{sid}/run', json={}).status_code, 403)
        self.assertEqual(self.ed.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).status_code, 200)    # stopping is allowed
        self.assertEqual(self.ed.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': False}).status_code, 403)
        with mock.patch.object(engine, 'get', return_value={'kind': 'tasks', 'ref': str(admin), 'mode': 'apply', 'options': {}, 'title': 't'}), \
                mock.patch.object(deploy, 'start_group') as start:
            self.assertEqual(self.ed.post('/api/deploy/groups/' + 'a' * 32 + '/retry', json={}).status_code, 403)
        start.assert_not_called()

    def step(self, **kw):
        return {'method': 'copy', 'src': {'host': 'nas', 'path': '/mnt/data'}, 'dst': {'host': 'nas', 'path': '/mnt/copy'}, **kw}

    def test_move_hooks(self):
        raw = {'name': 'm', 'steps': [self.step(options={'pre': ['curl x | sh']})]}
        self.assertEqual(self.ed.post('/api/moves', json=raw).status_code, 403)
        plain = {'name': 'p', 'steps': [self.step(options={'pre': ['docker compose -p immich stop'], 'post': ['docker compose -p immich start']})]}
        r = self.ed.post('/api/moves', json=plain)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        pid = r.get_json()['id']
        self.assertEqual(self.ed.put(f'/api/moves/{pid}', json={**plain, 'steps': [self.step(options={'post': ['docker compose -p x stop; id']})]}).status_code, 403)
        admin = self.boss.post('/api/moves', json=raw).get_json()['id']
        self.assertEqual(self.ed.post(f'/api/moves/{admin}/copy', json={}).status_code, 403)
        self.assertEqual(self.ed.post('/api/deploy/start', json={'kind': 'jobs', 'ref': admin, 'mode': 'apply'}).status_code, 403)
        self.assertEqual(self.ed.post('/api/deploy/start', json={'kind': 'jobs', 'ref': admin, 'mode': 'report'}).status_code, 409)     # a dry run runs nothing

    def test_only_admin_holds_it_by_default(self):
        from storageforge_index import permissions
        self.assertIn('hosts.command', permissions.HIGH_RISK)
        for role in ('search', 'viewer', 'operator'):
            self.assertNotIn('hosts.command', permissions.BUILTIN[role][1])
        self.assertIn('hosts.command', permissions.BUILTIN['admin'][1])


class Step5Tests(SafetyCase):
    """SF-35, SF-36, SF-37, PF-27 and EQ-05."""

    def test_schedule_runs_are_pruned(self):                 # SF-35
        sid, other = self.schedule(), self.schedule(name='other')
        for s, n in ((sid, 205), (other, 3)):
            for i in range(n):
                self.conn.execute("INSERT INTO schedule_runs (schedule_id, host, status, started_at, nonce) VALUES (:s, 'nas', 'reported', :t, :n)",
                                  {'s': s, 't': i, 'n': f'{s}-{i}'})
        self.db.prune(self.conn)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM schedule_runs WHERE schedule_id = :s', {'s': sid}), 200)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM schedule_runs WHERE schedule_id = :s', {'s': other}), 3)
        self.assertEqual(self.conn.scalar('SELECT min(started_at) FROM schedule_runs WHERE schedule_id = :s', {'s': sid}), 5)

    def test_links_die_when_what_they_grant_changes(self):   # SF-36
        u = self.users
        u.save_role(self.conn, 'small', '', ['search.files'], 'boss', True)
        u.create(self.conn, 't', self.PW, 'small')
        _, reset = u.create_reset(self.conn, 't', 'boss')
        _, invite = u.create_invite(self.conn, 'small', 'boss')
        self.assertIsNotNone(u.open_invite(self.conn, reset))
        self.assertIsNotNone(u.open_invite(self.conn, invite))
        u.save_role(self.conn, 'small', '', ['search.files', 'keys.manage'], 'boss', False)
        self.assertIsNone(u.open_invite(self.conn, reset))
        self.assertIsNone(u.open_invite(self.conn, invite))
        u.save_role(self.conn, 'small', '', [], 'boss', False)        # narrower is no threat
        _, invite = u.create_invite(self.conn, 'small', 'boss')
        u.save_role(self.conn, 'small', '', [], 'boss', False)
        self.assertIsNotNone(u.open_invite(self.conn, invite))

    def test_a_reset_link_is_for_one_account_as_it_was(self):      # SF-36
        u = self.users
        u.create(self.conn, 't', self.PW, 'viewer')
        _, first = u.create_reset(self.conn, 't', 'boss')
        _, second = u.create_reset(self.conn, 't', 'boss')
        self.assertIsNone(u.open_invite(self.conn, first))          # a new link ends the last
        self.assertIsNotNone(u.open_invite(self.conn, second))
        u.remove(self.conn, 't')
        u.create(self.conn, 't', self.PW, 'viewer')                 # same name and role: another person
        self.assertIsNone(u.open_invite(self.conn, second))
        _, third = u.create_reset(self.conn, 't', 'boss')
        u.set_password(self.conn, 't', 'another long password')
        self.assertIsNone(u.open_invite(self.conn, third))

    def test_a_link_from_before_the_checks_is_dead(self):    # SF-36
        _, token = self.users.create_invite(self.conn, 'viewer', 'boss')
        self.conn.execute('UPDATE invites SET grants_json = NULL')
        self.assertIsNone(self.users.open_invite(self.conn, token))

    def test_risky_permissions_say_so(self):                 # SF-37
        from storageforge_index import permissions
        self.assertLessEqual({'backups.manage', 'settings.manage'}, permissions.HIGH_RISK)

    def backup_file(self, data=b'SQLite secret-password-hash ' * 80000):
        src = Path(self.tmp) / 'storageforge-essentials-1.db'
        src.write_bytes(data)
        return src, data

    def test_an_off_box_copy_is_encrypted(self):             # SF-37
        from unittest import mock
        from storageforge_index import backup, deploy
        src, data = self.backup_file()
        dst = Path(tempfile.mkdtemp(dir=self.tmp))

        def run(db, host, script, *a, **kw):
            done = subprocess.run(['bash', '-c', script], input=b''.join(kw['data']), capture_output=True, timeout=30)
            return {'status': 'ok' if done.returncode == 0 else 'failed', 'output': done.stderr.decode()}
        with mock.patch.object(deploy, 'run', run), mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'v' * 40}):
            backup.copy_off(self.db, self.conn, str(src), {'host': 'x', 'path': str(dst)}, 2)
        sent = dst / (src.name + '.enc')
        self.assertNotIn(b'secret-password-hash', sent.read_bytes())
        back = Path(self.tmp) / 'back.db'
        backup.decrypt_file(str(sent), str(back), b'v' * 40)
        self.assertEqual(back.read_bytes(), data)

        for label, change in (('wrong secret', None), ('changed byte', 100), ('cut short', -1)):
            bad = Path(self.tmp) / f'{label}.enc'
            raw = bytearray(sent.read_bytes())
            if change == 100:
                raw[change] ^= 1
            elif change == -1:
                raw = raw[:(1 << 20) + 200]        # a whole chunk and part of the next
            bad.write_bytes(raw)
            with self.assertRaises(SystemExit, msg=label):
                backup.decrypt_file(str(bad), str(back), b'w' * 40 if change is None else b'v' * 40)

    def test_no_secret_means_no_copy(self):                  # SF-37
        from unittest import mock
        from storageforge_index import backup, deploy, vault
        src, _ = self.backup_file()
        env = {k: v for k, v in os.environ.items() if not k.startswith('STORAGEFORGE_VAULT_SECRET')}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(deploy, 'run') as run, self.assertRaises(vault.VaultError):
            backup.copy_off(self.db, self.conn, str(src), {'host': 'x', 'path': '/y'}, 2)
        run.assert_not_called()

    @unittest.skipIf(dbfactory.PG, 'backups are of SQLite databases')
    def test_restore_takes_an_encrypted_copy(self):          # SF-37
        from unittest import mock
        from storageforge_index import backup
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'v' * 40}):
            (Path(self.tmp) / 'bk').mkdir()
            made = backup.create(self.db, 'essentials', Path(self.tmp) / 'bk')
            sealed = Path(self.tmp) / 'copy.db.enc'
            sealed.write_bytes(b''.join(backup.encrypted(made['path'], b'v' * 40)))
            tmp2 = Path(tempfile.mkdtemp(dir=self.tmp))
            target = Database(f'sqlite:///{tmp2}/restored.db')
            out = backup.restore(target, str(sealed))
        self.assertTrue(out)
        self.assertEqual(sorted(p.name for p in tmp2.iterdir() if p.name.startswith('.restore')), [])
        self.assertEqual(sqlite3.connect(f'{tmp2}/restored.db').execute("SELECT count(*) FROM hosts").fetchone()[0], 2)

    def test_file_map_is_kept_until_something_changes(self):       # PF-27
        from unittest import mock
        from storageforge_index import filemap
        real = filemap.build
        with mock.patch.object(filemap, 'build', side_effect=real) as build:
            self.assertEqual(self.view.get('/api/filemap').status_code, 200)
            self.assertEqual(self.view.get('/api/filemap').status_code, 200)
            self.assertEqual(build.call_count, 1)
            self.assertEqual(self.boss.put('/api/files/ignore', json={'host': '', 'paths': ['/srv/junk']}).status_code, 200)
            self.view.get('/api/filemap')
            self.assertEqual(build.call_count, 2)

    def test_a_long_ignore_list_fits(self):                  # PF-27
        paths = [f'/srv/some/long/path/number/{i}' for i in range(1500)]
        self.assertEqual(self.boss.put('/api/files/ignore', json={'host': '', 'paths': paths}).status_code, 200)
        self.assertEqual(self.boss.put('/api/git/ignore', json={'host': '', 'paths': paths[:400]}).status_code, 200)

    def test_only_duplicates_are_read_for_the_map(self):     # PF-27
        from storageforge_index import filemap
        mid = self.conn.scalar("SELECT mount_id FROM mounts WHERE mount_point = '/mnt/data'")
        did = self.conn.scalar('SELECT dir_id FROM directories LIMIT 1')
        for name, sha in (('a', 'same'), ('b', 'same'), ('c', 'alone')):
            self.conn.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, is_directory, file_size_bytes, modified_at, is_symlink, checksum_hash)
                                  VALUES (:m, :d, :n, FALSE, 5000000, {self.db.ts(':t')}, FALSE, :s)""", {'m': mid, 'd': did, 'n': name, 't': 1, 's': sha})
        groups, _ = filemap.file_groups(self.conn, None, 1, {}, False)
        self.assertEqual([g['sha256'] for g in groups], ['same'])
        self.assertEqual(sorted(c['path'].rsplit('/', 1)[1] for c in groups[0]['copies']), ['a', 'b'])

    def test_retiring_a_host_with_a_schedule_is_refused(self):     # PF-27
        from storageforge_index import retire
        self.schedule()
        with self.assertRaises(ValueError) as e:
            retire.retire(self.conn, 'nas')
        self.assertIn('schedule', str(e.exception))

    def test_a_git_link_out_of_the_source_is_refused(self):  # EQ-05
        from storageforge_index import jobscript
        text = jobscript.JOB_SCRIPT
        at = text.index('[[ -d $path/.git ]] && path=$path/.git')
        self.assertIn('under "$path" "$ROOT" "$snap" || die', text[at:at + 200])
        src = Path(tempfile.mkdtemp(dir=self.tmp))
        (src / 'root' / 'repo').mkdir(parents=True)
        (src / 'secret.git').mkdir()
        (src / 'root' / 'repo' / '.git').symlink_to(src / 'secret.git')
        probe = text[text.index('under() {'):text.index('run_cmds()')] + f"""
path={src}/root/repo; ROOT={src}/root; snap=
under "$path" "$ROOT" "$snap" || exit 3
[[ -d $path/.git ]] && path=$path/.git
under "$path" "$ROOT" "$snap" || exit 4
"""
        self.assertEqual(subprocess.run(['bash', '-c', probe], capture_output=True).returncode, 4)


class LastItemsTests(SafetyCase):
    """PF-23, PF-03 and PF-14."""

    def test_a_schedule_keeps_working_after_its_plan_is_renamed(self):   # PF-23
        task = self.boss.post('/api/tasks', json={'name': 'nightly copy', 'host': 'nas', 'blocks': []}).get_json()['id']
        sid = self.schedule(task_type='task', task_ref='Nightly Copy')
        self.assertEqual(scheduler.get_schedule(self.conn, sid)['task_ref'], str(task))
        self.boss.put(f'/api/tasks/{task}', json={'name': 'renamed', 'host': 'nas', 'blocks': []})
        self.assertTrue(scheduler.generate_task_script(self.conn, scheduler.get_schedule(self.conn, sid))[0])

    def test_other_snapshot_tools_are_detected(self):        # PF-03
        from storageforge_index import health, protection
        snaps = health.parse_snapshots('snapper\troot\t/\nsnapper\thome\t/home\nsnapper\tmystery\t\nsanoid\ttank/data\nsanoid\ttemplate_x\ntool\ttimeshift\n')
        self.assertEqual(snaps['snapper'], ['root', 'home', 'mystery'])
        self.assertEqual(snaps['sanoid'], ['tank/data'])
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'snapshots': snaps})})
        rows = protection.overlay(self.conn, 'nas', [{'path': '/home'}, {'path': '/'}, {'dataset': 'tank/data'}, {'path': '/srv'}])
        by = {r.get('path') or r['dataset']: (r.get('snapshots') or {}).get('tool') for r in rows}
        self.assertEqual(by['/home'], 'snapper')
        self.assertEqual(by['tank/data'], 'sanoid')
        self.assertIn(by['/'], ('snapper', 'timeshift'))

    def test_the_scan_reads_those_tools(self):               # PF-03
        from storageforge_index import remote
        text = open(remote.__file__).read()
        for path in ('/etc/snapper/configs', '/etc/timeshift/timeshift.json', '/etc/btrbk/btrbk.conf', '/etc/sanoid/sanoid.conf'):
            self.assertIn(path, text)

    def test_the_canvas_shows_shares_and_stacks(self):       # PF-14
        from storageforge_index import canvas
        graph = {'nodes': [{'id': f'host:{h}', 'kind': 'Host', 'label': h, 'host': h, 'health': 'unknown', 'props': {}} for h in ('nas', 'pc')], 'edges': []}
        extras = {'nas': {'shares': [{'protocol': 'NFSv4.2', 'name': 'media', 'path': '/srv/media', 'clients': 'pc 10.0.0.9'}], 'stacks': ['immich']}}
        out = canvas.to_canvas(graph, extras)
        text = ' '.join(n.get('text', '') for n in out['nodes'])
        self.assertIn('media', text)
        self.assertIn('immich', text)
        labels = sorted(e.get('label') for e in out['edges'])
        self.assertEqual(labels, ['client', 'runs', 'serves'])
        ids = {n['id'] for n in out['nodes']}
        for e in out['edges']:
            self.assertLessEqual({e['fromNode'], e['toNode']}, ids)
        self.assertEqual(canvas.extras(self.conn, None), {})      # nothing designed or running here: no cards
