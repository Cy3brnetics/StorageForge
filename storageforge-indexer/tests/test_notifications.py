"""The notification center (notifications.py, roadmap section 12): every alert ranked in one list, what cannot be ignored, a snooze and
a mute for what can, who is on it, and a history that outlives the alert. alerts.problems is replaced by what each test says is wrong,
and alerts.send by a recorder: nothing is gathered from hosts and nothing is sent."""
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts, changes, logrules, notifications, scheduler, server, users
from storageforge_index.db import Database

PW = 'correct horse battery staple'


def problem(kind, ref, level='warn', title=None):
    return (kind, ref, title or f'{kind} on {ref}', f'what is wrong with {ref}', level)


class Center(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = self.make(tmp)
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for i, host in enumerate(('nas', 'pc', 'edge')):
            self.conn.execute(f"INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:h, :h, 'scan', '{{}}', {self.db.ts(':t')})", {'h': host, 't': 1600000000 + i})
        self.now = {}
        self.sent = []
        patches = (mock.patch.object(alerts, 'problems', lambda conn: dict(self.now)),
                   mock.patch.object(alerts, 'send', lambda cfg, title, message, level='warn', extra=None: self.sent.append((title, level)) or ['recorded']))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def make(self, tmp):
        return dbfactory.make(self, tmp / 'index.db')

    def wrong(self, **problems):
        """What is wrong now, by key, and one evaluation of it."""
        self.now = problems
        alerts.evaluate(self.db)
        return notifications.center(self.conn)

    def titles(self, groups):
        return [x['title'] for g in groups for x in g['items']]


class Ranking(Center):
    def test_critical_first_then_warning_then_information_and_the_newest_first_within_one(self):
        self.wrong(a=problem('disk-warn', 'nas:/srv', 'warn', 'warn, older'))
        self.conn.execute("UPDATE alerts SET first_at = first_at - 100 WHERE alert_key = 'a'")
        got = self.wrong(a=problem('disk-warn', 'nas:/srv', 'warn', 'warn, older'), b=problem('note', 'pc', 'ok', 'information'),
                         c=problem('job-failed', 'j1', 'crit', 'critical'), d=problem('scan-failed', 'pc', 'warn', 'warn, newer'))
        self.assertEqual(self.titles(got['groups']), ['critical', 'warn, newer', 'warn, older', 'information'])
        self.assertEqual(got['counts'], {'crit': 1, 'warn': 2, 'info': 1})
        self.assertEqual(got['total'], 4)

    def test_a_flood_of_one_kind_on_one_host_is_one_row_with_a_count(self):
        got = self.wrong(**{f'm{i}': problem('mount-gone', f'nas:/mnt/{i}') for i in range(40)}, other=problem('mount-gone', 'pc:/mnt/x'))
        rows = [(g['host'], g['kind'], g['count']) for g in got['groups']]
        self.assertEqual(sorted(rows), [('nas', 'mount-gone', 40), ('pc', 'mount-gone', 1)])
        self.assertEqual(len(next(g for g in got['groups'] if g['host'] == 'nas')['items']), 40, 'every one is still there to open')

    def test_an_alert_knows_its_host_from_what_it_refers_to(self):
        sid = scheduler.create_schedule(self.conn, {'name': 'nightly', 'host': 'edge', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true'}, 'test')[0]['schedule_id']
        got = self.wrong(a=problem('disk-warn', 'NAS:/srv'), b=problem('scan-failed', 'pc'), c=problem('schedule-failed', str(sid), 'crit'),
                         d=problem('backup-stale', 'controller'), e=problem('scan-failed', '10.9.9.9'))
        hosts = {x['key']: x['host'] for g in got['groups'] for x in g['items']}
        self.assertEqual(hosts, {'a': 'nas', 'b': 'pc', 'c': 'edge', 'd': None, 'e': None})
        self.assertEqual(self.titles(notifications.center(self.conn, host='nas')['groups']), ['disk-warn on NAS:/srv'])
        self.assertEqual(notifications.center(self.conn, level='crit')['total'], 1)
        with self.assertRaises(ValueError):
            notifications.center(self.conn, level='loud')

    def test_the_summary_is_what_the_page_header_counts(self):
        self.wrong(a=problem('job-failed', 'j1', 'crit'), b=problem('scan-failed', 'pc'))
        notifications.snooze(self.conn, 'b', 3600, 'gabe')
        summary = notifications.summary(self.conn)
        self.assertEqual(summary['counts'], {'crit': 1, 'warn': 0, 'info': 0})
        self.assertEqual(summary['total'], 1)
        self.assertEqual(summary['mark'], notifications.summary(self.conn)['mark'])


class WhatCannotBeIgnored(Center):
    KEPT = {'crit': problem('disk-crit', 'nas:/srv', 'crit'), 'drift': problem('drift', 'nas:fstab', 'warn'), 'sec': problem('security-renames', 'nas', 'warn'),
            'virus': problem('clamav', 'pc', 'warn'), 'telnet': problem('device-telnet', 'sw1', 'warn'), 'shared': problem('shared-key', 'k', 'warn')}

    def test_a_critical_notification_drift_and_a_security_finding_cannot_be_snoozed(self):
        self.wrong(**self.KEPT)
        for key in self.KEPT:
            with self.assertRaisesRegex(ValueError, 'cannot be snoozed or muted'):
                notifications.snooze(self.conn, key, 3600, 'gabe')
        self.assertEqual(notifications.center(self.conn)['total'], len(self.KEPT))
        self.assertEqual(notifications.center(self.conn)['quiet'], [])

    def test_they_cannot_be_muted_by_kind_and_a_wide_mute_does_not_cover_them(self):
        for kind in ('drift', 'security-renames', 'security-*x', 'clamav', 'device-telnet'):
            with self.assertRaisesRegex(ValueError, 'cannot be snoozed or muted', msg=kind):
                notifications.mute(self.conn, '*', kind, 'gabe')
        notifications.mute(self.conn, '*', '*', 'gabe', 'quiet please')
        got = self.wrong(**self.KEPT, plain=problem('scan-failed', 'pc'))
        self.assertEqual(sorted(x['key'] for g in got['groups'] for x in g['items']), sorted(self.KEPT), 'all of them still at the top')
        self.assertEqual([x['key'] for g in got['quiet'] for x in g['items']], ['plain'])
        self.assertEqual(len(self.sent), len(self.KEPT), 'and each was still pushed: only the plain one was not')

    def test_an_acknowledgement_says_who_is_on_it_and_removes_nothing(self):
        self.wrong(**self.KEPT)
        got = notifications.acknowledge(self.conn, 'crit', 'gabe', 'ordering a disk')
        self.assertEqual((got['acked']['by'], got['acked']['note'], got['quiet']), ('gabe', 'ordering a disk', False))
        self.assertEqual(notifications.center(self.conn)['counts']['crit'], 1)
        self.assertIsNone(notifications.unacknowledge(self.conn, 'crit', 'gabe')['acked'])

    def test_they_leave_only_when_resolved(self):
        self.wrong(**self.KEPT)
        notifications.acknowledge(self.conn, 'drift', 'gabe')
        left = {k: v for k, v in self.KEPT.items() if k != 'drift'}
        self.assertEqual(self.wrong(**left)['total'], len(left))
        with self.assertRaises(LookupError):
            notifications.acknowledge(self.conn, 'drift', 'gabe')

    def test_a_snooze_does_not_survive_the_notification_becoming_critical(self):
        self.wrong(a=problem('disk-warn', 'nas:/srv', 'warn', 'filling'))
        notifications.snooze(self.conn, 'a', 86400, 'gabe')
        self.sent.clear()
        got = self.wrong(a=problem('disk-warn', 'nas:/srv', 'crit', 'filling'))
        self.assertEqual((got['counts']['crit'], got['quiet']), (1, []))
        self.assertEqual(self.sent, [('filling', 'crit')], 'it is said again as it gets worse')
        self.assertIn('escalated', [e['event'] for e in notifications.history(self.conn)['events']])


class SnoozeAndMute(Center):
    def test_a_snoozed_notification_is_listed_apart_until_its_time_is_up(self):
        self.wrong(a=problem('scan-failed', 'pc'), b=problem('disk-warn', 'nas:/srv'))
        got = notifications.snooze(self.conn, 'a', 3600, 'gabe')
        self.assertTrue(got['quiet'])
        c = notifications.center(self.conn)
        self.assertEqual((self.titles(c['groups']), self.titles(c['quiet'])), (['disk-warn on nas:/srv'], ['scan-failed on pc']))
        later = notifications.center(self.conn, now=time.time() + 3700)
        self.assertEqual((later['total'], later['quiet']), (2, []))
        self.assertFalse(notifications.unsnooze(self.conn, 'a', 'gabe')['quiet'])
        for bad in (10, 31 * 86400, -5):
            with self.assertRaisesRegex(ValueError, 'a minute to 30 days'):
                notifications.snooze(self.conn, 'a', bad, 'gabe')

    def test_a_muted_kind_on_a_host_is_not_pushed_and_other_hosts_still_are(self):
        made = notifications.mute(self.conn, 'nas', 'disk-*', 'gabe', 'being rebuilt', days=2)
        self.assertEqual((made['host'], made['kind'], made['note'], made['by']), ('nas', 'disk-*', 'being rebuilt', 'gabe'))
        got = self.wrong(a=problem('disk-warn', 'nas:/srv'), b=problem('disk-warn', 'pc:/srv'), c=problem('scan-failed', 'nas'))
        self.assertEqual(sorted(t for t, _ in self.sent), ['disk-warn on pc:/srv', 'scan-failed on nas'])
        self.assertEqual(self.titles(got['quiet']), ['disk-warn on nas:/srv'])
        self.assertEqual(got['quiet'][0]['items'][0]['muted'], made['id'])
        self.sent.clear()
        self.wrong(b=problem('disk-warn', 'pc:/srv'), c=problem('scan-failed', 'nas'))
        self.assertEqual(self.sent, [], 'its resolving is not pushed either')
        self.assertEqual(notifications.center(self.conn, now=time.time() + 3 * 86400)['mutes'], [], 'a mute with an end ends')
        self.assertTrue(notifications.unmute(self.conn, made['id']))
        self.assertFalse(notifications.unmute(self.conn, made['id']))
        for days in (0, -1, 400):
            with self.assertRaises(ValueError):
                notifications.mute(self.conn, 'nas', 'scan-failed', 'gabe', days=days)

    def test_a_resolved_notification_that_was_loud_is_pushed_as_resolved(self):
        self.wrong(a=problem('scan-failed', 'pc', title='Scan failed on pc'))
        self.sent.clear()
        self.wrong()
        self.assertEqual(self.sent, [('Resolved: Scan failed on pc', 'ok')])


class History(Center):
    def test_it_keeps_every_opening_and_who_did_what_after_the_alert_opens_again(self):
        self.wrong(a=problem('scan-failed', 'pc', title='Scan failed on pc'))
        notifications.acknowledge(self.conn, 'a', 'gabe', 'rebooting it')
        self.wrong()
        self.wrong(a=problem('scan-failed', 'pc', title='Scan failed on pc'))
        self.assertIsNone(notifications.get(self.conn, 'a')['acked'], 'a new occurrence is nobody\'s yet')
        got = notifications.history(self.conn)['events']
        self.assertEqual([(e['event'], e['actor']) for e in reversed(got)], [('opened', None), ('acknowledged', 'gabe'), ('resolved', None), ('opened', None)])
        self.assertEqual({e['host'] for e in got}, {'pc'})

    def test_it_is_searchable_by_text_host_kind_and_event(self):
        self.wrong(a=problem('scan-failed', 'pc', title='Scan failed on pc'), b=problem('disk-warn', 'nas:/srv', title='/srv is 91% full on nas'))
        notifications.acknowledge(self.conn, 'b', 'gabe', 'old photos to prune 100%_done')
        find = lambda **kw: [(e['key'], e['event']) for e in notifications.history(self.conn, **kw)['events']]
        self.assertEqual(find(q='91%'), [('b', 'acknowledged'), ('b', 'opened')])
        self.assertEqual(find(q='100%_done'), [('b', 'acknowledged')])
        self.assertEqual(find(q='%'), [('b', 'acknowledged'), ('b', 'opened')], 'a percent sign is a percent sign')
        self.assertEqual(find(host='PC'), [('a', 'opened')])
        self.assertEqual(find(kind='disk-warn', event='opened'), [('b', 'opened')])
        with self.assertRaises(ValueError):
            find(event='deleted')
        page = notifications.history(self.conn, limit=1)
        self.assertEqual((len(page['events']), page['more']), (1, True))


class Fixes(Center):
    """A fix is a change plan made ready, offered only where there is a way back, and never applied from the center."""

    def failing(self, line="nginx.service: Failed with result 'exit-code'.", builtin='unit-failed', host='nas'):
        rid = next(r['id'] for r in logrules.rules(self.conn) if r['builtin'] == builtin)
        self.conn.execute('INSERT INTO log_rule_hits (rule_id, host, bucket, hits, sample) VALUES (:r, :h, :b, 3, :s)', {'r': rid, 'h': host, 'b': int(time.time() // 300), 's': line})
        key = f'log-rule:{rid}:{host}'
        self.wrong(**{key: problem('log-rule', f'{host}:{rid}', 'warn', f'Services failing on {host}')})
        return key

    def test_a_failing_service_carries_a_restart_and_says_its_way_back(self):
        key = self.failing()
        fix = notifications.get(self.conn, key) and notifications.center(self.conn)['groups'][0]['items'][0]['fix']
        self.assertEqual(fix, {'label': 'Restart nginx.service on nas', 'undo': 'Stop nginx.service again, as it was found', 'plan': None})

    def test_preparing_it_saves_a_plan_and_runs_nothing(self):
        key = self.failing()
        got = notifications.prepare_fix(self.conn, key, 'gabe')
        plan = changes.get_plan(self.conn, got['plan'])
        self.assertEqual([(t['type'], t['host'], t['params']) for t in plan['tasks']], [('unit-state', 'nas', {'unit': 'nginx.service', 'state': 'restarted'})])
        self.assertTrue(plan['name'].startswith('Fix: Restart nginx.service on nas'))
        self.assertIsNone(plan['ran_at'], 'nothing was deployed: that takes the password, in Changes')
        self.assertEqual(notifications.center(self.conn)['groups'][0]['items'][0]['fix']['plan'], got['plan'])
        self.assertEqual(notifications.history(self.conn, event='fix-prepared')['events'][0]['actor'], 'gabe')

    def test_the_way_back_is_a_plan_too_and_can_be_made_after_the_notification_resolved(self):
        key = self.failing()
        got = notifications.prepare_fix(self.conn, key, 'gabe')
        self.wrong()                                         # the restart worked, and the alert resolved
        undo = notifications.prepare_undo(self.conn, got['plan'], 'gabe')
        plan = changes.get_plan(self.conn, undo['plan'])
        self.assertEqual([(t['type'], t['host'], t['params']) for t in plan['tasks']], [('unit-state', 'nas', {'unit': 'nginx.service', 'state': 'stopped'})])
        self.assertEqual(undo['of'], got['plan'])
        self.assertEqual(notifications.history(self.conn, event='undo-prepared')['events'][0]['key'], key)

    def test_a_plan_that_was_not_a_fix_or_was_changed_since_has_no_way_back_made(self):
        other = changes.save_plan(self.conn, {'name': 'mine', 'tasks': [{'type': 'unit-state', 'host': 'nas', 'params': {'unit': 'nginx.service', 'state': 'restarted'}}]}, 'gabe')
        with self.assertRaisesRegex(LookupError, 'no fix was prepared as that plan'):
            notifications.prepare_undo(self.conn, other, 'gabe')
        got = notifications.prepare_fix(self.conn, self.failing(), 'gabe')
        changes.save_plan(self.conn, {'name': 'edited', 'tasks': [{'type': 'dir', 'host': 'nas', 'params': {'path': '/srv/x'}}]}, 'gabe', got['plan'])
        with self.assertRaisesRegex(ValueError, 'no way back'):
            notifications.prepare_undo(self.conn, got['plan'], 'gabe')

    def test_undo_refuses_a_restart_retargeted_to_another_unit(self):
        got = notifications.prepare_fix(self.conn, self.failing(), 'gabe')
        edited = changes.get_plan(self.conn, got['plan'])
        edited['tasks'][0]['params']['unit'] = 'postgresql.service'
        changes.save_plan(self.conn, edited, 'gabe', got['plan'])
        with self.assertRaisesRegex(ValueError, 'no way back'):
            notifications.prepare_undo(self.conn, got['plan'], 'gabe')
        self.assertFalse(notifications.history(self.conn, event='undo-prepared')['events'])

    def test_nothing_is_offered_where_there_is_no_way_back(self):
        """A job run now and a scan run again cannot be taken back, a full disk is never cleared from here, and SSH is done by hand."""
        got = self.wrong(a=problem('job-stale', 'j1'), b=problem('scan-failed', 'pc'), c=problem('disk-crit', 'nas:/srv', 'crit'), d=problem('drift', 'nas:fstab'))
        self.assertEqual([x['fix'] for g in got['groups'] for x in g['items']], [None] * 4)
        for line, builtin in (("sshd.service: Failed with result 'exit-code'.", 'unit-failed'), ('Failed to start a thing with no unit named', 'unit-failed'),
                              ('write failed: No space left on device', 'disk-full')):
            with self.subTest(line):
                self.conn.execute('DELETE FROM log_rule_hits')
                key = self.failing(line, builtin)
                self.assertIsNone(notifications.center(self.conn)['groups'][0]['items'][0]['fix'])
                with self.assertRaisesRegex(ValueError, 'only where it can be taken back'):
                    notifications.prepare_fix(self.conn, key, 'gabe')

    def test_a_unit_name_a_host_wrote_reaches_the_plan_only_as_a_unit_name(self):
        key = self.failing("evil$(reboot).service; rm -rf / app.service: Failed with result 'x'")
        fix = notifications.center(self.conn)['groups'][0]['items'][0]['fix']
        self.assertEqual(fix['label'], 'Restart app.service on nas' if fix else None)
        key2 = self.failing("`x`.service: Failed with result 'x'", host='pc')
        self.assertIsNone(notifications.get(self.conn, key2) and next(x for g in notifications.center(self.conn, host='pc')['groups'] for x in g['items'])['fix'])
        self.assertTrue(key)


class OverTheWeb(Center):
    def make(self, tmp):          # the web app opens the database by its path, and the CLI tests do the same
        return Database(str(tmp / 'index.db'))

    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def audited(self):
        return [tuple(r) for r in self.conn.all("SELECT action, outcome FROM audit_log WHERE action LIKE 'notification.%' ORDER BY rowid")]

    def test_a_viewer_reads_the_center_and_can_change_nothing_in_it(self):
        self.wrong(a=problem('scan-failed', 'pc'), b=problem('disk-crit', 'nas:/srv', 'crit'))
        c = self.client('viewer')
        got = c.get('/api/notifications').get_json()
        self.assertEqual((got['counts'], [g['level'] for g in got['groups']]), ({'crit': 1, 'warn': 1, 'info': 0}, ['crit', 'warn']))
        self.assertEqual(c.get('/api/notifications/summary').get_json()['counts']['crit'], 1)
        self.assertEqual(c.get('/api/notifications/history').get_json()['events'][0]['event'], 'opened')
        self.assertEqual(c.get('/api/notifications?level=loud').status_code, 400)
        for method, path in (('post', '/api/notifications/ack/a'), ('delete', '/api/notifications/ack/a'), ('post', '/api/notifications/snooze/a'),
                             ('delete', '/api/notifications/snooze/a'), ('post', '/api/notifications/mutes'), ('delete', '/api/notifications/mutes/1')):
            self.assertEqual(getattr(c, method)(path, json={}).status_code, 403, f'{method} {path}')

    def test_an_operator_acknowledges_snoozes_and_mutes_and_each_is_audited(self):
        self.wrong(**{'scan-failed:pc': problem('scan-failed', 'pc'), 'disk-crit:nas:/srv': problem('disk-crit', 'nas:/srv', 'crit')})
        c = self.client('operator')
        got = c.post('/api/notifications/ack/disk-crit:nas:/srv', json={'note': 'on it'})
        self.assertEqual((got.status_code, got.get_json()['acked']['by']), (200, 'web:operator'), 'a key holds colons and slashes')
        self.assertEqual(c.post('/api/notifications/snooze/disk-crit:nas:/srv', json={'hours': 2}).status_code, 400, 'a critical one is not snoozed')
        self.assertIn('cannot be snoozed', c.post('/api/notifications/snooze/disk-crit:nas:/srv', json={'hours': 2}).get_json()['error'])
        self.assertEqual(c.post('/api/notifications/snooze/scan-failed:pc', json={'hours': 2}).status_code, 200)
        self.assertEqual(c.delete('/api/notifications/snooze/scan-failed:pc').status_code, 200)
        self.assertEqual(c.delete('/api/notifications/ack/disk-crit:nas:/srv').status_code, 200)
        self.assertEqual(c.post('/api/notifications/ack/no-such-key', json={}).status_code, 404)
        made = c.post('/api/notifications/mutes', json={'host': 'pc', 'kind': 'scan-failed', 'note': 'being moved', 'days': 1})
        self.assertEqual((made.status_code, made.get_json()['host']), (200, 'pc'))
        self.assertEqual(c.post('/api/notifications/mutes', json={'kind': 'drift'}).status_code, 400)
        self.assertEqual(c.post('/api/notifications/mutes', json={'kind': 'scan-failed', 'days': 'soon'}).status_code, 400)
        self.assertEqual(c.delete(f'/api/notifications/mutes/{made.get_json()["id"]}').status_code, 200)
        self.assertEqual(c.delete('/api/notifications/mutes/999').status_code, 404)
        self.assertEqual(self.audited(), [('notification.acknowledge', 'ok'), ('notification.snooze', 'denied'), ('notification.snooze', 'denied'), ('notification.snooze', 'ok'),
                                          ('notification.unsnooze', 'ok'), ('notification.unacknowledge', 'ok'), ('notification.acknowledge', 'denied'), ('notification.mute', 'ok'),
                                          ('notification.mute', 'denied'), ('notification.mute', 'denied'), ('notification.unmute', 'ok'), ('notification.unmute', 'denied')])

    def test_a_fix_is_prepared_by_someone_who_may_edit_plans_and_is_audited(self):
        rid = next(r['id'] for r in logrules.rules(self.conn) if r['builtin'] == 'unit-failed')
        self.conn.execute('INSERT INTO log_rule_hits (rule_id, host, bucket, hits, sample) VALUES (:r, :h, :b, 3, :s)', {'r': rid, 'h': 'nas', 'b': int(time.time() // 300), 's': 'smbd.service: Failed with result x'})
        key = f'log-rule:{rid}:nas'
        self.wrong(**{key: problem('log-rule', f'nas:{rid}'), 'scan-failed:pc': problem('scan-failed', 'pc')})
        viewer = self.client('viewer')
        self.assertEqual(viewer.post(f'/api/notifications/fix/{key}').status_code, 403)
        c = self.client('operator')
        got = c.post(f'/api/notifications/fix/{key}')
        self.assertEqual((got.status_code, got.get_json()['label']), (200, 'Restart smbd.service on nas'))
        self.assertEqual(c.get(f'/api/changes/{got.get_json()["plan"]}').get_json()['tasks'][0]['params']['state'], 'restarted')
        self.assertEqual(c.post('/api/notifications/fix/scan-failed:pc').status_code, 400)
        undo = c.post(f'/api/notifications/undo/{got.get_json()["plan"]}')
        self.assertEqual((undo.status_code, undo.get_json()['of']), (200, got.get_json()['plan']))
        self.assertEqual(c.post('/api/notifications/undo/99999').status_code, 404)
        self.assertEqual([r for r in self.audited() if r[0] in ('notification.fix', 'notification.undo')],
                         [('notification.fix', 'ok'), ('notification.fix', 'denied'), ('notification.undo', 'ok'), ('notification.undo', 'denied')])

    def test_nobody_reads_it_without_signing_in(self):
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        for path in ('/api/notifications', '/api/notifications/summary', '/api/notifications/history'):
            self.assertIn(c.get(path).status_code, (401, 302), path)


if __name__ == '__main__':
    unittest.main()
