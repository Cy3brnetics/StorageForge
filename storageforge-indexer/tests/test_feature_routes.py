"""The web routes the test audit of 2026-11-03 found no test had ever called, on real data: a real scan of a real folder, and
scripts that really run wherever the machine running the tests can answer them. tests/lab/tiers_features.py runs the same features on the VMs.
Run with: python3 -m unittest discover -s tests -v"""
import base64
import csv
import hashlib
import io
import os
import shutil
import socket
import subprocess
import tarfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from storageforge_index import alerts, backup, clamav, deploy, engine, folders, graph, hostkeys, jobs, preflight, secplus, security, vault, workloads
from storageforge_index.db import Database
from storageforge_index.remote import Transport
from storageforge_index.scanner import ScanOptions, scan_host
from test_security import Base

SECRET = 'feature routes secret, thrown away with its database'
SSHD = shutil.which('sshd') or next((p for p in ('/usr/sbin/sshd', '/usr/bin/sshd') if os.path.exists(p)), None)


class Scanned(Base):
    """A folder really scanned, so every view has rows that came from the same path a host's do."""

    def setUp(self):
        super().setUp()
        noise = mock.patch.object(folders, 'NOISE_DIRS', tuple(d for d in folders.NOISE_DIRS if d != '/tmp'))   # the tests' folders are under it, and a host's are not
        noise.start()
        self.addCleanup(noise.stop)
        self.data = self.tmp / 'scanned'
        (self.data / 'album').mkdir(parents=True)
        (self.data / 'album-copy').mkdir()
        (self.data / 'old').mkdir()
        same = os.urandom(1 << 16)
        for name in ('a.jpg', 'b.jpg', 'c.jpg'):
            (self.data / 'album' / name).write_bytes(same + name.encode())
            (self.data / 'album-copy' / name).write_bytes(same + name.encode())
        (self.data / 'report.pdf').write_bytes(same)
        (self.data / 'report-copy.pdf').write_bytes(same)
        (self.data / 'gone.txt').write_text('soon gone\n')
        (self.data / 'edited.txt').write_text('first\n')
        old = self.data / 'old' / 'archive.bin'
        old.write_bytes(os.urandom(1 << 21))
        long_ago = time.time() - 10 * 365 * 86400
        os.utime(old, (long_ago, long_ago))
        os.utime(self.data / 'old', (long_ago, long_ago))
        self.result = self.scan(checksum=True)
        self.name = self.result['host']

    def scan(self, checksum=False):
        opts = ScanOptions(roots=[str(self.data)], checksum=checksum, checksum_min_size=1, include_tmpfs=True)
        result = scan_host(self.db, Transport('localhost', local=True), opts, log=lambda m: None)
        graph.rebuild_host(self.db, self.conn, result['host'])
        return result


class DiscoveryViews(Scanned):
    def test_a_host_schedule_keeps_what_it_is_given_and_refuses_the_rest(self):
        url = f'/api/hosts/{self.name}/schedule'
        got = self.client.put(url, json={'interval': '90m', 'quiet_hours': '22-6'}).get_json()
        self.assertEqual((got['interval'], got['quiet_hours']), (5400, '22-6'))
        self.assertEqual(self.client.get(url).get_json(), got)
        for bad in ({'quiet_hours': '25-6'}, {'quiet_hours': '6-6'}, {'quiet_hours': 'night'}, {'interval': 'soon'}):
            self.assertEqual(self.client.put(url, json=bad).status_code, 400, bad)
        self.assertEqual(self.client.get('/api/hosts/nobody/schedule').status_code, 404)

    def test_changes_between_two_scans_are_counted_and_grouped_by_folder(self):
        (self.data / 'gone.txt').unlink()
        (self.data / 'edited.txt').write_text('second, and longer\n')
        (self.data / 'new.txt').write_text('new\n')
        self.scan()
        got = self.client.get(f'/api/file-changes?host={self.name}').get_json()
        self.assertEqual((got['scan']['added'], got['scan']['modified'], got['scan']['deleted']), (1, 2, 1))     # the edited file, and its folder
        self.assertFalse(got['truncated'])
        self.assertEqual(sum(f['added'] for f in got['folders']), 1)
        self.assertEqual(sum(f['deleted'] for f in got['folders']), 1)
        self.assertEqual(self.client.get('/api/file-changes').status_code, 400)
        self.assertIsNone(self.client.get('/api/file-changes?host=nobody').get_json()['scan'])

    def test_capacity_has_a_real_reading_of_the_mount(self):
        self.scan()
        rows = self.client.get(f'/api/capacity?host={self.name}').get_json()['mounts']
        self.assertTrue(rows)
        self.assertTrue(all(r['host'] == self.name and r['total'] >= r['used'] >= 0 and r['points'] for r in rows))
        self.assertEqual(self.client.get('/api/capacity?host=nobody').get_json()['mounts'], [])

    def test_duplicates_are_the_files_with_the_same_bytes(self):
        groups = self.client.get(f'/api/dupes?host={self.name}&min_size=1').get_json()['groups']
        text = str(groups)
        self.assertIn('report-copy.pdf', text)
        self.assertNotIn('edited.txt', text)
        self.assertEqual(self.client.get(f'/api/dupes?host={self.name}&min_size=1GiB').get_json()['groups'], [])

    def test_twin_folders_and_cold_folders(self):
        twins = self.client.get(f'/api/folders/duplicates?host={self.name}&min_files=3&min_size=1').get_json()
        self.assertIn('album-copy', str(twins))
        cold = str(self.client.get(f'/api/folders/cold?host={self.name}&years=2&min_size=1MiB').get_json())
        self.assertIn(str(self.data / 'old'), cold)
        self.assertNotIn('album', cold)

    def test_browsing_lists_a_folder_and_nothing_outside_the_index(self):
        got = str(self.client.get(f'/api/browse?host={self.name}&path={self.data}').get_json())
        for name in ('album', 'album-copy', 'old'):
            self.assertIn(name, got)
        fs = self.client.get(f'/api/fs/browse?host={self.name}&path={self.data}')
        self.assertEqual(fs.status_code, 200, fs.get_data(as_text=True))
        self.assertIn('album', str(fs.get_json()))

    def test_search_hosts_and_jobs_answer_for_the_scanned_host(self):
        self.assertIn(self.name, self.client.get('/api/search/hosts').get_json()['hosts'])
        hits = self.client.get('/api/search?q=report-copy.pdf').get_json()['results']
        self.assertEqual([h['host'] for h in hits], [self.name])
        self.assertEqual(self.client.get('/api/search').status_code, 400)

    def test_host_config_versions_scripts_and_the_bundle(self):
        got = self.client.get(f'/api/hostconfigs?host={self.name}').get_json()
        self.assertTrue(got['versions'], 'a scan captured no configuration')
        cid = got['versions'][0]['config_id']
        one = self.client.get(f'/api/hostconfigs/{cid}').get_json()
        self.assertEqual(one['host'], self.name)
        self.assertEqual(self.client.get('/api/hostconfigs/999999').status_code, 404)
        script = self.client.get(f'/api/hostconfigs/script?host={self.name}')
        self.assertEqual(script.status_code, 200)
        checked = subprocess.run(['bash', '-n'], input=script.get_data(), capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(self.client.get('/api/hostconfigs/script?host=nobody').status_code, 404)
        bundle = self.client.get(f'/api/hostconfigs/bundle?host={self.name}')
        names = tarfile.open(fileobj=io.BytesIO(bundle.get_data()), mode='r:gz').getnames()
        self.assertTrue(any(n.endswith('.sh') for n in names), names)
        self.assertEqual(self.client.get('/api/hostconfigs/bundle?host=nobody').status_code, 404)


class Reports(Scanned):
    def test_the_activity_log_filters_exports_and_keeps_its_own_trail(self):
        self.client.put(f'/api/hosts/{self.name}/schedule', json={'interval': '1d'})
        page = self.client.get(f'/api/log?host={self.name}&limit=100').get_json()
        self.assertTrue(page['entries'])
        self.assertFalse(page['more'])
        only = self.client.get(f'/api/log?host={self.name}&sources=audit&q=hosts.schedule').get_json()['entries']
        self.assertTrue(only)
        self.assertEqual({e['source'] for e in only}, {'audit'})
        self.assertEqual(self.client.get('/api/log?q=nothing-holds-this').get_json()['entries'], [])
        out = self.client.get(f'/api/log/output?id={only[0]["id"]}').get_json()
        self.assertEqual(out['id'], only[0]['id'])
        exported = self.client.get(f'/api/log/export?host={self.name}&format=csv')
        self.assertIn('attachment', exported.headers['Content-Disposition'])
        self.assertGreater(len(list(csv.reader(io.StringIO(exported.get_data(as_text=True))))), 1)
        self.assertEqual(self.client.get('/api/log/export?format=word').status_code, 400)
        self.assertTrue(any(e['action'] == 'log.export' for e in self.client.get('/api/audit?limit=20').get_json()['entries']))

    def test_the_canvas_is_a_canvas_with_no_dangling_edge(self):
        got = self.client.get(f'/api/canvas?host={self.name}')
        self.assertIn('attachment', got.headers['Content-Disposition'])
        doc = got.get_json()
        known = {n['id'] for n in doc['nodes']}
        self.assertTrue(known)
        self.assertEqual([e for e in doc['edges'] if e['fromNode'] not in known or e['toNode'] not in known], [])

    def test_the_file_map_and_ignored_paths(self):
        got = self.client.get(f'/api/filemap?host={self.name}&min_size=1&folders=1')
        self.assertEqual(got.status_code, 200, got.get_data(as_text=True))
        before = str(got.get_json())
        self.assertIn('album-copy', before)
        r = self.client.put('/api/files/ignore', json={'host': '', 'paths': [str(self.data / 'album-copy')]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn(str(self.data / 'album-copy'), str(r.get_json()['ignore']))
        self.assertEqual(self.client.put('/api/files/ignore', json={'paths': 'not a list'}).status_code, 400)

    def test_the_planner_reads_a_scan_saves_and_compares(self):
        hosts = {h['host']: h for h in self.client.get('/api/planner/hosts').get_json()['hosts']}
        self.assertTrue(hosts[self.name]['scanned'])
        self.assertFalse(hosts[self.name]['saved'])
        read = self.client.get(f'/api/planner/design?host={self.name}&source=scan').get_json()
        self.assertEqual(read['source'], 'scan')
        bp = read['blueprint']
        self.assertEqual(self.client.post('/api/planner/changes', json=bp).status_code, 200)
        self.assertEqual(self.client.put('/api/planner/design', json=bp).status_code, 200)
        self.assertTrue(next(h for h in self.client.get('/api/planner/hosts').get_json()['hosts'] if h['host'] == self.name)['saved'])
        self.assertEqual(self.client.get(f'/api/planner/design?host={self.name}').get_json()['source'], 'saved')
        for bad in ({'apiVersion': 'nope'}, {**bp, 'metadata': {'host': 'two words'}}):
            self.assertEqual(self.client.put('/api/planner/design', json=bad).status_code, 400)
        self.assertEqual(self.client.get('/api/planner/design?host=nobody').status_code, 404)
        self.assertEqual(self.client.get('/api/planner/design').status_code, 400)
        self.assertEqual(self.client.put('/api/planner/offsite', json={'host': self.name, 'offsite': True}).get_json()['offsite'], True)
        self.assertTrue(self.client.get(f'/api/planner/design?host={self.name}').get_json()['offsite'])
        self.assertEqual(self.client.put('/api/planner/offsite', json={}).status_code, 400)
        self.assertEqual(self.client.put('/api/planner/example', json={'show': False}).get_json()['example'], False)
        self.assertFalse(self.client.get('/api/planner/hosts').get_json()['example'])
        self.assertEqual(self.client.get(f'/api/planner/activity?host={self.name}').status_code, 200)
        self.assertEqual(self.client.get('/api/planner/activity').status_code, 400)


class Administration(Scanned):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET, 'STORAGEFORGE_BACKUP_DIR': str(self.tmp / 'backups')})
        env.start()
        self.addCleanup(env.stop)
        vault.KDF_DEFAULTS.update(time_cost=1, memory_kib=8192, lanes=1)
        vault.Vault(self.db, self.conn, vault.secret_from_env()).init()

    def test_the_audit_chain_verifies_until_a_row_changes(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            log = vault.AuditLog(self.db, self.conn, v.audit_key)
            for i in range(3):
                log.append('test', 'something', 'ok', None, None, {'i': i})
        got = self.client.get('/api/audit/verify').get_json()
        self.assertTrue(got['valid'])
        self.assertGreaterEqual(got['entries_checked'], 3)
        row = self.conn.scalar("SELECT min(audit_id) FROM audit_log WHERE action = 'something'")
        try:
            self.conn.execute("UPDATE audit_log SET outcome = 'denied' WHERE audit_id = :i", {'i': row})
        except Exception:
            return                      # the database itself refused: as good
        got = self.client.get('/api/audit/verify').get_json()
        self.assertFalse(got['valid'])
        self.assertEqual(got['first_bad_id'], row)

    def test_a_key_with_a_binding_stays_until_the_binding_goes(self):
        made = self.client.post('/api/keys', json={'name': 'lab'})
        self.assertLess(made.status_code, 300, made.get_data(as_text=True))
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.bind('lab', 'nas', 'scan')
        got = self.client.get('/api/keys').get_json()
        self.assertTrue(got['keys'][0]['public_key'].startswith('ssh-ed25519'))
        self.assertEqual(self.client.delete('/api/keys/nobody').status_code, 404)
        self.assertEqual(self.client.delete('/api/keys/lab').status_code, 409)
        self.assertEqual(self.client.delete(f'/api/bindings/{got["bindings"][0]["binding_id"]}').status_code, 200)
        self.assertEqual(self.client.delete('/api/keys/lab').status_code, 200)
        self.assertEqual(self.client.get('/api/keys').get_json()['keys'], [])

    def test_bindings_are_made_and_changed_in_the_ui(self):
        """The console said to run vault bind, with no way in the UI (bug report 2026-11-10)."""
        self.client.post('/api/keys', json={'name': 'cons'})
        made = self.client.post('/api/bindings', json={'key': 'cons', 'host': '10.42.0.100', 'user': 'archie', 'actions': ['console']})
        self.assertEqual(made.status_code, 200, made.get_data(as_text=True))
        bid = made.get_json()['binding_id']
        self.assertEqual(self.client.post('/api/bindings', json={'key': 'cons', 'host': '10.42.0.100', 'user': 'archie', 'actions': ['scan']}).status_code, 409)
        for bad in ([], ['deploy'], ['checksum'], 'console'):
            self.assertEqual(self.client.put(f'/api/bindings/{bid}', json={'actions': bad}).status_code, 400, bad)
        self.assertEqual(self.client.put(f'/api/bindings/{bid}', json={'actions': ['console', 'scan', 'checksum']}).get_json()['actions'], 'scan,checksum,console')
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.resolve('10.42.0.100', 'console').user, 'archie')
            self.assertEqual(v.resolve('10.42.0.100', 'checksum').binding_id, bid)
        self.assertEqual(self.client.post('/api/bindings', json={'key': 'cons', 'host': 'nas-*', 'user': 'scan', 'actions': ['scan']}).status_code, 200)
        self.assertEqual(self.client.post('/api/bindings', json={'key': 'cons', 'host': 'a b', 'user': 'scan', 'actions': ['scan']}).status_code, 400)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'vault.bind%' ORDER BY audit_id")]
        self.assertEqual(actions, ['vault.bind', 'vault.bind.actions', 'vault.bind'])

    def test_backups_are_made_listed_and_keep_a_copy_target(self):
        made = self.client.post('/api/backups', json={}).get_json()
        self.assertTrue(Path(made['path']).exists())
        got = self.client.get('/api/backups').get_json()
        self.assertEqual([b['path'] for b in got['backups']], [made['path']])
        self.assertFalse(got['external'])
        self.assertEqual(self.client.put('/api/backups/target', json={'host': 'nas'}).status_code, 400)
        self.assertEqual(self.client.put('/api/backups/target', json={'host': 'nas', 'path': '../etc'}).status_code, 400)
        self.assertEqual(self.client.put('/api/backups/target', json={'host': 'nas', 'path': '/srv/backups'}).get_json()['target'], {'host': 'nas', 'path': '/srv/backups'})
        self.assertEqual(self.client.get('/api/backups').get_json()['target']['path'], '/srv/backups')
        self.assertIsNone(self.client.put('/api/backups/target', json={}).get_json()['target'])

    def test_a_restored_backup_brings_the_accounts_back(self):
        made = backup.create(self.db)
        self.conn.execute("DELETE FROM users WHERE username = 'admin2'")
        restored = backup.restore(self.db, made['path'])
        self.assertEqual(restored['restored'], made['path'])
        conn = self.db.connect()
        self.addCleanup(conn.close)
        self.assertEqual(conn.scalar("SELECT count(*) FROM users WHERE username = 'admin2'"), 1)
        self.assertTrue(Path(restored['previous']).exists())

    def test_retiring_a_host_is_refused_while_a_job_needs_it_and_takes_it_out_of_every_view(self):
        deploy.mark_deployed(self.conn, self.name, 'tasks', '7', 'digest', {}, 'test')
        r = self.client.delete(f'/api/hosts/{self.name}')
        self.assertEqual(r.status_code, 409)
        self.assertIn('still in use', r.get_json()['error'])
        self.conn.execute('DELETE FROM deployed WHERE host = :h', {'h': self.name})
        self.assertEqual(self.client.delete('/api/hosts/nobody').status_code, 404)
        r = self.client.delete(f'/api/hosts/{self.name}')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotIn(self.name, [h['hostname'] for h in self.client.get('/api/hosts').get_json()['indexed']])
        self.assertEqual(self.client.get('/api/search?q=report-copy.pdf').get_json()['results'], [])
        self.assertEqual(self.client.get(f'/api/hosts/{self.name}/schedule').status_code, 404)
        self.assertTrue(any(e['action'] == 'hosts.retire' for e in self.client.get('/api/audit?limit=10').get_json()['entries']))


class RemovedJobs(Scanned):
    def test_a_plan_whose_jobs_were_removed_can_be_deleted_and_its_host_retired(self):
        plan = self.client.post('/api/moves', json={'name': 'gone soon', 'steps': []}).get_json()
        deploy.mark_deployed(self.conn, self.name, 'jobs', f'p{plan["id"]}', 'digest', {'jobs': ['x'], 'hosts': [self.name]}, 'test')
        self.assertEqual(self.client.delete(f'/api/moves/{plan["id"]}').status_code, 409)
        self.assertEqual(self.client.delete(f'/api/hosts/{self.name}').status_code, 409)
        for item in jobs.deploy_items(self.db, self.conn, {**plan, 'steps': []}, 'apply', None, 'test'):
            if item.get('on_ok'):
                item['on_ok']({'status': 'ok'})
        self.assertEqual(deploy.deployed(self.conn, kind='jobs'), [])
        self.assertEqual(self.client.delete(f'/api/moves/{plan["id"]}').status_code, 200)
        self.assertEqual(self.client.delete(f'/api/hosts/{self.name}').status_code, 200)


class MapViews(Scanned):
    def test_a_node_and_an_edge_come_back_and_what_is_not_there_is_404(self):
        got = self.client.get(f'/api/map?host={self.name}').get_json()
        self.assertTrue(got['nodes'] and got['edges'])
        node_id = got['nodes'][0]['id']
        self.assertEqual(self.client.get(f'/api/map/node/{node_id}').get_json()['node']['id'], node_id)
        self.assertEqual(self.client.get('/api/map/node/no-such-thing').status_code, 404)
        e = got['edges'][0]
        r = self.client.get('/api/map/edge', query_string={'src': e['src'], 'dst': e['dst'], 'rel': e['rel']})
        self.assertEqual(r.get_json()['edge']['rel'], e['rel'])
        self.assertEqual(self.client.get('/api/map/edge?src=a&dst=b&rel=c').status_code, 404)

    def test_exposure_answers_for_each_scope_and_refuses_another(self):
        for scope in ('lan', 'vpn', 'any'):
            got = self.client.get(f'/api/map/exposure?host={self.name}&scope={scope}').get_json()
            self.assertEqual((got['scope'], got['hosts'][0]['host']), (scope, self.name))
        self.assertEqual(self.client.get('/api/map/exposure?scope=mars').status_code, 400)
        self.assertEqual(self.client.get('/api/map/exposure?host=nobody').status_code, 400)

    def test_coverage_says_what_has_not_been_read(self):
        got = self.client.get(f'/api/map/coverage?host={self.name}').get_json()
        self.assertIn('coverage', got)
        self.assertIn('warnings', got)


class ClamavRoutes(Base):
    SIG = 'Win.Test.EICAR_HDB-1'

    def found(self, path='/srv/eicar.com'):
        end = int(time.time())
        line = f'run\t{uuid.uuid4()}\t{end - 5}\t{end}\t1\t3\tClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026\nfound\t{base64.b64encode(path.encode()).decode()}\t{self.SIG}'
        self.assertTrue(clamav.ingest(self.conn, 'nas', line))
        return self.client.get('/api/clamav?host=nas').get_json()['detections'][0]['id']

    def answers(self, *outputs, status='ok'):
        said = iter(outputs)
        calls = []

        def run(db, host, script, args=(), **kw):
            calls.append({'host': host, 'args': list(args), 'script': script, **kw})
            return {'status': status, 'output': next(said), 'run_id': len(calls)}
        p = mock.patch.object(deploy, 'run', run)
        p.start()
        self.addCleanup(p.stop)
        return calls

    def test_a_host_lists_its_config_and_a_bad_config_is_refused(self):
        got = self.client.post('/api/clamav/hosts/nas/config', json={'schedule': 'daily', 'paths': ['/srv']}).get_json()
        self.assertEqual((got['schedule'], got['paths'], got['custom_paths']), ('daily', ['/srv'], True))
        host = self.client.get('/api/clamav?host=nas').get_json()['hosts'][0]
        self.assertEqual(host['config']['paths'], ['/srv'])
        self.assertFalse(host['installed'])
        for bad in ({'schedule': 'hourly'}, {'paths': ['relative']}, {'paths': ['/srv/../etc']}):
            self.assertEqual(self.client.post('/api/clamav/hosts/nas/config', json=bad).status_code, 400, bad)

    def test_quarantine_then_restore_change_state_only_when_the_host_says_it_happened(self):
        did = self.found()
        digest = hashlib.sha256(b'x').hexdigest()
        self.answers('it went wrong')
        r = self.client.post(f'/api/clamav/detections/{did}/quarantine', json={})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(clamav.get_detection(self.conn, did)['state'], 'open')
        mock.patch.stopall()

        calls = []

        def moved(db, host, script, args=(), **kw):
            qid = kw.get('ref', '')
            calls.append(script)
            import re
            m = re.search(r'\b([0-9a-f]{32})\b', script)
            return {'status': 'ok', 'output': f'QUARANTINED {m[1]} {digest}\nRESTORED {m[1]}\n', 'run_id': 1, 'ref': qid}
        with mock.patch.object(deploy, 'run', moved):
            r = self.client.post(f'/api/clamav/detections/{did}/quarantine', json={})
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            d = self.client.get('/api/clamav?host=nas').get_json()['detections'][0]
            self.assertEqual((d['state'], d['sha256']), ('quarantined', digest))
            self.assertEqual(self.client.post(f'/api/clamav/detections/{did}/quarantine', json={}).status_code, 400)
            r = self.client.post(f'/api/clamav/detections/{did}/restore', json={})
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            d = self.client.get('/api/clamav?host=nas').get_json()['detections'][0]
            self.assertEqual((d['state'], d['ignored']), ('open', True))         # someone decided it is safe
            self.assertEqual(self.client.post(f'/api/clamav/detections/{did}/restore', json={}).status_code, 400)

    def test_ignoring_keeps_a_reason_and_can_be_undone(self):
        did = self.found()
        self.assertTrue(self.client.post(f'/api/clamav/detections/{did}/ignore', json={'ignore': True, 'reason': 'the test file'}).get_json()['ok'])
        d = self.client.get('/api/clamav?host=nas').get_json()['detections'][0]
        self.assertEqual((d['ignored'], d['ignore_reason']), (True, 'the test file'))
        self.client.post(f'/api/clamav/detections/{did}/ignore', json={'ignore': False})
        self.assertFalse(self.client.get('/api/clamav?host=nas').get_json()['detections'][0]['ignored'])

    def test_collect_reads_the_hosts_last_result(self):
        self.answers('no result yet\n')
        r = self.client.post('/api/clamav/hosts/nas/collect')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertFalse(r.get_json()['new'])

    def test_a_failed_collect_is_not_reported_as_an_empty_one(self):
        self.answers('', status='failed')
        self.assertEqual(self.client.post('/api/clamav/hosts/nas/collect').status_code, 409)

    def test_the_malware_preview_reads_bytes_and_never_runs_the_file(self):
        target = self.tmp / 'sample.bin'
        target.write_bytes(b'MZ readable text inside it\x00\x01\x02')
        target.chmod(0o755)
        did = self.found(str(target))
        r = self.post('/api/security/malware/preview', id=did)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        out = r.get_json()['output']
        self.assertIn(hashlib.sha256(target.read_bytes()).hexdigest(), out)
        self.assertIn('readable text', out)
        target.unlink()
        self.assertIn('GONE', self.post('/api/security/malware/preview', id=did).get_json()['output'])


class SecurityPolicies(Base):
    """What an operator saves, each read back, refused when wrong, and gone when deleted."""

    def round_trip(self, url, body, listed, *bad):
        r = self.client.post(url, json=body)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        for wrong in bad:
            self.assertEqual(self.client.post(url, json=wrong).status_code, 400, wrong)
        rows = self.client.get(url).get_json()[listed]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(self.client.delete(f'{url}/{rows[0]["id"]}').status_code, 200)
        self.assertEqual(self.client.get(url).get_json()[listed], [])
        return rows[0]

    def test_a_waiver(self):
        got = self.round_trip('/api/security/waivers', {'host': 'nas', 'finding': 'KRNL-6000', 'reason': 'kept for a legacy client', 'days': 30}, 'waivers',
                              {'host': 'nas', 'finding': 'KRNL-6000', 'reason': 'short', 'days': 30}, {'host': 'nas', 'finding': 'KRNL-6000', 'reason': 'a real reason', 'days': 0},
                              {'host': 'nobody', 'finding': 'x', 'reason': 'a real reason', 'days': 3})
        self.assertEqual(got['finding'], 'KRNL-6000')

    def test_a_profile(self):
        got = self.round_trip('/api/security/profiles', {'name': 'lab', 'base': 'cis-l1', 'overrides': {'target_lynis': 70}}, 'profiles',
                              {'name': 'x', 'base': 'not a standard'}, {'name': 'x', 'base': 'cis-l1', 'overrides': {'target_lynis': 101}},
                              {'name': 'x', 'base': 'cis-l1', 'overrides': {'add': ['no-such-check']}})
        self.assertEqual(got['name'], 'lab')

    def test_a_retention_policy(self):
        self.round_trip('/api/security/worm/policies', {'host': 'nas', 'pattern': 'tank/*', 'days': 14}, 'policies',
                        {'host': 'nas', 'pattern': 'bad pattern;', 'days': 1}, {'host': 'nas', 'pattern': 'tank/*', 'days': 0})

    def test_a_yara_rule_set(self):
        self.round_trip('/api/security/behavior/yara/rules', {'name': 'lab', 'body': 'rule x { condition: true }'}, 'rules',
                        {'name': 'lab', 'body': 'not yara'}, {'name': 'two;words', 'body': 'rule x { condition: true }'})

    def test_a_playbook(self):
        trigger, action = next(iter(secplus.TRIGGERS)), next(iter(secplus.ACTIONS))
        self.round_trip('/api/security/playbooks', {'name': 'lab', 'trigger': trigger, 'actions': [action]}, 'playbooks',
                        {'name': 'lab', 'trigger': 'not one', 'actions': [action]}, {'name': 'lab', 'trigger': trigger, 'actions': []})

    def test_ban_tiers_thresholds_filters_watch_and_context_read_back(self):
        tiers = {t: {'label': f'tier {t}', 'minutes': int(t) * 10} for t in ('1', '2', '3')}
        self.assertEqual(self.client.post('/api/security/firewall/tiers', json={'tiers': tiers}).status_code, 200)
        self.assertEqual(self.client.get('/api/security/firewall/tiers').get_json()['tiers']['3']['minutes'], 30)
        self.assertEqual(self.client.post('/api/security/firewall/tiers', json={'tiers': {**tiers, '1': {'minutes': -1}}}).status_code, 400)

        r = self.client.post('/api/security/behavior/filters', json={'skip_over_mb': 100, 'skip_ext': ['ISO', '.mp4', ''], 'deep_ext': ['docx']})
        self.assertEqual(r.get_json()['skip_ext'], ['.iso', '.mp4'])
        self.assertEqual(self.client.post('/api/security/behavior/filters', json={'skip_over_mb': 0}).status_code, 400)

        r = self.client.post('/api/security/integrity/aide/watch', json={'paths': ['/etc', '/etc', '/srv/data']})
        self.assertEqual(r.get_json()['paths'], ['/etc', '/srv/data'])
        self.assertEqual(self.client.get('/api/security/integrity/aide/watch').get_json()['paths'], ['/etc', '/srv/data'])

        r = self.client.post('/api/security/mac/context', json={'rules': [{'pattern': '/srv/share(/.*)?', 'type': 'samba_share_t'}]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(self.client.post('/api/security/mac/context', json={'rules': [{'pattern': '/srv', 'type': 'not a type;'}]}).status_code, 400)

    def test_every_dashboard_tile_answers_and_the_read_only_views_name_their_host(self):
        for tile in self.client.get('/api/security/dash/tiles').get_json()['tiles']:
            kind = tile['kind'] if isinstance(tile, dict) else tile
            r = self.client.get(f'/api/security/dash/tile/{kind}?host=nas')
            self.assertEqual(r.status_code, 200, f'{kind}: {r.get_data(as_text=True)}')
        self.assertEqual(self.client.get('/api/security/trend?host=nas').get_json()['host'], 'nas')
        self.assertIn('hosts', self.client.get('/api/security/badges').get_json())
        standards = self.client.get('/api/security/compliance/standards').get_json()
        self.assertIn('cis-l1', str(standards))
        self.assertEqual(self.client.get('/api/security/trend').status_code, 400)


class SecurityActions(Base):
    def test_a_rollback_preview_counts_what_a_restore_would_really_do(self):
        if not shutil.which('rsync'):
            self.skipTest('needs rsync')
        snap, live = self.tmp / 'snap', self.tmp / 'live'
        snap.mkdir()
        live.mkdir()
        (snap / 'same.txt').write_text('same\n')
        (live / 'same.txt').write_text('same\n')
        (snap / 'changed.txt').write_text('before\n')
        (live / 'changed.txt').write_text('after!\n')
        (live / 'since.txt').write_text('new since the snapshot\n')
        (snap / 'lost.txt').write_text('deleted since\n')
        r = self.post('/api/security/worm/preview', host='nas', snapshot=str(snap), live=str(live))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        got = r.get_json()
        self.assertEqual(got['counts'], {'M': 1, '+': 1, '-': 1})
        self.assertEqual(sorted(s['path'] for s in got['samples']), ['changed.txt', 'lost.txt', 'since.txt'])

    def test_a_preview_of_nothing_says_so(self):
        got = self.post('/api/security/worm/preview', host='nas', snapshot='/nowhere/snap', live='/nowhere/live').get_json()
        self.assertFalse(got['ok'])
        self.assertIn('no folder', got['error'])
        self.assertEqual(self.post('/api/security/worm/preview', host='nas', snapshot='relative', live='/x').status_code, 400)

    def test_a_freeze_holds_every_snapshot_and_a_dry_run_holds_none(self):
        self.snap('tank/shares@a')
        self.snap('tank/shares@b')
        with self.zstate.open('a') as f:
            f.write('tank/shares\n')
        with mock.patch.object(security, '_b64text', lambda s: base64.b64decode(s).decode()):
            dry = self.post('/api/security/worm/freeze', host='nas', target='tank/shares', mode='report')
            self.assertEqual(dry.status_code, 200, dry.get_data(as_text=True))
            self.assertIsNone(self.hold_status())
            self.assertEqual(self.post('/api/security/worm/freeze', host='nas', target='bad target;', mode='apply').status_code, 400)

    def test_the_clean_room_sweep_tells_a_hit_from_nothing_from_a_mount_it_refuses(self):
        said = []

        def run(db, host, script, args=(), **kw):
            return {'status': 'ok', 'output': said[0], 'run_id': 1, 'host': host}
        with mock.patch.object(deploy, 'run', run):
            said[:] = ['NOTCLEANROOM\n']
            got = self.post('/api/security/incident/clean-room/sweep', host='nas', mount='/mnt/x').get_json()
            self.assertFalse(got['ok'])
            self.assertIn('read-only', got['error'])
            said[:] = ['FILES 12\nCLAM rc=0\nYARA rc=0\nSWEEP done\n']
            got = self.post('/api/security/incident/clean-room/sweep', host='nas', mount='/mnt/x').get_json()
            self.assertTrue(got['clean'])
            self.assertEqual((got['files'], got['ran']), (12, ['clam', 'yara']))
            said[:] = ['FILES 12\nCLAM rc=1\nHIT clam /mnt/x/bad: Eicar FOUND\nSWEEP done\n']
            got = self.post('/api/security/incident/clean-room/sweep', host='nas', mount='/mnt/x').get_json()
            self.assertFalse(got['clean'])
            self.assertEqual(got['hits'][0]['tool'], 'clam')
            said[:] = ['FILES 0\nSWEEP done\n']
            got = self.post('/api/security/incident/clean-room/sweep', host='nas', mount='/mnt/x').get_json()
            self.assertFalse(got['clean'], 'no tool ran: nothing was looked at, which is not clean')

    def test_the_package_check_reports_the_tools_as_the_host_does(self):
        def run(db, host, script, args=(), **kw):
            self.assertEqual(kw['mode'], 'report')
            return {'status': 'ok', 'output': 'PM apt-get\nTOOL aide present\nTOOL yara blocked\nDONE\n', 'run_id': 1}
        with mock.patch.object(deploy, 'run', run):
            got = self.post('/api/security/packages/check', host='nas').get_json()
        self.assertEqual((got['pm'], got['tools']), ('apt-get', {'aide': 'present', 'yara': 'blocked'}))
        reading = self.client.get('/api/security/packages?host=nas').get_json()['reading']
        self.assertEqual(reading['tools']['yara'] if 'tools' in reading else reading['data']['tools']['yara'], 'blocked')

    def test_a_check_cut_short_is_not_a_clean_reading(self):
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'ok', 'output': 'PM apt-get\n', 'run_id': 1}):
            got = self.post('/api/security/packages/check', host='nas')
        self.assertIn(got.status_code, (200, 409))
        self.assertFalse(got.get_json()['ok'])
        self.assertIsNone(self.client.get('/api/security/packages?host=nas').get_json()['reading'])

    def test_falco_rules_must_be_falco_rules(self):
        for bad in ('rule: not a list', '- not: a rule', '- rule: [unclosed'):
            got = self.post('/api/security/behavior/falco', host='nas', mode='report', rules=bad)
            self.assertEqual(got.status_code, 400, f'{bad[:30]}: {got.get_data(as_text=True)}')
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'ok', 'output': 'FALCO on\n', 'run_id': 1}):
            good = self.post('/api/security/behavior/falco', host='nas', mode='apply', rules='- rule: lab\n  desc: x\n  condition: open_write\n  output: x\n  priority: WARNING\n')
        self.assertEqual(good.status_code, 200, good.get_data(as_text=True))
        self.assertEqual(alerts.get_setting(self.conn, secplus.FALCO_RULES)[:10], '- rule: la')

    def test_the_audited_tools_refuse_what_they_do_not_know(self):
        self.assertEqual(self.post('/api/security/integrity/run', host='nas', tool='rm').status_code, 400)
        self.assertEqual(self.post('/api/security/integrity/run', host='nobody', tool='lynis').status_code, 400)


class ContainerFindings(unittest.TestCase):
    def test_what_makes_a_container_root_on_its_host_is_said(self):
        self.assertEqual(workloads.container_findings({}), [])
        self.assertIn('privileged', workloads.container_findings({'privileged': True})[0])
        self.assertIn('socket', workloads.container_findings({'mounts': [{'source': '/var/run/docker.sock'}]})[0])
        self.assertIn('host network', workloads.container_findings({'network_mode': 'host'})[0])
        self.assertIn('CAP_SYS_ADMIN', workloads.container_findings({'cap_add': ['CAP_SYS_ADMIN']})[0])
        self.assertEqual(workloads.container_findings({'cap_add': ['CAP_CHOWN']}), [])
        self.assertIn('confinement', workloads.container_findings({'security_opt': ['seccomp=unconfined']})[0])


@unittest.skipUnless(SSHD, 'needs sshd (CI has it)')
class RealSshServer(unittest.TestCase):
    """Host keys and login methods, from a real sshd on a port of its own: nothing here is parsed from a sample."""

    def setUp(self):
        self.tmp = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        key = self.tmp / 'host_key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.fingerprint = subprocess.run(['ssh-keygen', '-lf', f'{key}.pub'], capture_output=True, text=True, check=True).stdout.split()[1]
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        conf = self.tmp / 'sshd_config'
        conf.write_text(f'Port {self.port}\nListenAddress 127.0.0.1\nHostKey {key}\nPidFile {self.tmp}/pid\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n')
        self.sshd = subprocess.Popen([SSHD, '-D', '-e', '-f', str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.sshd.wait)
        self.addCleanup(self.sshd.kill)
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1', self.port)) == 0:
                    break
            time.sleep(0.05)
        else:
            self.skipTest('sshd would not start here')
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_DATA_DIR': str(self.tmp), 'STORAGEFORGE_RUNTIME_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        self.db = Database(f'sqlite:///{self.tmp}/i.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def test_offered_reads_the_key_the_server_presents(self):
        got = hostkeys.offered('127.0.0.1', self.port)
        self.assertEqual(got[0]['fingerprint'], self.fingerprint)

    def test_offered_says_when_nothing_answers_and_refuses_a_bad_address(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            free = s.getsockname()[1]
        with self.assertRaisesRegex(ValueError, 'no SSH server answered'):
            hostkeys.offered('127.0.0.1', free)
        with self.assertRaises(ValueError):
            hostkeys.offered('-oProxyCommand=x', self.port)

    def test_a_password_waits_for_a_person_to_compare_the_key(self):
        with self.assertRaises(hostkeys.HostKeyNeeded) as seen:
            hostkeys.require_confirmed(self.conn, '127.0.0.1', self.port)
        self.assertEqual(seen.exception.as_dict()['keys'][0]['fingerprint'], self.fingerprint)
        with self.assertRaisesRegex(ValueError, 'different key'):
            hostkeys.confirm(self.conn, '127.0.0.1', self.port, 'SHA256:not-the-key', 'test')
        hostkeys.confirm(self.conn, '127.0.0.1', self.port, self.fingerprint, 'test')
        hostkeys.require_confirmed(self.conn, '127.0.0.1', self.port)
        with self.assertRaisesRegex(ValueError, 'not the key StorageForge holds'):
            hostkeys.confirm(self.conn, '127.0.0.1', self.port, 'SHA256:another', 'test')

    def test_the_login_methods_are_what_the_server_offers(self):
        methods = preflight.auth_methods('127.0.0.1', self.port)
        self.assertIn('publickey', methods)
        self.assertFalse(preflight.takes_password(methods))
        self.assertTrue(preflight.takes_password(['publickey', 'password']))


class EngineCancel(unittest.TestCase):
    def test_cancelling_what_is_not_running_says_so(self):
        with self.assertRaises(LookupError):
            engine.cancel(None, 'no-such-group', 'test')

    def test_force_kills_what_is_running_and_plain_cancel_does_not(self):
        killed = []
        live = type('Live', (), {'cancelled': False, 'by': None, 'procs': {1: type('P', (), {'kill': lambda self: killed.append(1)})()}})()
        with mock.patch.dict(engine._live, {'g': live}):
            self.assertEqual(engine.cancel(None, 'g', 'me')['killed'], 0)
            self.assertEqual((live.cancelled, live.by, killed), (True, 'me', []))
            self.assertEqual(engine.cancel(None, 'g', 'me', force=True)['killed'], 1)
            self.assertEqual((live.cancelled, killed), ('force', [1]))


if __name__ == '__main__':
    unittest.main()
