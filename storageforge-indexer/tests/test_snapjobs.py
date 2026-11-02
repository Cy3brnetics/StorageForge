"""rsnapshot and snapper jobs nobody here deployed: finding them, importing them, what each tool's actions do.
Run with: python3 -m unittest discover -s tests -v"""
import json
import os
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
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import alerts, deploy, graph, jobs, moves, protection, server, snapfind, snapjobs, users
from storageforge_index.db import Database
from storageforge_index.remote import INVENTORY_SCRIPT, SECTIONS

CONF = '/etc/rsnapshot-sdcard.conf'
NOW = int(time.time())


def found_text(newest=NOW - 3600, log='', cron='30 2 * * *\troot\t/usr/bin/rsnapshot -c /etc/rsnapshot-sdcard.conf daily', fstype='ext4'):
    return '\n'.join(filter(None, [
        f'C\t/etc/cron.d/sdcard\t1\t{cron}' if cron else '',
        f'R\t{CONF}\tsnapshot_root\t/mnt/sdcard/snapshots/',
        f'R\t{CONF}\tretain\tdaily\t7', f'R\t{CONF}\tretain\tweekly\t4',
        f'R\t{CONF}\tbackup\t/home/\tlocalhost/', f'R\t{CONF}\tbackup\t/etc/\tlocalhost/', f'R\t{CONF}\tlogfile\t/var/log/rsnapshot.log',
        f'M\t{CONF}\t{fstype}\t/mnt/sdcard\t1',
        f'S\t{CONF}\tdaily.0\t{newest}.5', f'S\t{CONF}\tdaily.1\t{newest - 86400}.0', f'S\t{CONF}\tnot-a-snapshot\t{newest}.0',
        f'L\t{CONF}\t{log}' if log else '']))


SNAPPER = '\n'.join(['P\troot\tSUBVOLUME="/"', 'P\troot\tFSTYPE="btrfs"', 'P\troot\tTIMELINE_CREATE="yes"', 'P\troot\tTIMELINE_CLEANUP="yes"',
                     'P\troot\tTIMELINE_LIMIT_HOURLY="10"', 'P\troot\tNUMBER_LIMIT="50"', 'W\troot\tbtrfs\t/\t1',
                     f'Q\troot\t12\t{NOW - 600}.1', f'Q\troot\t11\t{NOW - 4200}.1', 'G\tsnapper-timeline.timer\tenabled', 'G\tsnapper-cleanup.timer\tdisabled'])


class Parse(unittest.TestCase):
    def test_a_custom_named_config_and_its_cron_line(self):
        j = snapfind.parse(found_text())[0]
        self.assertEqual((j['tool'], j['config'], j['root'], j['fstype'], j['mount']), ('rsnapshot', CONF, '/mnt/sdcard/snapshots', 'ext4', '/mnt/sdcard'))
        self.assertEqual(j['levels'], {'daily': 7, 'weekly': 4})
        self.assertEqual(j['lowest'], 'daily')
        self.assertEqual([s['name'] for s in j['snapshots']], ['daily.0', 'daily.1'])
        self.assertEqual(j['schedule'][0]['calendar'], '*-*-* 2:30:00')
        self.assertTrue(j['schedule'][0]['enabled'])

    def test_a_cron_line_with_no_c_means_the_default_config(self):
        j = snapfind.parse('C\t/etc/crontab\t1\t0 3 * * * root rsnapshot daily')[0]
        self.assertEqual((j['config'], j['readable']), (snapfind.DEFAULT_CONF, False))

    def test_paused_lines_scripts_and_comments(self):
        entry = snapfind._cron_entry('/etc/cron.d/x', '1', f'{snapfind.PAUSED}0 3 * * * root rsnapshot daily')
        self.assertFalse(entry['enabled'])
        self.assertEqual(entry['line'], '0 3 * * * root rsnapshot daily')
        self.assertIsNone(snapfind._cron_entry('/etc/cron.d/x', '1', '# 0 3 * * * root rsnapshot daily'))
        self.assertIsNone(snapfind._cron_entry('/etc/cron.d/x', '1', '0 3 * * * root rsnapshot configtest'))
        script = snapfind._cron_entry('/etc/cron.weekly/rs', '0', 'rsnapshot -c /a.conf weekly')
        self.assertEqual((script['kind'], script['enabled'], script['calendar'], script['conf']), ('script', False, 'weekly', '/a.conf'))

    def test_own_units_and_stock_configs_are_left_out(self):
        self.assertEqual(snapfind.parse(f'U\tsf-move-1\tenabled\tdaily\t/usr/bin/rsnapshot -c {CONF} daily\nR\t{CONF}\tsnapshot_root\t/x/'), [])
        self.assertEqual(snapfind.parse(f'R\t{CONF}\tlogfile\t/x'), [])

    def test_snapper_config(self):
        j = snapfind.parse(SNAPPER)[0]
        self.assertEqual((j['tool'], j['root'], j['fstype'], j['newest']), ('snapper', '/', 'btrfs', NOW - 600))
        self.assertEqual(j['levels'], {'hourly': 10, 'number': 50})
        self.assertEqual(j['schedule'][0]['unit'], 'snapper-timeline.timer')
        self.assertFalse(j['cleanup_on'])

    def test_the_section_is_in_the_scan(self):
        self.assertIn('snapjobs', SECTIONS)
        self.assertNotIn('@@SNAPFIND@@', INVENTORY_SCRIPT)

    def test_the_search_runs_and_finds_a_config_by_its_cron_line(self):
        """The real script, with the search roots pointed at a sandbox."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        root = tmp / 'snaps'
        (root / 'daily.0').mkdir(parents=True)
        (root / 'unrelated').mkdir()
        conf, cron = tmp / 'weird name.conf', tmp / 'cron.d'
        conf.write_text(f'snapshot_root\t{root}/\nretain\tdaily\t7\nbackup\t/home/\tlocalhost/\n')
        cron.mkdir()
        (cron / 'x').write_text(f'0 3 * * * root rsnapshot -c {tmp}/other.conf daily\n')
        (tmp / 'other.conf').write_text(f'snapshot_root\t{root}/\nretain\tdaily\t3\n')
        script = snapfind.SNAPFIND.replace('/etc/crontab /etc/cron.d/*', f'{cron}/*').replace('/etc /usr/local/etc /root', str(tmp))
        out = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=60).stdout
        by = {j['config']: j for j in snapfind.parse(out) if j['tool'] == 'rsnapshot'}
        self.assertEqual(by[str(conf)]['levels'], {'daily': 7})         # found by what is in it, whatever it is called
        self.assertEqual(by[f'{tmp}/other.conf']['levels'], {'daily': 3})
        self.assertEqual([s['name'] for s in by[str(conf)]['snapshots']], ['daily.0'])
        self.assertEqual(by[f'{tmp}/other.conf']['schedule'][0]['level'], 'daily')


class Advice(unittest.TestCase):
    def test_each_filesystem_gets_its_tool(self):
        self.assertEqual(snapjobs.recommend('btrfs')['tool'], 'snapper')
        for fs in ('ext4', 'xfs', 'f2fs'):
            self.assertEqual(snapjobs.recommend(fs)['tool'], 'rsnapshot')
        self.assertIsNone(snapjobs.recommend('zfs')['tool'])
        self.assertEqual((snapjobs.recommend('vfat')['tool'], snapjobs.recommend('exfat')['level']), (None, 'crit'))

    def test_a_card_without_hard_links_is_called_out(self):
        j = snapfind.parse(found_text(fstype='exfat'))[0]
        self.assertEqual(snapjobs.fit(j)[0]['level'], 'crit')
        self.assertEqual(snapjobs.fit(snapfind.parse(found_text())[0]), [])

    def test_snapper_with_cleanup_off_is_called_out(self):
        self.assertIn('snapper-cleanup.timer', snapjobs.fit(snapfind.parse(SNAPPER)[0])[0]['text'])


class Imported(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.scan(found_text() + '\n' + SNAPPER)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def scan(self, text, host='pi'):
        inv = json.dumps({'snapjobs': snapfind.parse(text)})
        if self.conn.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
            self.conn.execute('UPDATE hosts SET inventory_json = :i WHERE hostname = :h', {'i': inv, 'h': host})
        else:
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', :i)", {'h': host, 'i': inv})

    def job(self, jid):
        return next(j for j in jobs.overview(self.conn) if j['id'] == jid)

    def test_found_then_imported_then_ok_from_its_snapshots(self):
        found = {(c['tool'], c['config']): c for c in snapjobs.candidates(self.conn)}
        self.assertIsNone(found[('rsnapshot', CONF)]['job'])
        self.assertEqual(found[('rsnapshot', CONF)]['count'], 2)
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        self.assertEqual({c['job'] for c in snapjobs.candidates(self.conn) if c['config'] == CONF}, {jid})
        j = self.job(jid)
        self.assertEqual((j['state'], j['imported'], j['method'], j['dst']), ('ok', True, 'rsnapshot', '/mnt/sdcard/snapshots'))
        self.assertEqual(j['sources'], ['/home', '/etc'])
        self.assertEqual(j['last_ok']['message'], 'snapshot daily.0 seen')

    def test_the_same_snapshot_seen_twice_is_one_run(self):
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        snapjobs.refresh(self.conn, 'pi', snapjobs.found_on(self.conn, 'pi'))
        self.assertEqual(len(jobs.runs(self.conn, jid)), 1)

    def test_late_failed_and_gone(self):
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        self.conn.execute('DELETE FROM job_runs')
        snapjobs.refresh(self.conn, 'pi', snapfind.parse(found_text(newest=NOW - 9 * 86400)))
        self.assertEqual(self.job(jid)['state'], 'stale')
        self.assertIn(f'job-stale:{jid}', alerts.problems(self.conn))
        stamp = time.strftime('%Y-%m-%dT%H:%M:%S')
        snapjobs.refresh(self.conn, 'pi', snapfind.parse(found_text(log=f'[{stamp}] /usr/bin/rsnapshot daily: ERROR: /usr/bin/rsync returned 23')))
        self.assertEqual(self.job(jid)['state'], 'failed')
        snapjobs.refresh(self.conn, 'pi', [])
        self.assertEqual(self.job(jid)['state'], 'missing')

    def test_no_snapshots_visible_is_unseen_not_late(self):
        self.scan(f'R\t{CONF}\tsnapshot_root\t/root/snaps/\nR\t{CONF}\tretain\tdaily\t7\nC\t/etc/crontab\t1\t0 3 * * * root rsnapshot -c {CONF} daily')
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        self.conn.execute('UPDATE jobs SET deployed_at = 1 WHERE job_id = :j', {'j': jid})
        self.assertEqual(self.job(jid)['state'], 'unseen')

    def test_cannot_import_what_it_cannot_read(self):
        self.scan('C\t/etc/crontab\t1\t0 3 * * * root rsnapshot daily')
        with self.assertRaisesRegex(ValueError, 'look on pi as root'):
            snapjobs.import_job(self.conn, 'pi', 'rsnapshot', snapfind.DEFAULT_CONF, 't')
        with self.assertRaises(LookupError):
            snapjobs.import_job(self.conn, 'pi', 'rsnapshot', '/etc/none.conf', 't')

    def test_a_root_look_fills_in_what_a_scan_cannot_see(self):
        self.scan(f'N\t{CONF}')
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'ok', 'output': found_text()}):
            snapjobs.probe(None, self.conn, 'pi', 't')
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        self.assertEqual(self.job(jid)['state'], 'ok')
        calls = []
        self.conn.execute("INSERT INTO deploy_access (host, state, updated_at) VALUES ('pi', 'ready', 1)")
        with mock.patch.object(deploy, 'run', lambda *a, **k: calls.append(k) or {'status': 'ok', 'output': found_text()}):
            snapjobs.after_scan(None, self.conn, 'pi', snapfind.parse(f'N\t{CONF}'))         # the scan alone can't see it
            self.assertEqual(calls[0]['mode'], 'report')
            snapjobs.after_scan(None, self.conn, 'pi', snapfind.parse(found_text()))         # now it can: no signed run
        self.assertEqual(len(calls), 1)

    def test_forget_leaves_the_host_alone(self):
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        with mock.patch.object(deploy, 'run', side_effect=AssertionError):
            snapjobs.forget(self.conn, jid)
        self.assertNotIn(jid, [j['id'] for j in jobs.overview(self.conn)])
        self.assertEqual(snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't'), jid)

    def test_it_fills_the_matrix_and_adds_no_drift(self):
        snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        snapjobs.import_job(self.conn, 'pi', 'snapper', 'root', 't')
        rows = protection.overlay(self.conn, 'pi', [{'path': '/home', 'node': 'a'}, {'path': '/etc', 'node': 'b'}, {'path': '/', 'node': 'c'}])
        self.assertEqual(rows[0]['backup']['target'], 'pi:/mnt/sdcard/snapshots')
        self.assertEqual(rows[1]['backup']['target'], 'pi:/mnt/sdcard/snapshots')
        self.assertEqual(rows[2]['snapshots']['tool'], 'snapper')
        self.assertEqual(alerts.drift(self.conn), [])

    def test_actions_go_to_the_right_tool(self):
        rs = jobs.get(self.conn, snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't'))
        sn = jobs.get(self.conn, snapjobs.import_job(self.conn, 'pi', 'snapper', 'root', 't'))
        self.assertIn('rsnapshot -c', snapjobs.script(rs, 'dryrun'))
        self.assertIn('mountpoint -q /mnt/sdcard', snapjobs.script(rs, 'run'))
        self.assertIn('snapper -c root create -c timeline', snapjobs.script(sn, 'run'))
        self.assertIn('TIMELINE_CREATE=no', snapjobs.script(sn, 'pause'))
        self.assertNotIn(deploy.JOBBIN, snapjobs.script(rs, 'run') + snapjobs.script(sn, 'run'))
        for verb in ('verify', 'cutover', 'dedupe'):
            with self.assertRaises(ValueError):
                snapjobs.script(rs, verb)

    def test_restore_lands_beside_the_original(self):
        rs = jobs.get(self.conn, snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't'))
        spec = {**rs['spec'], 'backups': [{'src': '/home/', 'dst': 'localhost/'}, {'src': 'pi@nas:/data/', 'dst': 'nas/'}]}
        self.assertEqual(snapjobs.original_of(spec, 'localhost/a/b.txt'), '/home/a/b.txt')
        with self.assertRaisesRegex(ValueError, 'another host'):
            snapjobs.original_of(spec, 'nas/x')
        with self.assertRaisesRegex(ValueError, 'not inside'):
            snapjobs.original_of(spec, 'other/x')
        for snap, rel in (('../x', 'localhost/a'), ('daily.0', '../etc/shadow'), ('daily.0/..', 'a'), ('daily.0', '/etc')):
            with self.assertRaises(ValueError):
                snapjobs._snapshot_dir(rs['spec'], snap, rel)

    def test_retention_only_changes_existing_levels(self):
        jid = snapjobs.import_job(self.conn, 'pi', 'rsnapshot', CONF, 't')
        for keep in ({'hourly': 3}, {'daily': 0}, {'daily': 'x; rm -rf /'}, {}):
            with self.assertRaises(ValueError):
                snapjobs.retention(None, self.conn, jid, keep, 't')
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'ok', 'output': ''}):
            snapjobs.retention(None, self.conn, jid, {'daily': 14}, 't')
        self.assertEqual(jobs.get(self.conn, jid)['spec']['levels']['daily'], 14)

    def test_a_plan_is_told_when_rsnapshot_does_not_suit(self):
        def said(fstype):
            mounts = [{'id': 1, 'target': '/', 'source': '/dev/a', 'fstype': fstype, 'total': 1 << 40, 'used': 0, 'state': 'indexed', 'options': ''}]
            h = {'id': 1, 'name': 'pi', 'ssh_host': 'pi', 'ssh_user': None, 'ssh_port': 22, 'mounts': mounts}
            plan = moves.normalize({'name': 'p', 'steps': [{'id': 'a', 'method': 'rsnapshot', 'src': {'host': 'pi', 'path': '/data'}, 'dst': {'host': 'pi', 'path': '/snaps'}}]})
            with mock.patch.object(moves, 'hosts', lambda c: {'pi': h}):
                return {(i['level'], i['text'].split(':')[0]) for i in moves.check(self.conn, plan)['steps'][0]['items']}
        self.assertIn(('crit', '/snaps is on exfat, which has no hard links'), said('exfat'))
        self.assertIn(('note', 'source and destination share one btrfs volume'), said('btrfs'))
        self.assertFalse([t for _, t in said('ext4') if 'hard links' in t or 'btrfs' in t])

    def test_snapper_only_goes_on_btrfs(self):
        h = {'id': 1, 'name': 'pi', 'ssh_host': 'pi', 'ssh_user': None, 'ssh_port': 22, 'mounts': [
            {'target': '/', 'fstype': 'ext4', 'state': 'indexed'}, {'target': '/data', 'fstype': 'btrfs', 'state': 'indexed'}]}
        with mock.patch.object(moves, 'hosts', lambda c: {'pi': h}), mock.patch.object(deploy, 'run', side_effect=AssertionError):
            self.assertEqual(snapjobs.advice_for(self.conn, 'pi', '/data/x')['tool'], 'snapper')
            self.assertEqual(snapjobs.advice_for(self.conn, 'pi', '/home')['tool'], 'rsnapshot')
            with self.assertRaisesRegex(ValueError, 'ext4'):
                snapjobs.create_snapper(None, self.conn, 'pi', '/home', 'home', 't')
            with self.assertRaisesRegex(ValueError, 'config name'):
                snapjobs.create_snapper(None, self.conn, 'pi', '/data', 'a b; x', 't')


class Maps(unittest.TestCase):
    """Importing has to show on the maps straight away, not after the next scan."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/idx.db')
        conn = self.db.connect()
        self.addCleanup(conn.close)
        self.db.migrate(conn)
        users.create(conn, 'root', 'a long enough password', 'admin')
        conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES ('pi', 'pi', 'scan', :i, 1)",
                     {'i': json.dumps({'snapjobs': snapfind.parse(found_text())})})
        hid = conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'pi'")
        for target, fs in (('/', 'ext4'), ('/mnt/sdcard', 'ext4')):
            conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state)
                            VALUES (:h, :m, '/dev/x', :f, 'indexed')""", {'h': hid, 'm': target, 'f': fs})
        conn.execute("INSERT INTO scans (host_id, status, started_at) VALUES (:h, 'ok', 1)", {'h': hid})
        self.conn = conn
        self.web = server.create_app(server.App(self.db), 'x' * 32)
        self.c = self.web.test_client()
        self.assertEqual(self.c.post('/api/login', json={'username': 'root', 'password': 'a long enough password'}).status_code, 200)

    def lines(self):
        r = self.c.get('/api/filemap')
        self.assertEqual(r.status_code, 200, r.text)
        return sorted((x['src']['path'], x['dst']['path']) for x in r.json['relations'] if x['kind'] == 'job')

    def edges(self):
        return [e for e in graph.load(self.conn)['edges'] if e['rel'] == 'REPLICATES_TO' and str(e['props'].get('detail', '')).startswith('job ')]

    def test_import_and_forget_redraw_the_maps_without_a_scan(self):
        self.assertEqual(self.lines(), [])                  # and this answer is now cached
        r = self.c.post('/api/deploy/snapjobs/import', json={'host': 'pi', 'tool': 'rsnapshot', 'config': CONF})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.lines(), [('/etc', '/mnt/sdcard/snapshots'), ('/home', '/mnt/sdcard/snapshots')])     # every backup line, no trailing slash
        self.assertEqual(len(self.edges()), 1)              # both on / : one line from that filesystem
        self.assertEqual(self.c.post(f'/api/deploy/jobs/{r.json["job"]}/forget', json={}).status_code, 200)
        self.assertEqual(self.lines(), [])
        self.assertEqual(self.edges(), [])


class Scripts(unittest.TestCase):
    """The bash that really runs, against stand-ins for root's tools."""
    HOSTILE = "/tmp/x'; touch /tmp/sf-pwned; echo '"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def bash(self, script, env=None):
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30, env={**os.environ, **(env or {})})

    def spec(self, **kw):
        return {'id': 'x-rs-1', 'runner': 'pi', 'spec': {'imported': True, 'tool': 'rsnapshot', 'config': str(self.tmp / 'c.conf'), 'root': str(self.tmp), 'mount': '/',
                                                         'lowest': 'daily', 'levels': {'daily': 7}, 'schedule': [], 'backups': [], **kw}}

    def test_a_config_others_can_write_is_refused(self):
        conf = self.tmp / 'c.conf'
        conf.write_text('x')
        conf.chmod(0o666)
        r = self.bash(snapjobs.script(self.spec(), 'dryrun'))
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stderr, 'not owned by root|written by others')

    def test_pause_and_resume_swap_exactly_the_cron_line(self):
        cron = self.tmp / 'cron'
        line = "30 2 * * * root rsnapshot -c /a.conf daily # it's \\ odd $(x)"
        cron.write_text(f'MAILTO=me\n{line}\n# another\n')
        cron.chmod(0o640)
        funcs = snapjobs.HEAD + snapjobs.CRON_FUNCS
        import shlex
        r = self.bash(funcs + f'swap_line {shlex.quote(str(cron))} {shlex.quote(line)} {shlex.quote(snapfind.PAUSED + line)}')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(cron.read_text(), f'MAILTO=me\n{snapfind.PAUSED}{line}\n# another\n')
        self.bash(funcs + f'swap_line {shlex.quote(str(cron))} {shlex.quote(snapfind.PAUSED + line)} {shlex.quote(line)}')
        self.assertEqual(cron.read_text(), f'MAILTO=me\n{line}\n# another\n')
        self.assertEqual(stat.S_IMODE(cron.stat().st_mode), 0o640)

    def test_only_cron_files_can_be_edited(self):
        for bad in ('/etc/passwd', '/etc/cron.d/../shadow', '/tmp/cron'):
            with self.assertRaises(ValueError):
                snapjobs._schedule_lines({'schedule': [{'kind': 'cron', 'file': bad, 'line': 'x'}]}, True)

    def test_hostile_values_stay_data(self):
        marker = Path('/tmp/sf-pwned')
        marker.unlink(missing_ok=True)
        j = self.spec(config=self.HOSTILE, root=self.HOSTILE)
        for verb in ('run', 'dryrun', 'log', 'snapshots'):
            self.bash(snapjobs.script(j, verb), {'PATH': f'{self.tmp}:{os.environ["PATH"]}'})
        self.assertFalse(marker.exists())

    def test_a_link_cannot_lead_out_of_a_snapshot(self):
        snap = self.tmp / 'daily.0'
        (snap / 'localhost').mkdir(parents=True)
        os.symlink('/etc', snap / 'localhost' / 'out')
        (snap / 'localhost' / 'a.txt').write_text('hi')
        import shlex
        run = lambda rel: self.bash(snapjobs.HEAD + f'BASE={shlex.quote(str(snap))} REL={shlex.quote(rel)}\n' + snapjobs._INSIDE)  # noqa: E731
        self.assertEqual(run('localhost/a.txt').returncode, 0)
        self.assertIn('leads out', run('localhost/out/passwd').stderr)


if __name__ == '__main__':
    unittest.main()
