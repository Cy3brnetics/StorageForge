"""Ransomware defense. Two things are tested throughout: nothing is reported that was not measured, and nothing is recorded
that a script on the host did not confirm. So the controller is driven against its scripts really running, with stand-ins
for what needs root or a pool (zfs, systemctl), and real nft, inotifywait and python where this machine has them."""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from storageforge_index import alerts, backup, db as dbmod, deploy, permissions, retire, secscripts as sx, security, server, users
from storageforge_index.db import Database

PW = 'a very secure password for tests'
DAY = 86400

ZFS = r"""#!/bin/bash
# snapshots in $STUB_ZFS, one a line; holds as "snapshot<TAB>tag"
args=(); for a in "$@"; do [[ $a == -- ]] || args+=("$a"); done; set -- "${args[@]}"
echo "zfs $*" >>"$STUB_LOG"
case $1 in
  list) grep -qxF -- "${@: -1}" "$STUB_ZFS" && echo "${@: -1}" ;;
  snapshot) echo "$2" >>"$STUB_ZFS" ;;
  hold) [[ -e $STUB_HOLD_FAILS ]] && exit 0; printf '%s\t%s\n' "$3" "$2" >>"$STUB_ZFS" ;;
  release) grep -vxF -- "$(printf '%s\t%s' "$3" "$2")" "$STUB_ZFS" >"$STUB_ZFS.new"; mv "$STUB_ZFS.new" "$STUB_ZFS" ;;
  holds) s=${@: -1}; grep -F -- "$s"$'\t' "$STUB_ZFS" | while IFS=$'\t' read -r n t; do printf '%s\t%s\tMon Jan  1\n' "$n" "$t"; done ;;
  set) echo "$2 $3" >>"$STUB_ZFS.props" ;;
esac
exit 0
"""
NFT = r"""#!/bin/bash
# just enough nft: elements in $STUB_NFT
echo "nft $*" >>"$STUB_LOG"
all="$*"
case "$all" in
  'list table inet storageforge_fence') [[ -e $STUB_NFT.table ]] ;;
  'list table inet storageforge_airgap') [[ -e $STUB_NFT.airgap ]] ;;
  'list tables') [[ -e $STUB_NFT.table ]] && echo 'table inet storageforge_fence'; [[ -e $STUB_NFT.airgap ]] && echo 'table inet storageforge_airgap'; exit 0 ;;
  '-f -') cat >"$STUB_NFT.rules"; if grep -q airgap "$STUB_NFT.rules"; then touch "$STUB_NFT.airgap"; else touch "$STUB_NFT.table"; fi ;;
  '-c -f -') cat >/dev/null ;;
  'delete table inet storageforge_airgap') rm -f "$STUB_NFT.airgap" ;;
  add\ element*) e=${all##*\{ }; e=${e%% *}; echo "$e" >>"$STUB_NFT" ;;
  delete\ element*) e=${all##*\{ }; e=${e%% *}; grep -vxF -- "$e" "$STUB_NFT" >"$STUB_NFT.new"; mv "$STUB_NFT.new" "$STUB_NFT" ;;
  get\ element*) e=${all##*\{ }; e=${e%% *}; grep -qxF -- "$e" "$STUB_NFT" ;;
  list\ set*) [[ ${*} == *q4* && -s $STUB_NFT ]] && { echo 'table inet storageforge_fence {'; echo "set q4 { elements = { $(paste -sd, "$STUB_NFT") } }"; echo '}'; }; exit 0 ;;
  *) exit 0 ;;
esac
"""
SYSTEMCTL = r"""#!/bin/bash
echo "systemctl $*" >>"$STUB_LOG"
[[ $1 == is-active ]] && [[ $2 == -q ]] && exit 0
[[ $1 == is-active ]] && echo active
exit 0
"""
OK = '#!/bin/bash\necho "$(basename "$0") $*" >>"$STUB_LOG"\nexit 0\n'


def event_line(kind='canary_tripped', summary='s', detail='', at=None, uid=None):
    enc = lambda s: base64.b64encode(s.encode()).decode()
    return f'ev\t{uid or uuid.uuid4()}\t{kind}\t{at or int(time.time())}\t{enc(summary)}\t{enc(detail)}'


TEMPLATE: dict = {}


def template_db() -> Path:
    if 'dir' not in TEMPLATE:
        TEMPLATE['dir'] = tempfile.TemporaryDirectory()
        db = Database(f'sqlite:///{TEMPLATE["dir"].name}/t.db')
        conn = db.connect()
        db.migrate(conn)
        old = int(time.time()) - 30 * DAY
        for name in ('admin1', 'admin2'):
            users.create(conn, name, PW, 'admin')
            conn.execute('UPDATE users SET created_at = :t WHERE username = :u', {'t': old, 'u': name})
        conn.close()
    return Path(TEMPLATE['dir'].name) / 't.db'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copy(template_db(), self.tmp / 'test.db')
        self.db = Database(f'sqlite:///{self.tmp}/test.db')
        self.conn = self.db.connect()
        self.app = server.App(self.db)
        self.web = server.create_app(self.app, 's' * 48)
        self.client = self.web.test_client()
        self.login('admin1')
        self.add_host('nas')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.conn.close)
        self.real_host()
        p = mock.patch.object(deploy, 'run', self.run_for_real)
        p.start()
        self.addCleanup(p.stop)
        security._clock_seen.clear()

    def login(self, name='admin1'):
        self.client = self.web.test_client()
        self.assertEqual(self.client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)

    def solo(self):
        self.conn.execute("DELETE FROM users WHERE username = 'admin2'")

    def add_host(self, name, ready=True):
        self.conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                              VALUES (:n, :n, 'scan', '{{}}', {self.db.ts(':t')})""", {'n': name, 't': 1600000000})
        if ready:
            deploy.set_access(self.conn, name, 'ready', '', 'test')

    def real_host(self):
        """A bin of stand-ins and a root to write under: scripts really run, and only their surroundings are pretend."""
        self.root = self.tmp / 'root'
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.root / 'share').mkdir(parents=True)
        for name, body in (('zfs', ZFS), ('nft', NFT), ('systemctl', SYSTEMCTL), ('auditctl', OK), ('augenrules', OK), ('systemd-run', OK), ('sync', OK), ('chattr', OK)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        if not shutil.which('inotifywait'):
            (self.bin / 'inotifywait').write_text(OK)
            (self.bin / 'inotifywait').chmod(0o755)
        self.log, self.zstate, self.nstate = self.tmp / 'log', self.tmp / 'zfs', self.tmp / 'nft'
        for f in (self.log, self.zstate, self.nstate):
            f.write_text('')
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_LOG': str(self.log), 'STUB_ZFS': str(self.zstate), 'STUB_NFT': str(self.nstate),
                    'STUB_HOLD_FAILS': str(self.tmp / 'hold-fails'), 'SF_SEC_ROOT': str(self.root)}
        self.calls = []
        self.outage = None

    def sh(self, script, *args, data=None, timeout=60):
        return subprocess.run(['bash', '-c', script, 'script', *args], input=data, capture_output=True, timeout=timeout, env=self.env)

    def run_for_real(self, db, host, script, args=(), *, kind, ref=None, mode='report', actor=None, data=None, timeout=1800, **_):
        self.calls.append({'host': host, 'args': list(args), 'ref': ref, 'mode': mode, 'actor': actor, 'script': script})
        if self.outage:
            return {'run_id': 1, 'host': host, 'status': 'failed', 'exit_code': 255, 'output': self.outage}
        r = self.sh(script, *args, data=data, timeout=timeout)
        out = (r.stdout + r.stderr).decode('utf-8', 'replace')
        return {'run_id': len(self.calls), 'group_id': 'g', 'host': host, 'status': deploy.run_status(r.returncode, mode, out), 'exit_code': r.returncode, 'output': out}

    def post(self, url, **body):
        return self.client.post(url, json=body)

    def snap(self, name='tank/shares@s1'):
        with self.zstate.open('a') as f:
            f.write(name + '\n')
        return name

    def hold(self, name='tank/shares@s1', **kw):
        self.snap(name)
        r = self.post('/api/security/worm/hold', host='nas', snapshot=name, mode='apply', **{'retention_days': 14, **kw})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()['hold_id']

    def measure(self, host='nas'):
        r = self.post('/api/security/measure', host=host)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def hold_status(self, hid=None):
        return self.conn.scalar('SELECT status FROM security_retention_holds' + (' WHERE id = :i' if hid else ''), {'i': hid})


class NothingIsInvented(Base):
    """What was wrong before, each as it was found: a page that says all is well when nothing has been looked at."""

    def test_no_hosts_is_not_secure(self):
        self.conn.execute('DELETE FROM deploy_access')
        self.conn.execute('DELETE FROM hosts')
        p = self.client.get('/api/security/posture').get_json()
        self.assertEqual(p['state'], 'unknown')
        self.assertNotIn('hardened', p['banner'])

    def test_a_host_nobody_measured_is_unknown_and_has_no_numbers(self):
        p = self.client.get('/api/security/posture?host=nas').get_json()
        self.assertEqual(p['state'], 'unknown')
        h = p['hosts'][0]
        self.assertIn('never measured', h['gaps'])
        self.assertIsNone(h['measured_at'])
        self.assertIsNone(h['lynis'])
        self.assertIsNone(h['mac'])
        self.assertIsNone(self.client.get('/api/security/mac/status?host=nas').get_json()['measured_at'])
        self.assertIsNone(self.client.get('/api/security/integrity?host=nas').get_json()['measured_at'])
        self.assertIsNone(self.client.get('/api/security/worm/holds?host=nas').get_json()['clock']['measured_at'])
        self.assertIsNone(self.client.get('/api/security/compliance/status/nas').get_json()['score'])

    def test_a_good_reading_alone_does_not_say_secure(self):
        self.measure()
        p = security.posture(self.conn, 'nas')
        self.assertNotEqual(p['state'], 'secure')       # no decoys and no holds: not enough is known to say so
        self.assertIn('no decoys armed', p['hosts'][0]['gaps'])

    def test_a_host_nobody_scanned_cannot_be_acted_on(self):
        for path, body in (('/api/security/incident/brake', {'mode': 'apply'}), ('/api/security/compliance/init', {'mode': 'apply'}), ('/api/security/firewall/quarantine', {'mode': 'apply', 'ip_address': '10.0.0.5'}),
                           ('/api/security/worm/hold', {'mode': 'apply', 'snapshot': 'a@b', 'retention_days': 1}), ('/api/security/measure', {})):
            r = self.post(path, host='ghost', **body)
            self.assertEqual(r.status_code, 400, path)
        self.assertEqual(self.calls, [])

    def test_a_failed_run_records_nothing_and_says_so(self):
        self.outage = 'SSH failed: the host is unreachable'
        self.snap()
        for path, body in (('/api/security/worm/hold', {'snapshot': 'tank/shares@s1', 'retention_days': 7}), ('/api/security/firewall/quarantine', {'ip_address': '10.0.0.5'})):
            r = self.post(path, host='nas', mode='apply', **body)
            self.assertEqual(r.status_code, 409, path)
            self.assertIn('SSH failed', r.get_json()['output'])
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_retention_holds'), 0)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_quarantine'), 0)

    def test_the_brake_reports_what_ran_not_a_list_of_hopes(self):
        self.outage = 'SSH failed: the host is unreachable'
        r = self.post('/api/security/incident/brake', host='nas', client_ip='10.0.0.9', mode='apply')
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.get_json()['steps'], [])
        self.assertIn('did not run', r.get_json()['error'])

    def test_setting_a_baseline_does_not_award_a_score(self):
        self.post('/api/security/compliance/init', host='nas', profile='hipaa', mode='report')
        self.assertIsNone(self.client.get('/api/security/compliance/status/nas?profile=hipaa').get_json()['score'])

    def test_every_compliance_check_is_a_reading(self):
        self.measure()
        status = self.client.get('/api/security/compliance/status/nas?profile=cis-l2').get_json()
        self.assertLess(status['score'], 100)            # no decoys, no holds, no Lynis on this machine
        self.assertTrue(all(c['detail'] for c in status['checks']))
        self.assertEqual(status['passed'] + status['failed'] + status['unknown'], len(status['checks']))

    def test_the_fakes_are_gone(self):
        self.assertFalse(hasattr(security, 'DEFAULT_PLAYBOOKS'))
        src = Path(security.__file__).read_text()
        for invented in ('Ring Buffer (0% drops)', 'latency_ms\': 1.2', 'rpo_seconds\': 12', "'plaintext_pct': 65", 'KRNL-6000'):
            self.assertNotIn(invented, src)
        rules = {r.rule for r in self.web.url_map.iter_rules()}
        for gone in ('/api/security/malware/shred', '/api/security/malware/restore'):
            self.assertNotIn(gone, rules)


class Holds(Base):
    def test_a_hold_is_on_the_host_before_it_is_in_the_database(self):
        hid = self.hold()
        self.assertIn('tank/shares@s1\tsf-worm-14d', self.zstate.read_text())
        row = security.hold_rows(self.conn, 'nas')[0]
        self.assertEqual((row['id'], row['status'], row['filesystem']), (hid, 'locked', 'zfs'))
        self.assertAlmostEqual(row['expires_at'] - row['created_at'], 14 * DAY, delta=5)

    def test_a_dry_run_and_a_preview_change_nothing(self):
        self.snap()
        r = self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', retention_days=7, mode='report')
        self.assertIn('missing', r.get_json()['output'])
        r = self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', retention_days=7, mode='preview')
        self.assertIn('zfs hold', r.get_json()['script'])
        self.assertNotIn('\tsf-', self.zstate.read_text())
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_retention_holds'), 0)

    def test_a_hold_that_did_not_take_is_not_recorded(self):
        (self.tmp / 'hold-fails').write_text('')
        self.snap()
        r = self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', retention_days=7, mode='apply')
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_retention_holds'), 0)

    def test_asking_again_never_weakens_a_hold(self):
        hid = self.hold(retention_days=30, hold_tag='sf-x')
        far = self.conn.scalar('SELECT expires_at FROM security_retention_holds')
        self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', hold_tag='sf-x', retention_days=1, mode='apply')
        self.assertEqual(self.conn.scalar('SELECT expires_at FROM security_retention_holds WHERE id = :i', {'i': hid}), far)
        self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', hold_tag='sf-x', legal_hold=True, mode='apply')
        self.post('/api/security/worm/hold', host='nas', snapshot='tank/shares@s1', hold_tag='sf-x', retention_days=1, mode='apply')
        row = security.hold_rows(self.conn, 'nas')[0]
        self.assertTrue(row['legal_hold'])
        self.assertIsNone(row['expires_at'])

    def test_a_legal_hold_has_to_be_named_to_ask_for_its_release(self):
        hid = self.hold(legal_hold=True)
        r = self.post('/api/security/worm/release', hold_id=hid)
        self.assertEqual(r.status_code, 409)
        self.assertIn('legal hold', r.get_json()['error'])
        self.assertEqual(self.hold_status(hid), 'locked')
        self.assertEqual(self.post('/api/security/worm/release', hold_id=hid, release_legal=True).status_code, 200)

    def test_a_solo_admin_cannot_approve_their_own_cool_off(self):
        self.solo()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.assertEqual(t['mode'], 'cool_off')
        r = self.post('/api/security/worm/quorum/approve', timelock_id=t['timelock_id'])
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.hold_status(hid), 'release_pending')
        self.assertIn('sf-worm-14d', self.zstate.read_text())

    def test_the_cool_off_runs_by_itself_and_only_when_it_is_up(self):
        self.solo()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'release_pending')
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1 WHERE id = :i', {'i': t['timelock_id']})
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'released')
        self.assertNotIn('sf-worm-14d', self.zstate.read_text())

    def test_a_release_the_host_refused_stays_held_and_says_so(self):
        self.solo()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1 WHERE id = :i', {'i': t['timelock_id']})
        self.outage = 'SSH failed'
        security.tick(self.db)
        self.outage = None
        self.assertEqual(self.hold_status(hid), 'locked')
        self.assertEqual(self.conn.scalar('SELECT status FROM security_timelock_queue'), 'failed')

    def test_abort_stops_a_release(self):
        self.solo()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.assertEqual(self.post('/api/security/worm/abort', timelock_id=t['timelock_id']).status_code, 200)
        self.assertEqual(self.hold_status(hid), 'locked')
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1')
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'locked')

    def test_two_admins_means_two_people(self):
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.assertEqual(t['mode'], 'dual_admin')
        self.assertEqual(self.post('/api/security/worm/quorum/approve', timelock_id=t['timelock_id']).status_code, 409)
        self.assertEqual(self.hold_status(hid), 'release_pending')
        self.login('admin2')
        self.assertEqual(self.post('/api/security/worm/quorum/approve', timelock_id=t['timelock_id']).status_code, 200)
        self.assertEqual(self.hold_status(hid), 'released')

    def test_a_new_admin_can_neither_approve_nor_make_the_fleet_dual(self):
        self.solo()
        hid = self.hold()
        users.create(self.conn, 'mallory', PW, 'admin')
        self.assertEqual(security.quorum_state(self.conn)['mode'], 'cool_off')      # a second account, made a moment ago, changes nothing
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.login('mallory')
        self.assertEqual(self.post('/api/security/worm/quorum/approve', timelock_id=t['timelock_id']).status_code, 409)
        # and in a dual-admin fleet, it does not count as the second admin
        users.create(self.conn, 'old', PW, 'admin')
        self.conn.execute("UPDATE users SET created_at = 1 WHERE username = 'old'")
        self.conn.execute("UPDATE security_timelock_queue SET mode = 'dual_admin'")
        self.assertEqual(self.post('/api/security/worm/quorum/approve', timelock_id=t['timelock_id']).status_code, 409)

    def test_when_the_second_admin_goes_a_request_falls_back_to_the_cool_off(self):
        hid = self.hold()
        self.post('/api/security/worm/release', hold_id=hid)
        self.conn.execute("UPDATE users SET disabled_at = 1 WHERE username = 'admin2'")
        security.tick(self.db)
        row = security._timelocks(self.conn)[0]
        self.assertEqual(row['mode'], 'cool_off')
        self.assertEqual(self.hold_status(hid), 'release_pending')

    def test_a_hold_past_its_date_needs_no_wait(self):
        hid = self.hold()
        self.conn.execute('UPDATE security_retention_holds SET expires_at = 1')
        self.assertEqual(self.post('/api/security/worm/release', hold_id=hid).status_code, 200)
        self.assertEqual(self.hold_status(hid), 'released')

    def test_a_hold_is_never_released_just_because_its_date_passed(self):
        hid = self.hold()
        self.conn.execute('UPDATE security_retention_holds SET expires_at = 1')
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'locked')
        self.assertIn('sf-worm-14d', self.zstate.read_text())

    def test_the_cool_off_cannot_be_shortened(self):
        self.assertEqual(self.post('/api/security/worm/cool-off', hours=48).status_code, 200)
        self.assertEqual(self.post('/api/security/worm/cool-off', hours=12).status_code, 400)
        self.assertEqual(security.cool_off_hours(self.conn), 48)


class OfflineKey(Base):
    def key(self):
        return self.post('/api/security/worm/break-glass/key').get_json()['break_glass_key']

    def test_the_key_skips_the_wait_loudly_and_only_once_per_use(self):
        self.solo()
        key = self.key()
        self.assertEqual(len(key), 64)
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.assertEqual(self.post('/api/security/worm/break-glass', timelock_id=t['timelock_id'], break_glass_key='0' * 64).status_code, 409)
        self.assertEqual(self.hold_status(hid), 'release_pending')
        self.assertEqual(self.post('/api/security/worm/break-glass', timelock_id=t['timelock_id'], break_glass_key=key).status_code, 200)
        self.assertEqual(self.hold_status(hid), 'released')
        self.assertTrue(any(e['kind'] == 'break_glass_used' for e in security.list_events(self.conn, 'nas')))

    def test_one_admin_cannot_mint_a_new_key_and_use_it_at_once(self):
        self.key()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        r = self.post('/api/security/worm/break-glass/key').get_json()
        self.assertTrue(r['requested'])
        self.assertNotIn('break_glass_key', r)
        self.assertEqual(self.post('/api/security/worm/break-glass', timelock_id=t['timelock_id'], break_glass_key='0' * 64).status_code, 409)
        self.assertEqual(self.hold_status(hid), 'release_pending')

    def test_a_replacement_key_comes_after_the_cool_off(self):
        self.solo()
        old = self.key()
        self.assertTrue(self.post('/api/security/worm/break-glass/key').get_json()['requested'])
        self.assertEqual(self.post('/api/security/worm/break-glass/key').status_code, 409)
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1')
        new = self.post('/api/security/worm/break-glass/key').get_json()['break_glass_key']
        self.assertNotEqual(old, new)

    def test_the_key_never_reaches_the_audit_log(self):
        key = self.key()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        self.post('/api/security/worm/break-glass', timelock_id=t['timelock_id'], break_glass_key=key)
        self.assertNotIn(key, json.dumps(self.conn.all('SELECT * FROM audit_log'), default=str))

    def test_the_key_does_not_get_past_the_clock_guard(self):
        key = self.key()
        hid = self.hold()
        t = self.post('/api/security/worm/release', hold_id=hid).get_json()
        security.freeze_clock(self.conn, 'nas', 'test', 'test')
        self.assertEqual(self.post('/api/security/worm/break-glass', timelock_id=t['timelock_id'], break_glass_key=key).status_code, 409)
        self.assertEqual(self.hold_status(hid), 'release_pending')


class ClockGuard(Base):
    def test_a_jump_stops_releases_on_that_host_until_someone_clears_it(self):
        hid = self.hold()
        self.add_host('other')
        security.ingest_events(self.conn, 'nas', event_line('clock_jump', 'moved 30 days'))
        r = self.post('/api/security/worm/release', hold_id=hid)
        self.assertEqual(r.status_code, 409)
        self.assertIn('clock guard', r.get_json()['error'])
        self.measure()                                   # a good reading afterwards proves nothing
        self.measure('other')                            # and neither does another host
        self.assertTrue(security.clock_frozen(self.conn, 'nas'))
        self.assertFalse(security.clock_frozen(self.conn, 'other'))
        self.assertEqual(self.post('/api/security/worm/clock/clear', host='nas').status_code, 200)
        self.assertEqual(self.post('/api/security/worm/release', hold_id=hid).status_code, 200)

    def test_a_cool_off_waits_while_the_clock_is_frozen(self):
        self.solo()
        hid = self.hold()
        self.post('/api/security/worm/release', hold_id=hid)
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1')
        security.freeze_clock(self.conn, 'nas', 'test', 'test')
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'release_pending')

    def test_a_measurement_notices_a_host_clock_that_is_off(self):
        out = self.sh(sx.measure_script()).stdout.decode()
        out = re.sub(r'(@@now\n)\d+', lambda m: f'{m[1]}{int(time.time()) + 30 * DAY}', out)
        data = security.parse_measure(out)
        now = int(time.time())
        security.store_measurement(self.conn, 'nas', data, now, now, 'test')
        self.assertTrue(security.clock_frozen(self.conn, 'nas'))
        self.assertEqual(security.measurement(self.conn, 'nas')['clock_offset'], data['host_now'] - now)

    def test_a_slow_measurement_is_not_a_clock_problem(self):
        data = security.parse_measure(self.sh(sx.measure_script()).stdout.decode())
        security.store_measurement(self.conn, 'nas', data, data['host_now'] - 5, data['host_now'] + 200, 'test')
        self.assertFalse(security.clock_frozen(self.conn, 'nas'))

    def test_the_runner_refusing_over_the_clocks_trips_the_guard(self):
        self.outage = 'x'
        with mock.patch.object(deploy, 'run', return_value={'run_id': 1, 'status': 'refused', 'exit_code': 97, 'output': 'the request is too old, or the clocks differ (issued 1, now 2)'}):
            self.assertEqual(self.post('/api/security/measure', host='nas').status_code, 409)
        self.assertTrue(security.clock_frozen(self.conn, 'nas'))

    def off_by(self, host, seconds):
        data = security.parse_measure(self.sh(sx.measure_script()).stdout.decode())
        data['host_now'] += seconds
        now = data['host_now'] - seconds
        security.store_measurement(self.conn, host, data, now, now, 'test')

    def test_most_hosts_off_by_the_same_amount_points_at_this_machine(self):
        """Seen on a real fleet: this machine 515 s behind, and every other host reported as critical."""
        for h in ('pi1', 'pi2'):
            self.add_host(h)
        self.off_by('pi1', 515)
        self.assertIsNone(security.controller_clock_suspect(self.conn))      # one host off is that host's business
        self.off_by('pi2', 517)
        self.off_by('nas', 0)
        s = security.controller_clock_suspect(self.conn)
        self.assertEqual((s['direction'], s['agree'], s['measured']), ('behind', 2, 3))
        p = self.client.get('/api/security/posture').get_json()
        self.assertIn('the hosts are probably fine', p['banner'])
        problems = security.problems(self.conn)
        self.assertIn('security-controller-suspect', problems)
        self.assertNotIn('security-clock:pi1', problems)                     # one alert, not one per host

    def test_clocks_off_by_different_amounts_are_each_their_own_problem(self):
        for h in ('pi1', 'pi2'):
            self.add_host(h)
        self.off_by('pi1', 515)
        self.off_by('pi2', 9000)
        self.off_by('nas', 0)
        self.assertIsNone(security.controller_clock_suspect(self.conn))
        self.assertIn('security-clock:pi1', security.problems(self.conn))

    def test_a_suspect_clock_stops_cool_offs(self):
        self.solo()
        hid = self.hold()
        self.post('/api/security/worm/release', hold_id=hid)
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1')
        for h in ('pi1', 'pi2'):
            self.add_host(h)
            self.off_by(h, 515)
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'release_pending')

    def test_clearing_this_machine_frees_hosts_blamed_for_it_but_not_a_real_jump(self):
        for h in ('pi1', 'pi2'):
            self.add_host(h)
        self.off_by('pi1', 515)
        self.off_by('pi2', 515)
        security.ingest_events(self.conn, 'nas', event_line('clock_jump', 'moved 30 days'))
        self.assertEqual(self.post('/api/security/worm/clock/clear', controller=True).status_code, 200)
        self.assertFalse(security.clock_frozen(self.conn, 'pi1'))
        self.assertTrue(security.clock_frozen(self.conn, 'nas'))

    def test_a_stock_nfs_boolean_is_not_called_too_open(self):
        m = security.parse_measure('@@now\n1\n@@sebool\nnfs_export_all_rw --> on\nsamba_export_all_rw --> on\n@@end\n')
        self.assertEqual({b['name']: b['ok'] for b in m['booleans']}, {'nfs_export_all_rw': True, 'samba_export_all_rw': False})
        self.assertEqual(self.post('/api/security/mac/remediate', host='nas', boolean='nfs_export_all_rw', value='off', mode='apply').status_code, 400)

    def test_moving_this_machines_clock_stops_cool_offs(self):
        self.solo()
        hid = self.hold()
        self.post('/api/security/worm/release', hold_id=hid)
        security.tick(self.db)
        self.conn.execute('UPDATE security_timelock_queue SET executes_at = 1')
        real = time.time
        with mock.patch.object(time, 'time', lambda: real() + 30 * DAY):
            security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'release_pending')
        self.assertEqual(self.client.get('/api/security/posture').get_json()['state'], 'critical')
        self.assertIn('security-controller-clock', security.problems(self.conn))
        self.assertEqual(self.post('/api/security/worm/clock/clear', controller=True).status_code, 200)
        security.tick(self.db)
        self.assertEqual(self.hold_status(hid), 'released')


class Measuring(Base):
    def test_the_script_runs_here_and_parses(self):
        self.measure()
        m = security.measurement(self.conn, 'nas')
        self.assertFalse(m['stale'])
        self.assertLess(abs(m['host_now'] - time.time()), 60)
        self.assertIn('nft', m['tools'])

    def test_a_reading_cut_short_is_not_a_reading(self):
        full = self.sh(sx.measure_script()).stdout.decode()
        self.assertIsNotNone(security.parse_measure(full))
        self.assertIsNone(security.parse_measure(full.split('@@end')[0]))
        self.assertIsNone(security.parse_measure(''))

    def test_parsing_real_shapes(self):
        text = textwrap.dedent("""\
            @@now
            1793000000
            @@uptime
            500
            @@tools
            getenforce
            chronyc
            @@selinux
            Permissive
            @@sebool
            samba_export_all_rw --> on
            nfs_export_all_rw --> off
            @@avc
            type=AVC msg=audit(1793000000.5:42): avc:  denied  { read } for pid=7 comm="smbd" name="x" path="/srv/data/x" scontext=system_u:system_r:smbd_t:s0 tcontext=u:object_r:var_t:s0 tclass=file permissive=0
            @@chrony
            A,time.example,3,1793000000.1,-0.0015,0,0,0,0,0,0,0,Normal
            @@chrony_auth
            time.example,NTS,1,15,256,3,0,0,8,100
            ptb.example,-,0,0,0,0,0,0,0,0
            @@auditd
            active
            4
            @@fence
            storageforge_fence
            @@lynis
            at 1793000000
            hardening_index=72
            warning[]=AUTH-9328|Default umask could be stricter|-|-|
            suggestion[]=SSH-7408|Harden sshd|-|-|
            @@end
            """)
        m = security.parse_measure(text)
        self.assertEqual(m['selinux'], 'Permissive')
        self.assertEqual([b['ok'] for b in m['booleans']], [False, True])
        self.assertEqual(m['avc'][0]['daemon'], 'smbd')
        self.assertEqual(m['avc'][0]['path'], '/srv/data/x')
        self.assertTrue(m['avc'][0]['storage'])
        self.assertEqual(m['chrony']['offset_ms'], 1.5)
        self.assertEqual(m['nts_sources'], 1)
        self.assertEqual(m['auditd'], {'active': True, 'storageforge_rules': 4})
        self.assertTrue(m['fence'])
        self.assertFalse(m['airgap'])
        self.assertEqual(m['lynis']['hardening_index'], 72)
        self.assertEqual(m['lynis']['warnings'][0]['id'], 'AUTH-9328')

    def test_a_hold_someone_removed_on_the_host_raises_the_alarm(self):
        self.hold()
        self.measure()
        self.assertIsNone(security.hold_rows(self.conn, 'nas')[0]['missing_at'])
        self.assertIsNotNone(security.hold_rows(self.conn, 'nas')[0]['verified_at'])
        self.zstate.write_text('tank/shares@s1\n')        # zfs release, by someone with root
        self.measure()
        self.assertIsNotNone(security.hold_rows(self.conn, 'nas')[0]['missing_at'])
        p = security.posture(self.conn, 'nas')
        self.assertEqual(p['state'], 'critical')
        self.assertTrue(any(e['kind'] == 'hold_missing' for e in p['events']))
        self.measure()
        self.assertEqual(sum(1 for e in security.list_events(self.conn, 'nas') if e['kind'] == 'hold_missing'), 1)

    def test_nothing_a_host_says_can_clear_an_alarm(self):
        security.ingest_events(self.conn, 'nas', event_line('canary_tripped', 'tripped'))
        self.measure()
        self.assertEqual(security.posture(self.conn, 'nas')['state'], 'critical')


class Events(Base):
    def setUp(self):
        super().setUp()
        self.token = 'a-report-token'
        alerts.set_setting(self.conn, security.host_key('nas'), {'host': 'nas', 'token_sha': __import__('hashlib').sha256(self.token.encode()).hexdigest()}, 'test')
        self.conn.execute("""INSERT INTO security_canaries (host, path, sha256, size, deployed_at, status) VALUES ('nas', '/srv/a.docx', :s, 1, 1, 'armed')""", {'s': 'a' * 64})

    def report(self, lines, token=None):
        return self.web.test_client().post('/api/security/report', json={'lines': lines}, headers={'Authorization': f'Bearer {token or self.token}'})

    def test_a_report_trips_the_decoy_and_alerts(self):
        path = base64.b64encode(b'/srv/a.docx').decode()
        r = self.report([event_line(detail=f'path_b64={path};client=10.0.0.9;pid=7;event=MODIFY')])
        self.assertEqual(r.get_json()['new'], 1)
        self.assertEqual(self.conn.scalar('SELECT status FROM security_canaries'), 'tripped')
        self.assertEqual(security.posture(self.conn, 'nas')['state'], 'critical')
        self.assertTrue(any(k.startswith('security-event:') for k in alerts.problems(self.conn)))

    def test_a_bad_token_gets_nothing(self):
        self.assertEqual(self.report([event_line()], 'wrong').status_code, 401)
        self.assertEqual(self.web.test_client().post('/api/security/report', json={'lines': []}).status_code, 401)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_events'), 0)

    def test_the_token_decides_the_host_not_the_report(self):
        self.add_host('other')
        self.report([event_line()])
        self.assertEqual(self.conn.scalar('SELECT host FROM security_events'), 'nas')

    def test_each_event_counts_once_by_whichever_road(self):
        line = event_line()
        self.assertEqual(self.report([line]).get_json()['new'], 1)
        self.assertEqual(security.ingest_events(self.conn, 'nas', line, 'scan'), 0)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_events'), 1)

    def test_a_host_cannot_date_its_way_out_of_sight_or_choose_its_severity(self):
        far = int(time.time()) + 365 * DAY
        security.ingest_events(self.conn, 'nas', event_line('watcher_stopped', 'x', at=far))
        at, sev = self.conn.all('SELECT occurred_at, severity FROM security_events')[0]
        self.assertLessEqual(at, time.time())
        self.assertEqual(sev, 'warn')

    def test_junk_is_dropped(self):
        for bad in ('', 'ev', 'ev\tnot-a-uuid\tcanary_tripped\t1\tAA==\tAA==', f'ev\t{uuid.uuid4()}\tmade_up\t1\tAA==\tAA==', f'ev\t{uuid.uuid4()}\tcanary_tripped\tsoon\tAA==\tAA==',
                    f'ev\t{uuid.uuid4()}\tcanary_tripped\t1\t!!\tAA=='):
            self.assertEqual(security.ingest_events(self.conn, 'nas', bad), 0, bad)

    def test_a_scan_carries_events_in(self):
        from storageforge_index import remote
        self.assertIn("echo '@@secevents'", Path(remote.__file__).read_text())
        self.assertEqual(security.ingest_events(self.conn, 'nas', event_line() + '\n' + event_line(), 'scan'), 2)

    def test_seeing_an_alarm_quiets_it(self):
        security.ingest_events(self.conn, 'nas', event_line('clock_jump', 'x'))
        security.clear_clock(self.conn, 'nas', 'admin1')
        eid = self.conn.scalar('SELECT event_id FROM security_events')
        self.assertEqual(self.post(f'/api/security/events/{eid}/ack').status_code, 200)
        self.assertFalse(any(k.startswith('security-event:') for k in alerts.problems(self.conn)))


class Firewall(Base):
    def test_a_quarantine_is_in_the_firewall_before_it_is_on_the_page(self):
        r = self.post('/api/security/firewall/quarantine', host='nas', ip_address='10.0.0.5', minutes=30, mode='apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn('10.0.0.5', self.nstate.read_text())
        self.measure()
        q = self.client.get('/api/security/firewall/quarantine?host=nas').get_json()
        self.assertEqual(q['quarantine'][0]['ip_address'], '10.0.0.5')
        self.assertTrue(q['quarantine'][0]['live'])
        self.assertTrue(q['fence_present'])
        r = self.client.delete('/api/security/firewall/quarantine/10.0.0.5?host=nas&mode=apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotIn('10.0.0.5', self.nstate.read_text())
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_quarantine'), 0)

    def test_targets_that_would_be_a_disaster_are_refused(self):
        for bad in ('0.0.0.0/0', '::/0', '10.0.0.0/8', '127.0.0.1', '127.0.0.0/8', '169.254.0.1', 'nonsense', '', '1.2.3.4; rm -rf /'):
            r = self.post('/api/security/firewall/quarantine', host='nas', ip_address=bad, mode='apply')
            self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(self.calls, [])

    def test_the_exempt_list_and_the_controller_are_protected_including_inside_a_network(self):
        self.post('/api/security/firewall/vip', vips=['10.9.9.9', '192.168.5.0/24'])
        with mock.patch.object(security, '_controller_ips', return_value=['172.16.0.2']):
            for bad in ('10.9.9.9', '10.9.0.0/16', '192.168.5.7', '172.16.0.2', '172.16.0.0/24'):
                r = self.post('/api/security/firewall/quarantine', host='nas', ip_address=bad, mode='apply')
                self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(self.calls, [])

    def test_ipv6_goes_in_the_ipv6_set(self):
        r = self.post('/api/security/firewall/quarantine', host='nas', ip_address='2001:db8::1', mode='apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn('nft add element inet storageforge_fence q6', self.log.read_text())

    def test_an_expired_quarantine_leaves_the_page(self):
        self.post('/api/security/firewall/quarantine', host='nas', ip_address='10.0.0.5', minutes=30, mode='apply')
        self.conn.execute('UPDATE security_quarantine SET expires_at = 1')
        self.assertEqual(self.client.get('/api/security/firewall/quarantine?host=nas').get_json()['quarantine'], [])
        security.tick(self.db)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_quarantine'), 0)

    def test_the_airgap_arms_its_rollback_first_and_confirms_through_itself(self):
        with mock.patch.object(security, '_controller_ips', return_value=['10.0.0.1']):
            r = self.post('/api/security/firewall/airgap', host='nas', mode='apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(r.get_json()['airgap'], True)
        log = self.log.read_text()
        self.assertLess(log.index('systemd-run'), log.index('nft -f -'))           # the way back is set before the door closes
        self.assertIn('systemctl stop sf-airgap-rollback.timer', log)
        self.assertEqual([c['args'] for c in self.calls[:2]], [['--apply'], ['--confirm']])
        self.assertIn('ip saddr { 10.0.0.1 } accept', (self.tmp / 'nft.rules').read_text())
        self.assertTrue(security.posture(self.conn, 'nas')['state'] == 'critical')
        r = self.post('/api/security/firewall/airgap', host='nas', enabled=False, mode='apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertFalse((self.tmp / 'nft.airgap').exists())

    def test_an_airgap_that_locks_us_out_says_it_rolls_back(self):
        real = self.run_for_real

        def cut_off(db, host, script, args=(), **kw):
            if '--confirm' in args:
                return {'run_id': 9, 'host': host, 'status': 'failed', 'exit_code': 255, 'output': 'ssh: connect to host: Connection timed out'}
            return real(db, host, script, args, **kw)
        with mock.patch.object(deploy, 'run', cut_off), mock.patch.object(security, '_controller_ips', return_value=['10.0.0.1']):
            r = self.post('/api/security/firewall/airgap', host='nas', mode='apply')
        self.assertEqual(r.status_code, 409)
        self.assertIn('lifts itself', r.get_json()['error'])
        self.assertIn('--on-active=10min', self.log.read_text())

    def test_the_airgap_will_not_start_without_knowing_who_to_keep(self):
        with mock.patch.object(security, '_controller_ips', return_value=[]):
            r = self.post('/api/security/firewall/airgap', host='nas', mode='apply')
        self.assertEqual(r.status_code, 409)
        self.assertFalse((self.tmp / 'nft.airgap').exists())


@unittest.skipUnless(shutil.which('nft') and shutil.which('unshare'), 'needs nft and unshare')
class RealNftables(Base):
    """In a network namespace of its own, so these are the kernel's real answers."""

    def in_ns(self, text):
        env = {**os.environ, 'SF_SEC_ROOT': str(self.root)}
        return subprocess.run(['unshare', '--user', '--map-current-user', '--keep-caps', '--net', 'bash', '-c', text], capture_output=True, text=True, env=env, timeout=30)

    def setUp(self):
        super().setUp()
        if self.in_ns('nft list tables').returncode:
            self.skipTest('this kernel or sandbox does not allow nft in a namespace')

    def wrap(self, script, name):
        path = self.tmp / name
        path.write_text(script)
        return path

    def test_quarantine_really_drops_and_can_be_lifted(self):
        q = self.wrap(sx.quarantine_script('10.0.0.5', 3600), 'q.sh')
        q6 = self.wrap(sx.quarantine_script('2001:db8::1', 0), 'q6.sh')
        net = self.wrap(sx.quarantine_script('10.1.0.0/16', 60), 'net.sh')
        u = self.wrap(sx.unquarantine_script('10.0.0.5'), 'u.sh')
        r = self.in_ns(f'''set -e
            bash {q} ; nft list tables | grep -c storageforge && echo NOT-REPORT-FIRST || true
            bash {q} --apply; bash {q} --apply; bash {q6} --apply; bash {net} --apply
            nft list table inet storageforge_fence
            nft get element inet storageforge_fence q4 '{{ 10.1.2.3 }}' >/dev/null && echo NET-MEMBER
            bash {u} --apply
            nft get element inet storageforge_fence q4 '{{ 10.0.0.5 }}' 2>/dev/null || echo LIFTED''')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('NOT-REPORT-FIRST', r.stdout)
        self.assertIn('QUARANTINED 10.0.0.5', r.stdout)
        self.assertIn('ip saddr @q4 drop', r.stdout)                # the rule that makes the set mean something
        self.assertIn('ip6 saddr @q6 drop', r.stdout)
        self.assertIn('timeout 1h', r.stdout)
        self.assertEqual(r.stdout.count('ip saddr @q4 drop'), 2)     # input and forward, once each, however many runs
        self.assertIn('NET-MEMBER', r.stdout)
        self.assertIn('LIFTED', r.stdout)

    def test_the_table_really_drops_packets(self):
        q = self.wrap(sx.quarantine_script('127.0.0.5', 0), 'q.sh')
        r = self.in_ns(f'''ip link set lo up
            ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 || {{ echo NO-PING; exit 0; }}
            ping -c1 -W1 -I 127.0.0.5 127.0.0.1 >/dev/null 2>&1 && echo BEFORE-OK
            bash {q} --apply >/dev/null
            ping -c1 -W1 -I 127.0.0.5 127.0.0.1 >/dev/null 2>&1 && echo AFTER-OK || echo AFTER-DROPPED''')
        if 'NO-PING' in r.stdout:
            self.skipTest('ping does not work in this namespace')
        self.assertIn('BEFORE-OK', r.stdout, r.stderr)
        self.assertIn('AFTER-DROPPED', r.stdout, r.stderr)

    def test_the_airgap_rules_load_and_disarm_really_removes_them(self):
        (self.bin / 'nft').unlink()                                 # the real one, here
        a = self.wrap(sx.airgap_script(['10.0.0.1', '2001:db8::9']), 'a.sh')
        r = subprocess.run(['unshare', '--user', '--map-current-user', '--keep-caps', '--net', 'bash', '-c', f'''export PATH={self.bin}:$PATH STUB_LOG={self.log}
            bash {a} && nft list tables | grep -c airgap && echo NOT-REPORT-FIRST
            bash {a} --apply; nft list table inet storageforge_airgap
            bash {a} --disarm; nft list tables | grep -c airgap && echo STILL-THERE; echo FINISHED'''], capture_output=True, text=True, timeout=30)
        self.assertNotIn('NOT-REPORT-FIRST', r.stdout, r.stderr)
        self.assertIn('AIRGAP pending', r.stdout, r.stderr)
        self.assertIn('policy drop', r.stdout)
        self.assertIn('ip saddr 10.0.0.1 accept', r.stdout)
        self.assertIn('ip6 saddr 2001:db8::9 accept', r.stdout)
        self.assertNotIn('established', r.stdout)                   # an attacker's open session must not survive it
        self.assertIn('AIRGAP off', r.stdout)
        self.assertNotIn('STILL-THERE', r.stdout)
        self.assertIn('FINISHED', r.stdout)


class DecoyBase(Base):
    def configure(self, **kw):
        share = self.root / 'share'
        r = self.post('/api/security/sentinel', host='nas', folders=[str(share)], **kw)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return share

    def deploy(self, mode='apply', **kw):
        items = security.deploy_items(self.db, self.conn, 'nas', mode, 'admin1', **kw)
        it = items[0]
        res = self.run_for_real(self.db, it['host'], it['script'], it['args'], kind=it['kind'], ref=it['ref'], mode=it['mode'], actor='admin1')
        self.assertEqual(res['exit_code'], 0, res['output'])
        if it.get('on_ok'):
            it['on_ok'](res)
        return res


class Decoys(DecoyBase):
    def test_nothing_is_written_without_apply(self):
        share = self.configure()
        self.deploy('report')
        self.assertEqual(list(share.iterdir()), [])
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_canaries'), 0)

    def test_decoys_are_real_files_with_the_hashes_the_host_read_back(self):
        share = self.configure()
        self.deploy()
        rows = self.conn.all('SELECT path, sha256, size, status FROM security_canaries ORDER BY path')
        self.assertEqual(len(rows), 3)
        sizes = set()
        for path, sha, size, status in rows:
            data = Path(path).read_bytes()
            self.assertEqual(sha, __import__('hashlib').sha256(data).hexdigest())
            self.assertEqual((size, status), (len(data), 'armed'))
            sizes.add(size)
        self.assertGreater(len(sizes), 1)
        self.assertTrue((share / '_AAAPasswords.docx').read_bytes().startswith(b'PK\x03\x04'))
        self.assertTrue((share / '00_Index.pdf').read_bytes().startswith(b'%PDF-'))
        self.assertIn(' -p wa -k sf_canary', (self.root / sx.AUDIT_RULES.lstrip('/')).read_text())
        self.assertEqual(deploy.deployed(self.conn, 'nas', 'security')[0]['ref'], 'security')

    def test_a_file_that_is_not_ours_is_left_alone(self):
        share = self.configure()
        (share / '00_Index.pdf').write_text('someone\'s real file')
        res = self.deploy()
        self.assertIn('is not one of mine', res['output'])
        self.assertEqual((share / '00_Index.pdf').read_text(), 'someone\'s real file')
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_canaries'), 2)

    def test_a_redeploy_keeps_a_tripped_decoy_tripped_until_rearmed(self):
        share = self.configure()
        self.deploy()
        self.measure()
        f = share / '00_Index.pdf'
        f.write_text('encrypted!')
        self.measure()
        self.assertEqual(self.conn.scalar("SELECT status FROM security_canaries WHERE path LIKE '%00_Index.pdf'"), 'tripped')
        self.deploy()
        self.assertEqual(f.read_text(), 'encrypted!')             # evidence
        self.deploy(rearm=True)
        self.assertNotEqual(f.read_bytes(), b'encrypted!')
        self.assertEqual(self.conn.scalar("SELECT status FROM security_canaries WHERE path LIKE '%00_Index.pdf'"), 'armed')

    def test_measuring_catches_a_decoy_even_with_the_sentinel_down(self):
        share = self.configure()
        self.deploy()
        (share / '_AAAPasswords.docx').unlink()
        self.measure()
        p = security.posture(self.conn, 'nas')
        self.assertEqual(p['state'], 'critical')
        self.assertTrue(any('_AAAPasswords' in e['summary'] and e['kind'] == 'canary_tripped' for e in p['events']))
        self.measure()
        self.assertEqual(sum(1 for e in security.list_events(self.conn, 'nas') if e['kind'] == 'canary_tripped'), 1)

    def test_removing_takes_unchanged_decoys_and_leaves_changed_ones(self):
        share = self.configure()
        self.deploy()
        (share / '00_Index.pdf').write_text('changed')
        res = self.deploy(remove=True)
        self.assertIn('stays', res['output'])
        self.assertEqual([p.name for p in share.iterdir()], ['00_Index.pdf'])
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_canaries'), 0)
        self.assertEqual(deploy.deployed(self.conn, 'nas', 'security'), [])

    def test_the_sentinel_is_off_until_someone_arms_it(self):
        self.configure()
        self.assertFalse(security.sentinel_config(self.conn, 'nas')['armed'])
        self.assertIn('ARMED_VALUE=0', security._install(self.conn, 'nas'))

    def test_hostile_names_never_reach_a_script_as_code(self):
        share = self.root / 'share'
        for bad in ('x\nEOF\ntouch /tmp/pwned\n', 'a/b', '..', '', '   padded  ', 'tab\there', 'x' * 101):
            r = self.post('/api/security/sentinel', host='nas', folders=[str(share)], names=[bad])
            self.assertEqual(r.status_code, 400, repr(bad))
        for bad in ('relative', '/a/../etc', '/x\ny'):
            self.assertEqual(self.post('/api/security/sentinel', host='nas', folders=[bad]).status_code, 400, repr(bad))

    def test_names_that_are_legal_but_nasty_stay_data(self):
        share = self.root / 'share'
        canary = self.tmp / 'PWNED'
        nasty = [f'$(touch {canary})', f'`touch {canary}`.docx', f"'; touch {canary}; '", 'sp ace.pdf', '!bang"quote.xlsx']
        r = self.post('/api/security/sentinel', host='nas', folders=[str(share)], names=[n.replace('/', '_') for n in nasty])
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.deploy()
        self.assertFalse(canary.exists())
        self.assertEqual(len(list(share.iterdir())), 5)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_canaries'), 5)

    def test_the_report_token_is_new_each_deploy_and_only_its_hash_is_kept(self):
        alerts.set_setting(self.conn, 'report_url', 'http://sf.example:8080', 'test')
        self.configure()
        self.deploy()
        header = (self.root / 'etc/storageforge/security/report.header').read_text()
        token = header.split('Bearer ')[1].strip()
        self.assertEqual(oct((self.root / 'etc/storageforge/security/report.header').stat().st_mode)[-3:], '600')
        self.assertEqual(security.report_host(self.conn, token), 'nas')
        self.assertNotIn(token, json.dumps(self.conn.all('SELECT * FROM settings')))
        self.deploy()
        self.assertIsNone(security.report_host(self.conn, token))

    def test_a_digest_tells_a_changed_config_and_ignores_the_token(self):
        self.configure()
        a = security.digest(self.conn, 'nas')
        self.assertEqual(a, security.digest(self.conn, 'nas'))
        self.configure(armed=True)
        self.assertNotEqual(a, security.digest(self.conn, 'nas'))


@unittest.skipUnless(shutil.which('inotifywait'), 'needs inotify-tools')
class RealSentinel(DecoyBase):
    """The sentinel itself, watching real files with real inotify, the moment something touches them."""

    def start(self, **conf):
        share = self.configure(**{k: v for k, v in conf.items() if k in ('armed', 'actions', 'minutes')})
        self.deploy()
        cf = self.root / 'etc/storageforge/security/sentinel.conf'
        cf.write_text(cf.read_text() + 'CLOCK_EVERY=1\n')
        p = subprocess.Popen(['bash', str(self.root / 'usr/local/sbin/storageforge-sentinel')], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: (os.killpg(p.pid, 9), p.wait()))
        self.events = self.root / 'var/lib/storageforge/security/events.tsv'
        self.wait_for('sentinel_started')
        time.sleep(0.5)
        return share

    def wait_for(self, kind, seconds=10):
        end = time.time() + seconds
        while time.time() < end:
            if self.events.exists():
                found = [e for e in map(security.parse_event_line, self.events.read_text().splitlines()) if e and e['kind'] == kind]
                if found:
                    return found
            time.sleep(0.1)
        self.fail(f'no {kind} event: {self.events.read_text() if self.events.exists() else "(no file)"}')

    def test_a_write_to_a_decoy_is_seen_and_the_controller_understands_it(self):
        share = self.start()
        with (share / '00_Index.pdf').open('ab') as f:
            f.write(b'encrypted')
        ev = self.wait_for('canary_tripped')[0]
        self.assertIn('00_Index.pdf', ev['summary'])
        self.assertEqual(security.ingest_events(self.conn, 'nas', self.events.read_text(), 'test') >= 2, True)
        self.assertEqual(self.conn.scalar("SELECT status FROM security_canaries WHERE path LIKE '%00_Index.pdf'"), 'tripped')

    def test_a_slow_program_that_reads_stdin_loses_no_alarm(self):
        """Found on a real host. The loop's stdin is the stream of events, ausearch reads stdin, and so it ate the next trip."""
        (self.bin / 'ausearch').write_text('#!/bin/bash\ncat >/dev/null &\nsleep 3\n')
        (self.bin / 'ausearch').chmod(0o755)
        share = self.start()
        t0 = time.time()
        (share / '00_Index.pdf').write_text('x')
        time.sleep(0.2)
        (share / '_AAAPasswords.docx').write_text('x')
        time.sleep(0.2)
        (share / '!Financial_2026.xlsx').write_text('x')
        end = t0 + 2
        while time.time() < end and sum(1 for e in map(security.parse_event_line, self.events.read_text().splitlines()) if e and e['kind'] == 'canary_tripped') < 3:
            time.sleep(0.05)
        found = [e['summary'] for e in map(security.parse_event_line, self.events.read_text().splitlines()) if e and e['kind'] == 'canary_tripped']
        self.assertEqual(len(found), 3, found)
        self.assertLess(time.time() - t0, 2)                       # none of them waited for attribution

    def test_a_burst_from_one_client_is_one_brake(self):
        share = self.start(armed=True, actions=['triage'])
        for name in ('00_Index.pdf', '_AAAPasswords.docx', '!Financial_2026.xlsx'):
            (share / name).write_text('x')
        self.wait_for('brake_ran')
        time.sleep(1.5)
        self.assertEqual(len(list((self.root / 'var/lib/storageforge/forensics').iterdir())), 1)

    def test_renaming_or_deleting_a_decoy_is_seen(self):
        share = self.start()
        (share / '_AAAPasswords.docx').rename(share / '_AAAPasswords.docx.locked')
        self.assertIn('_AAAPasswords', self.wait_for('canary_tripped')[0]['summary'])

    def test_reading_a_decoy_is_not(self):
        share = self.start()
        (share / '00_Index.pdf').read_bytes()
        time.sleep(1)
        self.assertEqual([e for e in map(security.parse_event_line, self.events.read_text().splitlines()) if e and e['kind'] == 'canary_tripped'], [])

    def test_unarmed_it_only_reports(self):
        share = self.start()
        (share / '00_Index.pdf').write_text('x')
        self.wait_for('canary_tripped')
        time.sleep(0.5)
        self.assertNotIn('brake_ran', self.events.read_text().split('\t'))
        self.assertFalse((self.root / 'var/lib/storageforge/forensics').exists())

    def test_armed_it_pulls_the_brake_by_itself(self):
        share = self.start(armed=True, actions=['triage'])
        (share / '00_Index.pdf').write_text('x')
        ev = self.wait_for('brake_ran')[0]
        self.assertIn('STEP triage ok', ev['detail'])
        found = list((self.root / 'var/lib/storageforge/forensics').iterdir())
        self.assertEqual(len(found), 1)
        self.assertIn('00_Index.pdf', (found[0] / 'incident.txt').read_text())
        self.assertTrue((found[0] / 'processes.txt').exists())

    def test_the_test_file_times_it_without_an_alarm(self):
        self.start()
        script = security._install(self.conn, 'nas')
        r = self.sh(script, '--test')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout.decode(), r'LATENCY \d+')
        self.wait_for('sentinel_test')
        self.assertEqual([e for e in map(security.parse_event_line, self.events.read_text().splitlines()) if e and e['kind'] == 'canary_tripped'], [])

    def test_a_clock_moved_against_uptime_is_caught(self):
        real = shutil.which('date')
        offset = self.tmp / 'offset'
        offset.write_text('0')
        (self.bin / 'date').write_text(f'#!/bin/bash\nif [[ $1 == +%s ]]; then echo $(( $({real} +%s) + $(cat {offset}) )); else exec {real} "$@"; fi\n')
        (self.bin / 'date').chmod(0o755)
        self.start()
        time.sleep(1.5)
        offset.write_text(str(30 * DAY))
        ev = self.wait_for('clock_jump')[0]
        self.assertIn(str(30 * DAY)[:3], ev['summary'])
        security.ingest_events(self.conn, 'nas', self.events.read_text(), 'test')
        self.assertTrue(security.clock_frozen(self.conn, 'nas'))


class Brake(Base):
    def run_brake(self, *args, findmnt='zfs tank/shares /srv/shares'):
        (self.bin / 'findmnt').write_text(f'#!/bin/bash\necho {findmnt}\n')
        (self.bin / 'findmnt').chmod(0o755)
        return self.sh(sx.brake_program(), *args)

    def steps(self, r):
        return dict(re.findall(r'^STEP (\w+) (\w+)', r.stdout.decode(), re.M))

    def test_it_only_says_what_it_would_do_without_apply(self):
        r = self.run_brake(*sx.brake_args('/srv/shares/x', '10.0.0.9'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.steps(r), {'triage': 'skipped', 'quarantine': 'skipped', 'snapshot': 'skipped', 'freeze': 'skipped'})
        self.assertEqual(self.nstate.read_text(), '')
        self.assertNotIn('zfs snapshot', self.log.read_text())

    def test_every_step_runs_in_order_on_zfs(self):
        r = self.run_brake(*sx.brake_args('/srv/shares/x', '10.0.0.9', apply=True, reason='r'))
        out = r.stdout.decode()
        self.assertEqual(r.returncode, 0, out + r.stderr.decode())
        self.assertEqual(self.steps(r), {'triage': 'ok', 'quarantine': 'ok', 'snapshot': 'ok', 'freeze': 'ok'})
        self.assertLess(out.index('STEP triage'), out.index('STEP quarantine'))
        self.assertLess(out.index('STEP quarantine'), out.index('STEP snapshot'))
        self.assertLess(out.index('STEP snapshot'), out.index('STEP freeze'))
        self.assertIn('10.0.0.9', self.nstate.read_text())
        self.assertIn('readonly=on tank/shares', (self.tmp / 'zfs.props').read_text())
        self.assertRegex(self.zstate.read_text(), r'tank/shares@sf-incident-\S+\tsf-incident')
        self.assertIn('QUARANTINED 10.0.0.9', out)

    def test_a_filesystem_the_host_runs_on_stays_writable(self):
        for fs in ('ext4 /dev/sda1 /', 'ext4 /dev/sda2 /var/lib', 'btrfs /dev/sda1 /usr'):
            r = self.run_brake(*sx.brake_args('/x', apply=True, actions=('freeze',)), findmnt=fs)
            self.assertEqual(self.steps(r)['freeze'], 'skipped', fs)
        self.assertNotIn('remount', self.log.read_text())

    def test_a_failed_step_says_so_and_the_rest_still_run(self):
        (self.bin / 'mount').write_text('#!/bin/bash\necho "target is busy" >&2\nexit 32\n')
        (self.bin / 'mount').chmod(0o755)
        r = self.run_brake(*sx.brake_args('/srv/x', '10.0.0.9', apply=True), findmnt='ext4 /dev/sdb1 /srv/x')
        self.assertEqual(r.returncode, 1)
        s = self.steps(r)
        self.assertEqual((s['triage'], s['quarantine'], s['snapshot'], s['freeze']), ('ok', 'ok', 'skipped', 'failed'))
        self.assertIn('busy', r.stdout.decode())

    def test_an_exempt_client_is_not_dropped(self):
        conf = self.root / 'etc/storageforge/security'
        conf.mkdir(parents=True)
        (conf / 'vip.list').write_text('10.0.0.0/24\n')
        r = self.run_brake(*sx.brake_args('/srv/x', '10.0.0.9', apply=True, actions=('quarantine',)))
        self.assertEqual(self.steps(r)['quarantine'], 'skipped')
        self.assertEqual(self.nstate.read_text(), '')

    def test_no_client_known_is_not_a_failure(self):
        r = self.run_brake(*sx.brake_args('/srv/x', apply=True, actions=('quarantine',)))
        self.assertEqual(self.steps(r)['quarantine'], 'skipped')
        self.assertEqual(r.returncode, 0)

    def test_the_answer_is_what_the_steps_reported(self):
        (self.bin / 'findmnt').write_text('#!/bin/bash\necho zfs tank/shares /srv/shares\n')
        (self.bin / 'findmnt').chmod(0o755)
        r = self.post('/api/security/incident/brake', host='nas', path='/srv/shares/x', client_ip='10.0.0.9', mode='apply', minutes=15).get_json()
        self.assertTrue(r['ok'], r)
        self.assertEqual({s['step']: s['status'] for s in r['steps']}, {'triage': 'ok', 'quarantine': 'ok', 'snapshot': 'ok', 'freeze': 'ok'})
        self.assertEqual(self.conn.scalar('SELECT ip_address FROM security_quarantine'), '10.0.0.9')
        hold = security.hold_rows(self.conn, 'nas')[0]
        self.assertTrue(hold['snapshot'].startswith('tank/shares@sf-incident-'))
        self.assertTrue(hold['legal_hold'])
        self.assertEqual(security.posture(self.conn, 'nas')['state'], 'critical')

    def test_a_brake_with_a_failed_step_is_not_called_a_success(self):
        (self.bin / 'mount').write_text('#!/bin/bash\nexit 32\n')
        (self.bin / 'mount').chmod(0o755)
        (self.bin / 'findmnt').write_text('#!/bin/bash\necho ext4 /dev/sdb1 /srv/x\n')
        (self.bin / 'findmnt').chmod(0o755)
        r = self.post('/api/security/incident/brake', host='nas', path='/srv/x', mode='apply', actions=['freeze'])
        self.assertEqual(r.status_code, 409)
        self.assertIn('freeze', r.get_json()['error'])

    def test_it_will_not_drop_the_exempt_list_either_by_hand(self):
        self.post('/api/security/firewall/vip', vips=['10.0.0.0/24'])
        self.assertEqual(self.post('/api/security/incident/brake', host='nas', client_ip='10.0.0.9', mode='apply').status_code, 400)


class Behaviour(Base):
    def scans(self, rates, gap=3600):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        now = int(time.time()) - len(rates) * gap
        ids = []
        for i, n in enumerate(rates):
            ids.append(self.conn.scalar("""INSERT INTO scans (host_id, started_at, finished_at, status, added, modified, deleted)
                                           VALUES (:h, :t, :t, 'ok', 0, :n, 0) RETURNING scan_id""", {'h': hid, 't': now + i * gap, 'n': n}))
        return ids, hid

    def change(self, scan, hid, name, kind='added', parent='/srv/a'):
        m = self.conn.scalar('SELECT mount_id FROM mounts WHERE host_id = :h', {'h': hid})
        if not m:
            m = self.conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type) VALUES (:h, '/srv', 'zfs') RETURNING mount_id", {'h': hid})
        self.conn.execute('INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename) VALUES (:s, :m, :k, :p, :f)', {'s': scan, 'm': m, 'k': kind, 'p': parent, 'f': name})

    def test_no_baseline_means_no_verdict(self):
        self.scans([10, 99999])
        v = security.velocity(self.conn, 'nas')
        self.assertIsNone(v['baseline_median'])
        self.assertFalse(v['anomaly'])

    def test_a_spike_against_its_own_past(self):
        self.scans([100, 110, 90, 105, 95, 100, 100, 5000])
        v = security.velocity(self.conn, 'nas')
        self.assertTrue(v['anomaly'])
        self.assertEqual(v['baseline_median'], 100)
        self.assertIn('security-velocity:nas', alerts.problems(self.conn))

    def test_a_quiet_host_doubling_is_not_an_alarm(self):
        self.scans([10, 12, 9, 11, 10, 10, 10, 60])
        self.assertFalse(security.velocity(self.conn, 'nas')['anomaly'])          # over the factor, under the floor

    def test_a_scan_a_long_time_after_the_last_is_judged_by_the_hour(self):
        self.scans([1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000], gap=DAY)
        self.assertEqual(security.velocity(self.conn, 'nas')['latest']['files_per_hour'], round(1000 / 24, 1))

    def test_ransomware_names_and_appended_extensions_are_found(self):
        ids, hid = self.scans([1, 1])
        self.change(ids[1], hid, 'budget.xlsx.LOCKED')
        self.change(ids[1], hid, 'HOW_TO_DECRYPT.txt')
        self.change(ids[1], hid, 'holiday.jpg')
        self.change(ids[0], hid, 'old.locked')                 # another scan: not this one's news
        v = security.velocity(self.conn, 'nas')
        self.assertEqual(v['ransom_names'], 2)
        self.assertEqual(sorted(v['ransom_samples']), ['/srv/a/HOW_TO_DECRYPT.txt', '/srv/a/budget.xlsx.LOCKED'])
        self.assertIn('security-names:nas', alerts.problems(self.conn))
        self.assertEqual(security.posture(self.conn, 'nas')['state'], 'critical')

    def test_renames_with_an_unknown_extension_show_the_same_shape(self):
        ids, hid = self.scans([1, 1])
        for i in range(60):
            self.change(ids[1], hid, f'f{i}.docx', 'deleted')
            self.change(ids[1], hid, f'f{i}.docx.qwzx', 'added')
        self.change(ids[1], hid, 'ordinary.txt', 'added')
        self.assertEqual(security.velocity(self.conn, 'nas')['appended_extensions'], 60)
        self.assertIn('security-renames:nas', alerts.problems(self.conn))

    def sample_dir(self):
        d = self.tmp / 'files'
        d.mkdir()
        random = os.urandom(4096)
        (d / 'locked.doc').write_bytes(random)
        (d / 'note.txt').write_bytes(b'the quick brown fox ' * 300)
        (d / 'real.zip').write_bytes(b'PK\x03\x04' + random)
        (d / 'tiny.bin').write_bytes(random[:100])
        (d / 'link.doc').symlink_to(d / 'locked.doc')
        return d

    @unittest.skipUnless(shutil.which('python3'), 'needs python3')
    def test_entropy_is_really_measured_on_really_read_files(self):
        d = self.sample_dir()
        names = ['locked.doc', 'note.txt', 'real.zip', 'tiny.bin', 'link.doc', 'absent']
        data = ''.join(sx.b64(str(d / n)) + '\n' for n in names).encode()
        r = self.sh(sx.entropy_script(), data=data)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = {Path(s['path']).name: s for s in security.parse_entropy(r.stdout.decode())}
        self.assertEqual(set(got), {'locked.doc', 'note.txt', 'real.zip'})      # too small, a symlink, and gone: not read
        self.assertTrue(got['locked.doc']['flagged'])
        self.assertGreater(got['locked.doc']['entropy'], 7.9)
        self.assertFalse(got['note.txt']['flagged'])
        self.assertLess(got['note.txt']['entropy'], 5)
        self.assertGreater(got['real.zip']['entropy'], 7.9)
        self.assertFalse(got['real.zip']['flagged'])                            # compressed, as its header says

    @unittest.skipUnless(shutil.which('python3'), 'needs python3')
    def test_the_sample_is_stored_with_what_was_asked_and_what_was_read(self):
        d = self.sample_dir()
        ids, hid = self.scans([1, 1])
        for n in ('locked.doc', 'note.txt', 'absent.txt'):
            self.change(ids[1], hid, n, parent=str(d))
        self.change(ids[1], hid, 'movie.mp4', parent=str(d))                    # compressed: not worth reading
        r = self.post('/api/security/behavior/entropy', host='nas').get_json()
        self.assertEqual((r['read'], r['flagged']), (2, 1))
        e = security.measurement(self.conn, 'nas', 'entropy')
        self.assertEqual((e['asked'], e['read']), (3, 2))
        self.assertEqual(Path(e['flagged'][0]['path']).name, 'locked.doc')

    def test_diff_scan_adds_and_never_closes(self):
        (self.bin / 'clamscan').write_text('#!/bin/bash\nfor a in "$@"; do [[ $a == --file-list=* ]] && while read -r p; do [[ $p == *evil* ]] && echo "$p: Win.Ransom FOUND"; done <"${a#*=}"; done\nexit 1\n')
        (self.bin / 'clamscan').chmod(0o755)
        d = self.tmp / 'f'
        d.mkdir()
        (d / 'evil.exe').write_text('x')
        (d / 'fine.txt').write_text('x')
        ids, hid = self.scans([1, 1])
        self.change(ids[1], hid, 'evil.exe', parent=str(d))
        self.change(ids[1], hid, 'fine.txt', parent=str(d))
        self.conn.execute("INSERT INTO clamav_detections (host, path_b64, path, signature, state, ignored, first_seen, last_seen) VALUES ('nas', 'eA==', '/other', 'Older', 'open', 0, 1, 1)")
        r = self.post('/api/security/behavior/diff-scan', host='nas').get_json()
        self.assertEqual((r['scanned'], r['found']), (2, 1))
        self.assertEqual(self.conn.scalar("SELECT state FROM clamav_detections WHERE signature = 'Older'"), 'open')
        self.assertEqual(self.conn.scalar("SELECT state FROM clamav_detections WHERE signature = 'Win.Ransom'"), 'open')
        self.assertEqual(self.post('/api/security/behavior/diff-scan', host='nas').get_json()['found'], 0)

    def test_a_blast_radius_without_a_scan_since_gives_no_counts(self):
        self.assertIsNone(security.blast_radius(self.conn, 'nas')['incident_at'])
        security.ingest_events(self.conn, 'nas', event_line())
        b = security.blast_radius(self.conn, 'nas')
        self.assertIsNotNone(b['incident_at'])
        self.assertIsNone(b['changed_since'])
        self.assertIsNone(b['unchanged_files'])
        self.assertIsNone(b['rpo_seconds'])

    def test_a_blast_radius_counts_what_came_after(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        hold = self.hold()
        self.conn.execute('UPDATE security_retention_holds SET created_at = :t WHERE id = :i', {'t': int(time.time()) - 7200, 'i': hold})
        at = int(time.time()) - 3600
        security.ingest_events(self.conn, 'nas', event_line(at=at))
        self.conn.execute("INSERT INTO scans (host_id, started_at, finished_at, status, modified) VALUES (:h, :t, :t, 'ok', 40)", {'h': hid, 't': at - 100})
        self.conn.execute("INSERT INTO scans (host_id, started_at, finished_at, status, modified) VALUES (:h, :t, :t, 'ok', 7)", {'h': hid, 't': at + 100})
        b = security.blast_radius(self.conn, 'nas')
        self.assertEqual(b['changed_since'], 7)
        self.assertEqual(b['rpo_seconds'], 3600)


class Scripts(Base):
    def everything(self):
        cfg = dict(decoys=['/srv/a/x.docx'], armed=True, actions=sx.BRAKE_ACTIONS, minutes=60, report_url='https://sf.example', token='t', vips=['10.0.0.1'], report_ca='-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n')
        yield 'measure', sx.measure_script(['a@b'], ['/b'], ['/c'], ['/d'])
        yield 'hold', sx.hold_script('a@b', 'sf-x')
        yield 'release', sx.release_script('a@b', 'sf-x')
        yield 'quarantine', sx.quarantine_script('10.0.0.5', 60)
        yield 'unquarantine', sx.unquarantine_script('10.0.0.5')
        yield 'airgap', sx.airgap_script(['10.0.0.1'])
        yield 'brake', sx.brake_program()
        yield 'install', sx.install_script(**cfg)
        yield 'relabel', sx.relabel_script('/srv', 'samba_share_t')
        yield 'boolean', sx.boolean_script('samba_export_all_rw', 'off')
        for tool in ('aide-init', 'aide-check', 'lynis'):
            yield tool, sx.tool_script(tool)
        yield 'entropy', sx.entropy_script()
        yield 'diff', sx.DIFF_SCAN
        yield 'cleanroom', sx.cleanroom_script('a@b', '/mnt/x')
        yield 'compliance', sx.compliance_script('cis-l2', 'nas')

    def test_all_parse(self):
        for name, text in self.everything():
            r = subprocess.run(['bash', '-n'], input=text.encode(), capture_output=True)
            self.assertEqual(r.returncode, 0, f'{name}: {r.stderr.decode()}')

    @unittest.skipUnless(shutil.which('shellcheck'), 'needs shellcheck (CI has it)')
    def test_shellcheck_finds_no_errors(self):
        for name, text in self.everything():
            r = subprocess.run(['shellcheck', '--severity=error', '-s', 'bash', '-'], input=text, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f'{name}:\n{r.stdout}')

    def test_nothing_hides_a_failure_where_it_matters(self):
        """The old scripts ended every step in 2>/dev/null || true, and so reported success whatever happened."""
        for name, text in self.everything():
            if name in ('measure', 'entropy', 'diff'):
                continue
            for line in text.splitlines():
                if '|| true' in line and 'storageforge' not in line:
                    self.assertNotRegex(line, r'\b(zfs|nft add|nft -f|mount|btrfs)\b.*\|\| true', f'{name}: {line}')

    def test_values_stay_data(self):
        pwned = self.tmp / 'PWNED'
        bad = f"$(touch {pwned}) `touch {pwned}` '; touch {pwned}; '"
        for script in (sx.hold_script(bad, bad), sx.release_script(bad, bad), sx.relabel_script(bad, bad), sx.boolean_script(bad, bad), sx.cleanroom_script(bad, bad)):
            self.sh(script)
        self.assertFalse(pwned.exists())

    def test_the_sysctl_names_are_spelled_as_the_kernel_spells_them(self):
        self.assertTrue(all(k == k.lower() for k in sx.SYSCTLS))     # net.ipv4.conf.all.accept_Redirects is no setting at all
        text = sx.compliance_script('cis-l2', 'nas')
        self.assertNotIn('accept_Redirects', text)
        self.assertIn('net.ipv4.conf.all.accept_redirects = 0', text)

    def test_a_compliance_dry_run_writes_nothing(self):
        r = self.sh(sx.compliance_script('cis-l2', 'nas'))
        self.assertIn(b'== Kernel settings ==', r.stdout)
        self.assertEqual(self.nstate.read_text(), '')
        self.assertNotIn('nft -f', self.log.read_text())

    def test_the_btrfs_hold_says_what_it_is(self):
        self.assertIn('root can make this writable again', sx.hold_script('/a', 'sf-x'))


class Wiring(Base):
    def test_every_table_in_a_backup_list(self):
        for t in ('security_events', 'security_retention_holds', 'security_timelock_queue', 'security_canaries', 'security_quarantine'):
            self.assertIn(t, backup.ESSENTIAL)
        self.assertIn('security_measurements', backup.REBUILDABLE)

    def test_retiring_a_host_leaves_nothing_behind(self):
        self.add_host('old', ready=False)
        security.ingest_events(self.conn, 'old', event_line())
        security.freeze_clock(self.conn, 'old', 'x', 'y')
        security.save_sentinel_config(self.conn, 'old', {'folders': ['/srv']}, 'a')
        self.conn.execute("INSERT INTO security_quarantine (host, ip_address, reason, added_at, actor) VALUES ('old', '10.0.0.1', 'r', 1, 'a')")
        retire.retire(self.conn, 'old')
        for t in ('security_events', 'security_quarantine'):
            self.assertEqual(self.conn.scalar(f'SELECT count(*) FROM {t}'), 0, t)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM settings WHERE key LIKE 'security.%:old'"), 0)

    def test_a_pending_release_goes_out_as_an_alert(self):
        self.solo()
        hid = self.hold()
        self.post('/api/security/worm/release', hold_id=hid)
        p = alerts.problems(self.conn)
        key = next(k for k in p if k.startswith('security-timelock:'))
        self.assertEqual(p[key][4], 'crit')
        self.assertIn('abort', p[key][3])

    def test_a_deployed_sentinel_that_stopped_is_an_alert(self):
        deploy.mark_deployed(self.conn, 'nas', 'security', 'security', 'x', {}, 'a')
        out = self.sh(sx.measure_script()).stdout.decode()
        out = re.sub(r'(@@sentinel\n)active', r'\1inactive', out)
        data = security.parse_measure(out)
        now = int(time.time())
        security.store_measurement(self.conn, 'nas', data, now, now, 'test')
        self.assertIn('security-sentinel:nas', alerts.problems(self.conn))

    def test_tick_measures_a_host_it_should_and_leaves_others_alone(self):
        self.add_host('quiet')
        deploy.mark_deployed(self.conn, 'nas', 'security', 'security', 'x', {}, 'a')
        security.tick(self.db)
        self.assertEqual({c['host'] for c in self.calls}, {'nas'})
        self.assertIsNotNone(security.measurement(self.conn, 'nas'))
        n = len(self.calls)
        security.tick(self.db)
        self.assertEqual(len(self.calls), n)                     # it is not due again yet

    def test_who_may_do_what(self):
        users.create(self.conn, 'vee', PW, 'viewer')
        users.create(self.conn, 'opal', PW, 'operator')
        self.login('vee')
        self.assertEqual(self.client.get('/api/security/posture').status_code, 200)
        for path in ('/api/security/measure', '/api/security/incident/brake', '/api/security/worm/hold', '/api/security/firewall/quarantine'):
            self.assertEqual(self.post(path, host='nas').status_code, 403, path)
        self.login('opal')
        self.assertEqual(self.post('/api/security/measure', host='nas').status_code, 200)
        for path in ('/api/security/incident/brake', '/api/security/firewall/airgap', '/api/security/worm/release', '/api/security/worm/break-glass', '/api/security/sentinel'):
            self.assertEqual(self.post(path, host='nas').status_code, 403, path)
        self.assertTrue(permissions.required('POST', '/api/security/report'))

    def test_a_preview_leaves_no_audit_row_and_a_change_does(self):
        n = lambda: self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'security.quarantine.add'")
        self.post('/api/security/firewall/quarantine', host='nas', ip_address='10.0.0.5', mode='preview')
        self.assertEqual(n(), 0)
        self.post('/api/security/firewall/quarantine', host='nas', ip_address='10.0.0.5', mode='apply')
        self.assertEqual(n(), 1)

    def test_a_static_file_with_an_inline_handler_is_dead_under_this_csp(self):
        """The whole Security tab was once built on onclick= attributes, which script-src 'self' silently refuses."""
        self.assertIn("script-src 'self'", server.SECURITY_HEADERS['Content-Security-Policy'])
        static = Path(server.__file__).with_name('static')
        for f in list(static.glob('*.html')) + [static / 'securityview.js']:
            self.assertNotRegex(f.read_text(), r'<[^>]+\son[a-z]+\s*=', f.name)
        self.assertIn('securityview.js', Path(server.__file__).read_text())


class Migration(unittest.TestCase):
    def test_what_v31_invented_does_not_survive(self):
        real = dbmod.MIGRATIONS
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / 'migrations'
            shutil.copytree(real, old)
            (old / 'sqlite' / '032_security_measured.sql').unlink()
            (old / 'sqlite' / '036_security_more.sql').unlink()      # it makes tables with the names v31 used, as 032 leaves them free
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            with mock.patch.object(dbmod, 'MIGRATIONS', old):
                db.migrate(conn)
            conn.execute("INSERT INTO security_retention_holds (host_name, dataset_name, snapshot_name, hold_tag, created_at) VALUES ('h', 'd', 's', 't', 1)")
            conn.execute("INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES ('security.break_glass_sha256', '\"x\"', 1, 'a')")
            self.assertEqual(db.migrate(conn), ['032_security_measured.sql', '036_security_more.sql', '037_sentinel_permission.sql'])
            self.assertEqual(conn.scalar('SELECT count(*) FROM security_retention_holds'), 0)
            self.assertEqual(conn.scalar("SELECT count(*) FROM settings WHERE key LIKE 'security.%'"), 0)
            conn.close()

    def test_the_two_databases_have_the_same_tables(self):
        mig = Path(server.__file__).with_name('migrations')
        tables = lambda d: sorted(re.findall(r'CREATE TABLE (\w+)', (mig / d / '032_security_measured.sql').read_text()))
        self.assertEqual(tables('sqlite'), tables('postgres'))


if __name__ == '__main__':
    unittest.main()
