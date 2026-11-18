"""StorageForge's own network against the index (sfnetwork.py), and the step that makes the interface (t_wg_interface), run for
real against stand-ins. What must hold: a host's private key is made on the host and never shown; a key is taken from a reading
once and never replaced by another; an interface StorageForge did not make is never touched; and every plan is one the change
engine takes."""
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import alerts, changes, server, sfnet, sfnetwork, steps_infra, users
from test_sfnet import key

PW = 'correct horse battery staple 9'


class Kept(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for name, address in (('ctl', '10.42.0.2'), ('nas', '10.42.0.10'), ('pi', '10.42.0.20')):
            self.conn.execute('INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES (:h, :a, :a)', {'h': name, 'a': address})

    def read(self, host, own=None, peers=None, others=()):
        """Store an infrastructure reading for the host: its sf0 with this key and these peers ({key number: [addresses]}), or none."""
        wg = list(others)
        if own is not None:
            wg.append({'name': 'sf0', 'public_key': key(own), 'listen_port': 51903, 'peers': [{'public_key': key(k), 'allowed_ips': a} for k, a in (peers or {}).items()]})
        self.conn.execute("DELETE FROM security_measurements WHERE host = :h AND kind = 'infra'", {'h': host})
        self.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                          {'h': host, 't': int(time.time()), 'd': json.dumps({'access': {'wireguard': wg}})})

    def up(self):
        if sfnetwork.load(self.conn) is None:
            sfnetwork.create(self.conn, 'gabe')
        for i, host in enumerate(('ctl', 'nas', 'pi'), 1):
            sfnetwork.join(self.conn, host, 'gabe', reachable=host != 'pi')
            self.read(host, own=i)
        return sfnetwork.status(self.conn)

    def kinds(self):
        return [(t['host'], t['type'], t['params'].get('state'), t['params'].get('pubkey', t['params'].get('address'))) for t in sfnetwork.tasks(self.conn)]

    def test_there_is_one_network_and_it_holds_no_secret(self):
        self.assertEqual(sfnetwork.status(self.conn), {'network': None, 'members': []})
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.join(self.conn, 'nas', 'gabe')
        made = sfnetwork.create(self.conn, 'gabe')
        self.assertEqual((made['range'], made['port'], made['topology'], made['members']), ('10.203.0.0/20', 51903, 'mesh', []))
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.create(self.conn, 'gabe')
        self.up()
        stored = json.dumps(alerts.get_setting(self.conn, sfnetwork.KEY))
        self.assertNotIn('private', stored.lower())
        self.assertEqual(sorted(set(re.findall(r'"([a-z_]+)":', stored))), ['address', 'endpoint', 'host', 'hub', 'members', 'next_public_key', 'port', 'public_key', 'range', 'state', 'topology'])

    def test_only_a_scanned_host_joins_and_is_called_where_scans_reach_it(self):
        sfnetwork.create(self.conn, 'gabe')
        with self.assertRaises(ValueError):
            sfnetwork.join(self.conn, 'never-scanned', 'gabe')
        self.assertEqual((sfnetwork.join(self.conn, 'nas', 'gabe')['endpoint'], sfnetwork.join(self.conn, 'pi', 'gabe', reachable=False)['endpoint']), ('10.42.0.10', None))
        self.assertEqual(sfnetwork.join(self.conn, 'ctl', 'gabe', endpoint='ctl.lab')['endpoint'], 'ctl.lab')
        for bad in ('10.0.0.1:51903', 'a b', '$(id)', 'x;y'):
            with self.subTest(bad), self.assertRaises(sfnet.NetworkError):
                sfnetwork.join(self.conn, 'ctl', 'gabe', endpoint=bad)

    def test_from_nothing_to_confirmed_in_two_plans(self):
        sfnetwork.create(self.conn, 'gabe')
        for host in ('ctl', 'nas', 'pi'):
            sfnetwork.join(self.conn, host, 'gabe', reachable=host != 'pi')
        self.assertEqual(self.kinds(), [('ctl', 'wg-interface', 'present', '10.203.0.1/20'), ('nas', 'wg-interface', 'present', '10.203.0.2/20'), ('pi', 'wg-interface', 'present', '10.203.0.3/20')],
                         'first the interfaces: nobody has a key yet, so nobody is anybody\'s peer')
        first = sfnetwork.plan(self.conn, 'gabe')
        self.assertEqual((first['tasks'], len(changes.get_plan(self.conn, first['plan_id'])['tasks'])), (3, 3), 'the change engine takes it')
        for i, host in enumerate(('ctl', 'nas', 'pi'), 1):
            self.read(host, own=i)
        self.assertEqual(sfnetwork.observe(self.conn), ['ctl', 'nas', 'pi'])
        self.assertEqual(sfnetwork.observe(self.conn), [], 'a key is taken once')
        second = sfnetwork.tasks(self.conn)
        self.assertEqual({t['type'] for t in second}, {'wg-peer'})
        self.assertEqual(sorted((t['host'], t['params']['pubkey'], t['params']['allowed'], t['params'].get('endpoint'), t['params'].get('keepalive')) for t in second),
                         sorted([('ctl', key(2), '10.203.0.2/32', '10.42.0.10:51903', None), ('ctl', key(3), '10.203.0.3/32', None, None),
                                 ('nas', key(1), '10.203.0.1/32', '10.42.0.2:51903', None), ('nas', key(3), '10.203.0.3/32', None, None),
                                 ('pi', key(1), '10.203.0.1/32', '10.42.0.2:51903', '25'), ('pi', key(2), '10.203.0.2/32', '10.42.0.10:51903', '25')]))
        changes.normalize({'name': 'p', 'tasks': second})
        self.read('ctl', 1, {2: ['10.203.0.2/32'], 3: ['10.203.0.3/32']})
        self.read('nas', 2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})
        self.read('pi', 3, {1: ['10.203.0.1/32'], 2: ['10.203.0.2/32']})
        self.assertEqual(sfnetwork.plan(self.conn, 'gabe'), {'plan_id': None, 'tasks': 0})
        self.assertEqual([(m['host'], m['state'], m['missing'], m['unknown']) for m in sfnetwork.status(self.conn)['members']], [(h, 'ok', [], []) for h in ('ctl', 'nas', 'pi')])
        self.assertEqual(sfnetwork.problems(self.conn), {})

    def test_a_different_key_on_a_member_is_a_finding_and_is_never_taken(self):
        self.up()
        self.read('nas', own=99)
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['public_key'], key(2), 'the key on record stays')
        nas = next(m for m in sfnetwork.status(self.conn)['members'] if m['host'] == 'nas')
        self.assertTrue(nas['key_changed'])
        found = sfnetwork.problems(self.conn)
        self.assertEqual([(k, v[4]) for k, v in found.items() if k.startswith('sfnet-key')], [('sfnet-key:nas', 'crit')])
        self.assertIn('sfnet-key:nas', alerts.problems(self.conn))
        self.assertNotIn(key(99), json.dumps(sfnetwork.tasks(self.conn)), 'no peer is told to trust it')

    def test_a_second_host_showing_a_key_already_on_record_stays_out(self):
        sfnetwork.create(self.conn, 'gabe')
        sfnetwork.join(self.conn, 'ctl', 'gabe')
        sfnetwork.join(self.conn, 'nas', 'gabe')
        self.read('ctl', own=1)
        self.read('nas', own=1)
        self.assertEqual(sfnetwork.observe(self.conn), ['ctl'])
        self.assertEqual([(m['host'], m['state']) for m in sfnetwork.status(self.conn)['members']], [('ctl', 'ok'), ('nas', 'key refused')])

    def test_a_peer_nobody_asked_for_is_reported_and_revoked_by_the_plan(self):
        self.up()
        self.read('nas', 2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32'], 77: ['0.0.0.0/0']})
        self.assertEqual([k for k in sfnetwork.problems(self.conn)], ['sfnet-peer:nas'])
        self.assertIn(('nas', 'wg-peer', 'absent', key(77)), self.kinds())

    def test_a_host_that_leaves_comes_off_every_member_and_loses_its_interface(self):
        self.up()
        self.read('ctl', 1, {2: ['10.203.0.2/32'], 3: ['10.203.0.3/32']})
        self.read('nas', 2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})
        self.read('pi', 3, {1: ['10.203.0.1/32'], 2: ['10.203.0.2/32']})
        sfnetwork.leave(self.conn, 'PI', 'gabe')
        self.assertEqual(sorted(self.kinds()), sorted([('ctl', 'wg-peer', 'absent', key(3)), ('nas', 'wg-peer', 'absent', key(3)), ('pi', 'wg-interface', 'absent', '10.203.0.3/20')]))
        changes.normalize({'name': 'p', 'tasks': sfnetwork.tasks(self.conn)})
        back = sfnetwork.join(self.conn, 'pi', 'gabe')
        self.assertEqual((back['address'], back['state']), ('10.203.0.4', 'pending'), 'a new address: the old one may still be written somewhere')
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.leave(self.conn, 'nobody', 'gabe')

    def test_an_interface_of_the_same_host_under_another_name_is_not_ours(self):
        sfnetwork.create(self.conn, 'gabe')
        sfnetwork.join(self.conn, 'nas', 'gabe')
        self.read('nas', others=[{'name': 'wg0', 'public_key': key(50), 'peers': []}])
        self.assertEqual((sfnetwork.observe(self.conn), self.kinds()), ([], [('nas', 'wg-interface', 'present', '10.203.0.1/20')]))

    def test_the_routes(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        self.assertEqual(viewer.get('/api/sfnet').get_json(), {'network': None, 'members': []})
        for path, body in (('/api/sfnet', {}), ('/api/sfnet/members', {'host': 'nas'}), ('/api/sfnet/members/remove', {'host': 'nas'}), ('/api/sfnet/plan', {})):
            self.assertEqual(viewer.post(path, json=body).status_code, 403, path)
        self.assertEqual(admin.post('/api/reauth', json={'password': PW}).status_code, 200)
        made = admin.post('/api/sfnet', json={'topology': 'hub'})
        self.assertEqual((made.status_code, made.get_json()['network']), (200, {'range': '10.203.0.0/20', 'port': 51903, 'topology': 'hub'}))
        self.assertEqual(admin.post('/api/sfnet', json={}).status_code, 400)
        self.assertEqual(admin.post('/api/sfnet/members', json={'host': 'never-scanned'}).status_code, 400)
        joined = admin.post('/api/sfnet/members', json={'host': 'nas', 'hub': True})
        self.assertEqual((joined.status_code, joined.get_json()['address'], joined.get_json()['hub']), (200, '10.203.0.1', True))
        planned = admin.post('/api/sfnet/plan', json={}).get_json()
        self.assertEqual(planned['tasks'], 1)
        self.assertEqual(admin.post('/api/sfnet/members/remove', json={'host': 'nas'}).get_json()['state'], 'revoked')
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'sfnet.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['sfnet.create', 'sfnet.join', 'sfnet.plan', 'sfnet.leave'])


class InterfaceStep(unittest.TestCase):
    """t_wg_interface itself, with stand-ins for wg, wg-quick, ip and systemctl that keep what they are told in a folder."""
    SECRET = 'cHJpdmF0ZS1rZXktbWFkZS1vbi10aGUtaG9zdC1uZXZlci1zaG93bg='

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.etc, self.bin, self.state = self.tmp / 'etc', self.tmp / 'bin', self.tmp / 'state'
        self.bin.mkdir()
        self.state.mkdir()
        s = self.state
        scripts = {
            'wg': f'''case "$1 $3" in
  "genkey ") echo {self.SECRET};;
  "show public-key") [ -e {s}/$2.up ] && echo PUBLIC-OF-$2;;
  "show listen-port") cat {s}/$2.port;;
  *) exit 1;;
esac''',
            'wg-quick': f'''echo "wg-quick $*" >> {s}/calls
conf=$SF_WG_DIR/$2.conf
case $1 in
  up) [ -e "$conf" ] || exit 1; sed -n 's/^Address = //p' "$conf" > {s}/$2.addr; sed -n 's/^ListenPort = //p' "$conf" > {s}/$2.port; : > {s}/$2.up;;
  down) rm -f {s}/$2.up {s}/$2.addr {s}/$2.port;;
esac''',
            'ip': f'[ -e {s}/$6.addr ] && echo "7: $6    inet $(cat {s}/$6.addr) scope global $6"',
            'systemctl': f'''echo "systemctl $*" >> {s}/calls
unit=${{@: -1}}; iface=${{unit#wg-quick@}}
case "$1" in enable) wg-quick up "$iface";; disable|stop) wg-quick down "$iface";; esac''',
        }
        for name, body in scripts.items():
            (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
            (self.bin / name).chmod(0o755)
        self.env = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_WG_DIR': str(self.etc)}

    def run_step(self, apply=True, **params):
        plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'wg-interface', 'host': 'nas', 'params': {'iface': 'sf0', 'address': '10.203.0.2/20', 'port': '51903'} | params}]})
        p = plan['tasks'][0]['params']
        body = re.search(r'^t_wg_interface\(\) \{.*?^\}$', steps_infra.BASH, re.M | re.S)[0]
        call = ' '.join(shlex.quote(str(p.get(a) or '')) for a in changes.ARGS['wg-interface'])
        act = 'act() { echo "changed: $*"; }' if apply else 'act() { echo "would: $*"; return 1; }'
        prelude = f'ok() {{ echo "ok: $*"; }}; conflict() {{ echo "conflict: $*"; }}; info() {{ echo "info: $*"; }}; {act}; try() {{ "$@"; }}; durable() {{ :; }}\n'
        ran = subprocess.run(['bash', '-c', prelude + body + f'\nt_wg_interface {call}\n'], capture_output=True, text=True, env=self.env)
        self.assertEqual(ran.stderr, '')
        self.assertNotIn(self.SECRET, ran.stdout, 'the private key is never printed')
        return ran.stdout

    def calls(self):
        f = self.state / 'calls'
        return f.read_text().splitlines() if f.exists() else []

    def test_it_makes_the_interface_with_a_key_only_root_on_the_host_can_read(self):
        out = self.run_step()
        self.assertIn('changed: make sf0 at 10.203.0.2/20 on port 51903, with a key pair made on this host', out)
        self.assertIn('ok: sf0 is up at 10.203.0.2/20 on port 51903, public key PUBLIC-OF-sf0', out)
        self.assertEqual((self.etc / 'sf0.key').read_text().strip(), self.SECRET)
        for name in ('sf0.key', 'sf0.conf'):
            self.assertEqual(stat.S_IMODE((self.etc / name).stat().st_mode), 0o600, name)
        self.assertEqual(stat.S_IMODE(self.etc.stat().st_mode), 0o700)
        conf = (self.etc / 'sf0.conf').read_text()
        self.assertNotIn(self.SECRET, conf, 'the key is in its own file, named by the configuration')
        self.assertIn(f'PostUp = wg set %i private-key {self.etc}/sf0.key', conf)
        again = self.run_step()
        self.assertEqual(again.strip(), 'ok: sf0 is up at 10.203.0.2/20 on port 51903, public key PUBLIC-OF-sf0')
        self.assertEqual(len([c for c in self.calls() if c.startswith('wg-quick up')]), 1, 'a second run changes nothing')

    def test_a_report_changes_nothing(self):
        out = self.run_step(apply=False)
        self.assertIn('would: make sf0', out)
        self.assertEqual((self.etc.exists(), self.calls()), (False, []))

    def test_an_interface_storageforge_did_not_make_is_left_alone(self):
        self.etc.mkdir()
        (self.etc / 'sf0.conf').write_text('[Interface]\nPrivateKey = theirs\n')
        for params in ({}, {'state': 'absent'}):
            out = self.run_step(**params)
            self.assertIn('conflict: sf0 is on this host and StorageForge did not make it', out)
        self.assertEqual(((self.etc / 'sf0.conf').read_text(), self.calls()), ('[Interface]\nPrivateKey = theirs\n', []))
        (self.etc / 'sf0.conf').unlink()
        (self.state / 'sf0.up').write_text('')
        self.assertIn('did not make it', self.run_step(), 'up, with no file of ours: someone made it by hand')

    def test_a_new_address_moves_it_and_keeps_the_key(self):
        self.run_step()
        out = self.run_step(address='10.203.0.9/20', port='51999')
        self.assertIn('changed: move sf0 from 10.203.0.2/20 port 51903 to 10.203.0.9/20 port 51999', out)
        self.assertIn('ok: sf0 is up at 10.203.0.9/20 on port 51999', out)
        self.assertEqual((self.etc / 'sf0.key').read_text().strip(), self.SECRET, 'the same key: its peers still know this host')

    def test_removing_takes_the_key_with_it(self):
        self.run_step()
        self.assertIn('ok: sf0 is gone, and its key with it', self.run_step(state='absent'))
        self.assertEqual(sorted(p.name for p in self.etc.iterdir()), [])
        self.assertIn('ok: there is no sf0', self.run_step(state='absent'))

    def test_a_host_without_the_tools_is_a_conflict_and_nothing_is_written(self):
        (self.bin / 'wg-quick').unlink()
        only = self.tmp / 'only'
        only.mkdir()
        for tool in ('bash', 'grep', 'awk', 'cat'):
            (only / tool).symlink_to(shutil.which(tool))
        (only / 'wg').symlink_to(self.bin / 'wg')
        self.env['PATH'] = str(only)
        self.assertIn('conflict: this host has no wg-quick', self.run_step())
        (only / 'wg').unlink()
        self.assertIn('conflict: this host has no wg command', self.run_step())
        self.assertFalse(self.etc.exists())

    def test_what_the_check_refuses_before_any_script_is_written(self):
        said = []
        for address, port, want in (('10.203.0.2', '51903', 'with its range'), ('10.203.0.0/20', '51903', 'with its range'), ('100.64.0.2/20', '51903', 'private'), ('8.8.8.8/24', '51903', 'private'),
                                    ('10.203.0.2/20', '0', 'one port'), ('10.203.0.2/20', '1:9', 'one port')):
            said.clear()
            steps_infra._check_wg_interface(None, None, {'name': 'nas'}, {'iface': 'sf0', 'address': address, 'port': port, 'state': 'absent'}, lambda level, text: said.append((level, text)))
            with self.subTest(address=address, port=port):
                self.assertTrue(any(level == 'crit' and want in text for level, text in said), said)


if __name__ == '__main__':
    unittest.main()
