"""Toolbox adapters (tbadapters.py) on the infrastructure reading: the sections they add run as Bash against stand-ins and are read back,
each adapter's detect, status, actions, links and metrics, an action staged as ordinary plan steps (the WireGuard peer manager reuses
wg-peer and wg-rotate, Cockpit unit-state), a tool read through a platform connection, and an adapter that fails: it says "status
unavailable", and the reading, the measurement and the other tools go on."""
import json
import shutil
import subprocess
import time
import unittest
from unittest import mock

try:
    from test_toolbox import CUSTOM, Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import CUSTOM, Base
from storageforge_index import changes, inframeasure, security, tbadapters, toolbox

KEY_A, KEY_B = 'A' * 43 + '=', 'B' * 43 + '='


def reading(**more):
    now = int(time.time())
    return {'tools': ['wg', 'podman'], 'listeners': [],
            'access': {'wireguard': [{'name': 'wg0', 'public_key': KEY_A, 'listen_port': 51820,
                                      'peers': [{'public_key': KEY_B, 'endpoint': '10.0.0.9:51820', 'allowed_ips': ['10.8.0.2/32'], 'handshake': now - 20},
                                                {'public_key': 'C' * 43 + '=', 'endpoint': None, 'allowed_ips': ['10.8.0.3/32'], 'handshake': None}]}]},
            'podman_rootless': [{'user': 'sf-uptime-kuma', 'containers': [{'name': 'sf-uptime-kuma', 'image': 'docker.io/louislam/uptime-kuma:2.0.2@sha256:' + '4' * 64,
                                                                           'state': 'running', 'labels': {'storageforge.tool': 'uptime-kuma'}}]}],
            'toolbox': {'cockpit': {'socket': 'active', 'enabled': 'enabled', 'service': 'inactive', 'version': '330'}, 'health': {'uptime-kuma': 200, 'cockpit': 200}},
            **more}


class Sections(unittest.TestCase):
    def test_the_sections_run_and_read_back(self):
        d = __import__('tempfile').mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, body in (('systemctl', 'case $1 in cat) exit 0 ;; is-active) [[ $2 == cockpit.socket ]] && echo active || echo inactive ;; is-enabled) echo enabled ;; esac'),
                           ('cockpit-bridge', 'printf "Version: 330\\nProtocol: 1\\n"'), ('curl', 'echo -n 200')):
            with open(f'{d}/{name}', 'w') as f:
                f.write('#!/bin/bash\n' + body + '\n')
            __import__('os').chmod(f'{d}/{name}', 0o755)
        health = tbadapters.health_body([('uptime-kuma', 'http://127.0.0.1:3001/'), ('evil', 'http://127.0.0.1:1/$(id)'), ('x;id', 'http://127.0.0.1:2/')])
        self.assertNotIn('$(id)', health)
        self.assertNotIn('x;id', health)
        script = 'sec() { printf "\\n@@%s\\n" "$1"; }\nhas() { command -v "$1" >/dev/null; }\n' + tbadapters.BODY + health
        p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env={'PATH': f'{d}:/usr/bin:/bin'}, timeout=30)
        sections = inframeasure._sections(p.stdout)
        got = tbadapters.sections_of(sections)
        self.assertEqual(got['cockpit'], {'socket': 'active', 'enabled': 'enabled', 'service': 'inactive', 'version': '330'})
        self.assertEqual(got['health'], {'uptime-kuma': 200})

    def test_the_reading_script_carries_them_and_is_valid_bash(self):
        text = inframeasure.script(tbadapters.health_body([('cockpit', 'https://127.0.0.1:9090/ping')]))
        self.assertIn('sec tb_cockpit', text)
        self.assertIn("https://127.0.0.1:9090/ping", text)
        self.assertNotIn('@TB_HEALTH@', text)
        self.assertNotIn('@TB_HEALTH@', inframeasure.script())
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        empty = inframeasure.script(tbadapters.health_body([]))          # a host with no tool installed: the section is still valid Bash
        self.assertEqual(subprocess.run(['bash', '-n'], input=empty, text=True, capture_output=True).returncode, 0)

    def test_what_a_host_prints_cannot_pass_for_more(self):
        self.assertEqual(tbadapters.read_health(['h\tcockpit\t200', 'h\t../x\t200', 'h\tkuma\tabc', 'junk']), {'cockpit': 200, 'kuma': 0})
        self.assertEqual(tbadapters.read_cockpit(['v\t1.2; rm -rf /', 's\tactive\tenabled']), {'socket': 'active', 'enabled': 'enabled'})


class Adapters(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman', 'wg'])
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure', reading())

    def test_detect_status_and_metrics(self):
        r, ctx = reading(), tbadapters.context(self.conn, 'box', reading())
        wg = tbadapters.ADAPTERS['wireguard']
        found = wg.detect(r, ctx)
        self.assertEqual(found['interfaces'], ['wg0'])
        st = wg.status(r, ctx, found)
        self.assertIn('1 of 2 peers connected', st['tiles'][0]['value'])
        self.assertEqual(wg.metrics(r, ctx), {'interfaces': 1, 'peers': 2, 'connected': 1})
        kuma = tbadapters.ADAPTERS['uptime-kuma']
        found = kuma.detect(r, ctx)
        self.assertTrue(found['managed'])
        self.assertEqual(kuma.status(r, ctx, found)['health'], 'ok')
        self.assertEqual(kuma.status(r, dict(ctx, health={'uptime-kuma': 502}), found)['health'], 'down')
        self.assertIsNone(tbadapters.ADAPTERS['cockpit'].detect({'toolbox': {}}, ctx))

    def test_refresh_fills_status_and_finds_a_staged_install(self):
        toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        got = tbadapters.refresh(self.conn, 'box', reading())
        self.assertEqual(got, {'cockpit': 'ok', 'uptime-kuma': 'ok', 'wireguard': 'ok'})
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'uptime-kuma')['status'], 'installed')
        rows = {s['tool']: s for s in tbadapters.status_rows(self.conn, 'box')}
        self.assertEqual(rows['wireguard']['metrics']['peers'], 2)
        self.assertEqual(len(rows['wireguard']['peers']), 2)
        # gone at the next reading: an install that was there is missing, and says so
        tbadapters.refresh(self.conn, 'box', reading(podman_rootless=[]))
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'uptime-kuma')['status'], 'missing')
        self.assertEqual({s['tool']: s['health'] for s in tbadapters.status_rows(self.conn, 'box')}['uptime-kuma'], 'missing')

    def test_a_failing_adapter_says_unavailable_and_blocks_nothing(self):
        with mock.patch.object(tbadapters.WireGuard, 'detect', side_effect=KeyError('boom')), mock.patch('storageforge_index.errlog.trace'):
            got = tbadapters.refresh(self.conn, 'box', reading())
        self.assertEqual(got['wireguard'], 'unavailable')
        self.assertEqual(got['cockpit'], 'ok')
        row = {s['tool']: s for s in tbadapters.status_rows(self.conn, 'box')}['wireguard']
        self.assertEqual(row['tiles'], [{'label': 'Status', 'value': 'unavailable', 'level': 'warn'}])
        self.assertIn('status unavailable', row['error'])

    def test_a_measurement_stands_when_the_toolbox_fails(self):
        out = '\n'.join(f'@@{s}' for s in inframeasure.SECTIONS)
        with mock.patch('storageforge_index.deploy.run', return_value={'status': 'ok', 'output': out}), \
                mock.patch.object(tbadapters, 'refresh', side_effect=RuntimeError('boom')), mock.patch('storageforge_index.errlog.trace'), \
                mock.patch.object(tbadapters, 'health_checks', side_effect=RuntimeError('boom')):
            got = inframeasure.measure(self.db, self.conn, 'box', 'test')
        self.assertTrue(got['ok'])

    def test_measure_reads_health_for_installs_and_refreshes(self):
        toolbox.stage(self.conn, 'box', 'cockpit', 'test')
        seen = {}

        def run(db, host, script, args, **kw):
            seen['script'] = script
            return {'status': 'ok', 'output': '\n'.join(f'@@{s}' for s in inframeasure.SECTIONS[:-2]) + '\n@@tb_cockpit\ns\tactive\tenabled\n@@tb_health\nh\tcockpit\t200\n@@end\n'}
        with mock.patch('storageforge_index.deploy.run', side_effect=run):
            self.assertTrue(inframeasure.measure(self.db, self.conn, 'box', 'test')['ok'])
        self.assertIn('https://127.0.0.1:9090/ping', seen['script'])
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'cockpit')['status'], 'installed')

    def test_peer_manager_actions_are_wg_peer_steps(self):
        st = tbadapters.read_status(self.conn, 'box', 'wireguard')
        self.assertEqual([a['id'] for a in st['actions']], ['add-peer', 'revoke-peer', 'rotate-prepare', 'rotate-switch'])
        got = tbadapters.stage_action(self.conn, 'box', 'wireguard', 'add-peer', {'iface': 'wg0', 'pubkey': KEY_B, 'allowed': '10.8.0.4/32'}, 'test')
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual(plan['tasks'][0]['type'], 'wg-peer')
        self.assertEqual(plan['tasks'][0]['params']['state'], 'present')
        got = tbadapters.stage_action(self.conn, 'box', 'wireguard', 'revoke-peer', {'iface': 'wg0', 'pubkey': KEY_B}, 'test')
        self.assertEqual(changes.get_plan(self.conn, got['plan_id'])['tasks'][0]['params']['state'], 'absent')
        with self.assertRaisesRegex(ValueError, 'Interface is one of wg0'):
            tbadapters.stage_action(self.conn, 'box', 'wireguard', 'add-peer', {'iface': 'eth0', 'pubkey': KEY_B, 'allowed': '10.8.0.4/32'}, 'test')
        with self.assertRaisesRegex(ValueError, 'is not valid'):
            tbadapters.stage_action(self.conn, 'box', 'wireguard', 'add-peer', {'iface': 'wg0', 'pubkey': 'not a key', 'allowed': '10.8.0.4/32'}, 'test')
        with self.assertRaisesRegex(ValueError, 'no actions|has no action'):
            tbadapters.stage_action(self.conn, 'box', 'uptime-kuma', 'restart', {}, 'test')

    def test_cockpit_restart_is_a_unit_state_step(self):
        got = tbadapters.stage_action(self.conn, 'box', 'cockpit', 'restart', {}, 'test')
        self.assertEqual(changes.get_plan(self.conn, got['plan_id'])['tasks'][0]['params'], {'unit': 'cockpit.service', 'state': 'restarted'})

    def test_links_follow_the_exposure(self):
        e = toolbox.find(self.conn, 'uptime-kuma')['entry']
        link = tbadapters.links(self.conn, 'box', e, None)[0]
        self.assertEqual(link['url'], 'http://127.0.0.1:3001/')
        self.assertEqual(link['tunnel'], 'ssh -L 3001:127.0.0.1:3001 box')
        toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test', exposure='management', bind='10.0.0.5')
        link = tbadapters.links(self.conn, 'box', e, toolbox.install_of(self.conn, 'box', 'uptime-kuma'))[0]
        self.assertEqual(link['url'], 'http://10.0.0.5:3001/')
        self.assertNotIn('tunnel', link)
        self.assertEqual(tbadapters.links(self.conn, 'box', toolbox.find(self.conn, 'wireguard')['entry'], None), [])

    def test_a_tool_read_through_a_platform_connection(self):
        text = CUSTOM.replace('id: whoami', 'id: portainer-ce').replace('gui:\n', 'gui:\n  panel: {level: status, api: portainer}\n')
        self.assertEqual(toolbox.load_entry(text)[1], [])
        toolbox.save_custom(self.conn, text, None, 'test')
        st = tbadapters.api_status(self.conn, 'box', 'portainer')
        self.assertIn('Platform connections', st['tiles'][0]['value'])
        self.assertEqual(st['guide'], '/api/keys/platforms/guide/portainer')
        self.conn.execute("""INSERT INTO platform_connections (kind, name, base_url, host, token_id, secret_name, created_at, read_at, read_ok)
                             VALUES ('portainer', 'pt', 'https://box:9443', 'box', '1', 'platform-pt', 1, 2, 1)""")
        cid = self.conn.scalar("SELECT conn_id FROM platform_connections WHERE name = 'pt'")
        self.conn.execute("INSERT INTO platform_objects (conn_id, kind, ref, data_json, read_at) VALUES (:c, 'stack', 's1', '{}', 2)", {'c': cid})
        st = tbadapters.api_status(self.conn, 'box', 'portainer')
        self.assertEqual(st['connection'], 'pt')
        self.assertIn({'label': 'stack', 'value': '1', 'level': 'ok'}, st['tiles'])
        got = tbadapters.refresh(self.conn, 'box', reading())
        self.assertIn('portainer-ce', got)
        self.assertNotIn('platform-pt', json.dumps(tbadapters.status_rows(self.conn, 'box')))


if __name__ == '__main__':
    unittest.main()
