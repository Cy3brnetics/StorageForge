"""Regressions for roadmap features that cross parser, API or CLI boundaries."""
import json
import os
import unittest
from unittest.mock import Mock, patch

from storageforge_index import accessproxies, alerts, apipve, cli, exposure, netconsole


class RoadmapFeatures(unittest.TestCase):
    def test_openvpn_alerts_without_an_https_certificate(self):
        conn = Mock()
        pki = {'crl': {'next': '2026-11-20T00:00:00Z'},
               'certificates': [{'name': 'client', 'expires': '2026-12-01T00:00:00Z'}]}
        reading = {'access': {'overlays': [{'network': 'openvpn', 'pki': pki}]}}
        conn.all.return_value = [('nas', json.dumps(reading))]
        with (patch.dict(os.environ, {'STORAGEFORGE_REPORT_CA_FILE': ''}),
              patch.object(alerts.time, 'time', return_value=1795392000)):
            self.assertEqual(set(alerts.openvpn_cert_problems(conn)), {'openvpn-crl-ended:nas', 'openvpn-cert-ending:nas'})

    def test_public_pomerium_route_uses_parsed_upstream_and_runtime_evidence(self):
        proxy = accessproxies.pomerium("""
routes:
  - from: https://public.example.com
    to: http://127.0.0.1:8080
    allow_public_unauthenticated_access: true
  - from: https://private.example.com
    to: http://127.0.0.1:8081
    allow_any_authenticated_user: true
""")
        access = {'proxies': [proxy]}
        item, = exposure.tunnel_items({'access': access})
        self.assertEqual((item['target_host'], item['target_port'], item['level']), ('127.0.0.1', 8080, 'unknown'))
        access['units'] = ['pomerium.service']
        item, = exposure.tunnel_items({'access': access})
        self.assertEqual(item['level'], 'any')

    def test_plain_netconsole_priority_prefix(self):
        lines = netconsole.parse_packet(b'<3>error message here\n<0>panic here\nplain info line\n', 100.0)
        self.assertEqual([(line['priority'], line['message']) for line in lines],
                         [(3, 'error message here'), (0, 'panic here'), (6, 'plain info line')])

    def test_proxmox_ceph_health_reaches_alerts(self):
        raw = json.dumps({'data': {'health': {'status': 'HEALTH_WARN'},
                                   'osdmap': {'num_osds': 6, 'num_up_osds': 5, 'num_in_osds': 5}}})
        ceph = {'kind': 'ceph', 'ref': 'status', **apipve.parse_ceph_status(raw)}
        found = apipve.problems(None, {'name': 'pve', 'host': 'nas'}, [ceph])
        self.assertEqual(found['api-pve-ceph:pve'][3], 'OSDs: 5/6 up')

    def test_copies_subcommand_dispatches(self):
        args = cli.build_parser().parse_args(['copies', 'sync', 'nas:/source', 'pi:/target'])
        conn = Mock()
        with (patch.object(cli, 'open_db', return_value=(None, conn)),
              patch('storageforge_index.copies.prepare_sync', return_value={'plan': 3, 'name': 'Mirror'}) as prepare,
              patch('builtins.print')):
            self.assertEqual(args.fn(args), 0)
        prepare.assert_called_once_with(conn, {'host': 'nas', 'path': '/source'}, {'host': 'pi', 'path': '/target'},
                                        'cli', delete=False, schedule='daily', keep_replaced=False)
        conn.close.assert_called_once()

    def test_wireguard_peer_config_and_qr_svg(self):
        from storageforge_index import tbadapters
        reading = {
            'tools': ['wg'],
            'access': {'wireguard': [{
                'name': 'wg0', 'public_key': 'A' * 43 + '=', 'listen_port': 51820,
                'peers': [{'public_key': 'B' * 43 + '=', 'endpoint': '10.0.0.2:51820', 'allowed_ips': ['10.8.0.2/32'], 'handshake': 1000}]
            }]}
        }
        wg = tbadapters.ADAPTERS['wireguard']
        found = wg.detect(reading, {'host': 'gw-01', 'now': 1010})
        st = wg.status(reading, {'host': 'gw-01', 'now': 1010}, found)
        self.assertEqual(len(st['peers']), 1)
        peer = st['peers'][0]
        self.assertIn('[Interface]', peer['config'])
        self.assertIn('PublicKey = ' + 'A' * 43 + '=', peer['config'])
        self.assertIn('Endpoint = gw-01:51820', peer['config'])
        self.assertTrue(peer['qr_svg'].startswith('<svg xmlns="http://www.w3.org/2000/svg"'))
        self.assertIn('<rect ', peer['qr_svg'])

    def test_cve_delta_on_updates(self):
        from storageforge_index import toolbox
        old_scan = {
            'image': 'docker.io/louislam/uptime-kuma:2.0.1',
            'scanner': 'trivy',
            'scanned_at': 1000,
            'counts': {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 1, 'LOW': 0, 'UNKNOWN': 0},
            'fixable': {'CRITICAL': 2, 'HIGH': 1, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0},
            'findings': [
                {'id': 'CVE-2026-0001', 'package': 'openssl', 'installed': '3.0.1', 'fixed': '3.0.2', 'severity': 'CRITICAL'},
                {'id': 'CVE-2026-0002', 'package': 'curl', 'installed': '8.0.0', 'fixed': '8.0.1', 'severity': 'CRITICAL'},
                {'id': 'CVE-2026-0003', 'package': 'zlib', 'installed': '1.2', 'fixed': '1.3', 'severity': 'HIGH'},
            ],
        }
        new_scan = {
            'image': 'docker.io/louislam/uptime-kuma:2.0.2',
            'scanner': 'trivy',
            'scanned_at': 2000,
            'counts': {'CRITICAL': 0, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0, 'UNKNOWN': 0},
            'fixable': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0},
            'findings': [
                {'id': 'CVE-2026-0003', 'package': 'zlib', 'installed': '1.2', 'fixed': '1.3', 'severity': 'HIGH'},
                {'id': 'CVE-2026-0099', 'package': 'libc', 'installed': '2.38', 'fixed': '', 'severity': 'HIGH'},
            ],
        }
        delta = toolbox.cve_delta(old_scan, new_scan)
        self.assertEqual(delta['fixed'], ['CVE-2026-0001', 'CVE-2026-0002'])
        self.assertEqual(delta['introduced'], ['CVE-2026-0099'])
        self.assertEqual(delta['delta']['CRITICAL'], -2)
        self.assertEqual(delta['delta']['HIGH'], -1)

    def test_sfnet_ula_ipv6_and_mirror_pull_script(self):
        from storageforge_index import sfnet
        net = sfnet.new(range6=True)
        self.assertEqual(net['range6'], 'fd53:466e:7400::/64')
        m1 = sfnet.join(net, 'ctl', '10.0.0.1', True)
        m2 = sfnet.join(net, 'nas', '10.0.0.2', False)
        self.assertEqual(m1['address6'], 'fd53:466e:7400::1')
        self.assertEqual(m2['address6'], 'fd53:466e:7400::2')
        sfnet.set_key(net, 'ctl', 'A' * 43 + '=')
        sfnet.set_key(net, 'nas', 'B' * 43 + '=')
        peers = sfnet.desired_peers(net, 'nas')
        self.assertEqual(peers[0]['allowed'], ['10.203.0.1/32', 'fd53:466e:7400::1/128'])
        script = sfnet.mirror_pull_script(['https://sf.example.com/api/sfnet/directory'], ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest'])
        self.assertIn('ssh-keygen', script)
        self.assertIn('storageforge-sfnet-directory', script)

    def test_openvpn_profile_strongswan_template_and_proxy_targets(self):
        from storageforge_index import overlays
        ovpn = overlays.openvpn_client_profile('vpn.example.com', '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----')
        self.assertIn('remote vpn.example.com 1194', ovpn)
        self.assertIn('<ca>', ovpn)
        swan = overlays.strongswan_site_template('hq-branch', '198.51.100.1', '203.0.113.2', '10.10.0.0/24', '10.20.0.0/24')
        self.assertIn('local_ts = 10.10.0.0/24', swan)
        self.assertIn('remote_ts = 10.20.0.0/24', swan)
        conn = Mock()
        conn.all.return_value = [('nas-01', '10.0.0.10', 22, 'Debian 13')]
        targets = accessproxies.inventory_targets(conn)
        self.assertEqual(targets[0]['teleport_node']['addr'], '10.0.0.10:22')
        self.assertEqual(targets[0]['boundary_target']['address'], '10.0.0.10')

    def test_agent_toolbox_status_and_ransomware_burst(self):
        from storageforge_index import agentfiles, agentplugins
        conn = Mock()
        with patch('storageforge_index.tbadapters.refresh', return_value=[{'tool': 'ntfy', 'state': 'active'}]) as ref:
            self.assertEqual(agentplugins.take_toolbox_status(conn, 'nas-01', {'readings': {'units': ['ntfy.service']}}, 1000), 1)
            ref.assert_called_once()
        conn.all.return_value = [(30, 'python3', 'alice', 55, 1800)]
        with patch.object(agentfiles, 'settings', return_value=agentfiles.DEFAULTS):
            signs = agentfiles.ransomware_signs(conn, 'nas-01', now=1810)
        self.assertEqual(len(signs), 1)
        self.assertEqual(signs[0]['count'], 55)


if __name__ == '__main__':
    unittest.main()
