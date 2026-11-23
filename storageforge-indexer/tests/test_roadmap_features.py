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
