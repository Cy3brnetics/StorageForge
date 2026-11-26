"""Proxmox detection and the node read: storages, ISOs and templates, and which runtimes a host can run."""
import time
import unittest

try:
    from test_tasks import Fleet
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_tasks import Fleet
from storageforge_index import pvenode, security, workloads

LINES = [
    's\tlocal\tdir\tactive\t98497780\t12345678',
    's\tlocal-lvm\tlvmthin\tactive\t365768704\t0',
    't\tlocal\tiso,vztmpl,backup',
    't\tlocal-lvm\timages,rootdir',
    'i\tlocal:iso/debian-13.iso\t786432000',
    'v\tlocal:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst\t126000000',
]


class Node(unittest.TestCase):
    def test_parse_node_reads_storages_isos_and_templates(self):
        n = pvenode.parse_node(LINES)
        self.assertEqual([(s['name'], s['type'], s['active'], s['content']) for s in n['storages']],
                         [('local', 'dir', True, ['iso', 'vztmpl', 'backup']), ('local-lvm', 'lvmthin', True, ['images', 'rootdir'])])
        self.assertEqual(n['storages'][0]['total_kib'], 98497780)
        self.assertEqual(n['storages'][1]['used_kib'], 0)
        self.assertEqual(n['isos'], [{'storage': 'local', 'volid': 'local:iso/debian-13.iso', 'size': 786432000}])
        self.assertEqual(n['templates'], [{'storage': 'local', 'volid': 'local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst', 'size': 126000000}])

    def test_parse_node_drops_what_it_cannot_read(self):
        n = pvenode.parse_node(['garbage', '', 's\tonly-two', 's\tx\tdir\tdisabled\t-\t-', 'i\tnovolid\t5'])
        self.assertEqual(n['storages'], [{'name': 'x', 'type': 'dir', 'active': False, 'content': [], 'total_kib': None, 'used_kib': None}])
        self.assertEqual((n['isos'], n['templates']), ([], []))

    def test_is_proxmox(self):
        self.assertTrue(pvenode.is_proxmox({'wl_units': {'markers': ['pve']}}))
        self.assertTrue(pvenode.is_proxmox({'tools': ['qm']}))
        self.assertTrue(pvenode.is_proxmox({'tools': ['pct']}))
        self.assertTrue(pvenode.is_proxmox({'platform': 'proxmox 8.2'}))
        self.assertFalse(pvenode.is_proxmox({'tools': ['docker'], 'wl_units': {'markers': ['puppet']}}))
        self.assertFalse(pvenode.is_proxmox(None))


class Listing(Fleet):
    def test_listing_says_proxmox_and_runtimes(self):
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct', 'lxc-ls']})
        by = {h['host']: h for h in workloads.listing(self.conn)['hosts']}
        self.assertIs(by['nas']['proxmox'], True)
        self.assertIn('proxmox', by['nas']['runtimes'])
        self.assertIn('lxc', by['nas']['runtimes'])
        self.assertIs(by['pc']['proxmox'], False)
        self.assertEqual(by['pc']['runtimes'], [])


if __name__ == '__main__':
    unittest.main()
