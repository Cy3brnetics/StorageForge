"""Block devices that lsblk calls disks but that live on other storage: a Proxmox VE node's ZFS volumes (zd*, one per VM disk) and
Ceph RBD images (rbd*). Counted as disks, they added every VM's disk to the host's raw capacity and every guest's own partitions to its
usable space."""
import unittest

from storageforge_index import osoffer
from storageforge_index.payloads import node_from_lsblk

TB = 10 ** 12


def lsblk():
    return {'blockdevices': [
        {'name': 'sda', 'type': 'disk', 'size': 4 * TB, 'rota': True, 'tran': 'sata', 'pttype': 'gpt', 'children': [
            {'name': 'sda1', 'type': 'part', 'size': 4 * TB, 'fstype': 'zfs_member', 'label': 'rpool', 'start': 2048}]},
        {'name': 'zd0', 'type': 'disk', 'size': 32 * 10 ** 9, 'rota': False, 'pttype': 'gpt', 'children': [
            {'name': 'zd0p1', 'type': 'part', 'size': 31 * 10 ** 9, 'fstype': 'ext4', 'start': 2048}]},
        {'name': 'zd16', 'type': 'disk', 'size': 500 * 10 ** 9, 'rota': False, 'children': [
            {'name': 'zd16p1', 'type': 'part', 'size': 499 * 10 ** 9, 'fstype': 'xfs', 'start': 2048}]},
        {'name': 'rbd0', 'type': 'disk', 'size': 100 * 10 ** 9, 'rota': False, 'fstype': 'ext4'},
    ]}


class VirtualDisks(unittest.TestCase):
    def test_zfs_volumes_and_rbd_images_are_not_disks_of_the_host(self):
        node = node_from_lsblk(lsblk(), 'pve101')
        self.assertEqual([d['dev'] for d in node['disks']], ['sda'])

    def test_raw_capacity_is_the_physical_disks_only(self):
        node = node_from_lsblk(lsblk(), 'pve101')
        self.assertEqual(sum(d['size'] for d in node['disks']), 4 * TB)

    def test_os_install_never_offers_a_vm_disk(self):
        data = lsblk()
        data['blockdevices'].append({'name': 'zd32', 'path': '/dev/zd32', 'type': 'disk', 'size': 64 * 10 ** 9})   # blank
        self.assertEqual([d['path'] for d in osoffer.disks({'lsblk': data})], ['/dev/sda'])


if __name__ == '__main__':
    unittest.main()
