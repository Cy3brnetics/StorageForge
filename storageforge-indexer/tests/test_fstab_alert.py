"""A host whose /etc/fstab has a line findmnt --verify rejects (an unplugged USB disk's line, on cachyos-x8664) is an alert: it can
stop the host at boot, and before 2026-11-26 it made every deploy that edits fstab fail. The scan reads findmnt --verify, and the alert
names each line, why, and how to fix it."""
import json
import tempfile
import unittest

from storageforge_index import alerts, hostconfig, remote
from storageforge_index.db import Database

VERIFY = """/mnt/UsbSSD
   [E] unreachable on boot required source: UUID=4419
/mnt/ssd/Data
   [W] recommended root FS passno is 1 (current is 0)
/mnt/old
   [E] unreachable on boot required target: No such file or directory
/mnt/net
   [E] unreachable source: srv:/x (nofail)

0 parse errors, 3 errors, 1 warning
"""


class Parse(unittest.TestCase):
    def test_errors_are_read_with_their_lines_and_warnings_left_out(self):
        self.assertEqual(hostconfig.parse_fstab_verify(VERIFY), [
            {'target': '/mnt/UsbSSD', 'error': 'unreachable on boot required source: UUID=4419', 'boot': True},
            {'target': '/mnt/old', 'error': 'unreachable on boot required target: No such file or directory', 'boot': True},
            {'target': '/mnt/net', 'error': 'unreachable source: srv:/x (nofail)', 'boot': False}])

    def test_a_clean_fstab_and_nonsense_give_nothing(self):
        self.assertEqual(hostconfig.parse_fstab_verify('Success, no errors or warnings detected\n'), [])
        self.assertEqual(hostconfig.parse_fstab_verify('   [E] orphan with no target\n\x00garbage'), [])

    def test_the_scan_reads_it(self):
        self.assertIn("echo '@@fstabverify'", remote.INVENTORY_SCRIPT)
        self.assertIn('fstabverify', remote.SECTIONS)


class Alert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def host(self, name, verify):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES (:h, '10.0.0.5', :i)",
                          {'h': name, 'i': json.dumps({'fstab_verify': verify})})

    def test_a_line_that_stops_boot_is_critical_and_says_how_to_fix_it(self):
        self.host('cachyos', VERIFY)
        found = alerts.scan_problems(self.conn)
        kind, ref, title, detail, level = found['fstab:cachyos']
        self.assertEqual((kind, ref, level), ('fstab', 'cachyos', 'crit'))
        self.assertIn('3 lines', title)
        self.assertIn('/mnt/UsbSSD: unreachable on boot required source: UUID=4419', detail)
        self.assertIn('Unmount', detail)
        self.assertIn('nofail', detail)

    def test_only_nofail_problems_is_a_warning(self):
        self.host('nas', '/mnt/net\n   [E] unreachable source: srv:/x (nofail)\n')
        self.assertEqual(alerts.scan_problems(self.conn)['fstab:nas'][4], 'warn')

    def test_a_clean_or_unread_fstab_gives_no_alert(self):
        self.host('a', 'Success, no errors or warnings detected\n')
        self.host('b', None)
        self.assertFalse([k for k in alerts.scan_problems(self.conn) if k.startswith('fstab:')])


if __name__ == '__main__':
    unittest.main()
