"""The agent's disks plugin from the controller's side (roadmap section 11.4 and PF-04; agentdisks.py): a disk's health as the plugin
sends it, read with the same code the SSH collector's report is read with, compared with that report, and its errors as they come.

What is real: the database on SQLite and PostgreSQL, health._smart, agentplugins.take and the notification center's view. The readings
are the plugin's form (agent/src/smart.rs, whose own tests decode the disk's bytes); the plugin itself runs in agent/tests/official.rs."""
import json
import time
import unittest

import test_agent_plugins
from storageforge_index import agentdisks, agentplugins, agentwatch, health


def ata(reallocated=0, pending=0, passed=True):
    return {'device': {'protocol': 'ATA'}, 'smart_status': {'passed': passed}, 'temperature': {'current': 36}, 'power_on_time': {'hours': 12345},
            'ata_smart_attributes': {'revision': 16, 'table': [{'id': 5, 'name': 'Reallocated_Sector_Ct', 'value': 100, 'worst': 100, 'raw': {'value': reallocated}},
                                                               {'id': 197, 'name': 'Current_Pending_Sector', 'value': 100, 'worst': 100, 'raw': {'value': pending}}]}}


def nvme(media_errors=0, warning=0):
    return {'device': {'protocol': 'NVMe'}, 'smart_status': {'passed': warning == 0}, 'temperature': {'current': 40}, 'power_on_time': {'hours': 10},
            'nvme_smart_health_information_log': {'critical_warning': warning, 'media_errors': media_errors, 'percentage_used': 3}}


class Disks(test_agent_plugins.Base):
    def take(self):
        return agentplugins.take(self.db)

    def test_a_disks_health_is_read_as_the_collectors_and_labelled_as_the_agents(self):
        self.record('disks', 'smart', {'disks': [{'dev': 'sda', 'kind': 'ata', 'model': 'WDC', 'smartctl': ata(reallocated=8)},
                                                 {'dev': 'nvme0n1', 'kind': 'nvme', 'smartctl': nvme()},
                                                 {'dev': 'sdb', 'kind': 'ata', 'error': 'the disk answered no SMART data'},
                                                 {'dev': '../etc', 'smartctl': ata()}, 'not a disk']})
        self.assertEqual(self.take(), {'disks': 1})
        got = {d['dev']: d for d in agentdisks.disks(self.conn, 'nas')}
        self.assertEqual(sorted(got), ['nvme0n1', 'sda', 'sdb'], 'a name that is not a disk is dropped')
        self.assertEqual(got['sda']['health']['smart'], 'warn')
        # the same reading through the collector's own parser: the two paths agree word for word
        self.assertEqual({k: v for k, v in got['sda']['health'].items() if k in health._smart(json.dumps(ata(reallocated=8)))},
                         health._smart(json.dumps(ata(reallocated=8))))
        self.assertEqual((got['sda']['label'], got['sdb']['error']), ('reported by agent', 'the disk answered no SMART data'))
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM agent_records WHERE plugin = 'disks'"), 0, 'taken once')
        # no scan reads these disks: the agent's word is the notification, labelled as its claim
        p = agentwatch.problems(self.conn)
        self.assertIn('agent-smart:nas:sda', p)
        self.assertIn('reported by agent', p['agent-smart:nas:sda'][3])
        self.assertNotIn('agent-smart:nas:nvme0n1', p)

    def test_the_agent_and_the_collector_are_compared(self):
        report = {'at': int(time.time()), 'disks': {'sda': {'smart': 'ok', 'reallocated': 0, 'pending': 0, 'uncorrectable': 0}}, 'btrfs': {}}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'health': report})})
        self.record('disks', 'smart', {'disks': [{'dev': 'sda', 'smartctl': ata(passed=False)}]})
        self.take()
        p = agentwatch.problems(self.conn)
        self.assertIn('agent-disk-disagree:nas:sda', p)
        self.assertNotIn('agent-smart:nas:sda', p, 'where a scan reads the disk, its alert is the scan\'s and the agent is compared with it')
        self.record('disks', 'smart', {'disks': [{'dev': 'sda', 'smartctl': ata()}]})
        self.take()
        self.assertNotIn('agent-disk-disagree:nas:sda', agentwatch.problems(self.conn))

    def test_errors_are_news_when_they_grow_and_kernel_lines_are_kept_by_disk(self):
        self.record('disks', 'errors', {'ioerr': {'sda': 4}, 'md': {'md0/sda1': 0}, 'lines': [], 'first': True})
        self.take()
        self.assertFalse([k for k in agentwatch.problems(self.conn) if k.startswith('agent-disk-errors')], 'what was counted before the agent started is not news')
        self.record('disks', 'errors', {'ioerr': {'sda': 6}, 'md': {'md0/sda1': 1}, 'lines': [
            {'at': int(time.time() * 1e6), 'dev': 'sda1', 'message': 'blk_update_request: I/O error, dev sda1, sector 2048'},
            {'at': 'later', 'dev': '../x', 'message': 'I/O error somewhere'}]})
        self.take()
        p = agentwatch.problems(self.conn)
        self.assertIn('the kernel counts 6 failed commands', p['agent-disk-errors:nas:sda'][3])
        self.assertIn('I/O error, dev sda1', p['agent-disk-errors:nas:sda'][3], 'a partition\'s line is its disk\'s')
        self.assertIn('agent-disk-errors:nas:md:md0/sda1', p)
        self.assertIn('agent-disk-errors:nas:', p, 'a line naming no disk is kept too')
        # a day later it is history
        later = time.time() + agentdisks.ERRORS_RECENT_SECS + 5
        self.assertFalse([k for k in agentdisks.problems(self.conn, later) if k.startswith('agent-disk-errors')])

    def test_a_reading_is_the_senders_whatever_it_names(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('web', '10.0.0.4', 22)")
        self.record('disks', 'smart', {'host': 'web', 'disks': [{'dev': 'sda', 'smartctl': ata(), 'host': 'web'}]})
        self.take()
        self.assertEqual(self.conn.all('SELECT host FROM agent_disks'), [('nas',)])


if __name__ == '__main__':
    unittest.main()
