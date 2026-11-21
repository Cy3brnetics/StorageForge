"""netconsole and pstore (roadmap 3 phase 5): kernel messages over UDP to a receiver on a real socket, taken only from a known address and
port and held to a rate; the plan step that sets netconsole up, its Bash run for real against stand-ins for ip and modprobe in a
directory that plays the host's /etc and /sys; and the last panic read from pstore by the scan's own script, run for real on files."""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import changes, hostlogs, logrules, netconsole, pstore, server, steps_netconsole, users
from storageforge_index.db import Database

PW = 'correct horse battery staple'


class Packets(unittest.TestCase):
    def test_the_extended_format_gives_each_line_its_level(self):
        lines = netconsole.parse_packet(b'0,1234,567890123,-;Kernel panic - not syncing: Fatal exception\n SUBSYSTEM=cpu\n DEVICE=c\n', 100.0)
        self.assertEqual([(x['priority'], x['message'], x['ident'], x['at_us']) for x in lines], [(0, 'Kernel panic - not syncing: Fatal exception', 'kernel', 100000000)])
        self.assertEqual(netconsole.parse_packet(b'14,7,1,-;usb 1-1: new device\n')[0]['priority'], 6, 'the facility is left out: user 1, info 6')
        self.assertEqual(netconsole.parse_packet(b'3,7,1,ncfrag=0/1200;part of a long one')[0]['message'], 'part of a long one')

    def test_the_plain_format_is_info_and_a_line_is_cleaned_as_every_line_is(self):
        lines = netconsole.parse_packet(b'[ 12.5] eth0: link up\x1b[31m\nmysql -psecret123 started\n')
        self.assertEqual([x['priority'] for x in lines], [6, 6])
        self.assertNotIn('\x1b', lines[0]['message'])
        self.assertNotIn('secret123', lines[1]['message'])

    def test_a_packet_is_anyones_bytes_and_never_throws(self):
        for junk in (b'', b'\xff\xfe\x00', b';;;', b'9999999,1,1,-;x', b'1,2;x', b'\n\n', b'0,' + b'9' * 30 + b',1,-;x', os.urandom(3000)):
            netconsole.parse_packet(junk)
        self.assertEqual(len(netconsole.parse_packet(b'x' * 5000)[0]['message']), netconsole.MAX_PACKET)

    def test_where_the_receiver_listens_is_read_from_one_setting(self):
        for v, want in (('', None), ('off', None), ('0.0.0.0:6666', ('0.0.0.0', 6666)), (':6666', ('0.0.0.0', 6666)), ('6666', ('0.0.0.0', 6666)),
                        ('[::]:6666', ('::', 6666)), ('10.0.0.1:70000', None), ('nonsense', None)):
            self.assertEqual(netconsole.listen_address(v), want, v)


class Db(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = tmp
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for host in ('nas', 'pc'):
            self.conn.execute(f"INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:h, :h, 'scan', '{{}}', {self.db.ts(':t')})", {'h': host, 't': 1600000000})


class Sources(Db):
    def test_a_source_is_a_known_host_one_address_and_one_port(self):
        got = netconsole.save_source(self.conn, 'NAS', '::ffff:10.42.0.7', 6665, 'gabe')
        self.assertEqual((got['host'], got['address'], got['port'], got['enabled']), ('nas', '10.42.0.7', 6665, True))
        with self.assertRaises(LookupError):
            netconsole.save_source(self.conn, 'nobody', '10.0.0.1', 6665, 'gabe')
        for address, port, why in (('10.0.0', 6665, 'IPv4 or IPv6'), ('10.0.0.9', 0, '1 to 65535'), ('10.0.0.9', 'x', 'whole number'),
                                   ('0.0.0.0', 6665, 'cannot be'), ('10.42.0.7', 6665, "already nas's")):
            with self.assertRaisesRegex(ValueError, why):
                netconsole.save_source(self.conn, 'pc', address, port, 'gabe')
        self.assertEqual(netconsole.save_source(self.conn, 'pc', '10.42.0.7', 6666, 'gabe')['port'], 6666, 'the same address from another port is another source')
        self.assertTrue(netconsole.delete_source(self.conn, 'pc'))
        self.assertFalse(netconsole.delete_source(self.conn, 'pc'))


class Receiver(Db):
    """The receiver on a real UDP socket on 127.0.0.1, and packets sent from real sockets."""

    def setUp(self):
        super().setUp()
        self.sock = netconsole.bind(('127.0.0.1', 0))
        self.addCleanup(self.sock.close)
        self.port = self.sock.getsockname()[1]
        self.nas = self.sender()
        self.stranger = self.sender()
        netconsole.save_source(self.conn, 'nas', '127.0.0.1', self.nas.getsockname()[1], 'gabe')

    def sender(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0))
        self.addCleanup(s.close)
        return s

    def serve(self, *packets):
        """Sends each (socket, bytes), then lets the receiver take them and store them."""
        stop = threading.Event()
        woke = []
        th = threading.Thread(target=netconsole.serve, args=(self.db, self.sock, stop, lambda: woke.append(1)), daemon=True)
        th.start()
        for s, data in packets:
            s.sendto(data, ('127.0.0.1', self.port))
        deadline = time.time() + 10
        want = sum(1 for s, _ in packets if s is self.nas)
        while time.time() < deadline:
            got = self.conn.scalar("SELECT packets + dropped FROM netconsole_sources WHERE host = 'nas'") or 0
            if got >= want:
                break
            time.sleep(0.2)
        stop.set()
        th.join(5)
        return woke

    def test_a_panic_from_the_known_port_is_stored_as_the_hosts_and_is_critical_at_once(self):
        before = netconsole.status()['unknown']
        woke = self.serve((self.nas, b'0,88,120000000,-;Kernel panic - not syncing: Attempted to kill init!\n'),
                          (self.stranger, b'0,1,1,-;Kernel panic - not syncing: forged from another port\n'))
        rows = self.conn.all("SELECT host, priority, via, message FROM host_log_lines ORDER BY line_id")
        self.assertEqual([tuple(r) for r in rows], [('nas', 0, 'netconsole', 'Kernel panic - not syncing: Attempted to kill init!')])
        self.assertEqual(netconsole.status()['unknown'], before + 1, 'the other port was counted and dropped')
        got = logrules.problems(self.conn)
        panic = next(v for k, v in got.items() if v[2] == 'The kernel panicked or locked up on nas')
        self.assertEqual(panic[4], 'crit')
        self.assertEqual(woke, [1], 'a rule that matched wakes the notification center')
        src = netconsole.sources(self.conn)[0]
        self.assertEqual((src['packets'], src['dropped']), (1, 0))
        self.assertIsNotNone(src['last_at'])

    def test_netconsole_lines_leave_the_journals_own_status_and_counts_alone(self):
        hostlogs.store(self.conn, 'nas', {'state': 'ok', 'cut': False, 'lines': [{'key': 'j1', 'at_us': int(time.time() * 1e6), 'priority': 6, 'unit': 'cron.service',
                                                                                 'ident': 'cron', 'pid': None, 'message': 'job ran'}]}, time.time())
        status = tuple(self.conn.all('SELECT via, state, collected_at, fresh_at FROM host_log_status WHERE host = :h', {'h': 'nas'})[0])
        counts = self.conn.scalar('SELECT sum(lines) FROM host_log_counts')
        self.serve((self.nas, b'4,9,1,-;EXT4-fs warning (device sda1): ext4_end_bio\n'))
        self.assertEqual(tuple(self.conn.all('SELECT via, state, collected_at, fresh_at FROM host_log_status WHERE host = :h', {'h': 'nas'})[0]), status)
        self.assertEqual(self.conn.scalar('SELECT sum(lines) FROM host_log_counts'), counts, 'a second copy of a kernel line is no part of a baseline')
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM host_log_lines WHERE via = 'netconsole'"), 1)
        e = hostlogs.page(self.conn, hostlogs.clean_filter('nas'))['entries'][0]
        self.assertEqual((e['via'], e['signed']), ('netconsole', False))

    def test_a_source_over_its_rate_or_with_a_packet_too_big_is_dropped_and_counted(self):
        with mock.patch.object(netconsole, 'BURST', 3), mock.patch.object(netconsole, 'PACKETS_PER_SEC', 0.001):
            self.serve(*[(self.nas, f'6,{i},1,-;line {i}\n'.encode()) for i in range(6)], (self.nas, b'6,99,1,-;' + b'x' * 3000))
        src = netconsole.sources(self.conn)[0]
        self.assertEqual((src['packets'], src['dropped']), (3, 4))
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM host_log_lines WHERE via = 'netconsole'"), 3)

    def test_a_source_turned_off_is_a_stranger(self):
        netconsole.save_source(self.conn, 'nas', '127.0.0.1', self.nas.getsockname()[1], 'gabe', enabled=False)
        before = netconsole.status()['unknown']
        stop = threading.Event()
        th = threading.Thread(target=netconsole.serve, args=(self.db, self.sock, stop), daemon=True)
        th.start()
        self.nas.sendto(b'6,1,1,-;hello\n', ('127.0.0.1', self.port))
        deadline = time.time() + 10
        while netconsole.status()['unknown'] == before and time.time() < deadline:
            time.sleep(0.1)
        stop.set()
        th.join(5)
        self.assertEqual(netconsole.status()['unknown'], before + 1)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_log_lines'), 0)


class OverTheWeb(Db):
    def setUp(self):
        super().setUp()
        self.db = Database(str(self.tmp / 'web.db'))
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")

    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def test_an_operator_adds_a_source_with_the_password_fresh_and_it_is_audited(self):
        c = self.client('operator')
        got = c.get('/api/hostlogs/netconsole').get_json()
        self.assertEqual((got['sources'], got['default_port']), ([], 6666))
        self.assertEqual(c.put('/api/hostlogs/netconsole/nas', json={'address': '10.42.0.7', 'port': 6665}).get_json()['address'], '10.42.0.7')
        self.assertEqual(c.put('/api/hostlogs/netconsole/nas', json={'address': 'x'}).status_code, 400)
        self.assertEqual(c.put('/api/hostlogs/netconsole/ghost', json={'address': '10.0.0.1'}).status_code, 404)
        self.assertEqual(c.delete('/api/hostlogs/netconsole/nas').status_code, 200)
        self.assertEqual(c.delete('/api/hostlogs/netconsole/nas').status_code, 404)
        self.assertEqual([r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'netconsole.%' ORDER BY rowid")],
                         ['netconsole.source.save', 'netconsole.source.delete'])

    def test_a_viewer_neither_reads_nor_writes_them(self):
        c = self.client('viewer')
        self.assertEqual(c.get('/api/hostlogs/netconsole').status_code, 403)
        self.assertEqual(c.put('/api/hostlogs/netconsole/nas', json={'address': '10.0.0.1'}).status_code, 403)


# ── the plan step ───────────────────────────────────────────────────
HEAD = ('APPLY=${APPLY:-1}; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }\n'
        'act() { if ((!APPLY)); then missing "would: $*"; return 1; fi; echo "doing: $*"; }\ndurable() { :; }\n')
IP = r'''#!/bin/bash
# a stand-in: a route to 10.42.0.10 on the LAN, to 192.0.2.10 through a gateway, and neighbours from $NEIGH
case "$1 $2 $3" in
  "-4 route get") case $4 in
      10.42.0.10) echo "10.42.0.10 dev enp3s0 src 10.42.0.7 uid 0" ;;
      192.0.2.10) echo "192.0.2.10 via 10.42.0.1 dev enp3s0 src 10.42.0.7 uid 0" ;;
      *) exit 2 ;;
    esac ;;
  "neigh show "*) grep "^$3 " "$NEIGH" || true ;;
esac
'''
MODPROBE = '#!/bin/bash\necho "modprobe $*" >> "$NC_ROOT/calls"\n[[ $1 == -r ]] && rm -rf "$NC_ROOT/sys/module/netconsole" || mkdir -p "$NC_ROOT/sys/module/netconsole"\n'


class TheStep(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / 'root'
        (self.root / 'proc/sys/kernel').mkdir(parents=True)
        (self.root / 'proc/sys/kernel/printk').write_text('4\t4\t1\t7\n')
        (self.root / 'dev').mkdir()
        (self.tmp / 'bin').mkdir()
        self.neigh = self.tmp / 'neigh'
        self.neigh.write_text('10.42.0.10 dev enp3s0 lladdr 52:54:00:aa:bb:cc REACHABLE\n10.42.0.1 dev enp3s0 lladdr 52:54:00:00:00:01 STALE\n')
        for name, text in (('ip', IP), ('modprobe', MODPROBE), ('modinfo', '#!/bin/bash\nexit 0\n'), ('ping', '#!/bin/bash\nexit 1\n'),
                           ('mount', '#!/bin/bash\necho "mount $*" >> "$NC_ROOT/calls"\nexit 32\n'), ('hostname', '#!/bin/bash\necho nas\n')):
            (self.tmp / 'bin' / name).write_text(text)
            (self.tmp / 'bin' / name).chmod(0o755)

    def run_step(self, target='10.42.0.10', port='', sport='', dev='', state='present', apply=True):
        script = HEAD + steps_netconsole.BASH + '\nt_netconsole "$@"\n'
        env = {'PATH': f'{self.tmp}/bin:{os.environ["PATH"]}', 'NC_ROOT': str(self.root), 'NEIGH': str(self.neigh), 'APPLY': '1' if apply else '0'}
        p = subprocess.run(['bash', '-c', script, 'x', target, port, sport, dev, state], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def read(self, rel):
        f = self.root / rel
        return f.read_text() if f.exists() else None

    def calls(self):
        return (self.read('calls') or '').splitlines()

    def test_it_writes_netconsole_for_boot_loads_it_and_a_second_run_finds_it_done(self):
        out = self.run_step()
        self.assertEqual(self.read('etc/modprobe.d/storageforge-netconsole.conf'), 'options netconsole netconsole=+6665@10.42.0.7/enp3s0,6666@10.42.0.10/52:54:00:aa:bb:cc\n')
        self.assertEqual(self.read('etc/modules-load.d/storageforge-netconsole.conf'), 'netconsole\n')
        self.assertEqual(self.calls(), ['modprobe netconsole'])
        self.assertIn('ok: netconsole is loaded and sending to 10.42.0.10 port 6666', out)
        self.assertIn('info: the console log level here is 4', out)
        self.assertIn('netconsole check from nas', self.read('dev/kmsg'))
        again = self.run_step()
        self.assertNotIn('doing:', again)
        self.assertIn('ok: netconsole starts at boot', again)
        self.assertIn('ok: netconsole is loaded with these settings', again)
        self.assertEqual(self.calls(), ['modprobe netconsole'])

    def test_through_a_gateway_it_sends_to_the_gateways_mac(self):
        self.run_step(target='192.0.2.10', port='5555', sport='6000')
        self.assertEqual(self.read('etc/modprobe.d/storageforge-netconsole.conf'), 'options netconsole netconsole=+6000@10.42.0.7/enp3s0,5555@192.0.2.10/52:54:00:00:00:01\n')

    def test_already_loaded_with_other_settings_it_sets_a_target_of_its_own_in_configfs(self):
        (self.root / 'sys/module/netconsole').mkdir(parents=True)
        (self.root / 'sys/kernel/config/netconsole').mkdir(parents=True)
        out = self.run_step()
        cfs = 'sys/kernel/config/netconsole/storageforge/'
        self.assertEqual({k: self.read(cfs + k).strip() for k in ('dev_name', 'local_port', 'remote_port', 'local_ip', 'remote_ip', 'remote_mac', 'extended', 'enabled')},
                         {'dev_name': 'enp3s0', 'local_port': '6665', 'remote_port': '6666', 'local_ip': '10.42.0.7', 'remote_ip': '10.42.0.10',
                          'remote_mac': '52:54:00:aa:bb:cc', 'extended': '1', 'enabled': '1'})
        self.assertIn('ok: netconsole is sending to 10.42.0.10 port 6666', out)
        self.assertEqual(self.calls(), [], 'not loaded again')

    def test_what_it_cannot_do_it_says_and_leaves_alone(self):
        self.assertIn('conflict: there is no route from here to 203.0.113.9', self.run_step(target='203.0.113.9'))
        self.neigh.write_text('')
        self.assertIn('conflict: could not find the MAC address of 10.42.0.10 on enp3s0', self.run_step())
        self.assertIsNone(self.read('etc/modprobe.d/storageforge-netconsole.conf'))
        (self.tmp / 'bin' / 'modinfo').write_text('#!/bin/bash\nexit 1\n')
        self.assertIn('conflict: this kernel has no netconsole module', self.run_step())
        (self.tmp / 'bin' / 'modinfo').write_text('#!/bin/bash\nexit 0\n')
        (self.root / 'sys/module/netconsole').mkdir(parents=True)
        self.neigh.write_text('10.42.0.10 dev enp3s0 lladdr 52:54:00:aa:bb:cc REACHABLE\n')
        self.assertIn('conflict: netconsole is loaded already, with other settings, and this kernel has no configfs for it', self.run_step())

    def test_a_report_writes_nothing(self):
        out = self.run_step(apply=False)
        self.assertIn('missing: would: netconsole at boot: to 10.42.0.10 port 6666 from 10.42.0.7 port 6665 on enp3s0, next hop 52:54:00:aa:bb:cc', out)
        self.assertIsNone(self.read('etc/modprobe.d/storageforge-netconsole.conf'))
        self.assertIsNone(self.read('dev/kmsg'))

    def test_the_way_back_takes_out_all_it_put_in(self):
        self.run_step()
        out = self.run_step(state='absent')
        self.assertIn('doing: remove', out)
        self.assertIn('doing: unload netconsole, which this step loaded', out)
        self.assertIsNone(self.read('etc/modprobe.d/storageforge-netconsole.conf'))
        self.assertIsNone(self.read('etc/modules-load.d/storageforge-netconsole.conf'))
        self.assertEqual(self.calls(), ['modprobe netconsole', 'modprobe -r netconsole'])
        self.assertIn('ok: netconsole is not set up by StorageForge here', self.run_step(state='absent'))

    def test_the_way_back_turns_off_its_configfs_target(self):
        (self.root / 'sys/module/netconsole').mkdir(parents=True)
        (self.root / 'sys/kernel/config/netconsole').mkdir(parents=True)
        self.run_step()
        self.run_step(state='absent')
        self.assertEqual(self.read('sys/kernel/config/netconsole/storageforge/enabled').strip(), '0')
        self.assertEqual(self.calls(), [], 'what this step did not load, it does not unload')


class StepInAPlan(Db):
    def test_a_plan_takes_an_ipv4_target_and_says_what_is_missing_on_the_controller(self):
        plan = changes.normalize({'name': 'nc', 'tasks': [{'type': 'netconsole', 'host': 'nas', 'params': {'target': '10.42.0.10'}}]})
        self.assertEqual(plan['tasks'][0]['params'], {'target': '10.42.0.10', 'port': '', 'source_port': '', 'interface': '', 'state': 'present'})
        with self.assertRaisesRegex(ValueError, 'not valid'):
            changes.normalize({'name': 'nc', 'tasks': [{'type': 'netconsole', 'host': 'nas', 'params': {'target': '10.42.0.300'}}]})
        said = []
        with mock.patch.dict(os.environ, {'STORAGEFORGE_NETCONSOLE_LISTEN': ''}):
            steps_netconsole._check(self.conn, None, {'name': 'nas'}, plan['tasks'][0]['params'], lambda level, text: said.append((level, text)))
        self.assertTrue(any(l == 'warn' and 'add nas under Logs, Netconsole, with port 6665' in t for l, t in said), said)
        self.assertTrue(any(l == 'warn' and 'STORAGEFORGE_NETCONSOLE_LISTEN' in t for l, t in said), said)
        self.assertTrue(any('no signature' in t for _, t in said))
        said.clear()
        steps_netconsole._check(self.conn, None, {'name': 'nas'}, {**plan['tasks'][0]['params'], 'port': '70000'}, lambda level, text: said.append((level, text)))
        self.assertIn(('crit', 'The controller port is a port, from 1 to 65535'), said)
        script = changes.script(self.conn, plan)
        self.assertIn("run 1 nas netconsole 'Send kernel messages to 10.42.0.10 port 6666 over netconsole' 10.42.0.10 '' '' '' present", script)
        self.assertIn('t_netconsole() {', script)


# ── pstore ──────────────────────────────────────────────────────────
DMESG = """Panic#1 Part1
<6>[  101.200000] sd 0:0:0:0: [sda] tag#1 timing out command
<4>[  101.300000] blk_update_request: I/O error, dev sda, sector 2048
<0>[  101.400000] Kernel panic - not syncing: Fatal exception in interrupt
<0>[  101.400001] password=hunter22 ---[ end Kernel panic ]---
"""


class Pstore(Db):
    def tree(self, readable=True):
        """A host's /sys/fs/pstore and /var/lib/systemd/pstore, as files in a folder, and the scan's own script pointed at them."""
        sysfs, kept = self.tmp / 'sys/fs/pstore', self.tmp / 'var/lib/systemd/pstore/1700000000'
        sysfs.mkdir(parents=True)
        kept.mkdir(parents=True)
        (kept / 'dmesg.txt').write_text(DMESG)
        os.utime(kept / 'dmesg.txt', (1700000000, 1700000000))
        (sysfs / 'console-ramoops-0').write_text('console\n')
        if not readable:
            (kept / 'dmesg.txt').chmod(0)
        roots = f'{self.tmp}/sys/fs/pstore {self.tmp}/var/lib/systemd/pstore'
        return pstore.SCRIPT.replace(pstore.ROOTS, roots)

    def run_scan(self, script):
        p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.replace(str(self.tmp), '')             # the paths as the host would print them

    def test_the_scan_reads_the_last_panic_and_it_is_one_warning_with_its_worst_line(self):
        out = self.run_scan(self.tree())
        got = pstore.parse(out, now=1700000500)
        self.assertEqual([f['path'] for f in got['files']], ['/var/lib/systemd/pstore/1700000000/dmesg.txt'])
        done = pstore.store(self.conn, 'nas', got, now=1700000500)
        self.assertEqual((done['records'], done['read']), (1, True))
        rows = self.conn.all("SELECT priority, message FROM host_log_lines WHERE via = 'pstore' ORDER BY at_us")
        self.assertEqual([r[1] for r in rows][-2:], ['Kernel panic - not syncing: Fatal exception in interrupt', 'password=[redacted] ---[ end Kernel panic ]---'])
        self.assertEqual(rows[2][0], 4)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM log_rule_hits'), 0, 'history raises no log rule: pstore says it once')
        p = pstore.problems(self.conn, now=1700000600)
        self.assertEqual(list(p), ['log-pstore:nas'])
        kind, ref, title, message, level = p['log-pstore:nas']
        self.assertEqual((kind, level, title), ('log-pstore', 'warn', 'The kernel on nas crashed and left a record'))
        self.assertIn('The worst line it holds: Kernel panic - not syncing', message)
        self.assertEqual(pstore.store(self.conn, 'nas', got, now=1700000900)['new'], 0, 'the same record read again is not new')
        self.assertEqual(pstore.problems(self.conn, now=1700000000 + pstore.ALERT_DAYS * 86400 + 60), {})

    @unittest.skipIf(os.geteuid() == 0, 'root reads every file')
    def test_a_scan_user_that_cannot_read_a_record_says_it_is_there(self):
        got = pstore.parse(self.run_scan(self.tree(readable=False)), now=1700000500)
        self.assertEqual((got['files'], [d['path'] for d in got['denied']]), ([], ['/var/lib/systemd/pstore/1700000000/dmesg.txt']))
        done = pstore.store(self.conn, 'nas', got, now=1700000500)
        self.assertIn('cannot read them', done['note'])
        self.assertIn('cannot read them', pstore.problems(self.conn, now=1700000600)['log-pstore:nas'][3])

    def test_a_host_with_nothing_in_pstore_says_nothing(self):
        got = pstore.parse('@@who 1000\n@@records\n@@end\n')
        pstore.store(self.conn, 'pc', got)
        self.assertEqual(pstore.problems(self.conn), {})
        self.assertEqual(self.conn.scalar("SELECT pstore_records FROM host_log_status WHERE host = 'pc'"), 0)

    def test_a_path_or_marker_a_host_made_up_is_not_taken(self):
        got = pstore.parse('@@records\n1 2 /etc/shadow\n1 2 /sys/fs/pstore/../x y\n@@file 1 /etc/passwd\n|root:x\n@@file 1 /sys/fs/pstore/dmesg-efi-1\n|<0>boom\n@@end\n', now=10)
        self.assertEqual([f['path'] for f in got['files']], ['/sys/fs/pstore/dmesg-efi-1'])
        self.assertEqual(got['records'], [])


if __name__ == '__main__':
    unittest.main()
