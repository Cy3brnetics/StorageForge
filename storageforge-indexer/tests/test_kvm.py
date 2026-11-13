"""Managing libvirt (steps_kvm.py, the VM task blocks, the vm receive tool): what a reading says of VMs, snapshots, networks
and pools; the checks of each step; the plan a VM copy is; the receive of a disk on one host; net_sig on the XML libvirt
writes; and the VM blocks of a task against a stand-in virsh. Real libvirt runs in the lab (tier 18)."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, scriptkit, server, steps_kvm, tasks, users
from storageforge_index.runtimes import guests

PW = 'a long enough password'
DOMAIN = """<domain type='kvm'><name>web</name><uuid>u-1</uuid><memory unit='KiB'>2097152</memory><vcpu>2</vcpu>
<os firmware='efi'><type arch='x86_64' machine='pc-q35-9.2'>hvm</type><loader secure='yes'/></os><cpu mode='host-passthrough'/>
<metadata><libosinfo:libosinfo xmlns:libosinfo='http://libosinfo.org/xmlns/libvirt/domain/1.0'><libosinfo:os id='http://debian.org/debian/12'/></libosinfo:libosinfo></metadata>
<devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/web.qcow2'/><backingStore type='file'><source file='/img/base.qcow2'/></backingStore><target dev='vda' bus='virtio'/></disk>
<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='/var/lib/libvirt/images/web-data.raw'/><target dev='vdb' bus='sata'/></disk>
<disk type='file' device='cdrom'><source file='/var/lib/libvirt/images/seed.iso'/><target dev='sda' bus='sata'/><readonly/></disk>
<interface type='network'><mac address='52:54:00:AA:BB:CC'/><source network='lan'/><model type='virtio'/></interface>
<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0' state='connected'/></channel>
<serial type='pty'/><graphics type='spice' listen='127.0.0.1'/><tpm model='tpm-crb'/></devices></domain>"""


def b64(text):
    return base64.b64encode(text.encode()).decode()


class Readings(unittest.TestCase):
    def test_a_domain_says_what_a_copy_and_a_snapshot_need(self):
        d = guests.parse_domain(DOMAIN)
        self.assertEqual((d['firmware'], d['secure_boot'], d['machine'], d['cpu_mode'], d['agent'], d['osinfo'], d['serial'], d['tpm']),
                         ('uefi', True, 'pc-q35-9.2', 'host-passthrough', 'connected', 'http://debian.org/debian/12', True, True))
        self.assertEqual([x['backing'] for x in d['disks']], [True, False, False])

    def test_snapshots_from_xml_cut_before_the_domain(self):
        disk_only = ("<domainsnapshot><name>sf-1</name><state>disk-snapshot</state><creationTime>1794190000</creationTime><memory snapshot='no'/>"
                     "<disks><disk name='vda' snapshot='external' type='file'><source file='/i/web.sf-1'/></disk></disks>")   # as sed leaves it
        internal = "<domainsnapshot><name>before</name><state>running</state><parent><name>sf-1</name></parent><creationTime>1794190100</creationTime><memory snapshot='internal'/></domainsnapshot>"
        got = guests.parse_libvirt_snapshots([f'web\tsf-1\t0\t{b64(disk_only)}', f'web\tbefore\t1\t{b64(internal)}', 'web\tbad\t0\t!!', 'short'])
        self.assertEqual([(s['name'], s['location'], s['disk_only'], s['current'], s['parent']) for s in got['web']],
                         [('sf-1', 'external', True, False, None), ('before', 'internal', False, True, 'sf-1')])
        doms = guests.with_snapshots([{'name': 'web'}, {'name': 'db'}], got)
        self.assertEqual([len(d['snapshots']) for d in doms], [2, 0])

    def test_networks_and_pools_say_whether_they_are_up(self):
        net = "<network><name>lab</name><forward mode='nat'/><bridge name='virbr3'/><ip address='10.77.0.1' netmask='255.255.255.0'><dhcp><range start='10.77.0.100' end='10.77.0.200'/></dhcp></ip></network>"
        info = 'Name: lab\nActive:         yes\nPersistent:     yes\nAutostart:      no\n'
        n = guests.parse_libvirt_networks([f'lab\t{b64(net)}\t{b64(info)}'])[0]
        self.assertEqual((n['mode'], n['dhcp'], n['active'], n['autostart']), ('nat', '10.77.0.100-10.77.0.200', True, False))
        pool = "<pool type='logical'><name>vg</name><source><name>vg0</name><format type='lvm2'/></source><target><path>/dev/vg0</path></target></pool>"
        info = 'State:          running\nAutostart:      yes\nCapacity:       1000 bytes\nAvailable:      400 bytes\n'
        p = guests.parse_libvirt_pools([f'vg\t{b64(pool)}\t{b64(info)}'])[0]
        self.assertEqual((p['type'], p['source'], p['active'], p['autostart'], p['capacity'], p['available']), ('logical', 'vg0', True, True, 1000, 400))
        old = guests.parse_libvirt_networks([f'lab\t{b64(net)}'])[0]        # a reading from before: nothing claimed
        self.assertIsNone(old['active'])


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        for name in ('kvm1', 'kvm2'):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:n, :n, 'scan', '{}')", {'n': name})
        web = {**guests.parse_domain(DOMAIN), 'state': 'running', 'autostart': True,
               'snapshots': [{'name': 'sf-1', 'location': 'external', 'state': 'disk-snapshot'}]}
        self.reading('kvm1', libvirt=[web, {'name': 'off', 'state': 'shut off', 'disks': [], 'nics': []}])
        self.reading('kvm2', libvirt=[{'name': 'db', 'state': 'running', 'disks': [{'device': 'disk', 'target': 'vda', 'source': '/srv/vms/db.qcow2'}],
                                       'nics': [{'type': 'network', 'source': 'default'}]}],
                     libvirt_pools=[{'name': 'default', 'type': 'dir', 'path': '/var/lib/libvirt/images'}, {'name': 'vms', 'type': 'dir', 'path': '/srv/vms'}],
                     libvirt_networks=[{'name': 'default', 'mode': 'nat', 'address': '192.168.122.1', 'netmask': '255.255.255.0', 'active': True}])

    def reading(self, host, **extra):
        from storageforge_index import security
        data = {'tools': ['virsh'], 'libvirt': [], 'libvirt_pools': [], 'libvirt_networks': [], **extra}
        security._save_measurement(self.conn, host, 'infra', int(time.time()), 'test', data)

    def items(self, type_, host='kvm1', **p):
        plan = changes.normalize({'name': 't', 'tasks': [{'type': type_, 'host': host, 'params': p}]})
        return [(i['level'], i['text']) for i in changes.check(self.conn, plan)['tasks'][0]['items']]

    def levels(self, *a, **k):
        return {lvl for lvl, _ in self.items(*a, **k)}


class Checks(Db):
    def test_snapshots(self):
        self.assertIn(('ok', 'its guest agent answers: filesystems are frozen for the moment of the snapshot'), self.items('vm-snapshot', name='web'))
        self.assertTrue(any('UEFI' in t for _, t in self.items('vm-snapshot', name='web', disk_only=False)))
        self.assertIn('crit', self.levels('vm-snapshot', name='web', action='delete'))          # which one?
        self.assertIn('crit', self.levels('vm-revert', name='web', snapshot='nope'))
        self.assertNotIn('crit', self.levels('vm-revert', name='web', snapshot='sf-1'))
        with self.assertRaises(ValueError):
            changes.normalize({'name': 't', 'tasks': [{'type': 'vm-snapshot', 'host': 'kvm1', 'params': {'name': 'web;id'}}]})

    def test_edit(self):
        self.assertIn('crit', self.levels('vm-edit', name='web'))                                 # nothing to change
        self.assertIn('crit', self.levels('vm-edit', name='web', grow_disk='vdz', grow_to='40G'))
        self.assertTrue(any('snapshots' in t for _, t in self.items('vm-edit', name='web', add_disk='10G')))
        self.assertTrue(any('next starts' in t for _, t in self.items('vm-edit', name='web', vcpus='4')))

    def test_networks(self):
        self.assertIn('crit', self.levels('libvirt-network', host='kvm2', name='new', address='192.168.122.5/24'))     # overlaps default
        self.assertIn('crit', self.levels('libvirt-network', host='kvm2', name='new', address='10.9.0.1/24', dhcp='10.9.1.10-10.9.1.20'))
        self.assertIn('crit', self.levels('libvirt-network', host='kvm2', name='new', address='10.9.0.1/24', dhcp='10.9.0.1-10.9.0.20'))
        self.assertNotIn('crit', self.levels('libvirt-network', host='kvm2', name='new', address='10.9.0.1/24', dhcp='10.9.0.10-10.9.0.20'))
        self.assertIn('crit', self.levels('libvirt-network', host='kvm2', name='default', state='absent'))           # db uses it
        self.assertIn('crit', self.levels('libvirt-network', host='kvm2', name='br', mode='bridge'))
        self.assertTrue(any('restart' in t for _, t in self.items('libvirt-network', host='kvm2', name='default', address='192.168.122.1/24')))

    def test_pools(self):
        self.assertIn('crit', self.levels('libvirt-pool', host='kvm2', name='vms', state='absent'))                  # db is in it
        self.assertNotIn('crit', self.levels('libvirt-pool', host='kvm2', name='default', state='absent'))
        self.assertIn('crit', self.levels('libvirt-pool', host='kvm2', name='x', type='dir'))
        self.assertIn('crit', self.levels('libvirt-pool', host='kvm2', name='vms', type='zfs', source='tank/vms'))

    def test_a_send_of_a_running_vm_must_be_live(self):
        self.assertIn('crit', self.levels('vm-send', name='web', dest_host='kvm2', dest='/srv/vms'))
        live = self.items('vm-send', name='web', dest_host='kvm2', dest='/srv/vms', live=True)
        self.assertTrue(any('frozen' in t for _, t in live))
        self.assertTrue(any('base image' in t for _, t in live))
        self.assertTrue(any('not enrolled' in t for lvl, t in live if lvl == 'crit'))             # kvm2 has no deploy access here


class Copy(Db):
    def test_the_plan_is_a_send_here_and_a_define_there_from_the_reading(self):
        plan = steps_kvm.copy_plan(self.conn, 'kvm1', 'web', 'kvm2', pool='vms', live=True)
        send, define = plan['tasks']
        self.assertEqual((send['type'], send['host'], send['params']['dest'], send['params']['live']), ('vm-send', 'kvm1', '/srv/vms', True))
        p = define['params']
        self.assertEqual((define['type'], define['host'], p['disks']), ('vm-define', 'kvm2', 'vda:virtio:qcow2:web-vda.qcow2,vdb:sata:raw:web-vdb.raw'))
        self.assertEqual((p['vcpus'], p['memory_mib'], p['firmware'], p['cpu'], p['machine'], p['osinfo'], p['graphics'], p['tpm'], p['autostart']),
                         ('2', '2048', 'uefi', 'host-passthrough', 'q35', 'debian12', 'spice', True, True))
        self.assertEqual(p['nics'], 'network=default:virtio:new')      # lan is not there: the default network, and a new MAC
        self.assertEqual(plan['skipped'], ['sda'])
        kept = steps_kvm.copy_plan(self.conn, 'kvm1', 'web', 'kvm2', keep_macs=True, network='default')['tasks'][1]['params']
        self.assertEqual((kept['nics'], kept['folder']), ('network=default:virtio:52:54:00:aa:bb:cc', '/var/lib/libvirt/images'))
        changes.normalize({'name': plan['name'], 'tasks': plan['tasks']})        # every value passes the field checks

    def test_what_a_copy_cannot_be_made_of(self):
        for args in (('kvm1', 'nope', 'kvm2'), ('kvm1', 'web', 'nowhere'), ('kvm2', 'db', 'kvm1')):       # kvm1 has no pool
            with self.assertRaises(ValueError, msg=args):
                steps_kvm.copy_plan(self.conn, *args)
        with self.assertRaises(ValueError):
            steps_kvm.copy_plan(self.conn, 'kvm1', 'web', 'kvm2', name='a b')


class Script(Db):
    """A plan of every new step, as the script a deploy runs (its own header: set -u, its helpers), reporting against a
    stand-in virsh: nothing it declares may be unbound, and nothing changes in a report."""
    def test_a_report_of_every_step_runs_clean(self):
        tmp = Path(self.tmp)
        (tmp / 'bin').mkdir()
        (tmp / 'vms').mkdir()
        (tmp / 'vms' / 'web.qcow2').write_bytes(b'disk')
        (tmp / 'snaps.web').write_text('sf-1\n')
        (tmp / 'bin' / 'virsh').write_text(STUB_VIRSH.replace('/vms/%s.qcow2', f'{tmp}/vms/%s.qcow2').replace('  blockcommit) ;;', (
            '  vcpucount) echo 2 ;; domblkinfo) echo "Capacity: 1073741824" ;;\n'
            '  snapshot-info) grep -qx "$3" "$STUB_SNAPS.$2" ;; snapshot-dumpxml) echo "<disks><disk snapshot=\'external\'/></disks>" ;;\n'
            '  net-info|pool-info) exit 1 ;; version) echo "Running against daemon: 10.0.0" ;;\n  blockcommit) ;;')))
        (tmp / 'bin' / 'qemu-img').write_text('#!/bin/bash\necho "file format: qcow2"\n')
        (tmp / 'bin' / 'virt-install').write_text('#!/bin/bash\nexit 0\n')
        for f in (tmp / 'bin').iterdir():
            f.chmod(0o755)
        plan = {'name': 'every libvirt step', 'tasks': [
            {'type': 'vm-snapshot', 'host': 'kvm1', 'params': {'name': 'web', 'quiesce': 'require'}},
            {'type': 'vm-snapshot', 'host': 'kvm1', 'params': {'name': 'web', 'snapshot': 'sf-1', 'action': 'delete'}},
            {'type': 'vm-revert', 'host': 'kvm1', 'params': {'name': 'web', 'snapshot': 'sf-1', 'start': True}},
            {'type': 'vm-edit', 'host': 'kvm1', 'params': {'name': 'web', 'vcpus': '4', 'memory_mib': '4096', 'autostart': 'on', 'add_disk': '10G',
                                                           'grow_disk': 'vda', 'grow_to': '20G', 'remove_disk': 'vdb', 'restart': True}},
            {'type': 'libvirt-network', 'host': 'kvm1', 'params': {'name': 'lab', 'address': '10.5.0.1/24', 'dhcp': '10.5.0.10-10.5.0.20'}},
            {'type': 'libvirt-network', 'host': 'kvm1', 'params': {'name': 'old', 'state': 'absent'}},
            {'type': 'libvirt-pool', 'host': 'kvm1', 'params': {'name': 'vms', 'path': '/srv/vms'}},
            {'type': 'libvirt-pool', 'host': 'kvm1', 'params': {'name': 'old', 'state': 'absent'}},
            {'type': 'vm-send', 'host': 'kvm1', 'params': {'name': 'web', 'dest_host': 'kvm1', 'dest': str(tmp / 'copy'), 'live': True, 'as_name': 'web2'}},
            {'type': 'vm-define', 'host': 'kvm1', 'params': {'name': 'web2', 'folder': str(tmp / 'copy'), 'disks': 'vda:virtio:qcow2:web2-vda.qcow2', 'vcpus': '2', 'memory_mib': '2048',
                                                             'nics': 'network=default:virtio:new'}},
            {'type': 'workload-action', 'host': 'kvm1', 'params': {'runtime': 'libvirt', 'name': 'web', 'action': 'force-off'}}]}
        text = changes.script(self.conn, changes.normalize(plan)).replace('ME=$(host_slug "$(uname -n)")', 'ME=kvm1')
        self.assertIn('ME=kvm1', text)
        (tmp / 'p.sh').write_text(text)
        log = tmp / 'log'
        r = subprocess.run(['bash', str(tmp / 'p.sh')], capture_output=True, text=True, timeout=120,
                           env={**os.environ, 'PATH': f'{tmp}/bin:{os.environ["PATH"]}', 'STUB_LOG': str(log), 'STUB_SNAPS': str(tmp / 'snaps')})
        self.assertNotIn("unbound variable", r.stderr + r.stdout)
        self.assertNotIn('command not found', r.stderr + r.stdout)
        for want in ('would: snapshot web', 'would: delete snapshot sf-1 of web', 'would: revert web to sf-1', 'would: 4 vCPUs', 'would: a new 10G disk',
                     'would: grow vda of web to 20G', 'web has no disk vdb', 'would: define network lab', 'would: define pool vms', 'would: copy web live', 'force off web'):
            self.assertIn(want, r.stdout)
        calls = log.read_text()
        self.assertFalse([c for c in calls.splitlines() if any(w in c for w in ('create-as', 'snapshot-delete', 'snapshot-revert', 'setvcpus', 'net-define', 'pool-define', 'destroy', ' define '))])


class Api(Db):
    def setUp(self):
        super().setUp()
        users.create(self.conn, 'alice', PW, 'admin')
        users.create(self.conn, 'vera', PW, 'viewer')
        self.app = server.create_app(server.App(self.db), 's' * 48)

    def client(self, who):
        c = self.app.test_client()
        self.assertEqual(c.post('/api/login', json={'username': who, 'password': PW}).status_code, 200)
        return c

    def test_vm_details_networks_pools_and_the_copy_plan(self):
        c = self.client('alice')
        web = next(w for w in c.get('/api/workloads?host=kvm1').json['workloads'] if w['name'] == 'web')
        self.assertEqual((web['agent'], web['snapshots'][0]['name'], [d['target'] for d in web['disks']]), ('connected', 'sf-1', ['vda', 'vdb', 'sda']))
        lv = c.get('/api/workloads/libvirt').json['hosts']
        self.assertEqual([(h['host'], [p['name'] for p in h['pools']]) for h in lv], [('kvm1', []), ('kvm2', ['default', 'vms'])])
        pre = c.post('/api/vm/copy/preview', json={'source': 'kvm1', 'name': 'web', 'target': 'kvm2', 'pool': 'vms', 'live': True}).json
        self.assertEqual([t['type'] for t in pre['plan']['tasks']], ['vm-send', 'vm-define'])
        self.assertEqual(c.post('/api/vm/copy/preview', json={'source': 'kvm1', 'name': 'nope', 'target': 'kvm2'}).status_code, 400)
        r = c.post('/api/vm/copy', json={'source': 'kvm1', 'name': 'web', 'target': 'kvm2', 'pool': 'vms', 'live': True})
        self.assertEqual(r.status_code, 201)
        self.assertEqual([t['type'] for t in changes.get_plan(self.conn, r.json['id'])['tasks']], ['vm-send', 'vm-define'])
        self.assertTrue(self.conn.scalar("SELECT 1 FROM audit_log WHERE action = 'vm.copy.plan'"))
        v = self.client('vera')
        self.assertEqual(v.get('/api/workloads/libvirt').status_code, 200)
        self.assertEqual(v.post('/api/vm/copy', json={'source': 'kvm1', 'name': 'web', 'target': 'kvm2'}).status_code, 403)


def bash(script, env=None, cwd=None):
    return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60, env={**os.environ, **(env or {})}, cwd=cwd)


class NetSig(unittest.TestCase):
    """net_sig reads the parts of a network the step sets, from the XML libvirt writes: apostrophes, netmask or prefix, indented."""
    def sig(self, xml):
        fns = steps_kvm.BASH[steps_kvm.BASH.index('mask_bits()'):steps_kvm.BASH.index('net_users()')]
        return subprocess.run(['bash', '-c', fns + '\nnet_sig'], input=xml, capture_output=True, text=True).stdout.strip()

    def test_the_forms_libvirt_writes(self):
        self.assertEqual(self.sig("""<network>
  <name>default</name>
  <forward mode='nat'>
    <nat><port start='1024' end='65535'/></nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>"""), 'nat|-|192.168.122.1/24|192.168.122.2-192.168.122.254')
        self.assertEqual(self.sig("<network><name>i</name><bridge name='virbr9'/><ip address='10.1.0.1' prefix='16'/></network>"), 'isolated|-|10.1.0.1/16|')
        self.assertEqual(self.sig("<network><name>b</name><forward mode='bridge'/><bridge name='br0'/></network>"), 'bridge|br0||')
        self.assertEqual(self.sig("<network><name>n</name><forward/><ip address='10.2.0.1' prefix='24'></ip></network>"), 'nat|-|10.2.0.1/24|')


class ReceiveVm(unittest.TestCase):
    """The vm tool of the receive kit on one host (RECV_LOCAL): a disk arrives whole as a new file of its own, with its checksum."""
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / 'pool'

    def kit(self, body):
        return bash('ETC=/nonexistent VAR=/nonexistent LOCKS=/tmp\n' + scriptkit.RECEIVE_KIT + scriptkit.SEND_KIT
                    + f'send_to vm local "" 22 {self.root}\n' + body)

    def test_a_disk_arrives_checked_and_is_never_written_over(self):
        disk = self.tmp / 'web.raw'
        disk.write_bytes(b'\0' * (4 << 20) + b'data' + b'\0' * (4 << 20))
        want = hashlib.sha256(disk.read_bytes()).hexdigest()
        r = self.kit(f'there recv-probe; there recv-mkdir; send_stream web-vda.raw {want} cat -- {disk}; echo rc=$?; there recv-state web-vda.raw; there recv-list')
        self.assertIn('rc=0', r.stdout, r.stderr)
        self.assertIn(f'done {want}', r.stdout)
        self.assertEqual((self.root / 'web-vda.raw').read_bytes(), disk.read_bytes())
        self.assertEqual((self.root / 'web-vda.raw').stat().st_mode & 0o777, 0o600)
        self.assertLessEqual((self.root / 'web-vda.raw').stat().st_blocks * 512, 1 << 20)  # the zeros stay holes: one dd block of 1 MiB holds the data
        self.assertEqual((self.root / 'web-vda.raw').stat().st_size, disk.stat().st_size)  # uutils dd left the last zeros out (Ubuntu 25.10 on)
        self.assertEqual(r.stdout.splitlines()[-1], 'web-vda.raw')
        again = self.kit(f'send_stream web-vda.raw {want} cat -- {disk}; echo rc=$?')
        self.assertIn('already there', again.stderr)
        self.assertNotIn('rc=0', again.stdout)
        wrong = self.kit(f'send_stream other.raw {"0" * 64} cat -- {disk}; echo rc=$?')
        self.assertIn('not this snapshot', wrong.stderr)

    def test_an_unfinished_disk_is_partial_until_discarded(self):
        self.root.mkdir()
        (self.root / '.web-vda.qcow2.sf-part').write_bytes(b'half')
        r = self.kit('there recv-state web-vda.qcow2; there recv-discard web-vda.qcow2; echo rc=$?; there recv-state web-vda.qcow2')
        self.assertEqual(r.stdout.split(), ['partial', 'rc=0', 'absent'])
        r = self.kit('there recv-state ../etc')
        self.assertNotIn('done', r.stdout)


STUB_VIRSH = r'''#!/bin/bash
echo "virsh $*" >>"$STUB_LOG"
[[ $1 == -c ]] && shift 2
case $1 in
  list) printf '%s\n' web db ;;
  dominfo) [[ $2 == web || $2 == db ]] ;;
  domstate) echo "${STUB_STATE:-running}" ;;
  qemu-agent-command) [[ $2 == web ]] ;;
  snapshot-create-as) echo "$3" >>"$STUB_SNAPS.$2" ;;
  snapshot-list) cat "$STUB_SNAPS.$2" 2>/dev/null ;;
  snapshot-delete) sed -i "/^$3\$/d" "$STUB_SNAPS.$2" ;;
  domblklist) printf ' Type Device Target Source\n------\n file disk vda /vms/%s.qcow2\n file cdrom sda /vms/seed.iso\n' "$2" ;;
  dumpxml) echo "<domain><name>$3</name></domain>" ;;
  blockcommit) ;;
esac
'''


class VmBlocks(unittest.TestCase):
    """The VM blocks of a task against a stand-in virsh and qemu-img that log what they were asked."""
    def setUp(self):
        from test_tasks import Fleet
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fleet = Fleet()
        self.fleet.setUp()
        self.addCleanup(self.fleet.doCleanups)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.bin / 'virsh').write_text(STUB_VIRSH)
        (self.bin / 'qemu-img').write_text('#!/bin/bash\necho "qemu-img $*" >>"$STUB_LOG"\n: >"${@: -1}"\n')
        (self.bin / 'logger').write_text('#!/bin/bash\n')
        for f in self.bin.iterdir():
            f.chmod(0o755)
        self.log = self.tmp / 'log'

    def run_task(self, blocks, run=True, env=None):
        text = (tasks.script(self.fleet.conn, {'name': 'T', 'host': 'nas', 'blocks': blocks})
                .replace('PATH=/usr/local/sbin', f'PATH={self.bin}:/usr/local/sbin').replace('STAMP=$(date +%Y-%m-%d_%H%M%S)', 'STAMP=2026-11-08_120000'))
        (self.tmp / 't.sh').write_text(text)
        self.log.write_text('')
        r = subprocess.run(['bash', str(self.tmp / 't.sh'), *(['--run'] if run else [])], capture_output=True, text=True, timeout=60,
                           env={**os.environ, 'STUB_LOG': str(self.log), 'STUB_SNAPS': str(self.tmp / 'snaps'), 'STORAGEFORGE_TASK_STATE': str(self.tmp / 'st'), **(env or {})})
        r.calls = self.log.read_text().splitlines()
        return r

    def test_snapshots_freeze_where_the_agent_answers_and_prune_only_their_own(self):
        (self.tmp / 'snaps.web').write_text('nightly-2026-11-01_120000\nnightly-2026-11-02_120000\nnightly-notes\nnightly-db-2026-01-01_000000\nby-hand\n')
        r = self.run_task([tasks._b('vm_snapshot', vms='web, db, gone', prefix='nightly', keep=2, quiesce='auto')])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        made = [c for c in r.calls if 'snapshot-create-as' in c]
        self.assertEqual(made, ['virsh -c qemu:///system snapshot-create-as web nightly-2026-11-08_120000 --disk-only --atomic --quiesce',
                                'virsh -c qemu:///system snapshot-create-as db nightly-2026-11-08_120000 --disk-only --atomic'])
        self.assertEqual([c.split()[-1] for c in r.calls if 'snapshot-delete' in c], ['nightly-2026-11-01_120000'])
        self.assertEqual((self.tmp / 'snaps.web').read_text().split(), ['nightly-2026-11-02_120000', 'nightly-notes', 'nightly-db-2026-01-01_000000', 'by-hand', 'nightly-2026-11-08_120000'])
        self.assertIn('there is no VM gone here', r.stdout + r.stderr)

    def test_require_refuses_a_vm_without_an_agent_and_fails_the_block(self):
        r = self.run_task([tasks._b('vm_snapshot', vms='db', prefix='n', keep=0, quiesce='require')])
        self.assertEqual(r.returncode, 1)
        self.assertFalse([c for c in r.calls if 'snapshot-create-as' in c])

    def test_a_backup_copies_from_a_snapshot_merges_it_back_and_keeps_the_newest(self):
        into = self.tmp / 'bk'
        for old in ('2026-11-01_120000', '2026-11-02_120000', 'not-a-backup'):
            (into / 'web' / old).mkdir(parents=True)
        r = self.run_task([tasks._b('vm_backup', vms='web', into=str(into), keep=2, quiesce='auto')])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('virsh -c qemu:///system snapshot-create-as web sfbackup-2026-11-08_120000 --disk-only --atomic --no-metadata --quiesce', r.calls)
        self.assertIn(f'qemu-img convert -U -O qcow2 -- /vms/web.qcow2 {into}/web/2026-11-08_120000.partial/vda.qcow2', r.calls)
        self.assertFalse([c for c in r.calls if 'sda' in c and 'convert' in c])                 # the cdrom is not a disk
        self.assertEqual(sorted(p.name for p in (into / 'web').iterdir()), ['2026-11-02_120000', '2026-11-08_120000', 'not-a-backup'])
        self.assertTrue((into / 'web' / '2026-11-08_120000' / 'domain.xml').exists())
        self.assertEqual((into / 'web' / '2026-11-08_120000' / 'vda.qcow2').stat().st_mode & 0o077, 0)

    def test_a_report_changes_nothing(self):
        r = self.run_task([tasks._b('vm_backup', vms='*', into=str(self.tmp / 'bk'), keep=2, quiesce='auto'),
                           tasks._b('vm_snapshot', vms='*', prefix='n', keep=1, quiesce='auto')], run=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse([c for c in r.calls if any(w in c for w in ('create-as', 'convert', 'delete', 'blockcommit'))])
        self.assertFalse((self.tmp / 'bk').exists())
        self.assertIn('would merge the snapshot back', r.stdout)


class Bash(unittest.TestCase):
    def test_the_functions_parse_and_hold_no_apostrophe(self):
        self.assertEqual(subprocess.run(['bash', '-n'], input=steps_kvm.BASH, text=True, capture_output=True).stderr, '')
        self.assertNotIn("'", steps_kvm.BASH)

    def test_a_plan_of_every_new_step_writes_a_script_that_parses(self):
        tasks_ = [{'type': 'vm-snapshot', 'host': 'h', 'params': {'name': 'web'}},
                  {'type': 'vm-revert', 'host': 'h', 'params': {'name': 'web', 'snapshot': 's1', 'start': True}},
                  {'type': 'vm-edit', 'host': 'h', 'params': {'name': 'web', 'vcpus': '4', 'add_disk': '10G'}},
                  {'type': 'libvirt-network', 'host': 'h', 'params': {'name': 'lab', 'address': '10.5.0.1/24', 'dhcp': '10.5.0.10-10.5.0.20'}},
                  {'type': 'libvirt-pool', 'host': 'h', 'params': {'name': 'vms', 'path': '/srv/vms'}},
                  {'type': 'vm-define', 'host': 'h', 'params': {'name': 'web', 'folder': '/srv/vms', 'disks': 'vda:virtio:qcow2:web-vda.qcow2', 'vcpus': '1', 'memory_mib': '512'}}]
        for t in tasks_:
            ans = changes.EXTRA[t['type']]['ansible'](changes.normalize({'name': 'x', 'tasks': [t]})['tasks'][0])
            self.assertEqual(subprocess.run(['bash', '-n'], input=ans['ansible.builtin.shell']['cmd'], text=True, capture_output=True).stderr, '', t['type'])


if __name__ == '__main__':
    unittest.main()
