"""Vault, ephemeral agent, audit chain, graph, .canvas export and HTTP API.
Run with: python3 -m unittest discover -s tests -v"""
import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from storageforge_index import blueprint, canvas, graph, vault
from storageforge_index.db import Database
from storageforge_index.payloads import (apply_df, apply_fstab, apply_zpool_status, load_structured, node_from_blueprint,
                                         parse_df, parse_fstab, parse_zpool_status)

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples' / 'atlas'
SECRET = b'correct horse battery staple, but longer than 32'
vault.KDF_DEFAULTS = {'time_cost': 1, 'memory_kib': 8192, 'lanes': 1}   # fast Argon2id for tests


def atlas_node():
    node = node_from_blueprint(load_structured(str(EXAMPLES / 'blueprint.json')))
    apply_zpool_status(node, parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text()))
    apply_fstab(node, parse_fstab((EXAMPLES / 'fstab').read_text()))
    apply_df(node, parse_df((EXAMPLES / 'df-h.txt').read_text()))
    return node


def private_pem():
    k = ed25519.Ed25519PrivateKey.generate()
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())


class DBCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-plat-'))
        self.db = Database(str(self.tmp / 'idx.db'))
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class VaultTests(DBCase):
    def unlocked(self, secret=SECRET):
        v = vault.Vault(self.db, self.conn, secret)
        v.init()
        return v.unlock()

    def test_roundtrip_and_no_plaintext_at_rest(self):
        pem = private_pem()
        with self.unlocked() as v:
            info = v.add_key('nas', pem)
            kid = self.conn.scalar('SELECT key_id FROM ssh_keys')
            with v.decrypt_key(kid) as buf:
                got = bytes(buf.view())
            self.assertEqual(serialization.load_ssh_private_key(got, None).public_key().public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(), info['public_key'].rsplit(' ', 1)[0])
        raw = Path(self.db.path).read_bytes()
        self.assertNotIn(b'OPENSSH PRIVATE KEY', raw)
        self.assertNotIn(pem[40:80], raw)

    def test_wrong_secret_is_refused(self):
        self.unlocked().close()
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn, b'x' * 40).unlock()

    def test_tampered_or_swapped_ciphertext_fails(self):
        with self.unlocked() as v:
            v.add_key('a', private_pem())
            v.add_key('b', private_pem())
            (a_id, a_ct), (b_id, b_ct) = self.conn.all('SELECT key_id, ciphertext FROM ssh_keys ORDER BY key_id')
            self.conn.execute('UPDATE ssh_keys SET ciphertext = :c WHERE key_id = :k', {'c': b_ct, 'k': a_id})
            with self.assertRaises(vault.VaultError):
                v.decrypt_key(a_id)          # b's ciphertext is bound to b's UUID
            flipped = bytearray(bytes(b_ct))
            flipped[10] ^= 1
            self.conn.execute('UPDATE ssh_keys SET ciphertext = :c WHERE key_id = :k', {'c': bytes(flipped), 'k': b_id})
            with self.assertRaises(vault.VaultError):
                v.decrypt_key(b_id)

    def test_rotation_rewraps_without_reencrypting(self):
        with self.unlocked() as v:
            v.add_key('a', private_pem())
            before = self.conn.scalar('SELECT ciphertext FROM ssh_keys')
            v.rotate_secret(b'n' * 48)
        self.assertEqual(self.conn.scalar('SELECT ciphertext FROM ssh_keys'), before)
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn, SECRET).unlock()
        with vault.Vault(self.db, self.conn, b'n' * 48).unlock() as v:
            v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys')).wipe()

    def test_binding_specificity_and_actions(self):
        with self.unlocked() as v:
            v.add_key('fleet', private_pem())
            v.add_key('nas', private_pem())
            v.bind('fleet', '10.0.0.0/8', 'scan')
            v.bind('fleet', '10.0.20.0/24', 'ops')
            v.bind('nas', '10.0.20.5', 'root', 2222, 'scan,checksum')
            self.assertEqual(v.resolve('10.0.20.5').user, 'root')
            self.assertEqual(v.resolve('10.0.20.9').user, 'ops')
            self.assertEqual(v.resolve('10.9.9.9').user, 'scan')
            with self.assertRaises(vault.NoBinding):
                v.resolve('10.0.20.9', 'checksum')
            with self.assertRaises(vault.NoBinding):
                v.resolve('192.168.1.1')

    def test_audit_chain_detects_edits(self):
        with self.unlocked() as v:
            log = vault.AuditLog(self.db, self.conn, v.audit_key)
            for i in range(5):
                log.append('test', 'ssh.scan', 'ok', f'h{i}', None, {'i': i})
            self.assertEqual(log.verify(), (True, 5, None))
            with self.assertRaises(Exception):
                self.conn.execute("UPDATE audit_log SET outcome = 'failed'")
            self.conn.execute('DROP TRIGGER audit_log_no_update')
            self.conn.execute("UPDATE audit_log SET target_host = 'forged' WHERE audit_id = 3")
            self.assertEqual(log.verify()[0], False)
            self.assertEqual(log.verify()[2], 3)

    def test_ephemeral_agent_holds_key_only_in_memory(self):
        from storageforge_index import runner
        os.environ['STORAGEFORGE_RUNTIME_DIR'] = str(self.tmp)
        try:
            with self.unlocked() as v:
                info = v.add_key('k', private_pem())
                buf = v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys'))
                with runner.ephemeral_agent(buf) as sock:
                    self.assertEqual(buf.length, 0)                     # plaintext wiped once loaded
                    listed = subprocess.run(['ssh-add', '-l'], env={'SSH_AUTH_SOCK': sock, 'PATH': os.environ['PATH']},
                                            capture_output=True, text=True).stdout
                    self.assertIn(info['fingerprint'], listed)
                    self.assertEqual(oct(os.stat(Path(sock).parent).st_mode & 0o777), '0o700')
                    files = [p for p in Path(sock).parent.iterdir()]
                    self.assertEqual([p.name for p in files], ['agent.sock'])  # no key file anywhere
                self.assertFalse(Path(sock).parent.exists())
        finally:
            del os.environ['STORAGEFORGE_RUNTIME_DIR']


class ShareLineTests(DBCase):
    """A client's NFS and SMB mounts get a line from the server folder they come from, and keep it across rebuilds."""

    def node(self, name, mounts, remotes=()):
        n = node_from_blueprint({'metadata': {'host': name}, 'devices': [], 'pools': []})
        n['mounts'] = [{'target': t, 'kind': 'block', 'fstype': 'ext4', 'source': f'/dev/{name}{i}', 'options': []}
                       for i, t in enumerate(mounts)]
        for src, fs, target in remotes:
            n['mounts'].append({'target': target, 'kind': 'remote', 'fstype': fs, 'source': src, 'options': []})
            n['remotes'].append({'name': src, 'proto': fs, 'endpoint': src, 'mount': target, 'status': 'connected'})
        n['peers'] = {'10.42.0.10': 'server', 'server': 'server', 'client': 'client'}
        return n

    def test_client_mount_lines_to_server_folder(self):
        server = self.node('server', ['/', '/mnt/ssd'])
        server['exports'] = [{'protocol': 'NFS', 'name': '/mnt/ssd/shared', 'path': '/mnt/ssd/shared', 'fromScan': True},
                             {'protocol': 'SMB', 'name': 'media', 'path': '/mnt/ssd/media', 'fromScan': True}]
        graph.save(self.db, self.conn, 'server', *graph.build(server))
        host = next(n for n in graph.load(self.conn)['nodes'] if n['id'] == 'host:server')
        self.assertEqual(host['props']['serves'], 'NFS + SMB')
        client = self.node('client', ['/'], [('10.42.0.10:/mnt/ssd/shared/docker', 'nfs4', '/mnt/shared'),
                                             ('//server/media/tv', 'cifs', '/mnt/tv')])
        client['peer_mounts'] = {'server': ['/', '/mnt/ssd']}
        client['peer_shares'] = {'server': server['exports']}
        graph.save(self.db, self.conn, 'client', *graph.build(client))
        lines = lambda: {(r[0], r[1]): json.loads(r[2]) for r in self.conn.all(
            "SELECT src, dst, props_json FROM graph_edges WHERE src LIKE 'mnt:server:%' AND dst LIKE 'mnt:client:%'")}
        got = lines()
        self.assertEqual(set(got), {('mnt:server:/mnt/ssd', 'mnt:client:/mnt/shared'), ('mnt:server:/mnt/ssd', 'mnt:client:/mnt/tv')})
        self.assertEqual(got[('mnt:server:/mnt/ssd', 'mnt:client:/mnt/tv')]['path'], '/mnt/ssd/media/tv')
        self.assertEqual(got[('mnt:server:/mnt/ssd', 'mnt:client:/mnt/shared')]['share'], 'NFS /mnt/ssd/shared')
        graph.save(self.db, self.conn, 'server', *graph.build(server))         # rebuilding the server keeps them
        self.assertEqual(set(lines()), set(got))


class OpsTests(DBCase):
    def test_deployed_share_is_one_share_and_keeps_its_clients(self):
        scanned = {'metadata': {'host': 'nas'}, 'devices': [], 'pools': [], 'remotes': [], 'links': [], 'protection': [],
                   'exports': [{'protocol': 'NFS', 'name': '/srv/media', 'path': '/srv/media/', 'fromScan': True},
                               {'protocol': 'SMB', 'name': 'Photos', 'path': '/srv/photos', 'fromScan': True}]}
        saved = {'exports': [{'protocol': 'NFSv4.2', 'name': 'media', 'path': '/srv/media'},
                             {'protocol': 'SMB3', 'name': 'photos', 'path': '/srv/photos', 'mounts': [{'host': 'desk', 'path': '/mnt/p'}]}]}
        out = blueprint.merge_intent(scanned, saved)['exports']
        self.assertEqual(len(out), 2)
        self.assertTrue(all(e['fromScan'] and e['designed'] for e in out))
        self.assertEqual(out[1]['mounts'], [{'host': 'desk', 'path': '/mnt/p'}])
        self.assertEqual(blueprint.merge_intent(scanned, {'exports': out})['exports'], out)    # stable when saved again

    def test_one_name_per_host_and_no_scan_burst_after_restart(self):
        from storageforge_index import server
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host, inventory_json) "
                          "VALUES ('cachyos-x8664', '10.42.0.100', '10.42.0.100', '{}')")
        app = server.App(self.db)
        self.assertEqual(app.canonical(self.conn, '10.42.0.100'), 'cachyos-x8664')
        self.assertEqual(app.canonical(self.conn, 'CachyOS-x8664'), 'cachyos-x8664')
        self.assertEqual(app.canonical(self.conn, 'new-host'), 'new-host')
        vlt = vault.Vault(self.db, self.conn, SECRET)
        vlt.init()
        with vlt.unlock() as v:
            v.generate_key('k', 'ed25519')
            v.bind('k', '10.42.0.100', 'archie')
        self.assertEqual(app.due_hosts(3600), ['cachyos-x8664'])        # never scanned: due
        self.conn.execute("INSERT INTO scan_jobs (host, requested_by, queued_at, status) VALUES "
                          "('10.42.0.100', 'scheduler', :t, 'ok')", {'t': int(time.time()) - 600})
        self.assertEqual(app.due_hosts(3600), [])                       # scanned 10 min ago under its IP: not due
        self.assertEqual(app.due_hosts(300), ['cachyos-x8664'])
        self.conn.execute("UPDATE hosts SET last_scanned_at = :t", {'t': int(time.time())})      # a scan run from the CLI
        self.assertEqual(app.due_hosts(300), [])

    def test_backup_restore_and_prune(self):
        from storageforge_index import backup
        vlt = vault.Vault(self.db, self.conn, SECRET)
        vlt.init()
        with vlt.unlock() as v:
            v.generate_key('fleet', 'ed25519')
        self.conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('nas', '{}')")
        hid = self.conn.scalar('SELECT host_id FROM hosts')
        old = int(time.time()) - 200 * 86400
        for sid, t in ((1, old), (2, old + 1)):
            self.conn.execute('INSERT INTO scans (scan_id, host_id, started_at, status) VALUES (:s, :h, :t, \'ok\')', {'s': sid, 'h': hid, 't': t})
            self.conn.execute("INSERT INTO scan_denied (scan_id, mount_point, path) VALUES (:s, '/', '/root')", {'s': sid})
        mid = self.conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type) VALUES (:h, '/', 'ext4') RETURNING mount_id", {'h': hid})
        for sid in (1, 2):
            self.conn.execute("INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename) "
                              "VALUES (:s, :m, 'added', '/', 'x')", {'s': sid, 'm': mid})
        r = self.db.prune(self.conn)
        self.assertEqual((r['changes'], r['denied']), (1, 1))            # the newest scan's rows always stay
        dest = Path(self.tmp) / 'bk'
        dest.mkdir()
        ess = backup.create(self.db, 'essentials', dest, keep=1)
        full = backup.create(self.db, 'full', dest)
        time.sleep(1.1)
        ess2 = backup.create(self.db, 'essentials', dest, keep=1)
        self.assertEqual(ess2['removed'], [ess['path']])
        self.assertEqual({b['kind'] for b in backup.listing(dest)}, {'essentials', 'full'})
        self.conn.close()
        r = backup.restore(self.db, ess2['path'])
        self.assertEqual((r['keys'], r['files']), (1, 0))
        self.assertTrue(Path(r['previous']).exists())
        self.conn = self.db.connect()
        self.assertEqual(self.conn.scalar('SELECT name FROM ssh_keys'), 'fleet')
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM mounts'), 0)          # the index comes back by rescanning
        with self.assertRaises(SystemExit):
            backup.restore(self.db, __file__)                                          # not a backup
        self.assertTrue(Path(full['path']).stat().st_size > Path(ess2['path']).stat().st_size)


class DockerTests(DBCase):
    """Shapes from a real host: a manager in a container (Dockhand) records stack folders as it sees them."""
    ENGINE = '\n'.join([
        '@@engine\tdocker\tdirect', '@@root', '/home/docker/imgs', '@@containers',
        json.dumps({'id': 'a' * 64, 'name': '/dockhand', 'image': 'dockhand', 'state': 'running', 'labels': {'x.secret': 'no'},
                    'mounts': [{'Type': 'volume', 'Name': 'dockhand_data', 'Source': '/home/docker/imgs/volumes/dockhand_data/_data',
                                'Destination': '/app/data', 'RW': True},
                               {'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/var/run/docker.sock', 'RW': True}]}),
        json.dumps({'id': 'b' * 64, 'name': '/jellyfin', 'image': 'jellyfin/jellyfin', 'state': 'running',
                    'labels': {'com.docker.compose.project': 'jellyfin',
                               'com.docker.compose.project.working_dir': '/app/data/stacks/Local/jellyfin',
                               'com.docker.compose.project.config_files': '/app/data/stacks/Local/jellyfin/docker-compose.yml'},
                    'mounts': [{'Type': 'bind', 'Source': '/mnt/data01/media', 'Destination': '/media', 'RW': False},
                               {'Type': 'volume', 'Name': 'jellyfin_cache', 'Source': '/home/docker/imgs/volumes/jellyfin_cache/_data',
                                'Destination': '/cache', 'RW': True}]}),
        '@@volumes',
        json.dumps({'name': 'jellyfin_cache', 'driver': 'local', 'mountpoint': '/home/docker/imgs/volumes/jellyfin_cache/_data', 'options': None}),
        json.dumps({'name': 'old', 'driver': 'local', 'mountpoint': '/home/docker/imgs/volumes/old/_data',
                    'options': {'type': 'cifs', 'o': 'username=g,password=hunter2,vers=3'}}),
        '@@sizes', json.dumps([{'Name': 'old', 'Size': '1.5GB'}, {'Name': 'jellyfin_cache', 'Size': '200MB'}]) + '@@end'])

    def test_engine_compose_stacks_and_usage(self):
        from storageforge_index import docker
        d = docker.parse_engine(self.ENGINE.replace('@@end', '\n@@end'))
        self.assertEqual((d['engine'], d['root_dir'], len(d['containers'])), ('docker', '/home/docker/imgs', 2))
        self.assertEqual(d['containers'][0]['labels'], {})                              # unknown labels are not kept
        old = next(v for v in d['volumes'] if v['name'] == 'old')
        self.assertEqual((old['options']['o'], old['size']), ('username=g,password=***,vers=3', 1_500_000_000))
        self.assertEqual(docker.to_host_path('/app/data/stacks/Local/jellyfin', d['containers']),
                         '/home/docker/imgs/volumes/dockhand_data/_data/stacks/Local/jellyfin')
        stored = docker.parse_compose('/opt/stacks/paperless/compose.yaml', """
name: paperless
services:
  web:
    image: paperless-ngx
    environment: [PAPERLESS_SECRET_KEY=topsecret]
    volumes: ['./data:/usr/src/paperless/data', 'media:/usr/src/paperless/media',
              {type: bind, source: /srv/consume, target: /consume, read_only: true}, '${ROOT}/x:/x']
volumes:
  media: {driver: local, driver_opts: {type: nfs, o: 'addr=10.0.0.5,password=pw', device: ':/srv/media'}}
""")
        self.assertNotIn('topsecret', json.dumps(stored))                               # environment never kept
        vols = stored['services'][0]['volumes']
        self.assertEqual([(v['type'], v.get('source'), v['rw']) for v in vols],
                         [('bind', '/opt/stacks/paperless/data', True), ('volume', 'media', True), ('bind', '/srv/consume', False),
                          ('bind', '${ROOT}/x', True)])
        self.assertTrue(vols[3]['unresolved'])
        self.assertEqual(stored['volumes']['media']['options']['o'], 'addr=10.0.0.5,password=***')
        self.assertIn('error', docker.parse_compose('/x/compose.yml', 'services: [oops'))
        self.conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('tr01', '{}')")
        hid = self.conn.scalar('SELECT host_id FROM hosts')
        self.conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json)
                             VALUES (:h, 'docker', 'direct', :r, :c, :v, :f)""",
                          {'h': hid, 'r': d['root_dir'], 'c': json.dumps(d['containers']), 'v': json.dumps(d['volumes']),
                           'f': json.dumps([stored])})
        [h] = docker.listing(self.conn)
        st = {s['project'] or '-': s for s in h['stacks']}
        self.assertEqual((st['jellyfin']['state'], st['jellyfin']['manager']), ('running', 'Dockhand'))
        self.assertEqual(st['paperless']['state'], 'stored')                               # on disk, nothing deployed
        self.assertTrue(st['-']['socket'])                                                  # dockhand holds the docker socket
        self.assertEqual([v['name'] for v in h['unused_volumes']], ['old'])
        users = docker.users_of(self.conn, 'tr01', '/mnt/data01/media/movies')
        self.assertEqual([(u['container'], u['rw']) for u in users], [('jellyfin', False)])
        self.assertEqual(docker.users_of(self.conn, 'tr01', '/mnt/elsewhere'), [])
        # a move plan touching that folder warns about the running container
        from storageforge_index import moves
        self.conn.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type, total_bytes, used_bytes, scan_state) "
                          "VALUES (:h, '/', 'ext4', 100, 1, 'indexed')", {'h': hid})
        c = moves.check(self.conn, moves.normalize({'name': 'm', 'steps': [
            {'method': 'move', 'src': {'host': 'tr01', 'path': '/mnt/data01/media'}, 'dst': {'host': 'tr01', 'path': '/srv/media'}}]}))
        self.assertTrue(any(i['level'] == 'warn' and 'jellyfin' in i['text'] and 'docker compose -p jellyfin stop' in i['text']
                            for i in c['steps'][0]['items']))


class ChangePlanTests(DBCase):
    LSBLK = {'blockdevices': [
        {'name': 'sda', 'type': 'disk', 'size': 500 * 10**9, 'tran': 'sata', 'children': [
            {'name': 'sda1', 'type': 'part', 'size': 499 * 10**9, 'fstype': 'ext4', 'uuid': 'aaaa', 'mountpoint': '/'}]},
        {'name': 'sdb', 'type': 'disk', 'size': 4 * 10**12, 'tran': 'sata', 'children': [
            {'name': 'sdb1', 'type': 'part', 'size': 4 * 10**12, 'fstype': 'btrfs', 'uuid': 'bbbb'}]},
        {'name': 'sdc', 'type': 'disk', 'size': 2 * 10**12, 'tran': 'usb', 'children': []}]}

    def setUp(self):
        super().setUp()
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', '10.0.0.5', 'scan', :i)",
                          {'i': json.dumps({'lsblk': self.LSBLK})})
        h = self.conn.scalar('SELECT host_id FROM hosts')
        for mp, src, fs in (('/', '/dev/sda1', 'ext4'), ('/mnt/pool', '/dev/sdb1[/@pool]', 'btrfs')):
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, "
                              "scan_state, mount_options) VALUES (:h, :m, :s, :f, 100, 1, 'indexed', 'rw,noatime')",
                              {'h': h, 'm': mp, 's': src, 'f': fs})
        pool = self.conn.scalar("SELECT mount_id FROM mounts WHERE mount_point = '/mnt/pool'")
        for parent, name, d, size in (('/mnt', 'pool', 1, 0), ('/mnt/pool', 'photos', 1, 0), ('/mnt/pool/photos', 'a.jpg', 0, 2048)):
            self.conn.execute("INSERT INTO file_records (mount_id, parent_path, filename, is_directory, file_size_bytes, modified_at) "
                              "VALUES (:m, :p, :n, :d, :s, 0)", {'m': pool, 'p': parent, 'n': name, 'd': d, 's': size})

    def plan(self, *tasks):
        from storageforge_index import changes
        return changes.normalize({'name': 'p', 'tasks': [{'type': k, 'host': 'nas', 'params': p} for k, p in tasks]})

    def levels(self, plan):
        from storageforge_index import changes
        return [[(i['level'], i['text']) for i in t['items']] for t in changes.check(self.conn, plan)['tasks']]

    def has(self, items, level, words):
        return any(l == level and words in t for l, t in items)

    def test_checks_follow_the_plan_order(self):
        r = self.levels(self.plan(
            ('subvolume', {'path': '/mnt/pool/media'}),
            ('dir', {'path': '/mnt/pool/media/films', 'owner': 'gabe', 'mode': '0750'}),   # inside the subvolume staged above
            ('rename', {'path': '/mnt/pool/photos', 'dest': '/mnt/pool/media/photos'}),
            ('rename', {'path': '/mnt/pool/photos', 'dest': '/srv/photos'}),                # already moved by the task above
            ('subvolume', {'path': '/srv/x'}),                                             # ext4
            ('snapshot', {'source': '/mnt/pool', 'dest': '/mnt/pool/.snap-1'}),
            ('trash', {'path': '/mnt/pool/missing'}),
            ('mount', {'source': 'UUID=bbbb', 'subvol': '@media', 'target': '/srv/media', 'fstype': 'btrfs', 'options': 'noatime'}),
            ('mount', {'source': 'UUID=bbbb', 'target': '/mnt/pool', 'fstype': 'btrfs'}),     # already mounted
            ('unmount', {'target': '/'}),
            ('mount-options', {'target': '/mnt/pool', 'options': 'noatime,compress=zstd:3'})))
        self.assertTrue(self.has(r[0], 'ok', 'new subvolume'))
        self.assertFalse([x for x in r[1] if x[0] == 'crit'])
        self.assertTrue(self.has(r[2], 'ok', '1 files') and self.has(r[2], 'note', 'instant rename'))
        self.assertTrue(self.has(r[3], 'crit', 'does not exist'))
        self.assertTrue(self.has(r[4], 'crit', 'not btrfs'))
        self.assertTrue(self.has(r[5], 'ok', 'read-only snapshot'))
        self.assertTrue(self.has(r[6], 'crit', 'does not exist'))
        self.assertTrue(self.has(r[7], 'ok', 'UUID=bbbb is sdb1') and self.has(r[7], 'note', 'nofail'))
        self.assertTrue(self.has(r[8], 'crit', 'already mounted'))
        self.assertTrue(self.has(r[9], 'crit', 'running system'))
        self.assertTrue(self.has(r[10], 'ok', 'now: rw,noatime'))

    def test_drive_tasks_are_guarded(self):
        from storageforge_index import changes
        with self.assertRaises(ValueError):                                  # destructive tasks need the device typed twice
            self.plan(('format', {'device': '/dev/sdc', 'fstype': 'ext4', 'confirm': '/dev/sdb'}))
        with self.assertRaises(ValueError):
            self.plan(('dir', {'path': 'relative/path'}))
        with self.assertRaises(ValueError):
            self.plan(('mount-options', {'target': '/mnt/pool', 'options': 'rw; rm -rf /'}))
        r = self.levels(self.plan(
            ('format', {'device': '/dev/sda1', 'fstype': 'ext4', 'wipe': True, 'confirm': '/dev/sda1'}),
            ('partition', {'disk': '/dev/sdc', 'fstype': 'btrfs', 'label': 'media', 'confirm': '/dev/sdc'}),
            ('format', {'device': '/dev/sdb1', 'fstype': 'xfs', 'confirm': '/dev/sdb1'}),
            ('btrfs-balance', {'target': '/mnt/pool', 'data': 'raid1', 'metadata': 'raid1'}),
            ('label', {'target': '/dev/sdc', 'label': 'way-too-long-for-vfat-x'})))
        self.assertTrue(self.has(r[0], 'crit', 'in use') and self.has(r[0], 'crit', 'operating system disk'))
        self.assertFalse([x for x in r[1] if x[0] == 'crit'])
        self.assertTrue(self.has(r[2], 'crit', 'holds btrfs'))
        self.assertTrue(self.has(r[3], 'crit', 'raid1 needs 2 devices'))
        plan = self.plan(('partition', {'disk': '/dev/sdc', 'fstype': 'btrfs', 'label': 'media', 'confirm': '/dev/sdc'}),
                         ('subvolume', {'path': '/mnt/pool/media', 'nocow': True}),
                         ('mount', {'source': 'UUID=bbbb', 'subvol': '@media', 'target': '/srv/media', 'fstype': 'btrfs'}))
        sh = Path(self.tmp) / 'c.sh'
        sh.write_text(changes.script(self.conn, plan))
        self.assertEqual(subprocess.run(['bash', '-n', str(sh)]).returncode, 0)
        self.assertIn("run 1 nas partition 'Partition /dev/sdc and format it btrfs' /dev/sdc btrfs media ''", sh.read_text())
        import yaml
        plays = yaml.safe_load(changes.ansible(self.conn, plan))
        self.assertEqual([p['hosts'] for p in plays], ['nas'])
        names = [next(k for k in t if '.' in k) for t in plays[0]['tasks']]
        self.assertEqual(names, ['community.general.parted', 'community.general.filesystem', 'ansible.builtin.command',
                                 'ansible.builtin.command', 'ansible.posix.mount'])
        self.assertEqual(plays[0]['tasks'][0]['when'], 'storageforge_destructive | default(false) | bool')
        self.assertEqual(plays[0]['tasks'][4]['ansible.posix.mount']['opts'], 'subvol=@media')

    def test_api(self):
        from storageforge_index import server, users
        users.create(self.conn, 'alice', 'a long enough password')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        self.assertIn('format', client.get('/api/changes/types').json['types'])
        body = {'name': 'Tidy', 'tasks': [{'type': 'dir', 'host': 'nas', 'params': {'path': '/mnt/pool/new'}}]}
        pid = client.post('/api/changes', json=body).json['id']
        self.assertEqual(client.post('/api/changes/check', json=body).json['crit'], 0)
        r = client.get(f'/api/changes/{pid}/ansible')
        self.assertIn('attachment; filename="changes-tidy.yml"', r.headers['Content-Disposition'])
        self.assertIn(b'ansible.builtin.file', r.data)
        self.assertEqual(client.get(f'/api/changes/{pid}/script').status_code, 200)
        self.assertEqual(client.delete(f'/api/changes/{pid}').status_code, 200)
        self.assertEqual(client.get('/changes.js').status_code, 200)


class ConnectAddressTests(DBCase):
    def test_indexed_hostname_maps_to_the_address_it_was_scanned_at(self):
        from storageforge_index.runner import connect_address
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host, inventory_json) "
                          "VALUES ('cachyos-x8664', '10.42.0.100', '10.42.0.100', '{}')")
        self.assertEqual(connect_address(self.conn, 'cachyos-x8664'), '10.42.0.100')
        self.assertEqual(connect_address(self.conn, 'CachyOS-x8664'), '10.42.0.100')
        self.assertEqual(connect_address(self.conn, '10.42.0.100'), '10.42.0.100')
        self.assertEqual(connect_address(self.conn, 'never-scanned'), 'never-scanned')


class GraphTests(DBCase):
    def test_atlas_graph(self):
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        kinds = {n['kind'] for n in nodes.values()}
        self.assertEqual(kinds, set(graph.KINDS))
        rels = {e['rel'] for e in edges}
        self.assertEqual(rels, set(graph.RELS))
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/vm']['health'], 'broken')
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/photos']['health'], 'protected')
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/media']['health'], 'local-only')
        loop = {(e['src'], e['dst']) for e in edges if e['rel'] == 'SYMLINK_TO' and e['src'].startswith('link:atlas:/opt')}
        self.assertEqual(loop, {('link:atlas:/opt/app/current', 'link:atlas:/opt/app/releases/live'),
                                ('link:atlas:/opt/app/releases/live', 'link:atlas:/opt/app/current')})
        self.assertIn('host:nas-02.tail4c2e.ts.net', {e['dst'] for e in edges if e['rel'] == 'REPLICATES_TO'})
        self.assertNotIn('host:nas-02 nightly 02:30', nodes)

    def test_remote_server_that_is_also_scanned_links_to_its_host(self):
        node = atlas_node()
        node['peers'] = {'nas-02.tail4c2e.ts.net': 'nas-02', 'nas-02': 'nas-02'}
        nodes, edges = graph.build(node, dt.date(2026, 10, 26))
        self.assertEqual(nodes['host:nas-02']['host'], 'nas-02')          # owned by nas-02, not an external stub
        self.assertNotIn('host:nas-02.tail4c2e.ts.net', nodes)
        self.assertTrue(any(e['dst'] == 'host:nas-02' or e['src'] == 'host:nas-02' for e in edges))
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, props_json, updated_at) "
                          "VALUES ('host:nas-02', 'Host', 'nas-02', 'nas-02', '{\"ip\": \"10.0.0.2\"}', 0)")
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        self.assertEqual(self.conn.scalar("SELECT props_json FROM graph_nodes WHERE node_id = 'host:nas-02'"),
                         '{"ip": "10.0.0.2"}')                              # atlas's build never overwrites it
        into = {(e['src'], e['dst'], e['rel']) for e in edges if 'host:nas-02' in (e['src'], e['dst'])}
        nas = node_from_blueprint({'metadata': {'host': 'nas-02'}, 'devices': [], 'pools': []})
        graph.save(self.db, self.conn, 'nas-02', *graph.build(nas))         # rebuilding nas-02 itself...
        kept = set(self.conn.all("SELECT src, dst, rel FROM graph_edges WHERE src = 'host:nas-02' OR dst = 'host:nas-02'"))
        self.assertEqual(kept, into)                                         # ...keeps atlas's edges into it
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        self.assertEqual(set(self.conn.all("SELECT src, dst, rel FROM graph_edges WHERE src = 'host:nas-02' OR dst = 'host:nas-02'")), into)

    def test_save_load_and_canvas(self):
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        graph.save(self.db, self.conn, 'atlas', nodes, edges)          # idempotent rebuild
        g = graph.load(self.conn)
        self.assertEqual(len(g['nodes']), len(nodes))
        c = canvas.to_canvas(g)
        ids = [n['id'] for n in c['nodes']]
        self.assertEqual(len(ids), len(set(ids)))
        for n in c['nodes']:
            self.assertIn(n['type'], ('text', 'group'))
            for k in ('x', 'y', 'width', 'height'):
                self.assertIsInstance(n[k], int)
        for e in c['edges']:
            self.assertIn(e['fromNode'], ids)
            self.assertIn(e['toNode'], ids)
            self.assertIn(e['fromSide'], ('left', 'right'))
        text_nodes = [n for n in c['nodes'] if n['type'] == 'text']
        boxes = [(n['x'], n['y'], n['x'] + n['width'], n['y'] + n['height']) for n in text_nodes]
        for i, a in enumerate(boxes):                                    # layout never overlaps cards
            for b in boxes[i + 1:]:
                self.assertFalse(a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3], (a, b))
        json.loads(canvas.dumps(g))


class BlueprintTests(DBCase):
    def test_from_node_round_trips_through_the_indexer(self):
        bp = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        self.assertEqual((bp['apiVersion'], bp['metadata']['host']), ('storageforge/v1', 'atlas'))
        self.assertTrue(all(d['dev'].startswith('/dev/') for d in bp['devices']))
        pools = {p['name']: p for p in bp['pools']}
        self.assertEqual((pools['tank']['type'], pools['tank']['level']), ('zfs', 'raidz2'))
        nodes = {r['node'] for r in bp['protection']}
        self.assertIn('ds:tank/media', nodes)
        self.assertTrue(all(r['sync']['state'] == 'None' for r in bp['protection']))
        node = node_from_blueprint(json.loads(json.dumps(bp)))       # the graph/report side reads it back
        self.assertEqual({p['name'] for p in node['pools']}, set(pools))

    def test_merge_keeps_operator_intent(self):
        scanned = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        saved = json.loads(json.dumps(scanned))
        saved['devices'][0]['tier'] = 'remote'
        row = next(r for r in saved['protection'] if r['node'] == 'ds:tank/media')
        row['backup'] = {'target': 'restic → B2', 'enc': 'age', 'ratio': 1.2, 'last': '2026-10-20', 'offsite': True}
        saved['protection'].append({'node': 'ds:gone/x', 'dataset': 'gone/x', 'sync': {'state': 'None'}, 'backup': {}})
        saved['exports'] = [{'protocol': 'SMB3', 'name': 'photos', 'path': '/mnt/storage_array/photos'}]
        saved['links'].append({'kind': 'symlink', 'path': '/srv/planned', 'target': '/mnt/storage_array/media'})
        out = blueprint.merge_intent(scanned, saved)
        self.assertEqual(out['devices'][0]['tier'], 'remote')
        self.assertEqual(next(r for r in out['protection'] if r['node'] == 'ds:tank/media')['backup']['target'], 'restic → B2')
        self.assertIn('ds:gone/x', {r['node'] for r in out['protection']})
        self.assertEqual([{k: v for k, v in e.items() if k not in ('designed', 'fromScan')} for e in out['exports']], saved['exports'])
        self.assertTrue(all(e['designed'] and not e['fromScan'] for e in out['exports']))     # designed, not deployed yet
        self.assertIn('/srv/planned', {l['path'] for l in out['links']})
        self.assertEqual(out['metadata']['source'], 'scan+design')


class ServerTests(DBCase):
    def setUp(self):
        super().setUp()
        from storageforge_index import server, users
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        users.create(self.conn, 'alice', 'a long enough password')
        self.web = server.create_app(server.App(self.db), 's' * 48)
        self.client = self.web.test_client()

    def login(self, password='a long enough password', username='Alice'):
        return self.client.post('/api/login', json={'username': username, 'password': password})

    def test_health_auth_graph_canvas_ui(self):
        r = self.client.get('/healthz')
        self.assertEqual((r.status_code, r.json['status'], r.json['users']), (200, 'ok', 1))
        self.assertEqual(self.client.get('/api/graph').status_code, 401)
        self.assertEqual(self.login('wrong password!!').status_code, 401)
        self.assertEqual(self.login(username='nobody').status_code, 401)
        r = self.login()
        self.assertEqual((r.status_code, r.json['username']), (200, 'alice'))
        cookie = r.headers['Set-Cookie']
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        self.assertEqual(self.client.get('/api/me').json['username'], 'alice')
        r = self.client.get('/api/graph?host=atlas')
        self.assertGreater(len(r.json['nodes']), 40)
        self.assertIn("default-src 'self'", r.headers['Content-Security-Policy'])
        r = self.client.get('/api/canvas')
        self.assertIn('attachment', r.headers['Content-Disposition'])
        self.assertIn('nodes', json.loads(r.data))
        self.assertIn(b'<canvas id="graph"', self.client.get('/').data)
        self.assertEqual(self.client.get('/app.js').status_code, 200)
        self.assertEqual(self.client.get('/server.py').status_code, 404)
        self.client.post('/api/logout')
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        actions = [(e['action'], e['outcome']) for e in vault.AuditLog(self.db, self.conn, None).tail(10)]
        self.assertEqual(actions.count(('web.login', 'denied')), 2)
        self.assertIn(('web.login', 'ok'), actions)

    def test_password_change_and_disable_end_sessions(self):
        from storageforge_index import users
        self.login()
        users.set_password(self.conn, 'alice', 'another long password')
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.login('another long password').status_code, 200)
        users.set_disabled(self.conn, 'alice', True)
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.assertEqual(self.login('another long password').status_code, 401)

    def test_scan_requires_json_and_session(self):
        self.assertEqual(self.client.post('/api/scan', json={'host': 'nas-02'}).status_code, 401)
        self.login()
        self.assertEqual(self.client.post('/api/scan', data='host=nas-02',
                                          content_type='application/x-www-form-urlencoded').status_code, 400)
        r = self.client.post('/api/scan', json={'host': 'nas-02'})
        self.assertEqual(r.status_code, 202)
        job = self.client.get('/api/jobs').json['jobs'][-1]
        self.assertEqual((job['job_id'], job['requested_by']), (r.json['job_id'], 'web:alice'))
        self.assertEqual(self.client.post('/api/scan', json={'host': 'x' * 5000}).status_code, 413)

    def test_failed_logins_are_rate_limited(self):
        from storageforge_index import users
        users.create(self.conn, 'bob', 'bob has a long password')
        for _ in range(4):
            self.assertEqual(self.login('wrong password!!').status_code, 401)
        self.assertEqual(self.login().status_code, 200)              # successes are not counted
        self.assertEqual(self.login('wrong password!!').status_code, 401)
        r = self.login()                                              # 5 failures for alice: locked even with the right one
        self.assertEqual(r.status_code, 429)
        self.assertIn('too many failed sign-ins', r.json['error'])
        self.assertIn('Retry-After', r.headers)
        for _ in range(4):                                            # bob is still open: 9 failures from this IP
            self.assertEqual(self.login('wrong password!!', 'bob').status_code, 401)
        self.assertEqual(self.login('wrong password!!', 'carol').status_code, 401)   # 10th
        self.assertEqual(self.login('bob has a long password', 'bob').status_code, 429)

    def test_key_generate_and_install_routes(self):
        from unittest import mock
        from storageforge_index import keyinstall
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        try:
            vault.Vault(self.db, self.conn, SECRET).init()
            self.login()
            r = self.client.post('/api/keys', json={'name': 'fleet', 'type': 'ed25519'})
            self.assertEqual(r.status_code, 201)
            self.assertTrue(r.json['public_key'].startswith('ssh-ed25519 '))
            self.assertEqual(self.client.post('/api/keys', json={'name': 'fleet'}).status_code, 400)
            self.assertEqual(self.client.post('/api/keys', json={'name': '../x'}).status_code, 400)
            body = {'key': 'fleet', 'host': 'nas-02', 'user': 'scan', 'port': 22, 'password': 'pw', 'bind': True}
            for bad in ({'host': '-oProxyCommand=sh'}, {'user': '-l'}, {'port': 70000}, {'key': 'missing'}):
                self.assertEqual(self.client.post('/api/keys/install', json=body | bad).status_code, 400, bad)
            calls = []
            def fake_install(public, host, user, password, port):
                calls.append((public, host, user, password, port))
                return {'host': host, 'user': user, 'port': port, 'keys_added': 1}
            works = iter([False, True, True])
            with mock.patch.object(keyinstall, 'install_public_key', fake_install), \
                 mock.patch.object(keyinstall, 'key_login_works', lambda *a: next(works)):
                r = self.client.post('/api/keys/install', json=body)
                self.assertEqual((r.status_code, r.json['verified'], r.json['keys_added']), (200, True, 1))
                bid = r.json['binding_id']
                r = self.client.post('/api/keys/install', json=body)         # key already works: no second copy
                self.assertEqual((r.json['keys_added'], r.json['binding_id']), (0, bid))
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][0].startswith('ssh-ed25519 '))           # only the public key goes to ssh-copy-id
            keys = self.client.get('/api/keys').json
            self.assertEqual([(b['pattern'], b['user'], b['actions']) for b in keys['bindings']], [('nas-02', 'scan', 'scan')])
            self.assertNotIn('ciphertext', json.dumps(keys))
            with mock.patch.object(keyinstall, 'key_login_works', lambda *a: False), \
                 mock.patch.object(keyinstall, 'install_public_key',
                                   mock.Mock(side_effect=keyinstall.InstallError('Permission denied'))):
                self.assertEqual(self.client.post('/api/keys/install', json=body).status_code, 502)
            audit = json.dumps(vault.AuditLog(self.db, self.conn, None).tail(20))
            self.assertIn('ssh.copy-id', audit)
            self.assertNotIn('"pw"', audit)
        finally:
            del os.environ['STORAGEFORGE_VAULT_SECRET']

    def test_askpass_answers_password_prompts_only(self):
        from storageforge_index import askpass
        from unittest import mock
        import io
        with mock.patch.dict(os.environ, {'STORAGEFORGE_ASKPASS_SECRET': 's3cret'}):
            for prompt, code, out in (("scan@nas's password: ", 0, 's3cret\n'), ('Password: ', 0, 's3cret\n'),
                                      ("Enter passphrase for key 'id': ", 1, ''),
                                      ('Are you sure you want to continue connecting (yes/no)? ', 1, '')):
                with mock.patch('sys.argv', ['askpass', prompt]), mock.patch('sys.stdout', io.StringIO()) as so:
                    self.assertEqual((askpass.main(), so.getvalue()), (code, out), prompt)

    def test_access_and_duplicate_folder_api(self):
        self.assertEqual(self.client.get('/api/access').status_code, 401)
        self.login()
        self.assertEqual(self.client.get('/api/access').json, {'hosts': []})
        r = self.client.get('/api/access/script?user=scan')
        self.assertEqual(r.status_code, 200)
        self.assertIn('U=scan', r.json['script'])
        self.assertEqual(self.client.get('/api/access/script?user=bad;user').status_code, 400)
        self.assertEqual(self.client.post('/api/access/grant', json={'host': 'nas', 'password': ''}).status_code, 400)
        r = self.client.get('/api/folders/duplicates')
        self.assertEqual((r.status_code, r.json['groups']), (200, []))
        for name in ('checks.js', 'topology.js'):
            self.assertEqual(self.client.get('/' + name).status_code, 200)

    def test_move_plan_api(self):
        self.assertEqual(self.client.get('/api/moves').status_code, 401)
        self.login()
        self.assertEqual(self.client.get('/api/moves').json, {'plans': []})
        self.assertEqual(self.client.post('/api/moves', json={'name': '', 'steps': []}).status_code, 400)
        body = {'name': 'Media', 'steps': [{'method': 'mirror', 'src': {'host': 'nas', 'path': '/srv/media'},
                                            'dst': {'host': 'atlas', 'path': '/mnt/media'}, 'options': {'delete': True}}]}
        r = self.client.post('/api/moves', json=body)
        self.assertEqual(r.status_code, 201)
        pid = r.json['id']
        self.assertTrue(r.json['steps'][0]['options']['delete'])
        r = self.client.post('/api/moves/check', json=body)
        self.assertEqual(r.json['crit'], 2)                              # neither host has been scanned here
        r = self.client.get(f'/api/moves/{pid}/script')
        self.assertEqual(r.status_code, 200)
        self.assertIn('attachment; filename="media.sh"', r.headers['Content-Disposition'])
        self.assertIn(b'S_METHOD=(mirror)', r.data)
        self.assertEqual(self.client.put(f'/api/moves/{pid}', json={**body, 'name': 'Media 2'}).json['name'], 'Media 2')
        self.assertEqual(self.client.delete(f'/api/moves/{pid}').status_code, 200)
        self.assertEqual(self.client.get(f'/api/moves/{pid}').status_code, 404)
        self.assertEqual(self.client.get('/moves.js').status_code, 200)

    def test_git_shares_and_cold_api(self):
        self.login()
        self.assertEqual(self.client.get('/api/git').json['repos'], [])
        self.assertEqual(self.client.get('/api/shares/check?host=nowhere').status_code, 404)
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host, ssh_user, inventory_json) VALUES "
                          "('nas', '10.0.0.5', '10.0.0.5', 'root', '{}'), ('desk', '10.0.0.6', '10.0.0.6', 'me', '{}')")
        graph.store_blueprint(self.conn, {'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint', 'metadata': {'host': 'nas'},
                                          'exports': [{'protocol': 'NFS', 'name': '/srv/a', 'path': '/srv/a', 'clients': ''},
                                                      {'protocol': 'SMB3', 'name': 'media', 'path': '/srv/media', 'clients': 'gabe',
                                                       'mounts': [{'host': 'desk', 'path': '/mnt/media'}]}]})
        c = self.client.get('/api/shares/check?host=nas').json
        self.assertEqual(c['crit'], 1)                                  # NFS without clients
        self.assertTrue(any('Samba accounts needed: gabe' in x['text'] for x in c['items']))
        r = self.client.get('/api/shares/script?host=nas')
        self.assertIn('attachment; filename="shares-nas.sh"', r.headers['Content-Disposition'])
        self.assertIn(b"C_SOURCE=(//10.0.0.5/media)", r.data)
        self.assertEqual(self.client.get('/api/folders/cold?years=1').json['folders'], [])
        self.assertEqual(self.client.get('/gitview.js').status_code, 200)
        self.assertEqual(self.client.get('/dockerview.js').status_code, 200)
        self.assertEqual(self.client.get('/api/docker').json, {'hosts': []})
        self.assertEqual(self.client.get('/api/docker/usage?path=/x').status_code, 400)     # path needs host

    def test_planner_page_and_designs(self):
        r = self.client.get('/planner')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'/planner.js', r.data)
        csp = r.headers['Content-Security-Policy']
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn('unsafe-inline', csp.split('style-src-attr')[0])        # only style attributes are relaxed
        self.assertNotIn(b'<style', self.client.get('/planner.js').data)
        self.assertEqual(self.client.get('/api/planner/hosts').status_code, 401)
        self.login()
        self.assertEqual(self.client.get('/api/planner/design?host=nowhere').status_code, 404)
        bp = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        bp['metadata']['host'] = 'planned-01'
        bp['exports'] = [{'protocol': 'NFSv4.2', 'name': 'media', 'path': '/mnt/storage_array/media'}] * 40  # > 4 KiB
        r = self.client.put('/api/planner/design', json=bp)
        self.assertEqual(r.status_code, 200, r.json)
        self.assertGreater(r.json['graph']['nodes'], 10)
        self.assertIn('host:planned-01', {n['id'] for n in self.client.get('/api/graph?host=planned-01').json['nodes']})
        hosts = {h['host']: h for h in self.client.get('/api/planner/hosts').json['hosts']}
        self.assertTrue(hosts['planned-01']['saved'])
        self.assertFalse(hosts['planned-01']['scanned'])
        got = self.client.get('/api/planner/design?host=planned-01').json
        self.assertEqual((got['source'], len(got['blueprint']['exports'])), ('saved', 40))
        self.assertEqual(self.client.put('/api/planner/design', json={'kind': 'x'}).status_code, 400)
        self.assertEqual(self.client.post('/api/scan', json={'host': 'x' * 5000}).status_code, 413)   # other routes keep 4 KiB

    def test_user_rules(self):
        from storageforge_index import users
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'ALICE', 'a long enough password')     # case-insensitive unique
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'bob', 'short')
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'bob smith', 'a long enough password')
        stored = self.conn.scalar("SELECT password_hash FROM users WHERE username = 'alice'")
        self.assertTrue(stored.startswith('scrypt:'))
        self.assertNotIn('a long enough password', stored)


if __name__ == '__main__':
    unittest.main()
