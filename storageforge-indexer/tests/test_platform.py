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

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import blueprint, canvas, graph, vault
from storageforge_index.db import Database, dir_id
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
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
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
        raw = Path(self.db.path).read_bytes() if self.db.dialect == 'sqlite' else b''.join(
            str(r).encode() for r in self.conn.all('SELECT * FROM ssh_keys'))
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
            self.conn.execute('DROP TRIGGER audit_log_no_update' + ('' if self.db.dialect == 'sqlite' else ' ON audit_log'))
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
        self.conn.execute(f"UPDATE hosts SET last_scanned_at = {self.db.ts(':t')}", {'t': int(time.time())})      # a scan run from the CLI
        self.assertEqual(app.due_hosts(300), [])

    @unittest.skipIf(dbfactory.PG, 'backups are of SQLite databases (PostgreSQL: pg_dump)')
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
        self.conn.execute('INSERT INTO scans (scan_id, host_id, started_at, status) VALUES (3, :h, :t, \'ok\')',
                          {'h': hid, 't': int(time.time())})
        for sid in (2, 3, 3):
            self.conn.execute("INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename) "
                              "VALUES (:s, :m, 'added', '/', 'y')", {'s': sid, 'm': mid})
        r = self.db.prune(self.conn, max_change_rows=2)                 # scan 2 is over the cap and no longer the newest
        self.assertEqual(r['changes'], 2)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM file_changes'), 2)
        for i in range(2000):                                            # index data: in full backups only
            self.conn.execute("INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename) "
                              "VALUES (3, :m, 'added', '/data', :f)", {'m': mid, 'f': f'file-{i:05}.jpg'})
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
            self.conn.execute("INSERT INTO file_records (mount_id, dir_id, filename, is_directory, file_size_bytes, modified_at) "
                              f"VALUES (:m, :p, :n, :d, :s, {self.db.ts('0')})",
                              {'m': pool, 'p': dir_id(self.conn, pool, parent), 'n': name, 'd': bool(d), 's': size})

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
        from storageforge_index import blueprint
        bp = blueprint.from_index(self.conn, 'nas')
        bp['links'].append({'kind': 'symlink', 'path': '/srv/photos', 'target': '/mnt/pool/photos'})
        r = client.post('/api/planner/changes', json=bp)
        self.assertEqual([t['type'] for t in r.json['tasks']], ['symlink'])
        bp['metadata']['host'] = 'never-scanned'
        self.assertEqual(client.post('/api/planner/changes', json=bp).status_code, 409)
        self.assertEqual(client.post('/api/planner/changes', json={'kind': 'x'}).status_code, 400)

    def design(self):
        from storageforge_index import blueprint
        return blueprint.from_index(self.conn, 'nas')

    def test_design_without_edits_needs_no_changes(self):
        from storageforge_index import fromdesign
        r = fromdesign.plan(self.conn, self.design())
        self.assertEqual((r['host'], r['tasks'], r['manual'], r['left']), ('nas', [], [], []))

    def test_design_edits_become_change_tasks(self):
        from storageforge_index import changes, fromdesign
        bp = self.design()
        disks = {d['dev']: d for d in bp['devices']}
        disks['/dev/sdc']['partitions'] = [{'id': 'sdc1', 'fs': 'ext4', 'label': 'backup', 'mount': '/mnt/backup',
                                            'options': ['noatime', 'nofail']}]
        sdb1 = disks['/dev/sdb']['partitions'][0]
        sdb1['subvolumes'].append({'name': '@media', 'mount': '/srv/media'})
        sdb1['options'] = ['noatime', 'compress=zstd:3']
        disks['/dev/sda']['partitions'][0]['fs'] = 'xfs'                       # reformat the system disk: never a task
        bp['pools'].append({'name': 'tank', 'type': 'zfs', 'level': 'mirror', 'members': ['sdd', 'sde']})
        bp['remotes'].append({'name': 'nas-02', 'protocol': 'NFSv4.2', 'endpoint': 'nas-02:/export/archive',
                              'mount': '/mnt/archive', 'options': ['_netdev']})
        bp['links'] += [{'kind': 'symlink', 'path': '/srv/photos', 'target': '/mnt/pool/photos'},
                        {'kind': 'bind', 'path': '/srv/www', 'target': '/mnt/pool/www'}]
        r = fromdesign.plan(self.conn, bp)
        self.assertEqual([t['type'] for t in r['tasks']], ['partition', 'mount', 'mount', 'mount', 'symlink'])
        part = r['tasks'][0]['params']
        self.assertEqual((part['disk'], part['fstype'], part['label'], part['wipe'], part['confirm']),
                         ('/dev/sdc', 'ext4', 'backup', False, ''))         # the device is typed again in Changes
        mounts = {t['params']['target']: t['params'] for t in r['tasks'] if t['type'] == 'mount'}
        self.assertEqual(mounts['/mnt/backup']['source'], 'LABEL=backup')       # no UUID until it exists
        self.assertEqual((mounts['/srv/media']['source'], mounts['/srv/media']['subvol']), ('UUID=bbbb', '@media'))
        self.assertEqual((mounts['/mnt/archive']['fstype'], mounts['/mnt/archive']['options']), ('nfs4', '_netdev,nofail'))
        manual = ' | '.join(f'{m["what"]}: {m["why"]}' for m in r['manual'])
        for words in ('ext4 → xfs', 'Create ZFS pool tank', 'Subvolume @media', 'bind /srv/www'):
            self.assertIn(words, manual)
        self.assertEqual(r['destructive'], 1)
        with self.assertRaises(ValueError):                                     # unconfirmed drive tasks can't be saved
            changes.normalize({'name': r['name'], 'tasks': r['tasks']})
        r['tasks'][0]['params']['confirm'] = '/dev/sdc'
        plan = changes.normalize({'name': r['name'], 'tasks': r['tasks']})
        res = changes.check(self.conn, plan)
        self.assertEqual(len(res['tasks']), 5)
        self.assertIn("partition 'Partition /dev/sdc and format it ext4' /dev/sdc ext4 backup ''", changes.script(self.conn, plan))

    def test_design_never_partitions_disks_that_have_partitions(self):
        from storageforge_index import fromdesign
        bp = self.design()
        sdb = next(d for d in bp['devices'] if d['dev'] == '/dev/sdb')
        sdb['partitions'] = [{'id': 'sdb2', 'fs': 'xfs', 'mount': '/data'}]
        r = fromdesign.plan(self.conn, bp)
        self.assertEqual(r['tasks'], [])
        self.assertIn('already has partitions', r['manual'][0]['why'])

    def test_design_text_cannot_reach_a_script(self):
        from storageforge_index import changes, fromdesign
        bp = self.design()
        bp['links'].append({'kind': 'symlink', 'path': '/srv/x\nrm -rf /', 'target': '/mnt/pool'})
        r = fromdesign.plan(self.conn, bp)
        with self.assertRaises(ValueError):                                     # the field checks every saved plan gets
            changes.normalize({'name': r['name'], 'tasks': r['tasks']})


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
        import base64, hashlib
        from unittest import mock
        from storageforge_index import hostkeys, keyinstall
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        os.environ['STORAGEFORGE_DATA_DIR'] = str(self.tmp / 'data')      # known_hosts lives here, never in ~
        blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
        line = 'nas-02 ssh-ed25519 ' + base64.b64encode(blob).decode()
        fp = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        presented = [{'type': 'ssh-ed25519', 'fingerprint': fp, 'line': line}]
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
            works, probes = iter([False, True, True]), []
            with mock.patch.object(keyinstall, 'install_public_key', fake_install), \
                 mock.patch.object(hostkeys, 'offered', lambda *a: presented), \
                 mock.patch.object(keyinstall, 'key_login_works', lambda *a: probes.append(a) or next(works)):
                r = self.client.post('/api/keys/install', json=body)         # nobody checked nas-02's key yet
                self.assertEqual((r.status_code, r.json['hostkey']['keys'][0]['fingerprint'], r.json['hostkey']['pinned']),
                                 (409, fp, False))
                self.assertEqual(calls, [])                                   # so no password went anywhere
                self.assertEqual(probes, [])                                  # nor a connection that would pin its key
                wrong = {'host': 'nas-02', 'port': 22, 'fingerprint': 'SHA256:' + 'A' * 43}
                self.assertEqual(self.client.post('/api/hostkey/confirm', json=wrong).status_code, 400)
                r = self.client.post('/api/hostkey/confirm', json={'host': 'nas-02', 'port': 22, 'fingerprint': fp})
                self.assertEqual(r.status_code, 200)
                self.assertIn(line, (self.tmp / 'data' / 'ssh' / 'known_hosts').read_text())   # pinned
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
            if shutil.which('ssh-agent'):
                made = []
                class Probe(keyinstall.Transport):
                    def run(self, script, timeout=120):
                        made.append(self.argv(script))
                        raise keyinstall.RemoteError('refused')
                with mock.patch.object(keyinstall, 'Transport', Probe):
                    self.assertFalse(keyinstall.key_login_works(self.db, self.conn, 'fleet', 'nas-02', 'scan', 22))
                self.assertIn('StrictHostKeyChecking=yes', made[0])          # the probe never pins a key (GM-04)
            audit = json.dumps(vault.AuditLog(self.db, self.conn, None).tail(20))
            self.assertIn('ssh.copy-id', audit)
            self.assertIn('ssh.hostkey.confirm', audit)
            self.assertNotIn('"pw"', audit)
        finally:
            del os.environ['STORAGEFORGE_VAULT_SECRET']
            del os.environ['STORAGEFORGE_DATA_DIR']

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
        self.assertEqual(self.client.get('/planner').status_code, 302)          # signed out: to /login
        self.login()
        r = self.client.get('/planner')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'/planner.js', r.data)
        csp = r.headers['Content-Security-Policy']
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn('unsafe-inline', csp.split('style-src-attr')[0])        # only style attributes are relaxed
        self.assertNotIn(b'<style', self.client.get('/planner.js').data)
        self.client.post('/api/logout')
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

    def test_planner_example_and_activity(self):
        self.login()
        self.assertTrue(self.client.get('/api/planner/hosts').json['example'])
        self.assertEqual(self.client.put('/api/planner/example', json={'show': False}).json, {'example': False})
        self.assertFalse(self.client.get('/api/planner/hosts').json['example'])
        self.client.put('/api/planner/example', json={'show': True})
        self.assertTrue(self.client.get('/api/planner/hosts').json['example'])
        self.assertEqual(self.client.get('/api/planner/activity').status_code, 400)
        self.client.post('/api/changes', json={'name': 'tidy', 'tasks': [
            {'type': 'dir', 'host': 'nas-02', 'params': {'path': '/srv/new'}},
            {'type': 'dir', 'host': 'elsewhere', 'params': {'path': '/srv/other'}}]})
        a = self.client.get('/api/planner/activity?host=nas-02.lan').json      # short names match
        self.assertEqual([(p['name'], p['tasks'], p['types']) for p in a['changes']], [('tidy', 1, ['Create folder'])])
        self.assertEqual((a['moves'], a['jobs'], a['deployed'], a['shares']), ([], [], [], None))

    def later(self, seconds):
        from unittest import mock
        return mock.patch('storageforge_index.server.time.time', return_value=time.time() + seconds)

    def test_session_ends_after_its_length(self):
        self.login()
        me = self.client.get('/api/me').json
        self.assertEqual((me['session_minutes'], me['max_minutes']), (30, 480))
        with self.later(29 * 60):
            self.assertEqual(self.client.get('/api/me').status_code, 200)
        with self.later(31 * 60):
            r = self.client.get('/api/me')
            self.assertEqual(r.status_code, 401)
            self.assertIn('session ended', r.json['error'])
        self.login()
        for bad in (10, 481, 'x'):
            self.assertEqual(self.client.put('/api/me', json={'session_minutes': bad}).status_code, 400)
        self.assertEqual(self.client.put('/api/me', json={'session_minutes': 240}).json['session_minutes'], 240)
        with self.later(3 * 3600):
            self.assertEqual(self.client.get('/api/me').status_code, 200)
        with self.later(4 * 3600 + 60):
            self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.client.post('/api/logout')
        self.assertEqual(self.client.get('/api/me').status_code, 401)

    def test_pages_need_a_session_and_send_strangers_to_login(self):
        for path, nxt in (('/', '%2F'), ('/planner', '%2Fplanner'), ('/index.html?x=1', '%2Findex.html%3Fx%3D1')):
            r = self.client.get(path)
            self.assertEqual((r.status_code, r.headers['Location']), (302, f'/login?next={nxt}'), path)
        for name in ('session.js', 'app.js', 'topology.js', 'planner.js', 'planner.css'):
            self.assertEqual(self.client.get('/' + name).status_code, 401, name)
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'/login.js', r.data)
        self.assertEqual(r.headers['Cache-Control'], 'no-store')
        for name in ('login.js', 'style.css', 'favicon.svg'):
            self.assertEqual(self.client.get('/' + name).status_code, 200, name)
        self.login()
        r = self.client.get('/')
        self.assertEqual((r.status_code, r.headers['Cache-Control']), (200, 'no-store'))
        self.assertNotIn(b'id="password"', r.data)                               # no sign-in form in the app page
        for nxt, where in (('/planner#x', '/planner#x'), ('//evil.example/', '/'), ('/\\evil.example', '/'),
                           ('https://evil.example/', '/')):
            self.assertEqual(self.client.get('/login', query_string={'next': nxt}).headers['Location'], where, nxt)
        with self.later(31 * 60):
            r = self.client.get('/planner')
            self.assertEqual(r.headers['Location'], '/login?next=%2Fplanner&ended=1')

    def test_every_route_needs_a_session_unless_listed(self):
        """A new route that forgets @login_required fails here, not in production."""
        import re
        public = {('GET', '/login'), ('GET', '/healthz'), ('POST', '/api/logout'), ('POST', '/api/login'),
                  ('GET', '/<any("login.js", "style.css", "favicon.svg"):name>')}
        answered = []
        for rule in self.web.url_map.iter_rules():
            path = re.sub(r'<int:\w+>', '1', rule.rule)
            path = re.sub(r'<any\(([^)]*)\):\w+>', lambda m: m.group(1).split(',')[0].strip().strip('"'), path)
            path = re.sub(r'<[^>]+>', 'x', path)
            for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
                if (method, rule.rule) in public:
                    continue
                code = getattr(self.client, method.lower())(path, json={}).status_code
                if code not in (401, 302):
                    answered.append((method, rule.rule, code))
        self.assertEqual(answered, [])

    def test_signing_out_kills_copies_of_the_cookie(self):
        from storageforge_index import users
        self.login()
        copied = self.client.get_cookie('sf_session').value
        self.client.post('/api/logout')
        self.client.set_cookie('sf_session', copied)
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.login()
        users.end_all_sessions(self.conn, 'alice')                      # storageforge-index user signout alice
        self.assertEqual(self.client.get('/api/me').status_code, 401)

    def test_numbers_in_queries_are_held_to_their_range(self):
        self.login()
        r = self.client.get('/api/audit?limit=-1')                       # SQLite reads LIMIT -1 as "everything"
        self.assertEqual(len(r.json['entries']), 1)
        self.assertEqual(self.client.get('/api/search?q=*&limit=-5').status_code, 200)
        self.assertEqual(self.client.get('/api/deploy/runs?limit=-1').status_code, 200)
        for bad in ('/api/folders/cold?years=nan', '/api/folders/cold?years=inf', '/api/audit?limit=abc'):
            self.assertEqual(self.client.get(bad).status_code, 400, bad)

    def test_health_details_and_login_limits_by_network(self):
        far = {'REMOTE_ADDR': '10.0.0.8'}
        r = self.client.get('/healthz', environ_base=far)
        self.assertEqual((r.status_code, r.json), (200, {'status': 'ok'}))
        self.assertEqual(r.headers['Server'], 'StorageForge')
        self.assertIn('users', self.client.get('/healthz').json)                  # the container's own healthcheck
        for _ in range(5):
            self.client.post('/api/login', json={'username': 'alice', 'password': 'wrong password!!'}, environ_base=far)
        r = self.client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'}, environ_base=far)
        self.assertEqual(r.status_code, 429)
        self.assertEqual(self.login().status_code, 200)                  # the owner, on another network, still gets in
        actions = [e['action'] for e in vault.AuditLog(self.db, self.conn, None).tail(10)]
        self.assertIn('web.login.limited', actions)

    def test_guessing_elsewhere_does_not_lock_the_owner_out(self):
        """GM-19: the per-account daily limit counts guesses from every network, so anyone could lock alice out for a
        day; the networks she signs in from are exempt. Empty passwords cost nothing; breaches are audited sparingly."""
        from unittest import mock
        from storageforge_index import server
        with mock.patch.object(server, 'LOGIN_LIMIT_PER_ACCOUNT', '3 per day'):
            web = server.create_app(server.App(self.db), 's' * 48)
        c = web.test_client()

        def login(addr, password='wrong password!!'):
            return c.post('/api/login', json={'username': 'alice', 'password': password}, environ_base={'REMOTE_ADDR': addr})
        self.assertEqual(login('192.168.1.20', 'a long enough password').status_code, 200)
        c.post('/api/logout')
        for i in range(5):                                       # nothing guessed: no try used up
            self.assertEqual(login(f'10.98.{i}.1', '').status_code, 400)
        audited = len(vault.AuditLog(self.db, self.conn, None).tail(1000))
        for i in range(3):                                       # guesses spread over networks use up the day
            self.assertEqual(login(f'10.{i}.0.1').status_code, 401)
        for _ in range(6):
            self.assertEqual(login('10.99.0.1', 'a long enough password').status_code, 429)   # a new network: held
        self.assertEqual(login('192.168.1.77', 'a long enough password').status_code, 200)   # her own network
        added = vault.AuditLog(self.db, self.conn, None).tail(1000)[:-audited or None]
        self.assertEqual(sum(e['action'] == 'web.login.limited' for e in added), 1)       # not one per refused request

    def test_alert_urls_cannot_reach_this_container_or_metadata(self):
        from storageforge_index import alerts
        for url in ('http://127.0.0.1:8080/x', 'http://localhost/x', 'http://169.254.169.254/latest', 'http://[::1]/x',
                    'http://0.0.0.0/x'):
            with self.assertRaisesRegex(ValueError, 'not an allowed alert destination'):
                alerts._check_target(url)
        alerts._check_target('http://10.0.0.5:2586')                     # a LAN ntfy is fine
        with self.assertRaisesRegex(ValueError, 'not an allowed alert destination'):
            alerts.save_settings(self.conn, {'alerts': {'webhook': {'url': 'http://127.0.0.1:8080/api'}}}, 't')
        alerts.save_settings(self.conn, {'alerts': {'gotify': {'url': 'http://10.0.0.5', 'token': 'secret-token'}}}, 't')
        alerts.save_settings(self.conn, {'alerts': {'gotify': {'url': 'http://10.0.0.5', 'token': '••••••'}}}, 't')
        self.assertEqual(alerts.get_setting(self.conn, 'alerts')['gotify']['token'], 'secret-token')
        alerts.save_settings(self.conn, {'alerts': {'gotify': {'url': 'http://10.0.0.66', 'token': '••••••'}}}, 't')
        self.assertEqual(alerts.get_setting(self.conn, 'alerts')['gotify']['token'], '')   # not sent to a new server
        self.assertEqual(alerts.send({'webhook': {'url': 'http://127.0.0.1:9/'}}, 't', 'm'),
                         ['webhook: 127.0.0.1 is not an allowed alert destination (loopback, link-local or multicast)'])
        # GM-06: IPv6 forms that carry 127.0.0.1 or the metadata address
        for url in ('http://[2002:7f00:1::1]/x', 'http://[2002:a9fe:a9fe::1]/x', 'http://[::ffff:127.0.0.1]/x',
                    'http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/x'):   # Teredo, client 127.0.0.1
            with self.assertRaisesRegex(ValueError, 'not an allowed alert destination'):
                alerts._check_target(url)

    def test_alert_tokens_stay_with_their_origin_and_the_checked_address(self):
        """GM-06: https -> http or another port keeps the host name, but the stored token must not follow it; and a
        name that resolves to an allowed address when checked must not connect somewhere else a moment later."""
        import socket
        from unittest import mock
        from storageforge_index import alerts
        tok = lambda: alerts.get_setting(self.conn, 'alerts')['ntfy']['token']   # noqa: E731
        alerts.save_settings(self.conn, {'alerts': {'ntfy': {'url': 'https://10.0.0.5', 'topic': 't', 'token': 'tk'}}}, 't')
        alerts.save_settings(self.conn, {'alerts': {'ntfy': {'url': 'https://10.0.0.5:443/', 'token': '••••••'}}}, 't')
        self.assertEqual(tok(), 'tk')                                         # the same origin, written differently
        for url in ('http://10.0.0.5', 'https://10.0.0.5:8443'):
            alerts.save_settings(self.conn, {'alerts': {'ntfy': {'url': 'https://10.0.0.5', 'token': 'tk'}}}, 't')
            alerts.save_settings(self.conn, {'alerts': {'ntfy': {'url': url, 'token': '••••••'}}}, 't')
            self.assertEqual(tok(), '', url)
        real = socket.getaddrinfo
        answers = iter(['93.184.216.34', '127.0.0.1'])                       # checked, then the rebound answer

        def rebinding(host, port, *a, **kw):
            if host != 'alerts.example':
                return real(host, port, *a, **kw)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (next(answers), port or 0))]
        with mock.patch.object(socket, 'create_connection', side_effect=AssertionError('connected')) as dial, \
             mock.patch.object(alerts.socket, 'getaddrinfo', rebinding):
            self.assertEqual(alerts.send({'webhook': {'url': 'http://alerts.example/hook'}}, 't', 'm'),
                             ['webhook: alerts.example (127.0.0.1) is not an allowed alert destination '
                              '(loopback, link-local or multicast)'])
        dial.assert_not_called()

    def test_secure_cookie_behind_the_tls_proxy(self):
        from storageforge_index import server
        web = server.create_app(server.App(self.db), 's' * 48, secure_cookies=True, proxy_hops=1)
        r = web.test_client().post('/api/login', json={'username': 'alice', 'password': 'a long enough password'},
                                   base_url='https://storageforge.lan', headers={'X-Forwarded-For': '10.0.0.7'})
        cookie = r.headers['Set-Cookie']
        self.assertTrue(cookie.startswith('__Host-sf_session='), cookie)
        self.assertIn('Secure', cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertEqual(vault.AuditLog(self.db, self.conn, None).tail(1)[0]['actor'], 'web:10.0.0.7')

    def test_setup_script_download_needs_a_json_post(self):
        """GM-11: the download makes the deploy keys on first use, so no cross-site GET or form may trigger it."""
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_VAULT_SECRET', None)
        vault.Vault(self.db, self.conn, SECRET).init()
        self.login()
        keys = lambda: self.conn.scalar('SELECT count(*) FROM ssh_keys')   # noqa: E731
        self.assertEqual(self.client.get('/api/deploy/setup-script').status_code, 405)
        self.assertEqual(self.client.post('/api/deploy/setup-script', data='remove=1',
                                          content_type='application/x-www-form-urlencoded').status_code, 400)
        self.assertEqual(keys(), 0)
        r = self.client.post('/api/deploy/setup-script', json={})
        self.assertEqual(r.status_code, 200)
        self.assertIn('storageforge-deploy', r.get_data(as_text=True))
        self.assertEqual(keys(), 2)

    def test_folder_results_are_not_kept_from_a_running_scan(self):
        """GM-25: the cache key was max(scan_id), which a scan sets when it starts: a result computed mid-scan was kept
        under the new id and served after the scan ended. Cold and duplicate folders also evicted each other."""
        from unittest import mock
        from storageforge_index import folders
        self.login()
        self.conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('nas', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        calls = []
        cold = lambda *a, **k: calls.append('cold') or {'folders': []}               # noqa: E731
        dupes = lambda *a, **k: calls.append('dupes') or {'groups': []}            # noqa: E731
        with mock.patch.object(folders, 'cold_folders', cold), mock.patch.object(folders, 'duplicate_folders', dupes):
            sid = self.conn.scalar(f"INSERT INTO scans (host_id, started_at, status) VALUES (:h, {self.db.ts('1')}, 'running') "
                                   "RETURNING scan_id", {'h': hid})
            for _ in range(2):
                self.client.get('/api/folders/cold')
            self.assertEqual(calls, ['cold', 'cold'])                       # mid-scan: computed, never kept
            self.conn.execute("UPDATE scans SET status = 'ok' WHERE scan_id = :s", {'s': sid})
            for _ in range(2):
                self.client.get('/api/folders/cold')
                self.client.get('/api/folders/duplicates')
            self.assertEqual(calls, ['cold', 'cold', 'cold', 'dupes'])      # both kept, side by side

    def test_restore_runs_in_the_background(self):
        """GM-12: a restore held one of the 8 web threads for up to 6 hours; now it answers with a group to poll."""
        import threading
        from unittest import mock
        from storageforge_index import deploy, jobs
        self.login()
        gate, seen = threading.Event(), []

        def slow(db, c, jid, snapshot, rel, who, gid=None, target=None):
            seen.append((jid, snapshot, rel, target))
            gate.wait(10)
            if rel == 'bad':
                raise deploy.DeployError('backup is not set up for deploys yet')
            c.execute("INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, output, actor, started_at, finished_at) "
                      "VALUES (:g, 'nas', 'restore', :j, 'apply', 'ok', 'restored', 't', 1, 2)", {'g': gid, 'j': jid})
        job = {'source': 'nas', 'spec': {'src': '/srv/data'}}
        with mock.patch.object(jobs, 'get', lambda *a: job), mock.patch.object(jobs, 'restore', slow):
            r = self.client.post('/api/deploy/jobs/p1-s1/restore', json={'snapshot': 'daily.0', 'path': 'a.txt'})
            self.assertEqual(r.status_code, 202)                              # answered while the copy still runs
            self.assertTrue(r.json['target'].startswith('/srv/data/a.txt.restored-'))
            group = lambda gid: self.client.get(f'/api/deploy/groups/{gid}').json['runs']   # noqa: E731
            self.assertEqual([x['status'] for x in group(r.json['group'])], ['running'])
            gate.set()
            for _ in range(100):
                runs = group(r.json['group'])
                if runs and 'running' not in [x['status'] for x in runs]:
                    break
                time.sleep(0.05)
            self.assertEqual([(x['status'], x['output']) for x in runs], [('ok', 'restored')])
            r = self.client.post('/api/deploy/jobs/p1-s1/restore', json={'snapshot': 'daily.0', 'path': 'bad'})
            for _ in range(100):
                runs = group(r.json['group'])
                if runs and 'running' not in [x['status'] for x in runs]:
                    break
                time.sleep(0.05)
            self.assertEqual([(x['status'], x['output']) for x in runs], [('failed', 'backup is not set up for deploys yet')])
            self.assertEqual(self.client.post('/api/deploy/jobs/p1-s1/restore', json={'snapshot': '../x', 'path': 'a'}).status_code, 400)
        self.assertEqual(seen[0][:3], ('p1-s1', 'daily.0', 'a.txt'))

    def test_forwarded_headers_count_only_from_the_proxy(self):
        """GM-17: anything on a shared Docker network could reach the app directly and claim any client address; with a
        second proxy in front (PROXY_HOPS=2) the nearest one's single X-Forwarded-Proto was ignored."""
        from storageforge_index import server
        actor = lambda: vault.AuditLog(self.db, self.conn, None).tail(1)[0]['actor']   # noqa: E731
        web = server.create_app(server.App(self.db), 's' * 48, secure_cookies=True, proxy_hops=1, proxy_host='127.0.0.2')
        body = {'username': 'alice', 'password': 'wrong password!!'}
        web.test_client().post('/api/login', json=body, environ_base={'REMOTE_ADDR': '10.0.0.9'},
                               headers={'X-Forwarded-For': '203.0.113.7'})
        self.assertEqual(actor(), 'web:10.0.0.9')                             # not the proxy: its claim is ignored
        web.test_client().post('/api/login', json=body, environ_base={'REMOTE_ADDR': '127.0.0.2'},
                               headers={'X-Forwarded-For': '203.0.113.7'})
        self.assertEqual(actor(), 'web:203.0.113.7')
        from flask import request
        web = server.create_app(server.App(self.db), 's' * 48, secure_cookies=True, proxy_hops=2, proxy_host='127.0.0.2')
        web.add_url_rule('/test-scheme', 'test_scheme', lambda: f'{request.scheme} {request.remote_addr}')
        r = web.test_client().get('/test-scheme', base_url='http://storageforge:8080', environ_base={'REMOTE_ADDR': '127.0.0.2'},
                                  headers={'X-Forwarded-For': '198.51.100.4, 10.1.1.1', 'X-Forwarded-Proto': 'https'})
        self.assertEqual(r.get_data(as_text=True), 'https 198.51.100.4')     # https from the nearest proxy; client 2 hops back

    def test_commands_on_hosts_need_the_password_again(self):
        self.login()
        with self.later(6 * 60):
            for method, path, body in (('post', '/api/deploy/start', {'kind': 'jobs', 'ref': 1}),
                                       ('post', '/api/deploy/jobs/p1-s1/run', None),
                                       ('post', '/api/deploy/jobs/p1-s1/restore', {}),
                                       ('post', '/api/keys/install', {}), ('post', '/api/access/grant', {}),
                                       ('post', '/api/deploy/access', {}), ('post', '/api/deploy/adopt', {}),
                                       ('put', '/api/me', {'session_minutes': 60}), ('put', '/api/deploy/settings', {})):
                r = getattr(self.client, method)(path, json=body)
                self.assertEqual((path, r.status_code, r.json.get('reauth')), (path, 403, True))
            self.assertEqual(self.client.post('/api/deploy/jobs/p1-s1/log').status_code, 404)   # reading needs no password
            self.assertEqual(self.client.post('/api/reauth', json={'password': 'wrong password!!'}).status_code, 403)
            self.assertEqual(self.client.get('/api/me').status_code, 200)                       # still signed in
            self.assertEqual(self.client.post('/api/reauth', json={'password': 'a long enough password'}).status_code, 200)
            r = self.client.post('/api/deploy/start', json={'kind': 'nothing'})
            self.assertEqual((r.status_code, r.json.get('reauth')), (400, None))
        actions = [(e['action'], e['outcome']) for e in vault.AuditLog(self.db, self.conn, None).tail(5)]
        self.assertIn(('web.reauth', 'denied'), actions)
        self.assertIn(('web.reauth', 'ok'), actions)

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


class HostIdentityTests(DBCase):
    """A host's name is what it says about itself; who it is, is what SSH verified at its address (SF-16)."""

    def scan_as(self, hostname, address, keys, machine='0' * 32):
        from types import SimpleNamespace
        inv = SimpleNamespace(hostname=hostname, ip=address, os_info='Linux', machine_id=machine, to_json=lambda: '{}')
        t = SimpleNamespace(host=address, user='scan', port=22, local=False)
        return self.db.upsert_host(self.conn, inv, t, keys)

    def row(self, name):
        r = self.conn.all('SELECT ssh_host, host_keys, machine_id FROM hosts WHERE hostname = :h', {'h': name})[0]
        return r[0], json.loads(r[1]) if r[1] else None, r[2]

    def test_a_machine_cannot_take_over_another_hosts_name(self):
        from storageforge_index.db import HostIdentityError
        hid = self.scan_as('nas.lan', '10.0.0.5', ['SHA256:nas'])
        self.assertEqual(self.scan_as('nas.lan', '10.0.0.7', ['SHA256:nas', 'SHA256:nas2']), hid)   # new address, same keys
        self.assertEqual(self.row('nas.lan')[:2], ('10.0.0.7', ['SHA256:nas', 'SHA256:nas2']))
        for claim in ('nas.lan', 'NAS.LAN', 'nas', 'nas.office'):          # same name, other case, same short name
            with self.assertRaisesRegex(HostIdentityError, 'Refused: nothing about nas.lan was changed'):
                self.scan_as(claim, '10.0.0.66', ['SHA256:evil'])
        self.assertEqual(self.row('nas.lan')[0], '10.0.0.7')                 # deploys still go to the real one
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM hosts'), 1)
        self.scan_as('pc.lan', '10.0.0.66', ['SHA256:pc'])                  # an unrelated name is fine

    def test_postgres_values_and_sql(self):
        """GM-13, without a server: what PostgreSQL returns (JSONB as objects, TIMESTAMPTZ as datetimes) and how SQL
        reaches psycopg (a literal % is doubled). The whole suite runs on PostgreSQL with STORAGEFORGE_TEST_PG."""
        from storageforge_index.db import Conn, epoch, loads
        self.assertEqual(loads({'a': 1}), {'a': 1})
        self.assertEqual(loads('{"a": 1}'), {'a': 1})
        self.assertEqual((loads(None, {}), loads('', {})), ({}, {}))
        self.assertEqual(epoch(dt.datetime(2026, 10, 30, tzinfo=dt.timezone.utc)), 1793318400)
        self.assertEqual(Conn(None, 'postgres')._sql("SELECT 1 WHERE src LIKE 'mnt:%' AND x = :x AND y::text = :y"),
                         "SELECT 1 WHERE src LIKE 'mnt:%%' AND x = %(x)s AND y::text = %(y)s")

    def test_nested_transactions_and_same_second_backups(self):
        """GM-25: a nested tx() failed on SQLite (BEGIN inside a transaction); it is a savepoint now, as on PostgreSQL.
        Two backups started in the same second wrote one .db.part file."""
        self.conn.execute("INSERT INTO settings (key, value_json, updated_at) VALUES ('a', '1', 0)")
        with self.conn.tx():
            self.conn.execute("UPDATE settings SET value_json = '2' WHERE key = 'a'")
            with self.assertRaises(ZeroDivisionError):
                with self.conn.tx():
                    self.conn.execute("UPDATE settings SET value_json = '3' WHERE key = 'a'")
                    1 / 0
        self.assertEqual(self.conn.scalar("SELECT value_json FROM settings WHERE key = 'a'"), '2')
        if self.db.dialect != 'sqlite':
            return
        from unittest import mock
        from storageforge_index import backup
        dest = self.tmp / 'bk'
        dest.mkdir()
        second = dt.datetime(2026, 10, 30, 2, 0, 0)
        with mock.patch.object(backup.dt, 'datetime', mock.Mock(now=lambda: second)):
            paths = [backup.create(self.db, 'essentials', dest)['path'] for _ in range(3)]
        self.assertEqual([Path(p).name for p in paths], ['storageforge-essentials-20261030-020000.db',
                                                         'storageforge-essentials-20261030-020000b.db',
                                                         'storageforge-essentials-20261030-020000c.db'])
        self.assertEqual([Path(b['path']).name for b in backup.listing(dest)][0], Path(paths[-1]).name)   # newest first

    def test_duplicate_files_of_one_host_list_only_its_copies(self):
        """GM-23: with a host filter the counts were that host's, but the file list held every host's copies."""
        from storageforge_index.db import dir_id
        from storageforge_index.search import run_dupes
        for host in ('nas', 'pc'):
            hid = self.conn.scalar("INSERT INTO hosts (hostname, inventory_json) VALUES (:h, '{}') RETURNING host_id", {'h': host})
            mid = self.conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type) VALUES (:h, '/', 'ext4') RETURNING mount_id", {'h': hid})
            for name in ('a.iso', 'b.iso'):
                self.conn.execute("INSERT INTO file_records (mount_id, dir_id, filename, file_size_bytes, modified_at, checksum_hash) "
                                  f"VALUES (:m, :d, :n, 4096, {self.db.ts('0')}, 'h1')", {'m': mid, 'd': dir_id(self.conn, mid, '/srv'), 'n': name})
        g = run_dupes(self.conn, 'nas', 1, 10)[0]
        self.assertEqual((g['copies'], g['files']), (2, ['nas:/srv/a.iso', 'nas:/srv/b.iso']))
        self.assertEqual(run_dupes(self.conn, None, 1, 10)[0]['copies'], 4)

    def test_rows_from_before_pinning_and_rekey(self):
        from storageforge_index.db import Database, HostIdentityError
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('old', '10.0.0.9', '{}')")
        with self.assertRaisesRegex(HostIdentityError, 'was scanned at 10.0.0.9'):
            self.scan_as('old', '10.0.0.66', ['SHA256:evil'])
        self.scan_as('old', '10.0.0.9', ['SHA256:old'])                      # its own address: pinned now
        self.assertEqual(self.row('old')[1], ['SHA256:old'])
        with self.assertRaises(HostIdentityError):
            self.scan_as('old', '10.0.0.9', ['SHA256:reinstalled'])          # same address, new keys: refused too
        self.conn.execute("INSERT INTO host_key_confirmations (address, port, fingerprint, confirmed_by, confirmed_at) "
                          "VALUES ('10.0.0.9', 22, 'SHA256:old', 't', 1)")
        self.assertEqual(Database.rekey_host(self.conn, 'OLD'), ('old', '10.0.0.9'))
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_key_confirmations'), 0)   # GM-04: not trusted again
        self.scan_as('old', '10.0.0.10', ['SHA256:reinstalled'], machine='f' * 32)
        self.assertEqual(self.row('old'), ('10.0.0.10', ['SHA256:reinstalled'], 'f' * 32))

    def test_canonical_prefers_name_and_scanned_address_over_reported_ip(self):
        from storageforge_index import deploy
        self.scan_as('nas.lan', '10.0.0.5', ['SHA256:nas'])
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host, inventory_json) "
                          "VALUES ('evil', '10.0.0.5', '10.0.0.66', '{}')")  # reports the victim's IP as its own
        self.assertEqual(deploy.canonical(self.conn, '10.0.0.5'), 'nas.lan')
        self.assertEqual(deploy.canonical(self.conn, 'NAS.lan'), 'nas.lan')

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'needs ssh-keygen')
    def test_host_keys_come_from_known_hosts(self):
        from storageforge_index.remote import Transport
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tmp / 'k')], check=True)
        pub = (self.tmp / 'k.pub').read_text().split()
        fp = subprocess.run(['ssh-keygen', '-lf', str(self.tmp / 'k.pub')], capture_output=True, text=True).stdout.split()[1]
        kh = self.tmp / 'known_hosts'
        kh.write_text(f'10.0.0.5 {pub[0]} {pub[1]}\n[10.0.0.6]:2222 {pub[0]} {pub[1]}\n')
        for host, port, want in (('10.0.0.5', 22, [fp]), ('10.0.0.6', 2222, [fp]), ('10.0.0.7', 22, [])):
            t = Transport(host=host, port=port, known_hosts=str(kh))
            self.assertEqual(t.host_keys(), want, host)
            shutil.rmtree(t._ctl_dir, ignore_errors=True)               # never connected: nothing to close
        self.assertEqual(Transport(host='x', local=True).host_keys(), ['local'])

    @unittest.skipUnless(shutil.which('ssh-keygen') and shutil.which('bash'), 'needs ssh-keygen and bash')
    @unittest.skipIf(os.geteuid() == 0, 'as root the runner ignores the test paths and uses /etc/storageforge')
    def test_runner_checks_machine_id_and_claims_nonces_once(self):
        import base64
        from storageforge_index import deploy
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pub = 'ssh-ed25519 ' + base64.b64encode(deploy._s(b'ssh-ed25519') + deploy._s(raw)).decode()
        etc = self.tmp / 'etc'
        etc.mkdir()
        (etc / 'allowed_signers').write_text(f'storageforge namespaces="storageforge-deploy" {pub}\n')
        (self.tmp / 'machine-id').write_text('a' * 32 + '\n')
        runner = self.tmp / 'storageforge-run'
        runner.write_text(deploy.RUNNER_SCRIPT)
        env = {**os.environ, 'STORAGEFORGE_RUN_ETC': str(etc), 'STORAGEFORGE_RUN_STATE': str(self.tmp / 'state'),
               'STORAGEFORGE_RUN_LOG': str(self.tmp / 'run.log'), 'STORAGEFORGE_RUN_MACHINE_ID': str(self.tmp / 'machine-id')}
        me = os.uname().nodename

        def run(req):
            p = subprocess.run(['bash', str(runner)], input=req, env=env, capture_output=True, timeout=30)
            return p.returncode, p.stdout.decode(), p.stderr.decode()
        good = deploy.request(key, me, deploy.RUNNER_UPDATE + 'echo "ran $1"', ['x'], machine='a' * 32)
        self.assertEqual(run(good)[:2], (0, 'ran x\n'))                    # the runner refresh prints nothing
        rc, _, err = run(good)
        self.assertEqual(rc, deploy.REFUSED)
        self.assertIn('already used', err)
        rc, _, err = run(deploy.request(key, me, 'echo ran', machine='b' * 32))
        self.assertEqual(rc, deploy.REFUSED)
        self.assertIn('signed for machine bbbb', err)
        self.assertEqual(run(deploy.request(key, me, 'echo ran'))[:2], (0, 'ran\n'))   # not scanned yet: name only


class HostAccessTests(DBCase):
    """GM-20 and GM-05: deploy access before any scan key, on another SSH port; adopt only binds one real host."""

    def setUp(self):
        super().setUp()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_VAULT_SECRET', None)
        vault.Vault(self.db, self.conn, SECRET).init()
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, inventory_json) VALUES ('nas', '10.0.0.5', 2222, '{}')")

    def test_sudo_run_needs_no_scan_key_with_an_admin_account(self):
        from unittest import mock
        from storageforge_index import access, hostkeys
        seen, calls = [], []

        def fake_run(argv, **kw):
            calls.append((argv, kw.get('input')))
            return subprocess.CompletedProcess(argv, 0, 'done', '')
        with mock.patch.object(hostkeys, 'require_confirmed', lambda *a: None), \
             mock.patch.object(access, 'askpass_path', lambda: '/bin/true'), \
             mock.patch.object(access.subprocess, 'run', fake_run):
            with self.assertRaisesRegex(ValueError, 'no scan key is bound'):
                access.sudo_run(self.db, self.conn, 'nas', lambda u: 'true', 'pw')
            r = access.sudo_run(self.db, self.conn, 'nas', lambda u: seen.append(u) or 'id', 'pw', admin_user='admin')
            with self.assertRaisesRegex(ValueError, 'bind one first'):       # scan access is for the scan user
                access.grant(self.db, self.conn, 'nas', 'pw', admin_user='admin')
        self.assertEqual((seen, r['port'], r['via']), ([None], 2222, 'admin'))
        argv, stdin = calls[0]
        self.assertEqual(argv[argv.index('-p') + 1], '2222')
        self.assertIn('admin@10.0.0.5', argv)
        self.assertTrue(argv[-1].startswith('sudo -S -p "" sh -c ') and 'exec </dev/null' in argv[-1])   # no read of the pw
        self.assertEqual(stdin, 'pw\n')

    def test_adopt_binds_one_host_and_only_while_it_works(self):
        from unittest import mock
        from storageforge_index import deploy
        for bad in ('*', '10.0.0.0/8', '-oProxyCommand=x', '*.lan'):
            with self.assertRaisesRegex(ValueError, 'host name'):
                deploy.adopt(self.db, self.conn, bad, 't')
        deploy_bindings = lambda: [b for b in vault.Vault(self.db, self.conn, SECRET).bindings() if b['key'] == deploy.DEPLOY_KEY]  # noqa: E731
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'failed', 'output': 'refused'}):
            self.assertEqual(deploy.adopt(self.db, self.conn, 'nas', 't')['state'], 'failed')
        self.assertEqual(deploy_bindings(), [])
        with mock.patch.object(deploy, 'run', lambda *a, **k: {'status': 'ok', 'output': 'works'}):
            self.assertEqual(deploy.adopt(self.db, self.conn, 'nas', 't')['state'], 'ready')
        self.assertEqual([(b['pattern'], b['port']) for b in deploy_bindings()], [('10.0.0.5', 2222)])


class ScriptHeaderTests(DBCase):
    """Free text ends up in the # header of scripts run as root: a line break there would start a command."""

    def assert_commented(self, text):
        hits = [l for l in text.splitlines() if 'PWNED' in l]
        self.assertTrue(hits)
        self.assertTrue(all(l.startswith('#') for l in hits), hits)

    def test_hosts_with_line_breaks_are_refused(self):
        from storageforge_index import changes, moves, shares
        bad = 'nas\nid > /tmp/PWNED #'
        step = {'src': {'host': bad, 'path': '/srv'}, 'dst': {'host': 'b', 'path': '/d'}}
        for body in ({'name': 'p', 'steps': [step]}, {'name': 'p', 'steps': [{**step, 'src': {'host': '-oProxyCommand=x', 'path': '/srv'}}]}):
            with self.assertRaisesRegex(ValueError, 'host name'):
                moves.normalize(body)
        with self.assertRaisesRegex(ValueError, 'host name'):
            changes.normalize({'name': 'c', 'tasks': [{'type': 'dir', 'host': bad, 'params': {'path': '/srv/x'}}]})
        with self.assertRaisesRegex(ValueError, 'host name'):
            shares.normalize_export({'protocol': 'NFS', 'path': '/srv', 'mounts': [{'host': bad, 'path': '/mnt/x'}]})
        self.assertEqual(moves.normalize({'name': 'p', 'steps': [{**step, 'src': {'host': '[fe80::1%eth0]', 'path': '/srv'}}]})
                         ['steps'][0]['src']['host'], '[fe80::1%eth0]')

    def test_scanned_and_designed_paths_stay_quoted_in_root_scripts(self):
        """A destination mount point is whatever the host (or a design) says; in "..." a $(...) would run as root."""
        import re
        from storageforge_index import alerts, jobs, tasks
        evil = '/mnt/$(touch /tmp/PWNED)'
        for host, mp in (('nas', evil), ('pc', '/')):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', '{}')", {'h': host})
            hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, "
                              "scan_state, mount_options) VALUES (:h, :m, '/dev/sdb1', 'ext4', 1099511627776, 1, 'indexed', 'rw')",
                              {'h': hid, 'm': mp})
        plan = {'id': 1, 'name': 'p', 'steps': [{'method': 'mirror', 'src': {'host': 'pc', 'path': '/srv'},
                                                 'dst': {'host': 'nas', 'path': evil + '/copy'}}]}
        sp = jobs.specs(self.conn, plan)
        self.assertEqual(sp[0]['dst_mount'], evil)
        script = jobs.host_script(plan, 'nas', sp, [], 'https://10.0.0.5:8443')
        # what bash would expand: drop quoted heredoc bodies (<<'TAG' … TAG), then single-quoted words
        unquoted = re.sub(r"'[^']*'", "''", re.sub(r"<<'(\w+)'\n.*?\n\1\n", '', script, flags=re.S))
        self.assertIn('PWNED', script)
        self.assertNotIn('$(touch', unquoted)
        t = tasks.normalize({'name': 't', 'blocks': [{'type': 'mkdir', 'params': {'path': '/srv/$(touch /tmp/PWNED)'}}]})
        code = [l for l in tasks.script(self.conn, t).splitlines() if not l.lstrip().startswith('#')]
        self.assertNotIn('$(touch', re.sub(r"'[^']*'", "''", '\n'.join(code)))
        for url in ('http://10.0.0.5:8443/$(touch${IFS}/tmp/PWNED)', 'http://x/`id`', "http://x/'a'", 'http://x;id'):
            with self.assertRaisesRegex(ValueError, 'report URL'):
                alerts.save_settings(self.conn, {'report_url': url}, 't')
        for url in ('https://10.42.0.100:8443', 'http://[fd7a::1]:8080/sf', 'https://nas.lan'):
            alerts.save_settings(self.conn, {'report_url': url}, 't')

    def write_job_prog(self, root):
        from storageforge_index.jobscript import JOB_SCRIPT
        etc = Path('/etc/storageforge') if os.geteuid() == 0 else self.tmp / 'etc'   # root ignores the test paths
        (etc / 'serve').mkdir(parents=True, exist_ok=True)
        (etc / 'serve' / 'p9-t1.conf').write_text(f'ROOT={root}\nSNAP=0\n')
        prog = self.tmp / 'storageforge-job'
        prog.write_text(JOB_SCRIPT)
        wrapper = self.tmp / 'fake-ssh'                     # sshd + the job key's forced command
        wrapper.write_text(f'#!/bin/bash\nshift; exec bash {prog} --serve p9-t1 "$*"\n')
        wrapper.chmod(0o755)
        env = {**os.environ, 'STORAGEFORGE_JOB_ETC': str(etc), 'STORAGEFORGE_JOB_VAR': str(self.tmp / 'var')}
        return prog, wrapper, env

    @unittest.skipUnless(shutil.which('bash'), 'needs bash')
    def test_job_keys_only_reach_the_chrooted_daemon(self):
        """The old rsync --server --sender form is gone: its path check could be bypassed (-s in a cluster) and client
        filter rules made the root sender read and print any file."""
        root = self.tmp / 'root'
        root.mkdir()
        prog, _, env = self.write_job_prog(root)
        p = subprocess.run(['bash', str(prog), '--serve', 'p9-t1', f'rsync --server --sender -logDtpre.iLs . {root}/'],
                           env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertIn("daemon mode only", p.stderr)

    @unittest.skipUnless(shutil.which('bash') and shutil.which('rsync'), 'needs bash and rsync')
    @unittest.skipUnless(os.geteuid() == 0, 'chroot needs root (runs in the Docker test stage)')
    def test_job_keys_read_the_job_folder_and_nothing_else(self):
        root, out = self.tmp / 'root', self.tmp / 'out'
        (root / 'sub').mkdir(parents=True)
        (root / 'a.txt').write_text('hello')
        secret = self.tmp / 'secret'
        secret.write_text('root:$6$NOT-FOR-JOB-KEYS:19000::::::\n')
        (root / 'link').symlink_to(secret)
        _, wrapper, env = self.write_job_prog(root)

        def pull(*opts, src='x::src/'):
            dest = out / str(len(list(out.glob('*'))) if out.exists() else 0)
            dest.mkdir(parents=True)
            p = subprocess.run(['rsync', '-a', *opts, '-e', str(wrapper), src, f'{dest}/'], env=env,
                               capture_output=True, text=True, timeout=60)
            return p, dest
        p, dest = pull()
        self.assertEqual((dest / 'a.txt').read_text(), 'hello')
        for opts, src in (((f'--filter=: {secret}',), 'x::src/'), (('-L',), 'x::src/'), ((), f'x::src/../../{secret}'),
                          (('-s',), f'x::src/{secret}')):
            p, dest = pull(*opts, src=src)
            seen = p.stdout + p.stderr + ''.join(f.read_text(errors='replace') for f in dest.rglob('*')
                                                 if f.is_file() and not f.is_symlink())   # a link arrives as a link
            self.assertNotIn('NOT-FOR-JOB-KEYS', seen, opts)
        p, _ = pull('--remove-source-files')
        self.assertIn('refuse', p.stderr)
        self.assertTrue((root / 'a.txt').exists())

    def test_no_generator_lets_a_value_run_as_code(self):
        """Every script StorageForge writes runs as root somewhere. Paths and free text may hold $(...), backticks and
        quotes (the validators allow them); each must reach bash as data: in single quotes, a quoted heredoc or a
        comment. And in Ansible, Jinja in a value must not be rendered."""
        import re
        from storageforge_index import changes, graph, jobs, moves, shares, tasks
        canary = '$(touch${IFS}/tmp/CANARY)`id`"q;x'
        path, text = '/srv/' + canary, 'note ' + canary
        for host in ('nas', 'pc'):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', '{}')", {'h': host})
            hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, "
                              "scan_state, mount_options) VALUES (:h, '/', '/dev/sdb1', 'btrfs', 1099511627776, 1, 'indexed', 'rw')", {'h': hid})

        def runnable(script):
            t = re.sub(r"<<-?'(\w+)'\n.*?\n\1\n", '', script, flags=re.S)
            t = re.sub(r"'[^']*'", "''", t)
            return [l for l in t.splitlines() if 'CANARY' in l and not l.lstrip().startswith('#')]
        out = {}
        for kind, spec in changes.TYPES.items():
            params = {f['name']: next(o for o in f['options'] if o) if f['kind'] == 'choice' else
                      {'path': path, 'text': text, 'spec': 'nas:/srv/' + canary.replace(' ', ''), 'bool': True, 'device': '/dev/sdb',
                       'user': 'root', 'mode': '0755', 'options': 'defaults', 'label': 'data', 'confirm': '/dev/sdb'}[f['kind']]
                      for f in spec['fields']}
            out[f'changes {kind}'] = changes.script(self.conn, {'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params, 'note': text}]})
        for kind, spec in tasks.TYPES.items():
            if kind in ('command', 'if', 'try'):             # a command block's value is code on purpose
                continue
            params = {p['name']: p['choices'][0] if p['kind'] == 'select' else
                      {'path': path, 'lines': [text], 'host': 'nas', 'int': 1, 'bool': True, 'prefix': 'snap',
                       'dataset': 'tank/data', 'unit': 'nginx.service'}.get(p['kind'], text) for p in spec['params']}
            if kind == 'rsync':
                params.update(src_host='', dst_host='pc')
            out[f'tasks {kind}'] = tasks.script(self.conn, tasks.normalize({'name': 't', 'host': 'nas', 'blocks': [{'type': kind, 'params': params}]}))
        plan = {'id': 1, 'name': 'p', 'steps': [{'method': 'mirror', 'src': {'host': 'pc', 'path': path}, 'dst': {'host': 'nas', 'path': path + '/c'},
                                               'excludes': [text], 'note': text, 'options': {'snapshot': True}}]}
        out['moves'] = moves.script(self.conn, plan)
        sp = jobs.specs(self.conn, plan)
        out['jobs runner'] = jobs.host_script(plan, 'nas', sp, [], 'https://10.0.0.5:8443')
        out['jobs source'] = jobs.host_script(plan, 'pc', [], sp, None)
        graph.store_blueprint(self.conn, {'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint', 'metadata': {'host': 'nas'},
                                          'exports': [shares.normalize_export({'protocol': 'NFS', 'path': path, 'rules': [{'clients': '10.0.0.0/24', 'options': 'rw'}],
                                                                               'mounts': [{'host': 'pc', 'path': '/mnt/' + canary}]})]})
        out['shares'] = shares.script(self.conn, 'nas')
        self.assertGreater(len(out), 30)
        self.assertEqual({k: runnable(v) for k, v in out.items() if runnable(v)}, {})
        y = changes.ansible(self.conn, {'name': 'p', 'tasks': [{'type': 'dir', 'host': 'nas', 'params': {'path': "/srv/{{ lookup('pipe','id') }}"}}]})
        self.assertIn('path: !unsafe "/srv/{{ lookup', y)
        y = changes.ansible(self.conn, {'name': 'p', 'tasks': [{'type': 'perms', 'host': 'nas', 'params': {
            'path': '/srv/share', 'owner': 'alice', 'group': '', 'mode': '0750', 'recursive': True}}]})
        import yaml
        files = [t['ansible.builtin.file'] for t in yaml.safe_load(y)[0]['tasks']]
        self.assertEqual(files, [{'path': '/srv/share', 'owner': 'alice', 'recurse': True},     # recursive: owner only
                                 {'path': '/srv/share', 'mode': '0750'}])

    def test_audit_verify_reports_entries_a_database_writer_could_rewrite(self):
        key = vault.SecretBuffer(32)
        key.buf[:32] = b'k' * 32
        key.length = 32
        vault.AuditLog(self.db, self.conn, None).append('cli', 'vault.init', 'ok')        # before the vault had a key
        keyed = vault.AuditLog(self.db, self.conn, key)
        keyed.append('web:alice', 'deploy.start', 'ok')
        self.assertEqual(keyed.unkeyed(), {'unkeyed': 1, 'unkeyed_after_keyed': 0, 'first_unkeyed_after_keyed': None})
        vault.AuditLog(self.db, self.conn, None).append('web:?', 'deploy.start', 'ok')   # vault locked later
        self.assertEqual(keyed.verify()[0], True)                                          # still "intact"...
        weak = keyed.unkeyed()
        self.assertEqual(weak['unkeyed_after_keyed'], 1)                                   # ...but flagged

    def test_job_reports_cannot_be_dated_ahead(self):
        import uuid
        from storageforge_index import jobs
        run = {'run': str(uuid.uuid4()), 'job': 'p1-s1', 'rc': 0, 'start': int(time.time()), 'end': int(time.time()) + 86400}
        with self.assertRaisesRegex(ValueError, 'future'):
            jobs.ingest(self.conn, run, 'report:10.0.0.5')

    def test_https_reports_trust_only_the_served_certificate(self):
        from unittest import mock
        from storageforge_index import jobs, jobscript
        pem = self.tmp / 'cert.pem'
        pem.write_text('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n')
        with mock.patch.dict(os.environ, {'STORAGEFORGE_REPORT_CA_FILE': str(pem)}):
            self.assertTrue(jobs.report_ca('https://10.0.0.5:8443').startswith('-----BEGIN CERTIFICATE-----'))
            self.assertIsNone(jobs.report_ca('http://10.0.0.5:8080'))
            pem.write_text('not a certificate')
            self.assertIsNone(jobs.report_ca('https://10.0.0.5:8443'))
        self.assertIn('--cacert "$ETC/report-ca.pem"', jobscript.JOB_SCRIPT)

    def test_notes_and_names_stay_inside_comments(self):
        from storageforge_index import changes, moves
        note = 'ok\nid > /tmp/PWNED\r\x1b[2K'
        plan = moves.normalize({'name': 'p', 'steps': [{'src': {'host': 'a', 'path': '/srv'}, 'dst': {'host': 'b', 'path': '/d'},
                                                        'note': note}]})
        self.assertNotIn('\n', plan['steps'][0]['note'])
        self.assert_commented(moves.script(self.conn, plan))
        cp = {'name': 'c', 'tasks': [{'type': 'dir', 'host': 'nas', 'params': {'path': '/srv/x'}, 'note': note}]}
        self.assertNotIn('\n', changes.normalize(cp)['tasks'][0]['note'])
        self.assertFalse([l for l in changes.script(self.conn, cp).splitlines() if l.startswith('id ')])
        from storageforge_index.scriptkit import comments
        self.assertEqual(comments(['#   a\nid > /tmp/PWNED', '#   b'], '#'), '#   a id > /tmp/PWNED\n#   b')


if __name__ == '__main__':
    unittest.main()
