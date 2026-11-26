"""The engine settings the scan reads (runtimes/docker.py), what is stored of daemon.json, and what the Workloads listing carries."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import workloads
from storageforge_index.runtimes import docker

SETTINGS = json.dumps({'storage_driver': 'overlay2', 'log_driver': 'json-file', 'cgroup_driver': 'systemd', 'live_restore': True,
                       'registry_mirrors': ['https://mirror.example/']})


def probe(engine='docker', settings=SETTINGS, daemon=None, root='/var/lib/docker'):
    """The text the probe prints, as far as the settings go."""
    lines = [f'@@engine\t{engine}\tdirect', '@@root', root, '@@settings', settings]
    if daemon == 'unreadable':
        lines.append('@@daemonjson-unreadable')
    elif daemon is not None:
        lines += ['@@daemonjson', daemon]
    return '\n'.join(lines + ['@@containers', '@@end']) + '\n'


class Parse(unittest.TestCase):
    def test_the_engine_answers_become_settings(self):
        s = docker.parse_engine(probe(daemon=''))['settings']
        self.assertEqual((s['storage_driver'], s['log_driver'], s['cgroup_driver'], s['live_restore'], s['registry_mirrors']),
                         ('overlay2', 'json-file', 'systemd', True, ['https://mirror.example/']))
        self.assertEqual((s['daemon_json'], s['daemon_json_read']), ({}, True))

    def test_only_the_known_keys_of_daemon_json_are_kept(self):
        raw = json.dumps({'hosts': ['tcp://0.0.0.0:2375'], 'tlskey': '/x', 'data-root': '/srv/docker', 'log-opts': {'max-size': '10m'}})
        got = docker.parse_engine(probe(daemon=raw))['settings']
        self.assertEqual(got['daemon_json'], {'data-root': '/srv/docker', 'log-opts': {'max-size': '10m'}})
        self.assertNotIn('tcp://', json.dumps(got))

    def test_daemon_json_that_is_not_json(self):
        for raw in ('{"data-root": ', '["a"]'):
            got = docker.parse_engine(probe(daemon=raw))['settings']
            self.assertEqual((got['daemon_json'], got['daemon_json_read']), (None, True), raw)
            self.assertTrue(got['daemon_json_error'], raw)

    def test_an_unreadable_daemon_json(self):
        got = docker.parse_engine(probe(daemon='unreadable'))['settings']
        self.assertEqual((got['daemon_json'], got['daemon_json_read']), (None, False))

    def test_podman(self):
        d = docker.parse_engine(probe('podman', json.dumps({'storage_driver': 'overlay', 'log_driver': 'journald', 'cgroup_driver': 'systemd'}),
                                      root='/var/lib/containers/storage'))
        self.assertEqual((d['root_dir'], d['settings']['storage_driver'], d['settings']['daemon_json_read']),
                         ('/var/lib/containers/storage', 'overlay', False))
        self.assertIsNone(d['settings']['live_restore'])

    def test_a_probe_without_settings(self):
        s = docker.parse_engine('@@engine\tdocker\tdirect\n@@root\n/var/lib/docker\n@@end\n')['settings']
        self.assertEqual((s['storage_driver'], s['registry_mirrors'], s['daemon_json_read']), (None, [], False))

    def test_the_probe_reads_daemon_json_with_the_engines_access_and_a_cap(self):
        self.assertIn('@@daemonjson', docker.ENGINE)
        self.assertIn('@@daemonjson-unreadable', docker.ENGINE)
        self.assertIn('65536', docker.ENGINE)
        self.assertIn("S='sudo -n'", docker.ENGINE)


class Stored(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")
        self.hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")

    def scan(self, text):
        with mock.patch.object(docker, '_stream', return_value=text), mock.patch.object(docker, 'compose_candidates', return_value=[]):
            return docker.survey(self.db, self.conn, None, self.hid, 1)

    def test_a_scan_stores_the_settings_and_the_listing_carries_them(self):
        self.scan(probe(daemon=json.dumps({'data-root': '/srv/docker', 'tlskey': '/x'})))
        got = workloads.listing(self.conn, 'nas')['hosts'][0]['engine_settings']
        self.assertEqual((got['root_dir'], got['storage_driver'], got['daemon_json']), ('/var/lib/docker', 'overlay2', {'data-root': '/srv/docker'}))
        self.assertEqual(got['registry_mirrors'], ['https://mirror.example/'])

    def test_a_row_stored_before_the_settings_existed(self):
        self.conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, updated_at) "
                          "VALUES (:h, 'docker', 'direct', '/var/lib/docker', '[]', '[]', '[]', 1)", {'h': self.hid})
        got = workloads.listing(self.conn, 'nas')['hosts'][0]['engine_settings']
        self.assertEqual(got, {'root_dir': '/var/lib/docker'})

    def test_the_migration_added_the_column(self):
        self.assertIsNone(self.conn.scalar('SELECT settings_json FROM docker_hosts'))


if __name__ == '__main__':
    unittest.main()
