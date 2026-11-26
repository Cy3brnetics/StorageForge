"""The 2026-11-25 bug hunt: injection through task and playbook fields, guards a path or an old account got around, ingest that one
record could stall, and the proxy lookup that made every request wait on a slow resolver."""
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test_security as T

from storageforge_index import agentplugins, clone, changes, secplus, security, server, sfagent, steps_osinstall, tasks, toolbox, users
from storageforge_index.db import Database
from storageforge_index.runtimes import docker

PW = T.PW


class Fresh(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = Database(f'sqlite:///{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)


class PlaybookFields(unittest.TestCase):
    """A file or process name the host saw must not choose which client is banned or which pid is killed."""

    def test_a_falco_path_cannot_add_fields(self):
        a = {'rule': 'r', 'priority': 'critical', 'time': 't', 'proc': 'smbd', 'path': '/srv/x;client=10.0.0.2;pid=812;.locked', 'user': 'u'}
        self.assertEqual(secplus.event_fields(json.dumps(a)), {})

    def test_the_first_of_a_key_stands_and_values_are_checked(self):
        f = secplus.event_fields('path_b64=eA==;pid=40;comm=x;pid=1;client=10.0.0.9')
        self.assertEqual((f['pid'], f['client']), ('40', '10.0.0.9'))
        self.assertNotIn('client', secplus.event_fields('client=not-an-address;pid=12x'))
        self.assertNotIn('pid', secplus.event_fields('client=10.0.0.1;pid=12x'))


class TaskHostUp(unittest.TestCase):
    """The "host up" condition took free text into `bash -c`: root on the host without hosts.command."""

    def block(self, arg):
        return {'name': 't', 'host': 'nas', 'blocks': [{'type': 'if', 'params': {'cond': 'host up', 'arg': arg}, 'slots': {'then': [], 'else': []}}]}

    def test_only_a_host_name_is_taken(self):
        with self.assertRaises(ValueError):
            tasks.normalize(self.block('a/1;id>/tmp/sf_pwn;#'))
        tasks.normalize(self.block('backup@nas2'))

    def test_reach_passes_the_host_as_data(self):
        reach = next(line for line in tasks.__dict__['BASH'].splitlines() if line.startswith('reach()')) if 'BASH' in tasks.__dict__ else None
        text = reach or Path(tasks.__file__).read_text()
        self.assertIn('''bash -c '</dev/tcp/$0/$1' "$h" "$2"''', text)
        marker = Path(tempfile.mkdtemp()) / 'pwned'
        fn = '''reach() { local h=${1#[}; h=${h%]}; timeout 5 bash -c '</dev/tcp/$0/$1' "$h" "$2" 2>/dev/null; }'''
        subprocess.run(['bash', '-c', f'{fn}; reach "a/1;touch {marker};#" 22'], capture_output=True, timeout=30)
        self.assertFalse(marker.exists())


class DataFolder(unittest.TestCase):
    def test_dot_segments_do_not_reach_system_folders(self):
        for bad in ('/./etc', '/.', '/.//root', '/srv/../etc', 'etc'):
            self.assertFalse(toolbox.data_folder_ok(bad), bad)
        self.assertTrue(toolbox.data_folder_ok('/srv/kuma') and toolbox.data_folder_ok('/tank/apps/kuma/'))


class AdminQuorum(T.Base):
    """An account counts toward the dual-admin quorum from when it became an admin, not from when it was made."""

    def test_promoting_an_old_account_restarts_its_cool_off(self):
        users.create(self.conn, 'viewer1', PW, 'viewer')
        self.conn.execute("UPDATE users SET created_at = 1 WHERE username = 'viewer1'")
        self.assertNotIn('viewer1', security.established_admins(self.conn))
        users.set_role(self.conn, 'viewer1', 'admin')
        self.assertNotIn('viewer1', security.established_admins(self.conn))
        self.assertIn('viewer1', security.established_admins(self.conn, now=int(time.time()) + 80 * 3600))

    def test_saving_an_enabled_account_does_not_restart_it(self):
        users.create(self.conn, 'old', PW, 'admin')
        self.conn.execute("UPDATE users SET created_at = 1 WHERE username = 'old'")
        users.set_disabled(self.conn, 'old', False)
        self.assertIn('old', security.established_admins(self.conn))
        users.set_disabled(self.conn, 'old', True)
        users.set_disabled(self.conn, 'old', False)
        self.assertNotIn('old', security.established_admins(self.conn))


class AgentArch(Fresh):
    def test_an_ssh_scanned_host_has_its_arch_from_the_package_survey(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', :i)",
                          {'i': json.dumps({'packages': 'pm apt-get', 'pkglist': {'arch': 'amd64'}})})
        self.assertEqual(sfagent.host_arch(self.conn, 'nas'), 'amd64')
        self.assertTrue(sfagent.agentctl_program.__doc__)          # amd64 is mapped to x86_64 there


class AgentIngest(Fresh):
    def test_a_reading_too_big_for_the_database_is_dropped_not_retried(self):
        self.conn.execute("""INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json)
                             VALUES ('nas', 'f', 1, 1, 'disks', 'errors', 1, :b)""", {'b': json.dumps({'ioerr': {'sda': 2 ** 70}})})
        with mock.patch.object(agentplugins.errlog, 'trace'):
            agentplugins.take(self.db)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM agent_records'), 0)


class OsPartitions(unittest.TestCase):
    def test_a_system_is_not_matched_by_a_longer_name(self):
        fn = next(line for line in steps_osinstall.bash().splitlines() if line.startswith('sf_os_parts()'))
        lsblk = f'lsblk() {{ printf "%s\\n" "/dev/sda5 {steps_osinstall.LABEL}nas-root" "/dev/sda6 {steps_osinstall.LABEL}nas-old-root" "/dev/sda7 {steps_osinstall.LABEL}nas-2"; }}'
        out = subprocess.run(['bash', '-c', f'{lsblk}\n{fn}\nsf_os_parts nas'], capture_output=True, text=True, timeout=30).stdout.split()
        self.assertEqual(out, ['/dev/sda5', '/dev/sda7'])


class CloneHolds(unittest.TestCase):
    def test_a_zfs_hold_names_the_snapshot_and_validates(self):
        self.assertTrue(changes.CHECKS['zfs-snapshot'].fullmatch('tank/data@sf-clone-1'))
        self.assertFalse(changes.CHECKS['zfs-snapshot'].fullmatch('tank/data'))
        self.assertIn("t[\"params\"][\"name\"]", Path(clone.__file__).read_text())


class ComposeIndex(Fresh):
    def test_compose_candidates_use_the_nocase_filename_index(self):
        sql = []
        real = self.conn.all

        def spy(q, params=None):
            sql.append(q)
            return real(q, params or {})
        with mock.patch.object(self.conn, 'all', spy):
            docker.compose_candidates(self.conn, 1, [])
        plan = ' '.join(str(r) for r in self.conn.all('EXPLAIN QUERY PLAN ' + sql[0], {'h': 1}))
        self.assertIn('ix_file_filename', plan)


class ProxyLookup(unittest.TestCase):
    """getaddrinfo has no timeout: a slow resolver made each request that refreshed the proxy's address wait 8 s."""

    def test_a_slow_lookup_never_holds_a_request(self):
        slow = threading.Event()

        def lookup(*_a, **_k):
            slow.wait(5)
            raise socket.gaierror('slow')
        app = lambda environ, start: (start('200 OK', []), [b'ok'])[1]   # noqa: E731
        with mock.patch.object(socket, 'getaddrinfo', lookup):
            t0 = time.monotonic()
            wrapped = server._FromProxy(app, 1, 'proxy')
            self.assertLess(time.monotonic() - t0, server._FromProxy.LOOKUP_SECS + 1)
            wrapped.at = 0
            t0 = time.monotonic()
            for _ in range(3):
                wrapped({'REMOTE_ADDR': '10.9.9.9', 'PATH_INFO': '/'}, lambda *a: None)
            self.assertLess(time.monotonic() - t0, 1.0)
            slow.set()


class ProfileStage(T.Base):
    def test_accepting_unsigned_entries_in_a_role_profile_takes_hosts_command(self):
        users.save_role(self.conn, 'planner', 'test', ['plans.edit', 'plans.view', 'hosts.view'], 'admin1', True)
        users.create(self.conn, 'pl', PW, 'planner')
        self.login('pl')
        r = self.post('/api/toolbox/profiles/host/nas/stage', accept_unsigned=True)
        self.assertEqual(r.status_code, 403)


class JobTokens(T.Base):
    def test_a_refused_apply_stores_no_new_job_tokens(self):
        from storageforge_index import jobs
        modes = []

        def items(db, conn, plan, mode, *a, **k):
            modes.append(mode)
            return [{'host': 'nothere', 'script': '', 'kind': 'jobs'}]
        with mock.patch.object(jobs, 'deploy_items', items), mock.patch.object(server, 'password_confirmed', lambda f: f, create=True):
            r = self.post('/api/deploy/start', kind='jobs', ref=7, mode='apply')
        self.assertEqual(r.status_code, 409, r.get_json())
        self.assertEqual(modes, ['report'])


if __name__ == '__main__':
    unittest.main()


import test_enclave as TE                                                  # noqa: E402
from storageforge_index import enclave as enclave_mod, vault as vault_mod  # noqa: E402


class EnclavePin(TE.Harness):
    """The caller brings the verifier as well as the secret, so a verifier that opens proved only that the caller made it. Once
    unlocked, the enclave takes no other vault secret until it restarts: not over a running unlock, not after lock, not to lift
    a lock-down. And turning the vault over to a new secret takes the one in force."""

    def other(self):
        db = TE.dbfactory.make(self, self.tmp / 'other.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        secret = b'o' * 48
        v = vault_mod.Vault(db, conn, secret)
        v.init()
        v.close()
        cols = ('kdf_salt', 'kdf_time_cost', 'kdf_memory_kib', 'kdf_lanes', 'verifier_nonce', 'verifier', 'audit_key_nonce', 'audit_key_wrapped')
        row = conn.all(f'SELECT {", ".join(cols)} FROM vault_meta WHERE id = 1')[0]
        return secret, {c: (bytes(x) if isinstance(x, (bytes, memoryview)) else x) for c, x in zip(cols, row)}

    def refused(self, fn, *a):
        with self.assertRaises(enclave_mod.EnclaveError) as e:
            fn(*a)
        self.assertIn('another vault secret', str(e.exception))

    def test_another_vaults_secret_is_refused_running_locked_or_locked_down(self):
        secret, meta = self.other()
        self.unlock()
        self.refused(self.e.unlock, secret, meta)
        self.e.lock()
        self.refused(self.e.unlock, secret, meta)
        self.assertEqual(self.e.status()['foreign_unlocks'], 2)
        self.assertEqual(self.unlock()['state'], 'unlocked', 'its own secret still opens it')

    def test_a_new_secret_takes_the_one_in_force(self):
        self.unlock()
        with self.assertRaises(enclave_mod.EnclaveError):
            self.e.rotate_begin(b'n' * 48, os.urandom(16), 3, 64 * 1024, 4)
        with self.assertRaises(enclave_mod.EnclaveError):
            self.e.rotate_begin(b'n' * 48, os.urandom(16), 3, 64 * 1024, 4, current=b'x' * 48)
        self.assertFalse(self.e.status()['rotating'])
