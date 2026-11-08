"""Joining a tailnet as a plan step, with the auth key kept out of every plan, script and log, and the fixes the
Raspberry Pi copy (2026-11-08) found: tools a copy's own steps need, the size of a copy with hard links, the VM login."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

try:
    from test_clone import Db
    from test_md_services import HARNESS, stub
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db
    from tests.test_md_services import HARNESS, stub
from storageforge_index import changes, clone, steps_tailscale

KEY = 'tskey-auth-kTEST000000CNTRL-NOTAREALKEY000000000000000000000'


class Step(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin = self.d / 'bin'
        self.bin.mkdir()
        self.secrets = self.d / 'secrets'
        self.secrets.mkdir()
        # tailscale as it behaves: logged out until up, which needs the key file, then Running
        stub(self.bin, 'tailscale', 'echo "tailscale $*" >>"$LOG"; case $1 in '
             'status) [[ -e $FAKE/up ]] && echo \'  "BackendState": "Running",\' || echo \'  "BackendState": "NeedsLogin",\' ;; '
             'up) for a; do case $a in --auth-key=file:*) [[ -r ${a#--auth-key=file:} ]] || exit 1 ;; esac; done; touch "$FAKE/up" ;; '
             'ip) echo 100.64.0.7 ;; logout) rm -f "$FAKE/up" ;; version) echo 1.104.5 ;; esac')
        stub(self.bin, 'systemctl', 'exit 0')

    def run_step(self, apply, *args):
        body = steps_tailscale.BASH.replace('/run/storageforge/secrets', str(self.secrets))
        call = 't_tailscale ' + ' '.join(f'"{a}"' for a in args)
        return subprocess.run(['bash', '-c', HARNESS + f'APPLY={int(apply)}\n' + body + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                              capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.d), 'LOG': str(self.d / 'log')})

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    def test_without_the_key_file_it_says_how_to_send_it(self):
        out = self.run_step(True, 'ts-test', '', '', '', '', 'present')
        self.assertIn('no auth key at', out.stdout)
        self.assertIn('vault send-secret ts-test', out.stdout)
        self.assertNotIn('tailscale up', self.log())

    def test_it_joins_from_the_file_and_then_removes_it(self):
        (self.secrets / 'ts-test').write_text(KEY + '\n')
        report = self.run_step(False, 'ts-test', 'tag:vm-test', 'web-copy', '1', '', 'present')
        self.assertIn('would: tailscale up --reset --auth-key=file:', report.stdout)
        self.assertNotIn('tailscale up', self.log())
        out = self.run_step(True, 'ts-test', 'tag:vm-test', 'web-copy', '1', '', 'present')
        self.assertIn('joined the tailnet as 100.64.0.7', out.stdout)
        up = next(l for l in self.log().splitlines() if l.startswith('tailscale up'))
        # --reset: a run states all of it, or tailscale refuses an up that does not repeat an earlier attempt's flags (the Pi run)
        self.assertEqual(up, f'tailscale up --reset --auth-key=file:{self.secrets}/ts-test --hostname=web-copy --advertise-tags=tag:vm-test --accept-routes --timeout=90s')
        self.assertNotIn(KEY, out.stdout + out.stderr + self.log())         # on no command line and in no output
        self.assertFalse((self.secrets / 'ts-test').exists())               # the node keeps a key of its own
        again = self.run_step(True, 'ts-test', '', '', '', '', 'present')
        self.assertIn('on a tailnet already', again.stdout)

    def test_absent_logs_out(self):
        (self.d / 'up').touch()
        out = self.run_step(True, 'ts-test', '', '', '', '', 'absent')
        self.assertIn('left the tailnet', out.stdout)
        self.assertIn('tailscale logout', self.log())

    def test_the_check(self):
        items = []
        steps_tailscale._check(None, None, {'name': 'web'}, {'secret': 'ts-test', 'tags': 'vm-test', 'hostname': 'Web_1', 'state': 'present'},
                               lambda level, text: items.append((level, text)))
        self.assertEqual([lvl for lvl, _ in items].count('crit'), 2)       # tags are tag:name; a machine name is lower case
        self.assertTrue(any('vault send-secret ts-test --host web' in t for _, t in items))


class Vault(Db):
    def test_a_secret_is_stored_sent_on_stdin_and_never_printed(self):
        from storageforge_index import cli
        secret = Path(self.tmp) / 'vault-secret'
        secret.write_text('s' * 48)
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(secret)
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_VAULT_SECRET_FILE', None)
        db = str(Path(self.tmp) / 'index.db')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['--db', db, 'vault', 'init']), 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                unittest.mock.patch('sys.stdin', io.StringIO(KEY + '\n')):
            self.assertEqual(cli.main(['--db', db, 'vault', 'secret-add', 'ts-test']), 0)
        self.assertNotIn(KEY, out.getvalue())
        seen = {}

        def fake_run(argv, input=None, **kw):
            seen['argv'], seen['input'] = argv, input
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), unittest.mock.patch('subprocess.run', fake_run):
            self.assertEqual(cli.main(['--db', db, 'vault', 'send-secret', 'ts-test', '--host', 'web-copy', '--user', 'rpi']), 0)
        self.assertEqual(seen['input'], (KEY + '\n').encode())                  # on stdin
        self.assertNotIn(KEY, ' '.join(seen['argv']) + out.getvalue())          # never in the command or the output
        self.assertIn('rpi@web-copy', seen['argv'])
        self.assertIn('/run/storageforge/secrets/ts-test', seen['argv'][-1])
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'vault.secret%'")]
        self.assertEqual(actions, ['vault.secret_add', 'vault.secret_send'])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['--db', db, 'vault', 'send-secret', 'ts-test', '--host=-oProxyCommand=x']), 2)


class PiCopyFixes(Db):
    def test_the_tools_the_storage_steps_run_come_with_the_packages(self):
        tasks = [{'type': 'partition', 'params': {'fstype': 'ext4'}}, {'type': 'md-array', 'params': {'fstype': 'xfs'}},
                 {'type': 'subvolume', 'params': {}}, {'type': 'zfs-pool', 'params': {}}]
        self.assertEqual(clone.tools_for(tasks, 'apt-get'), ['parted', 'mdadm', 'btrfs-progs', 'e2fsprogs', 'xfsprogs', 'zfsutils-linux'])
        self.assertIn('btrfsprogs', clone.tools_for(tasks, 'zypper'))
        self.assertNotIn('zfsutils-linux', clone.tools_for(tasks, 'dnf'))

    def test_a_report_knows_an_earlier_step_installs_a_tool(self):
        body = next(b for b in (changes.CHANGE_BODY_1, changes.CHANGE_BODY_2, changes.CHANGE_BODY_3) if 'need() {' in b)
        fn = body[body.index('need() {'):]
        fn = fn[:fn.index('; }\n') + 4]
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=0\n' + fn + '\nPLANNED_TOOLS=" parted"\nneed no-such-parted parted; need no-such-mdadm mdadm\n'],
                             capture_output=True, text=True, timeout=30).stdout
        self.assertIn('later: no-such-parted is installed by an earlier step (package parted)', out)
        self.assertIn('conflict: no-such-mdadm is not installed (package mdadm)', out)

    def test_a_copy_with_hard_links_needs_no_more_than_its_filesystem_uses(self):
        from storageforge_index import moves
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'web-01'")
        mid = self.conn.scalar("SELECT mount_id FROM mounts WHERE host_id = :h AND mount_point = '/srv/data'", {'h': hid})
        did = self.conn.scalar("INSERT INTO directories (mount_id, path) VALUES (:m, '/srv/data') RETURNING dir_id", {'m': mid})
        for i in range(3):    # one 4 GiB file under three names, as rsnapshot keeps it: the filesystem uses 8 GiB in all
            self.conn.execute("""INSERT INTO file_records (mount_id, dir_id, filename, file_size_bytes, is_directory, is_symlink, modified_at)
                                 VALUES (:m, :d, :f, :s, 0, 0, 0)""", {'m': mid, 'd': did, 'f': f'big{i}', 's': 4 * 2**30})
        mount = {'id': mid, 'target': '/srv/data', 'used': 8 * 2**30}
        self.assertEqual(moves.subtree(self.conn, mount, '/srv/data')['bytes'], 8 * 2**30)
        self.assertEqual(moves.subtree(self.conn, {**mount, 'used': None}, '/srv/data')['bytes'], 12 * 2**30)

    def test_vm_clone_names_the_login_after_the_first_person_on_the_source(self):
        from storageforge_index import cli
        self.assertEqual(cli._first_user(self.conn, 'web-01'), 'ana')      # uid 1500, below bob's 1501

    def test_a_pi_boot_partition_is_a_system_mount(self):
        self.assertIn('/boot/firmware', changes.OS_MOUNTS)


if __name__ == '__main__':
    import unittest.mock  # noqa: F401
    unittest.main()
