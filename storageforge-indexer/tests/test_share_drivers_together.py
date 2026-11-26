"""Every share protocol in one design: the script carries all the drivers' bash at once, so it must still parse, name no function twice
with different bodies, and run as a report on the server and on a client."""
import importlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

MODULES = ('sftp', 's3', 'webdav', 'rclone', 'iscsi', 'nvme', 'virtiofs', 'nbd', 'gluster')


class Together(Fleet):
    def setUp(self):
        super().setUp()
        self.conn.execute("UPDATE hosts SET host_keys = '[\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASE64\"]' WHERE hostname = 'nas'")
        # each driver test's own good share, all on nas; the block-device ones and gluster keep pc as their only client
        self.saved = []
        for m in MODULES:
            share = dict(importlib.import_module(f'test_share_{m}').SHARE)
            share['name'] = f'{m}x' if m not in ('s3',) else 's3-bucket'
            share['mounts'] = [{**mt, 'path': f'/mnt/{m}x'} for mt in share.get('mounts') or []]
            try:
                shares.save_export(self.db, self.conn, 'nas', share, None, 'test')
                self.saved.append(m)
            except (ValueError, LookupError) as exc:
                self.fail(f'{m}: {exc}')

    def test_all_are_offered(self):
        self.assertEqual(set(netshares.keys()), {m.upper() for m in MODULES})

    def test_the_combined_script_parses_and_no_function_is_defined_twice_differently(self):
        text = shares.script(self.conn, 'nas')
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        bodies = {}
        for name, body in re.findall(r'^([a-z_][a-z0-9_]*)\(\) *(\{.*?^\})', text, re.M | re.S):
            self.assertTrue(name not in bodies or bodies[name] == body, f'{name} is defined twice with different bodies')
            bodies[name] = body

    def report(self, as_host):
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        for tool in ('virsh', 'targetcli', 'gluster', 'nvme', 'iscsiadm', 'nbd-client'):     # never this machine's own hypervisor or targets
            (tmp / tool).write_text('#!/bin/sh\nexit 1\n')
            (tmp / tool).chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}'}
        for k in ('SFTP_ROOT', 'SFTP_CONF', 'NVMET_ROOT', 'NVME_DIR', 'NBD_CONF', 'NBD_CDIR', 'NBD_STATE', 'RCLONE_DIR', 'UNIT_DIR'):
            env[f'SF_{k}'] = str(tmp / k.lower())
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=180)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server(self):
        out = self.report('nas')
        for bad in ('unbound variable', 'command not found', 'syntax error'):
            self.assertNotIn(bad, out)

    def test_the_report_runs_on_a_client(self):
        out = self.report('pc')
        for bad in ('unbound variable', 'command not found', 'syntax error'):
            self.assertNotIn(bad, out)


if __name__ == '__main__':
    unittest.main()
