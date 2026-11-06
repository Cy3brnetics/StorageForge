"""The Terraform and Puppet exports of a design (mapdesign.terraform and mapdesign.puppet), checked by the tools that read them.

When `terraform` is on PATH the export is run through `terraform init -backend=false` and `terraform validate`; when `puppet` is, through
`puppet parser validate`. Neither is ever applied, and nothing here touches a host or a provider's account. A tool that is missing, or a
`terraform init` that cannot download the providers (no network), is a skip with the reason, never a pass. Without the tools, only the
checks that need none run: that the quoting holds and the braces balance. Whether a real apply works is not lab-tested."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import mapdesign

DOC = {'hosts': [
    {'name': 'nas', 'networks': [{'kind': 'bridge', 'name': 'br9', 'address': '10.0.5.1/24'}, {'kind': 'vlan', 'parent': 'eth0', 'vlan_id': 20}],
     'workloads': [{'kind': 'container', 'runtime': 'docker', 'name': 'web', 'image': 'nginx:1.27', 'publish': '127.0.0.1:8080:80,443:443/tcp', 'binds': '/srv/web:/usr/share/nginx/html:ro,/srv/logs:/var/log/nginx'},
                  {'kind': 'container', 'runtime': 'docker', 'name': 'plain', 'image': 'busybox'},
                  {'kind': 'container', 'runtime': 'podman', 'name': 'pod', 'image': 'app:1'},
                  {'kind': 'vm', 'name': 'db', 'disk': '/tank/db.qcow2', 'bridge': 'br9'},
                  {'kind': 'vm', 'name': 'cache', 'disk': '/tank/cache.qcow2', 'network': 'default'}],
     'firewall': [{'action': 'allow', 'proto': 'tcp', 'port': '445', 'source': '10.0.20.0/24'}, {'action': 'deny', 'proto': 'udp', 'port': '1000:1010'}]},
    {'name': 'second-host', 'workloads': [{'kind': 'container', 'runtime': 'docker', 'name': 'app', 'image': 'app:2'}]}]}


def design():
    return mapdesign.normalize(DOC)


def run(cmd, cwd, timeout=180):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                          env={**os.environ, 'TF_IN_AUTOMATION': '1', 'TF_INPUT': '0', 'CHECKPOINT_DISABLE': '1'})


class Terraform(unittest.TestCase):
    def test_the_export_is_balanced_and_names_what_it_leaves_out(self):
        text = mapdesign.terraform(design())
        code = '\n'.join(x for x in text.splitlines() if not x.lstrip().startswith('#'))
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
        self.assertEqual(code.count('{'), code.count('}'))
        self.assertEqual(code.count('['), code.count(']'))
        self.assertIn('podman container pod', text)
        self.assertIn('resource "libvirt_domain"', text)

    def test_terraform_validates_it(self):
        exe = shutil.which('terraform')
        if not exe:
            self.skipTest('terraform is not on PATH, so the export was not validated')
        with tempfile.TemporaryDirectory(prefix='sf-tf-') as tmp:
            Path(tmp, 'main.tf').write_text(mapdesign.terraform(design()))
            init = run([exe, 'init', '-backend=false', '-input=false', '-no-color'], tmp)
            if init.returncode:
                self.skipTest(f'terraform init could not get the providers (no network?), so the export was not validated: {(init.stderr or init.stdout)[-200:].strip()}')
            got = run([exe, 'validate', '-no-color'], tmp)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)


class Puppet(unittest.TestCase):
    def test_the_export_is_balanced_and_quotes_its_values(self):
        doc = design()
        doc['hosts'][0]['workloads'][0]['image'] = "x'; exec { 'bad': }"
        text = mapdesign.puppet(doc)
        self.assertIn("x\\'; exec", text)
        code = re.sub(r"'(?:[^'\\]|\\.)*'", "''", '\n'.join(x for x in text.splitlines() if not x.lstrip().startswith('#')))
        self.assertEqual(code.count('{'), code.count('}'))
        self.assertEqual(code.count('['), code.count(']'))

    def test_puppet_parser_validates_it(self):
        exe = shutil.which('puppet')
        if not exe:
            self.skipTest('puppet is not on PATH, so the export was not validated')
        with tempfile.TemporaryDirectory(prefix='sf-pp-') as tmp:
            path = Path(tmp, 'design.pp')
            path.write_text(mapdesign.puppet(design()))
            got = run([exe, 'parser', 'validate', str(path)], tmp, 120)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)


if __name__ == '__main__':
    unittest.main()
