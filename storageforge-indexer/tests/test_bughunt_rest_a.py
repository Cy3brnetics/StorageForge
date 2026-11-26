"""Regressions from the bug hunt (rest, set A): the container label, the egress firewall's port list."""
import re
import subprocess
import unittest
from pathlib import Path

import storageforge_index

ROOT = Path(__file__).resolve().parents[1]


class Versions(unittest.TestCase):
    def test_runtime_image_label_names_the_release(self):
        text = (ROOT / 'Dockerfile').read_text()
        arg = re.search(r'^FROM \$\{BASE_IMAGE\} AS runtime\n(?:#.*\n)*ARG VERSION=(\S+)$', text, re.M)
        self.assertIsNotNone(arg, 'the runtime stage takes its version from an ARG')
        self.assertEqual(arg.group(1), storageforge_index.__version__)
        self.assertIn('org.opencontainers.image.version="${VERSION}"', text)
        self.assertNotIn('0.3.2', text)
        for compose in ROOT.glob('docker-compose*.yml'):
            for tag in re.findall(r'^\s*image: storageforge[\w-]*:(\S+)$', compose.read_text(), re.M):
                self.assertEqual(tag, storageforge_index.__version__, compose.name)


class Firewall(unittest.TestCase):
    def test_udp_ports_are_accepted_and_bad_ones_refused_before_any_rule_changes(self):
        script = (ROOT / 'docker' / 'egress-firewall.sh').read_text()
        self.assertIn('*/udp', script)
        # the port check alone, run as the script runs it
        check = script[script.index('for p in $PORTS; do     # all checked'):script.index('hook() {')]

        def run(ports):
            return subprocess.run(['sh', '-c', 'PORTS=$1\n' + check + '\necho ok', '_', ports], capture_output=True, text=True).returncode
        self.assertEqual(run('22 443/tcp 51820/udp'), 0)
        for bad in ('22/foo', '99999', 'x/udp', '0/udp', '/udp'):
            self.assertEqual(run(bad), 2, bad)


class InitVolumes(unittest.TestCase):
    def run_block(self, app_secret, vault_secret):
        import tempfile
        script = (ROOT / 'docker' / 'init-volumes.sh').read_text()
        block = script[script.index('VAULT=$APP'):script.index('if [ ! -s "$VAULT/vault_secret" ]; then')]
        with tempfile.TemporaryDirectory() as tmp:
            app, vault = Path(tmp, 'app'), Path(tmp, 'vault')
            app.mkdir()
            vault.mkdir()
            if app_secret is not None:
                (app / 'vault_secret').write_text(app_secret)
            if vault_secret is not None:
                (vault / 'vault_secret').write_text(vault_secret)
            block = block.replace('/secrets/vault', str(vault))
            got = subprocess.run(['sh', '-c', 'set -eu\nAPP=$1\nlog() { :; }\n' + block + '\necho done', '_', str(app)], capture_output=True, text=True)
            return got.returncode, (app / 'vault_secret').exists(), (vault / 'vault_secret').read_text() if (vault / 'vault_secret').exists() else None

    def test_a_different_secret_beside_the_enclaves_is_not_deleted(self):
        self.assertEqual(self.run_block('new', 'old'), (64, True, 'old'))

    def test_the_same_secret_or_none_beside_it_is_moved_as_before(self):
        self.assertEqual(self.run_block('same', 'same'), (0, False, 'same'))
        self.assertEqual(self.run_block('moved', None), (0, False, 'moved'))


if __name__ == '__main__':
    unittest.main()
