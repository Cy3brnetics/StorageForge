"""The half of lab tier 19 (tests/lab/tiers_enclave.py) that runs without a lab: the tier loads, is registered the way the others are,
names every check of roadmap section 14's Lab paragraph, and the Python it sends into the server's container and onto sf-ctl is Python.
Whether the enclave does what the tier asks of it on the lab's controller is the lab's part, and that part has not run."""
import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load():
    """tiers_enclave imports the lab's helpers, which read SFLAB_STATE when they load. A directory with nothing in it is all they need here."""
    os.environ.setdefault('SFLAB_STATE', tempfile.mkdtemp(prefix='sf-enclave-lab-'))
    for p in (str(ROOT / 'examples' / 'lab'), str(ROOT / 'tests' / 'lab')):
        if p not in sys.path:
            sys.path.insert(0, p)
    import tiers_enclave
    return tiers_enclave


class Tier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tier = load()
        cls.text = (ROOT / 'tests' / 'lab' / 'tiers_enclave.py').read_text()

    def test_the_tier_is_registered_the_way_the_others_are(self):
        tiers = (ROOT / 'tests' / 'lab' / 'tiers.py').read_text()
        self.assertIn("19: 'Key enclave'", tiers)
        self.assertIn('tiers_enclave.tier19(r)', tiers)
        self.assertRegex((ROOT / 'examples' / 'lab' / 'lab.sh').read_text(), r'for t in [0-9 ]* 19[ ;]', 'lab.sh test-all runs it')
        self.assertIn('not run yet', self.text)

    def test_it_has_a_check_for_each_thing_the_roadmap_asks_the_lab_to_show(self):
        for check in ('enclave-labelled', 'enclave-boots', 'enclave-tasks', 'enclave-audit', 'enclave-no-network', 'enclave-memory', 'enclave-taken-over',
                      'enclave-killed', 'enclave-rebuilt'):
            self.assertIn(f"r.check('{check}'", self.text, check)
        self.assertIn('nested virtualization', self.text, 'where sf-ctl has no KVM the checks are skipped with the reason, not passed')

    def test_the_python_it_runs_elsewhere_parses(self):
        """The scripts it sends to the server's container and to sf-ctl are strings here: a typo in one would only show in a lab run."""
        found = 0
        for node in ast.walk(ast.parse(self.text)):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and '\nimport ' in node.value.value:
                ast.parse(node.value.value)
                found += 1
        self.assertGreaterEqual(found, 2)

    def test_it_uses_the_compose_file_the_product_ships_and_names_that_exist(self):
        self.assertTrue((ROOT / 'docker-compose.enclave.yml').exists())
        self.assertIn('docker-compose.enclave.yml', self.tier.ENCLAVE)
        compose = (ROOT / 'docker-compose.enclave.yml').read_text()
        for name in ('starter:', 'sf-vault-secret', '/run/sf-enclave', 'STORAGEFORGE_KVM_GID'):
            self.assertIn(name, compose)
        self.assertEqual(self.tier.RUN_DIR, '/run/sf-enclave')
        from storageforge_index import cli
        vault = next(a for a in cli.build_parser()._actions if a.dest == 'cmd').choices['vault']
        commands = next(a for a in vault._actions if a.dest == 'vault_cmd').choices
        for used in ('add', 'bind', 'unbind', 'secret-add', 'send-secret'):
            self.assertIn(used, commands)
        self.assertIn(f"vault {'add'} --name", self.text)


if __name__ == '__main__':
    unittest.main()
