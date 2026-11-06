"""The half of lab tier 17 (tests/lab/tiers_netlang.py) that runs without a lab: what the firewalld and ufw emitters write for the tier's text, and
that the words the tier looks for on the host are in it. Whether firewalld and ufw take the output and hold it is the lab's part, and that
part has not run: it is not lab-tested."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load():
    """tiers_netlang imports the lab's helpers, which read SFLAB_STATE when they load. A directory with nothing in it is all they need here."""
    os.environ.setdefault('SFLAB_STATE', tempfile.mkdtemp(prefix='sf-netlang-'))
    for p in (str(ROOT / 'examples' / 'lab'), str(ROOT / 'tests' / 'lab')):
        if p not in sys.path:
            sys.path.insert(0, p)
    import tiers_netlang
    return tiers_netlang


class CompiledHalf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nl = load()

    def test_every_word_the_tier_looks_for_is_in_the_compiled_output(self):
        nl = self.nl
        ufw = [x for x in nl.compile_for('ufw')['text'].splitlines() if x]
        for words in nl.UFW_RULES:
            self.assertTrue(any(nl.has_all(x, words) for x in ufw), (words, ufw))
        wall = [x for x in nl.compile_for('firewalld', zone=nl.ZONE)['text'].splitlines() if 'add-rich-rule' in x]
        for words in nl.FIREWALLD_RICH:
            self.assertTrue(any(nl.has_all(x, words) for x in wall), (words, wall))

    def test_what_the_tier_expects_to_be_absent_is_named_as_left_out(self):
        nl = self.nl
        for target, absent, options in (('ufw', nl.UFW_ABSENT, {}), ('firewalld', nl.FIREWALLD_ABSENT, {'zone': nl.ZONE})):
            got = nl.compile_for(target, **options)
            stated = ' '.join(u['statement'] for u in got['unsupported'])
            for port in absent:
                self.assertIn(f'dst-port={port}', stated, target)
                self.assertNotIn(port, got['text'], target)

    def test_firewalld_output_stays_inside_the_labs_own_zone_and_ipset(self):
        text = self.nl.compile_for('firewalld', zone=self.nl.ZONE)['text']
        for line in text.splitlines():
            if line.startswith('firewall-cmd') and '--reload' not in line:
                self.assertTrue(f'--zone={self.nl.ZONE}' in line or f'ipset={self.nl.LIST}' in line, line)

    def test_the_tier_is_registered_the_way_the_others_are(self):
        tiers = (ROOT / 'tests' / 'lab' / 'tiers.py').read_text()
        self.assertIn("17: 'Network language on firewalld and ufw'", tiers)
        self.assertIn('tiers_netlang.tier17(r)', tiers)
        self.assertIn('not lab-tested', (ROOT / 'tests' / 'lab' / 'tiers_netlang.py').read_text())


if __name__ == '__main__':
    unittest.main()
