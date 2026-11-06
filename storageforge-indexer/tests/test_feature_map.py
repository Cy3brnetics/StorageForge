"""feature_map.py against the code: every feature in the catalogue has a unit test and a place in the KVM lab, or says why it can't,
every test and lab check it names exists, every web route and every command is called by some test, and the docs name no tier that isn't there."""
import ast
import re
import unittest
from pathlib import Path

import feature_map as fm

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
DOCS = ROOT.parent / 'docs'
LAB = TESTS / 'lab'
TIER_FILE = {1: 'tiers.py', 3: 'tiers.py', 4: 'tiers.py', 5: 'tiers.py', 6: 'tiers.py', 7: 'tiers.py', 8: 'tiers.py', 2: 'gauntlet.py',
             9: 'tiers_platform.py', 10: 'tiers_platform.py', 11: 'tiers_platform.py', 12: 'tiers_network.py', 13: 'tiers_features.py', 16: 'tiers_sends.py', 17: 'tiers_netlang.py'}


def unit_names():
    """{'module.Class', 'module.Class.test_x'} for every test file."""
    out = set()
    for path in TESTS.glob('test_*.py'):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.ClassDef):
                out.add(f'{path.stem}.{node.name}')
                out.update(f'{path.stem}.{node.name}.{f.name}' for f in node.body if isinstance(f, ast.FunctionDef))
    return out


def tier_bodies():
    """{tier: its source}, by the def tierN in the file that holds it."""
    out = {2: (LAB / 'gauntlet.py').read_text(), 12: (LAB / 'tiers_network.py').read_text(), 13: (LAB / 'tiers_features.py').read_text()}
    for tier, name in TIER_FILE.items():
        if tier in out:
            continue
        text = (LAB / name).read_text()
        m = re.search(rf'^def tier{tier}\(r\):.*?(?=^def tier\d+\(r\):|^# ── report|\Z)', text, re.M | re.S)
        out[tier] = text[:0] + (m[0] if m else '')
    return out


def named_in_tier(check: str, body: str) -> bool:
    """A check is a quoted name, or a stage like job-run-mirror that gauntlet.py builds from job-run-{method}."""
    if f"'{check}'" in body:
        return True
    return any(f"f'{check[:i]}{{" in body for i in range(4, len(check)) if check[i - 1] == '-')


class TheCatalogue(unittest.TestCase):
    def test_every_row_of_the_catalogue_is_in_the_map(self):
        text = (DOCS / 'features' / 'README.md').read_text()
        rows = re.findall(r'^\| \[([^\]]+)\]\([^)]+\) \|', text, re.M)
        self.assertGreater(len(rows), 30, 'the catalogue moved: this test reads its table')
        catalogue = [r for r in rows if not r.endswith('.md')]
        pages = {'Discovery', 'Views', 'Planning', 'Deploying', 'Administration'}
        self.assertEqual(sorted(set(catalogue) - pages - set(fm.CATALOGUE)), [])
        self.assertEqual(sorted(set(fm.CATALOGUE) - set(catalogue)), [])

    def test_every_feature_has_a_unit_test_and_the_lab_or_a_reason(self):
        for name, f in {**fm.CATALOGUE, **fm.PLATFORM}.items():
            self.assertTrue(f.get('unit'), f'{name} has no unit test')
            self.assertTrue(f.get('lab') or f.get('why'), f'{name} is not verified in the lab, and does not say why')
            self.assertFalse(f.get('lab') and f.get('why'), f'{name} is in the lab and also says it cannot be')

    def test_the_unit_tests_it_names_exist(self):
        have = unit_names()
        missing = [(name, u) for name, f in {**fm.CATALOGUE, **fm.PLATFORM}.items() for u in f['unit'] if u not in have]
        self.assertEqual(missing, [])

    def test_the_lab_checks_it_names_exist(self):
        bodies = tier_bodies()
        missing = [(name, tier, check) for name, f in {**fm.CATALOGUE, **fm.PLATFORM}.items() for tier, check in f.get('lab', [])
                   if not named_in_tier(check, bodies[tier])]
        self.assertEqual(missing, [])

    def test_every_check_in_tier_13_is_for_a_feature(self):
        wanted = {check for f in {**fm.CATALOGUE, **fm.PLATFORM}.values() for tier, check in f.get('lab', []) if tier == 13}
        body = tier_bodies()[13][tier_bodies()[13].index('def tier13('):]
        written = {*re.findall(r"check\('([a-z0-9-]+)'", body), *re.findall(r"r\.add\('([a-z0-9-]+)'", body)}
        written |= {'containers-docker', 'containers-podman', 'canvas', 'markdown', 'file-map', 'structure-graph'}
        written -= {'browse'}       # part of the file search, and not a feature of its own
        self.assertEqual(sorted(wanted - written), [])
        self.assertEqual(sorted(written - wanted), [])


class EveryEntryPoint(unittest.TestCase):
    def test_every_web_route_is_called_by_a_test(self):
        from storageforge_index import server
        from storageforge_index.db import Database
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            db.migrate(conn)
            conn.close()
            web = server.create_app(server.App(db), 's' * 48)
            rules = {r.rule for r in web.url_map.iter_rules() if r.endpoint != 'static'}
        calling = '\n'.join(p.read_text() for p in [*TESTS.glob('test_*.py'), *LAB.glob('*.py')] if p.name != 'test_feature_map.py')

        def called(rule: str) -> bool:
            # the fixed part before the first <...>, as tests write it; a rule ending in a parameter is called with something after it
            fixed = re.split(r'<', rule)[0].rstrip('/')
            return bool(fixed) and fixed in calling
        missing = sorted(r for r in rules if r not in fm.UNCALLED_ROUTES and not r.startswith('/<') and not called(r))
        self.assertEqual(missing, [])

    def test_every_command_is_run_by_a_test(self):
        from storageforge_index import cli
        calling = '\n'.join(p.read_text() for p in [*TESTS.glob('test_*.py'), *LAB.glob('*.py'), *(ROOT / 'examples' / 'lab').glob('*.py')] if p.name != 'test_feature_map.py')
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if getattr(a, 'choices', None))
        # commands that replace the process or only run under a server, which the stack itself runs on every lab build
        served = {'serve'}
        missing = [c for c in sub.choices if c not in served and f"'{c}'" not in calling]
        self.assertEqual(missing, [])


class TheDocs(unittest.TestCase):
    def test_the_tiers_in_kvm_lab_md_are_files_that_exist_or_are_marked_as_not_built(self):
        text = (DOCS / 'kvm-lab.md').read_text()
        for tier, name in re.findall(r'^\| (\d+): [^|]+\| `tests/lab/([a-z0-9_]+\.py)` \|', text, re.M):
            self.assertTrue((LAB / name).exists(), f'tier {tier} names {name}, which does not exist')

    def test_lab_sh_and_the_report_run_every_tier_there_is(self):
        lab = (ROOT / 'examples' / 'lab' / 'lab.sh').read_text()
        loop = re.search(r'for t in ([\d ]+); do', lab)[1].split()
        self.assertEqual(sorted(int(t) for t in loop), sorted([0, *TIER_FILE]))
        tiers = (LAB / 'tiers.py').read_text()
        table = re.search(r'^TIERS = \{(.*?)\}$', tiers, re.M)[1]
        self.assertEqual(sorted(int(n) for n in re.findall(r'(\d+):', table)), sorted([0, *TIER_FILE]))


if __name__ == '__main__':
    unittest.main()
