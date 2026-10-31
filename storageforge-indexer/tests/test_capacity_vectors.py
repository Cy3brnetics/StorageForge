"""capacity.py and the planner's calcEngine must agree: both run tests/vectors/capacity.json."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from storageforge_index.capacity import pool_capacity

HERE = Path(__file__).parent / 'vectors'


class Vectors(unittest.TestCase):
    def test_python(self):
        for v in json.loads((HERE / 'capacity.json').read_text()):
            with self.subTest(v['name']):
                r = pool_capacity(v['kind'], v['level'], v['sizes'], width=v.get('width'), fs=v.get('fs'), ext4_reserve=v.get('reserve', True),
                                  recordsize=v.get('recordsize', 131072), ashift=v.get('ashift', 12))
                self.assertAlmostEqual(r['usable'], v['usable'], delta=max(1, v['usable'] * 1e-9))
                self.assertEqual(r['tolerance'], v['tolerance'])

    @unittest.skipUnless(shutil.which('node'), 'needs node (CI has it)')
    def test_planner(self):
        r = subprocess.run(['node', str(HERE / 'check.mjs')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
