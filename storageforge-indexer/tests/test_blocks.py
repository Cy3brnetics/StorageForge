"""tests/blocks.py names every class that is medium or heavy. A renamed or removed class would drop silently into light, which runs after every
change and has to stay quick, so a name that is no longer a class fails here. So does a class in both lists, and a browser test outside heavy."""
import ast
import unittest
from pathlib import Path

import blocks

HERE = Path(__file__).parent


def classes() -> set[str]:
    """'module.Class' for every TestCase-like class defined at the top of a test module, read from the source so nothing is imported."""
    out = set()
    for path in HERE.glob('test_*.py'):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.ClassDef):
                out.add(f'{path.stem}.{node.name}')
    return out


class Blocks(unittest.TestCase):
    def test_every_name_in_blocks_py_is_a_class_that_exists(self):
        self.assertEqual(sorted((blocks.HEAVY | blocks.MEDIUM) - classes()), [], 'rename it in tests/blocks.py too, or take it out')

    def test_no_class_is_in_two_blocks(self):
        self.assertEqual(sorted(blocks.HEAVY & blocks.MEDIUM), [])

    def test_the_browser_tests_are_heavy(self):
        browser = {c for c in classes() if c.startswith('test_browser_') and not c.split('.')[1].startswith('_')}
        light_or_medium = sorted(c for c in browser if blocks.block_of(c + '.test_x') != 'heavy' and self.is_test_case(c))
        self.assertEqual(light_or_medium, [], 'Chromium is heavy: put the class in HEAVY')

    def test_a_test_id_finds_its_block_by_module_and_class(self):
        name = next(iter(blocks.HEAVY))
        self.assertEqual(blocks.block_of(name + '.test_anything'), 'heavy')
        self.assertEqual(blocks.block_of('test_nowhere.Nothing.test_x'), 'light')
        self.assertTrue(blocks.is_random('test_props_netlang.WhatItAccepts.test_x'))
        self.assertFalse(blocks.is_random('test_routers.Language.test_x'))

    @staticmethod
    def is_test_case(name: str) -> bool:
        module, cls = name.split('.')
        for node in ast.parse((HERE / f'{module}.py').read_text()).body:
            if isinstance(node, ast.ClassDef) and node.name == cls:
                return any('TestCase' in ast.unparse(b) or ast.unparse(b)[:1].isupper() for b in node.bases)
        return False


if __name__ == '__main__':
    unittest.main()
