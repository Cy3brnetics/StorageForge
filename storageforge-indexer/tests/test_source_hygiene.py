"""SF-54: no source file holds a character that makes code read differently from how it runs ("Trojan Source"). A bidirectional control reorders a line on
screen and in a review tool and changes nothing the interpreter sees, so a comment can appear to be code or code to be a comment. Two of them sat in a character
class in the host-log scrubber and its test, for the honest reason that the class is about them; a class like that writes them as escapes."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = {'.py', '.js', '.mjs', '.css', '.html', '.sql', '.sh', '.yml', '.yaml', '.toml', '.json'}
SKIP = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'archive', '.obsidian', '.mypy_cache', '.ruff_cache'}
BIDI = re.compile('[\u202a-\u202e\u2066-\u2069]')      # embeddings, overrides and isolates; written as escapes so this file holds none itself


def sources():
    for path in ROOT.rglob('*'):
        if path.suffix in SOURCE and path.is_file() and not SKIP & set(path.relative_to(ROOT).parts) and path.stat().st_size < 4_000_000:
            yield path


class SourceHygiene(unittest.TestCase):
    def test_no_source_file_holds_a_bidirectional_control(self):
        found = []
        for path in sources():
            for number, line in enumerate(path.read_text(encoding='utf-8', errors='replace').split('\n'), 1):      # not splitlines: it splits on two of the characters it is looking among
                if BIDI.search(line):
                    found.append(f'{path.relative_to(ROOT)}:{number}')
        self.assertEqual(found, [], 'write it as an escape (\\u202e), not as the character')

    def test_the_check_sees_what_it_is_for(self):
        self.assertTrue(BIDI.search('a\u202eb') and BIDI.search('\u2066') and not BIDI.search('caf\u00e9 \u05e9\u05dc\u05d5\u05dd'))
