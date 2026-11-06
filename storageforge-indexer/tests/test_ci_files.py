"""The CI files under .forgejo/ and .github/ parse, and hold nothing a reviewer cannot see. A malformed workflow only shows up when the first
push fails, and a bidirectional control character in one can make the file read differently from what runs. Skipped when neither folder exists."""
import re
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
FOLDERS = [REPO / '.forgejo', REPO / '.github']
# the Unicode bidirectional controls and isolates, and the zero-width characters that hide in a diff
HIDDEN = re.compile('[‪-‮⁦-⁩​-‏⁠﻿]')


def ci_files():
    return sorted(p for folder in FOLDERS if folder.is_dir() for p in folder.rglob('*') if p.is_file() and p.suffix in ('.yml', '.yaml'))


class CiFiles(unittest.TestCase):
    def setUp(self):
        if not any(f.is_dir() for f in FOLDERS):
            self.skipTest('neither .forgejo/ nor .github/ exists in this checkout')

    def test_there_is_a_file_to_check(self):
        self.assertTrue(ci_files(), 'a CI folder exists and holds no .yml or .yaml file')

    def test_every_file_parses_and_is_a_mapping(self):
        for path in ci_files():
            with self.subTest(file=str(path.relative_to(REPO))):
                text = path.read_text(encoding='utf-8')
                self.assertTrue(text.strip(), 'the file is empty')
                try:
                    docs = [d for d in yaml.safe_load_all(text) if d is not None]
                except yaml.YAMLError as exc:
                    self.fail(f'does not parse: {exc}')
                self.assertTrue(docs, 'the file holds only comments')
                for doc in docs:
                    self.assertIsInstance(doc, dict, 'the top level is not a mapping')

    def test_a_workflow_has_jobs_with_steps_or_a_runner(self):
        for path in ci_files():
            if path.parent.name != 'workflows':
                continue
            with self.subTest(file=str(path.relative_to(REPO))):
                try:
                    doc = yaml.safe_load(path.read_text(encoding='utf-8'))
                except yaml.YAMLError as exc:
                    self.fail(f'does not parse: {exc}')
                self.assertIsInstance(doc, dict, 'the top level is not a mapping')
                jobs = doc.get('jobs')
                self.assertIsInstance(jobs, dict, 'no jobs')
                self.assertTrue(jobs, 'jobs is empty')
                for name, job in jobs.items():
                    self.assertIsInstance(job, dict, f'job {name} is not a mapping')
                    self.assertTrue(job.get('steps') or job.get('uses'), f'job {name} has no steps')

    def test_no_tabs_in_indentation_and_no_hidden_characters(self):
        for path in ci_files():
            with self.subTest(file=str(path.relative_to(REPO))):
                for n, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                    self.assertNotRegex(line, r'^[ ]*\t', f'line {n} is indented with a tab')
                    self.assertIsNone(HIDDEN.search(line), f'line {n} has a bidirectional or zero-width character')


if __name__ == '__main__':
    unittest.main()
