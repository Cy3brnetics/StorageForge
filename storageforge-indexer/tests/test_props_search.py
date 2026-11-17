"""Random tests of file search (search.py). A pattern takes one of four roads (an extension, an exact name, a prefix, a glob through the trigram
index or a regex), and each road has to find exactly what a plain matcher finds in the same names. The names go in through the scanner's own
write path (stage_insert and apply_diff), so the trigram table is filled the way a scan fills it. Runs on PostgreSQL too, through dbfactory."""
import fnmatch
import itertools
import shutil
import tempfile
import unittest
from pathlib import Path

import dbfactory
from props import HAVE, example, given, settings, st, scaled
from storageforge_index.search import SearchQuery, classify, glob_to_like, glob_to_regex, run_search
from storageforge_index.stream import extension, to_row

# Letters with case, digits, what file names hold, every character a pattern or LIKE gives meaning to, and two caseless non-ASCII characters
# (case folding past ASCII is up to the database's locale, which this does not test).
NAME_CHARS = 'abcAB019._- %\\!^日本'
PATTERN_CHARS = NAME_CHARS + '*?[]'
names = st.text(st.sampled_from(NAME_CHARS), min_size=1, max_size=10).filter(lambda n: n not in ('.', '..'))
patterns = st.text(st.sampled_from(PATTERN_CHARS), min_size=1, max_size=8)
counter = itertools.count()


def fold(s: str) -> str:
    """ASCII case folding, which both databases do the same way."""
    return s.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def expected(pattern: str, name: str) -> bool:
    kind, val = classify(pattern)
    if kind == 'ext':
        return extension(name, False) == val
    if kind == 'exact':
        return fold(name) == fold(pattern)
    return fnmatch.fnmatchcase(fold(name), fold(pattern))


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class EveryRoadFindsTheSameNames(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def scan(self, file_names) -> str:
        """A new host with one mount holding these names in /d, written as a scan writes them. Returns the host's name."""
        n = next(counter)
        host = f'h{n}'
        c = self.conn
        hid = c.scalar('INSERT INTO hosts (hostname) VALUES (:h) RETURNING host_id', {'h': host})
        mid = c.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})
        scan = self.db.begin_scan(c, hid)
        rows = [to_row([b'f', b'10', b'644', b'0', b'0', b'1700000000', b'', f'/d/{name}'.encode()]) for name in file_names]
        self.db.stage_create(c, n)
        self.db.stage_insert(c, n, rows)
        self.db.apply_diff(c, scan, n, mid, '/', True)
        self.db.stage_drop(c, n)
        return host

    def found(self, host, pattern):
        return {r['path'][len('/d/'):] for r in run_search(self.db, self.conn, SearchQuery(pattern=pattern, hosts=[host], limit=100_000))}

    @settings(max_examples=scaled(40, 600))
    @given(st.lists(names, min_size=1, max_size=25, unique=True), st.lists(patterns, min_size=1, max_size=4))
    @example(['a!b', 'axb', 'a^b'], ['a[!x]b', 'a[^x]b'])
    @example(['a_b', 'axb', 'a%b'], ['a_*', 'a%*', '*_b'])
    @example(['a', 'b', '-', ']'], ['[b-a]', '[!b-a]', '[]]', '[!]]', '[a-]', '[', 'a[b'])
    @example(['abc.TXT', 'abc.txt', 'x.tar.gz'], ['*.txt', '*.TXT', '*.tar.gz', 'ABC.txt'])
    def test_a_search_finds_what_a_plain_matcher_finds(self, file_names, pats):
        host = self.scan(file_names)
        for pattern in pats:
            want = {n for n in file_names if expected(pattern, n)}
            self.assertEqual(self.found(host, pattern), want, f'pattern {pattern!r} ({classify(pattern)[0]}) in {sorted(file_names)}')


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class Translations(unittest.TestCase):
    @given(patterns, names)
    def test_the_like_prefilter_never_drops_a_name_the_glob_matches(self, pattern, name):
        """glob_to_like is only a candidate filter: whatever the glob takes, the LIKE has to take too, or a match is lost before the exact test."""
        import re

        def like(p, s):
            rx = ''.join('.*' if c == '%' else '.' if c == '_' else re.escape(c) for c in p)
            return re.fullmatch(rx, s, re.S | re.I) is not None
        if fnmatch.fnmatchcase(fold(name), fold(pattern)):
            self.assertTrue(like(glob_to_like(pattern), name), (pattern, glob_to_like(pattern), name))

    @given(patterns, names)
    def test_the_regex_matches_as_the_glob_does(self, pattern, name):
        import re
        self.assertEqual(re.search(glob_to_regex(pattern), name, re.S) is not None, fnmatch.fnmatchcase(name, pattern), (pattern, glob_to_regex(pattern), name))


if __name__ == '__main__':
    unittest.main()
