"""Random tests of the folder analysis (folders.py). _noise decides which folders the file map and the folder views leave out; it became one
regular expression for speed (tests/stress/hammer.py found it was 3 s of a host's file map), and must say exactly what the rules one by one say."""
import unittest
from unittest import mock

from props import HAVE, example, given, st
from storageforge_index import folders

# the rules' own words, the same words a letter off, and ordinary names, so a path lands on every side of every rule
PARTS = sorted({*(d.strip('/').split('/')[-1] for d in folders.NOISE_DIRS), *folders.NOISE_NAMES, 'daily.0', 'weekly.12', 'monthly.x', 'daily.', 'dailyx.1',
                'usr2', 'xnode_modules', 'venv2', '.gitx', 'var', 'lib', 'opt', 'containerd', 'home', 'data', 'srv', 'a', ''})
path = st.lists(st.sampled_from(PARTS) | st.text(st.sampled_from('ab./-_0'), max_size=6), max_size=6).map(lambda ps: '/' + '/'.join(ps))


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class NoisePaths(unittest.TestCase):
    @given(path | st.text(max_size=30))
    @example('/usr')
    @example('/usr2/x')
    @example('/var/lib')
    @example('/var/library')
    @example('/srv/backup/daily.0/home')
    @example('/srv/daily.x')
    @example('node_modules')
    @example('/home/a/.git')
    @example('/home/a/.gitx')
    @example('/opt/containerd/x')
    def test_the_one_search_says_what_the_rules_say(self, p):
        self.assertEqual(folders._noise(p), folders._noise_by_parts(p), p)

    def test_it_follows_the_lists_as_they_are(self):
        """test_feature_routes takes /tmp out of NOISE_DIRS, as its folders are there: a search made once at import missed that."""
        self.assertTrue(folders._noise('/tmp/x'))
        with mock.patch.object(folders, 'NOISE_DIRS', tuple(d for d in folders.NOISE_DIRS if d != '/tmp')):
            self.assertFalse(folders._noise('/tmp/x'))
        self.assertTrue(folders._noise('/tmp/x'))


if __name__ == '__main__':
    unittest.main()
