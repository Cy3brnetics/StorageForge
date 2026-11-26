"""Is this path under that folder, and which mount holds it (paths.py): the one rule every module uses."""
import posixpath
import unittest

from props import HAVE, example, given, st
from storageforge_index import agentfiles, moves, paths, remote, workloads
from storageforge_index.runtimes import docker

part = st.sampled_from(['tank', 'tank2', 'tan', 'a', 'b', ''])
path = st.lists(part, max_size=4).map(lambda ps: '/' + '/'.join(ps)) | st.text(st.sampled_from('/tank2ab'), max_size=10)


def by_parts(p: str, root: str) -> bool:
    """The rule in names: a path is under root when it is root, or root's names are the first of more names of its own."""
    names, rnames = p.split('/'), root.rstrip('/').split('/')
    return p == root or (len(names) > len(rnames) and names[:len(rnames)] == rnames)


class Rule(unittest.TestCase):
    def test_a_folder_holds_itself_and_what_is_in_it_but_not_its_neighbour(self):
        self.assertTrue(paths.is_under('/tank', '/tank'))
        self.assertTrue(paths.is_under('/tank/a', '/tank'))
        self.assertTrue(paths.is_under('/tank/a', '/tank/'))
        self.assertFalse(paths.is_under('/tank2', '/tank'))
        self.assertFalse(paths.is_under('/tank2/a', '/tank'))
        self.assertFalse(paths.is_under('/tank', '/tank/a'))

    def test_the_root_holds_every_absolute_path_and_no_relative_one(self):
        for p in ('/', '/tank', '//x'):
            self.assertTrue(paths.is_under(p, '/'), p)
        for p in ('', 'tank', 'tank/a'):
            self.assertFalse(paths.is_under(p, '/'), p)

    def test_every_old_name_is_the_one_rule(self):
        self.assertIs(remote.is_under, paths.is_under)
        self.assertIs(moves._under, paths.is_under)
        self.assertIs(docker._under, paths.is_under)

    def test_the_deepest_mount_wins_and_the_first_of_equals(self):
        ms = [('/', 'a'), ('/tank', 'b'), ('/tank/a', 'c'), ('/tank', 'd'), ('/tank2', 'e')]
        key = lambda m: m[0]
        self.assertEqual(paths.deepest(ms, '/tank/a/x', key), ('/tank/a', 'c'))
        self.assertEqual(paths.deepest(ms, '/tank/ab', key), ('/tank', 'b'))
        self.assertEqual(paths.deepest(ms, '/tank2/x', key), ('/tank2', 'e'))
        self.assertEqual(paths.deepest(ms, '/srv', key), ('/', 'a'))
        self.assertIsNone(paths.deepest(ms, 'tank', key))
        self.assertIsNone(paths.deepest(ms[1:], '/srv', key))

    def test_the_three_mount_finders_answer_alike(self):
        mounts = [{'target': '/', 'state': 'indexed'}, {'target': '/tank', 'state': 'indexed'}, {'target': '/tank/a', 'state': 'skipped'},
                  {'target': '/tank2', 'state': 'gone'}]

        class Conn:
            def all(self, _q, _a):
                return [(i, m['target']) for i, m in enumerate(mounts) if m['state'] == 'indexed']
        self.assertEqual(moves.mount_of({'mounts': mounts}, '/tank/a/x')['target'], '/tank/a')
        self.assertEqual(moves.mount_of({'mounts': mounts}, '/tank2/x')['target'], '/')
        self.assertIsNone(moves.mount_of({'mounts': mounts}, 'tank'))
        self.assertEqual(agentfiles._mount_for(Conn(), 'h', '/tank/a/x'), (1, '/tank'))
        self.assertIsNone(agentfiles._mount_for(Conn(), 'h', 'tank'))
        self.assertEqual(workloads.sits_on([(m['target'], m['state']) for m in mounts], '/tank/a/x'), {'mount': '/tank/a', 'filesystem': 'skipped'})


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class Random(unittest.TestCase):
    @given(path, path)
    @example('/tank2', '/tank')
    @example('/tank', '/tank/')
    @example('tank', '/')
    @example('', '/')
    @example('/', '')
    def test_is_under_says_what_the_names_say(self, p, root):
        self.assertEqual(paths.is_under(p, root), by_parts(p, root), (p, root))

    @given(path, st.lists(path, max_size=6))
    def test_deepest_is_the_longest_folder_that_holds_the_path(self, p, roots):
        got = paths.deepest(roots, p)
        holding = [r for r in roots if paths.is_under(p, r)]
        if not holding:
            self.assertIsNone(got)
        else:
            self.assertEqual(len(got), max(map(len, holding)))
            self.assertEqual(got, next(r for r in holding if len(r) == len(got)))
            if posixpath.isabs(p):
                self.assertTrue(paths.is_under(p, got))


if __name__ == '__main__':
    unittest.main()
