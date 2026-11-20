"""The `trash` step's script. What must hold: a path counts as already trashed only when that very path is in the trash of its
filesystem, however deep it was and whether or not the folder it was in is still there. A file of the same name trashed from
another folder is not it."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes

PRELUDE = ('set -euo pipefail; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; later() { echo "later: $*"; }\n'
           'act() { if [[ ${APPLY:-1} == 1 ]]; then echo "changed: $*"; else echo "would: $*"; return 1; fi; }; try() { "$@"; }\n'
           'TODAY=2026-11-19; STAMP=101500\n')


def function(name: str) -> str:
    """One bash function, as the change scripts carry it."""
    text = next(v for v in vars(changes).values() if isinstance(v, str) and f'\n{name}() {{' in v)
    return re.search(rf'^{name}\(\) \{{.*?^\}}\n', text, re.S | re.M).group(0)


class Trash(unittest.TestCase):
    def setUp(self):
        self.top = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.top, True)
        # the top of the filesystem is this test's folder: the real one is /tmp or /, and a test writes no trash folder there
        self.bash = PRELUDE + f'fs_top() {{ printf %s {self.top}; }}\n' + function('t_trash')

    def trash(self, path, apply=True):
        ran = subprocess.run(['bash', '-c', self.bash + 't_trash "$1"', 'bash', str(path)], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'APPLY': '1' if apply else '0'})
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def make(self, rel):
        p = self.top / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(rel)
        return p

    def test_it_moves_under_the_date_and_a_second_run_finds_it_there(self):
        p = self.make('a/x.iso')
        self.assertIn('would: ', self.trash(p, apply=False))
        self.assertTrue(p.exists())
        self.assertIn('ok: in the trash', self.trash(p))
        self.assertEqual((self.top / '.storageforge-trash/2026-11-19/a/x.iso').read_text(), 'a/x.iso')
        self.assertIn(f'ok: {p} is already in the trash', self.trash(p))

    def test_the_same_name_trashed_from_another_folder_is_not_this_one(self):
        self.trash(self.make('a/x.iso'))
        self.assertEqual(self.trash(self.top / 'b/x.iso'), f'later: {self.top}/b/x.iso must exist\n')
        (self.top / 'b').mkdir()
        self.assertEqual(self.trash(self.top / 'b/x.iso'), f'later: {self.top}/b/x.iso must exist\n')

    def test_a_deep_path_is_found_again(self):
        p = self.make('1/2/3/4/5/6/7/8/9/10/x')
        self.trash(p)
        self.assertIn('already in the trash', self.trash(p))

    def test_a_path_inside_a_folder_that_was_trashed_whole(self):
        p = self.make('photos/Grade_1/Grade_1/img.jpg')
        self.trash(self.top / 'photos/Grade_1')
        self.assertFalse((self.top / 'photos/Grade_1').exists())
        self.assertIn('already in the trash', self.trash(p))
        self.assertIn('already in the trash', self.trash(p.parent))

    def test_a_second_one_from_the_same_place_the_same_day_keeps_both(self):
        self.trash(self.make('a/x'))
        self.trash(self.make('a/x'))
        self.assertEqual(sorted(f.name for f in (self.top / '.storageforge-trash/2026-11-19/a').iterdir()), ['x', 'x.101500'])

    def test_fs_top_is_the_folder_where_the_device_changes(self):
        ran = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + function('fs_top') + 'fs_top /proc/sys/kernel/ostype; echo; fs_top /proc/.'],
                             capture_output=True, text=True)
        self.assertEqual(ran.stdout.split(), ['/proc', '/proc'], ran.stderr)


if __name__ == '__main__':
    unittest.main()
