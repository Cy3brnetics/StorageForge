"""The `trash` step's script. What must hold: a host has one trash, on the local drive with the most free space (the owner's
choice of 2026-11-20), each path kept there under its whole path and the date. On that drive it is a rename; from another drive
it is copied there and only then gone from where it was, and not moved at all when the trash has no room. A report changes
nothing. A path counts as already trashed only when that very path is in the trash, however deep it was and whether or not the
folder it was in is still there; a file of the same name trashed from another folder is not it."""
import os
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


class Base(unittest.TestCase):
    """Files in a folder under /tmp; the trash in another folder of the same filesystem unless a test says otherwise."""
    def setUp(self):
        self.top = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.top, True)
        self.home = self.top / 'big'
        self.home.mkdir()
        self.bin = self.top / 'bin'
        self.bin.mkdir()
        # fs_top is the folder of the test: the real one is /tmp, and a test writes no trash folder there
        self.bash = PRELUDE + f'fs_top() {{ printf %s {self.top}; }}\n' + function('trash_home') + function('t_trash')

    def trash(self, path, apply=True, home=None, extra=''):
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'APPLY': '1' if apply else '0', 'SF_TRASH_HOME': str(home or self.home)}
        ran = subprocess.run(['bash', '-c', self.bash + extra + 't_trash "$1"', 'bash', str(path)], capture_output=True, text=True, env=env)
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def make(self, rel, body=None):
        p = self.top / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body or rel)
        return p

    def kept(self, p, home=None, day='2026-11-19'):
        return Path(f'{home or self.home}/.storageforge-trash/{day}{p}')


class Trash(Base):
    def test_it_moves_under_the_date_and_its_whole_path_and_a_second_run_finds_it_there(self):
        p = self.make('a/x.iso')
        self.assertIn('would: mv', self.trash(p, apply=False))
        self.assertTrue(p.exists())
        self.assertFalse((self.home / '.storageforge-trash').exists(), 'a report makes nothing, not even the trash folder')
        self.assertIn('ok: in the trash', self.trash(p))
        self.assertEqual(self.kept(p).read_text(), 'a/x.iso')
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
        p = self.make('a/x')
        self.trash(p)
        self.trash(self.make('a/x'))
        self.assertEqual(sorted(f.name for f in self.kept(p).parent.iterdir()), ['x', 'x.101500'])

    def test_one_trashed_by_an_older_script_at_the_top_of_its_filesystem_is_still_found(self):
        old = self.top / '.storageforge-trash/2026-11-01/a/x.iso'
        old.parent.mkdir(parents=True)
        old.write_text('older')
        self.assertIn('already in the trash', self.trash(self.top / 'a/x.iso'))

    def test_here_keeps_it_on_its_own_filesystem(self):
        """The subvolume step trashes the folder it just copied: copying it again to another drive would be the whole folder."""
        out = subprocess.run(['bash', '-c', self.bash + 't_trash "$1" here', 'bash', str(self.make('vol/other'))], capture_output=True, text=True,
                             env={'PATH': '/usr/bin:/bin', 'APPLY': '1', 'SF_TRASH_HOME': '/nonexistent'}).stdout
        self.assertIn('ok: in the trash', out)
        self.assertTrue(Path(f'{self.top}/.storageforge-trash/2026-11-19{self.top}/vol/other').exists())

    def test_fs_top_is_the_folder_where_the_device_changes(self):
        ran = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + function('fs_top') + 'fs_top /proc/sys/kernel/ostype; echo; fs_top /proc/.'],
                             capture_output=True, text=True)
        self.assertEqual(ran.stdout.split(), ['/proc', '/proc'], ran.stderr)


@unittest.skipUnless(os.path.isdir('/dev/shm') and os.stat('/dev/shm').st_dev != os.stat(tempfile.gettempdir()).st_dev, 'needs /dev/shm on a filesystem of its own')
class AnotherDrive(Base):
    """The trash on another filesystem than the files: /dev/shm, while the files are under /tmp."""
    def setUp(self):
        super().setUp()
        self.far = Path(tempfile.mkdtemp(dir='/dev/shm'))
        self.addCleanup(shutil.rmtree, self.far, True)

    def test_it_is_copied_there_and_gone_from_here_only_once_whole(self):
        p = self.make('films/a/b.mkv', 'x' * 5000)
        report = self.trash(p, apply=False, home=self.far)
        self.assertIn(f'would: copy {p} to the trash on {self.far}', report)
        self.assertTrue(p.exists())
        self.assertIn('ok: in the trash', self.trash(p, home=self.far))
        self.assertFalse(p.exists())
        self.assertEqual(self.kept(p, self.far).read_text(), 'x' * 5000)
        self.assertIn('already in the trash', self.trash(p, home=self.far))

    def test_no_room_there_and_nothing_moves(self):
        p = self.make('films/big.mkv', 'x' * 5000)
        (self.bin / 'df').write_text('#!/bin/sh\nprintf "Filesystem 1-blocks Used Available Capacity Mounted\\nshm 2000000000 1999990000 10000 99%% /dev/shm\\n"\n')
        (self.bin / 'df').chmod(0o755)
        out = self.trash(p, home=self.far)
        self.assertIn('conflict:', out)
        self.assertIn('not moved', out)
        self.assertTrue(p.exists())

    def test_a_folder_with_a_filesystem_mounted_inside_is_left_alone(self):
        d = self.top / 'srv'
        (d / 'mnt').mkdir(parents=True)
        (self.bin / 'findmnt').write_text(f'#!/bin/sh\necho /\necho {d}/mnt\n')
        (self.bin / 'findmnt').chmod(0o755)
        out = self.trash(d, home=self.far)
        self.assertIn('a filesystem is mounted inside', out)
        self.assertTrue(d.exists())


class Picked(Base):
    """Which drive is the trash when nothing names it: the local, writable one with the most free space."""
    def pick(self, df_rows):
        (self.bin / 'df').write_text('#!/bin/sh\nprintf "Filesystem 1-blocks Used Available Capacity Mounted\\n' + ''.join(r.replace('%', '%%') + '\\n' for r in df_rows) + '"\n')
        (self.bin / 'df').chmod(0o755)
        (self.bin / 'findmnt').write_text('#!/bin/sh\necho rw,relatime\n')
        (self.bin / 'findmnt').chmod(0o755)
        ran = subprocess.run(['bash', '-c', self.bash + 'trash_home'], capture_output=True, text=True, env={'PATH': f'{self.bin}:/usr/bin:/bin'})
        return ran.stdout

    def test_the_most_free_space_wins_and_boot_and_container_stores_never_do(self):
        small, big = self.top / 'small', self.top / 'big'
        rows = [f'/dev/sda2 100 50 50 50% {small}', f'/dev/sdb1 9000 1000 8000 11% {big}',
                '/dev/sda1 99999 1 99998 1% /boot', '/dev/sdc1 99999 1 99998 1% /var/lib/docker']
        self.assertEqual(self.pick(rows), str(big))

    def test_a_drive_this_account_cannot_write_is_passed_over(self):
        locked = self.top / 'locked'
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        if os.access(locked, os.W_OK):
            self.skipTest('running as root: every folder is writable')
        rows = [f'/dev/sdb1 9000 1000 8000 11% {locked}', f'/dev/sda2 100 50 50 50% {self.home}']
        self.assertEqual(self.pick(rows), str(self.home))


if __name__ == '__main__':
    unittest.main()
