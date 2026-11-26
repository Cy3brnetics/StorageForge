"""The pool steps for pools that exist, and LUKS (steps_pools.py): a vdev added to a ZFS pool only in the layout the pool has, a disk
replaced or attached; md disks added, replaced and grown with the reshape watched; LUKS formatted, opened, closed and given a key, with
the key on stdin and never on a command line. The Bash runs against stand-in zpool and mdadm that print what the real ones print, and
against the real cryptsetup on an image file where it is installed (format, add-key and the key test need no root; open does)."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

try:
    from test_clone import Db, blk
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db, blk
from storageforge_index import changes, steps_pools

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; later() { echo "later: $*"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
need() { command -v "$1" >/dev/null || { conflict "$1 is not installed"; return 1; }; }
durable() { :; }
dev_guard() { echo "guard $*" >>"$LOG"; [[ ! -e $FAKE/busy-${1##*/} ]] || { conflict "$1 is in use"; return 1; }; }
devs_guard() { local w=$1 d; shift; for d in "$@"; do dev_guard "$d" || return 1; done; }
wipefs() { echo "wipefs $*" >>"$LOG"; }
PROBLEMS=0 STAMP=20261120-120000
'''

MIRROR = '''  pool: tank
 state: ONLINE
  scan: resilvered 1.20G in 00:00:10 with 0 errors on Sun Nov 15 10:00:00 2026
config:

\tNAME           STATE     READ WRITE CKSUM
\ttank           ONLINE       0     0     0
\t  mirror-0     ONLINE       0     0     0
\t    /dev/vdb1  ONLINE       0     0     0
\t    /dev/vdc1  ONLINE       0     0     0
\tlogs
\t  /dev/vdf1    ONLINE       0     0     0

errors: No known data errors
'''
RAIDZ = MIRROR.replace('mirror-0', 'raidz1-0').replace('\t    /dev/vdc1  ONLINE       0     0     0\n',
                                                        '\t    /dev/vdc1  ONLINE       0     0     0\n\t    /dev/vdg1  ONLINE       0     0     0\n')
SINGLE = MIRROR.replace('\t  mirror-0     ONLINE       0     0     0\n\t    /dev/vdb1  ONLINE       0     0     0\n\t    /dev/vdc1  ONLINE       0     0     0\n',
                        '\t  /dev/vdb1    ONLINE       0     0     0\n')

ZPOOL = r'''echo "zpool $*" >>"$LOG"
case $1 in
  list) [[ -e $FAKE/status ]] || exit 1; [[ $2 == -H && $4 == size,health ]] && printf "20G\tONLINE\n"; exit 0 ;;
  get) echo 12 ;;
  status) [[ $2 == -g ]] && exit 0; cat "$FAKE/status" ;;
  add|replace|attach) touch "$FAKE/did-$1" ;;
esac'''

DETAIL = '''/dev/md/data:
           Version : 1.2
        Raid Level : raid1
        Array Size : 2094080 (2045.00 MiB 2144.34 MB)
     Used Dev Size : 2094080 (2045.00 MiB 2144.34 MB)
      Raid Devices : 2
     Total Devices : 2
             State : clean
{extra}
    Number   Major   Minor   RaidDevice State
       0     252       16        0      active sync   /dev/vdb
       1     252       32        1      active sync   /dev/vdc
{more}'''

MDADM = r'''echo "mdadm $*" >>"$LOG"
case "$*" in
  *--detail*--export*) echo MD_UUID=d5af489f ;;
  *--detail*--brief*) echo "ARRAY /dev/md/data metadata=1.2 UUID=d5af489f" ;;
  *--detail*) [[ -e $FAKE/detail ]] || exit 1; cat "$FAKE/detail" ;;
esac
exit 0'''


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor('!unsafe', lambda loader, node: loader.construct_scalar(node))     # what the playbook marks to keep Ansible from rendering it


def playbook(text):
    return yaml.load(text, Loader=Loader)


def stub(d: Path, name: str, body: str):
    p = d / name
    p.write_text('#!/bin/bash\n' + body + '\n')
    p.chmod(0o755)


class Bash(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin, self.fake = self.d / 'bin', self.d / 'fake'
        self.bin.mkdir()
        self.fake.mkdir()

    def run_bash(self, call, apply, extra=''):
        body = steps_pools.BASH.replace('/run/storageforge/secrets', '$FAKE/secrets')
        script = HARNESS + f'APPLY={int(apply)}\n' + extra + body + '\n' + call + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=120,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log')})

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    # ── ZFS ──
    def zfs(self, call, apply, status=MIRROR):
        stub(self.bin, 'zpool', ZPOOL)
        (self.fake / 'status').write_text(status)
        return self.run_bash(call, apply)

    def test_the_layout_is_read_as_zpool_status_prints_it(self):
        for status, want in ((MIRROR, 'mirror:2'), (RAIDZ, 'raidz1:3'), (SINGLE, 'stripe:1')):
            with self.subTest(want):
                out = self.zfs('zp_shape tank', False, status)
                self.assertEqual(out.stdout.split(), [want])

    def test_a_mirror_takes_a_mirror_and_the_report_changes_nothing(self):
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdd /dev/vde")} "" ""', False)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('would: zpool add tank mirror /dev/vdd /dev/vde', out.stdout)
        self.assertFalse((self.fake / 'did-add').exists())

    def test_apply_adds_it_with_the_sector_size_of_the_pool_and_never_forced(self):
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdd /dev/vde")} "" 1', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('zpool add -o ashift=12 -- tank mirror /dev/vdd /dev/vde', self.log())
        self.assertIn('wipefs -aq -- /dev/vdd', self.log())
        self.assertNotIn(' -f', self.log())

    def test_a_single_disk_is_not_added_to_a_mirror(self):
        """The mistake the step is there to stop: a stray disk makes a mirror pool depend on a disk with no copy."""
        out = self.zfs('t_zfs_add tank stripe /dev/vdd "" ""', True)
        self.assertEqual(out.returncode, 1)
        self.assertIn('pool tank is made of a 2-way mirror and the new vdev would be a single disk', out.stdout)
        self.assertIn('never forces it', out.stdout)
        self.assertFalse((self.fake / 'did-add').exists())
        self.assertNotIn('guard', self.log(), 'refused before any device is looked at')

    def test_a_wider_mirror_or_raidz_of_another_width_is_refused_too(self):
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdd /dev/vde /dev/vdh")} "" ""', True)
        self.assertIn('a 2-way mirror and the new vdev would be a 3-way mirror', out.stdout)
        out = self.zfs(f't_zfs_add tank raidz1 {shlex.quote("/dev/vdd /dev/vde")} "" ""', True, RAIDZ)
        self.assertIn('a raidz1 of 3 disks and the new vdev would be a raidz1 of 2 disks', out.stdout)
        out = self.zfs(f't_zfs_add tank raidz1 {shlex.quote("/dev/vdd /dev/vde /dev/vdh")} "" ""', True, RAIDZ)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('-- tank raidz1 /dev/vdd /dev/vde /dev/vdh', self.log())

    def test_a_log_or_cache_disk_goes_in_as_one(self):
        out = self.zfs('t_zfs_add tank stripe /dev/nvme0n1 cache ""', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('-- tank cache /dev/nvme0n1', self.log())
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdd /dev/vde")} log ""', True)
        self.assertIn('-- tank log mirror /dev/vdd /dev/vde', self.log())

    def test_devices_in_the_pool_already_are_nothing_to_do(self):
        out = self.zfs('t_zfs_add tank stripe /dev/vdb "" ""', True)
        self.assertIn('ok: /dev/vdb already in pool tank', out.stdout)
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdb /dev/vdx")} "" ""', True)
        self.assertIn('some of /dev/vdb /dev/vdx are in pool tank', out.stdout)

    def test_a_busy_device_stops_it(self):
        (self.fake / 'busy-vde').touch()
        out = self.zfs(f't_zfs_add tank mirror {shlex.quote("/dev/vdd /dev/vde")} "" ""', True)
        self.assertIn('conflict: /dev/vde is in use', out.stdout)
        self.assertFalse((self.fake / 'did-add').exists())

    def test_replace_resilvers_onto_the_new_disk(self):
        out = self.zfs('t_zfs_replace tank /dev/vdc /dev/vdd ""', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('zpool replace -- tank /dev/vdc /dev/vdd', self.log())
        self.assertIn('resilvering onto /dev/vdd: resilvered 1.20G', out.stdout)
        out = self.zfs('t_zfs_replace tank /dev/vdx /dev/vdd ""', True)
        self.assertIn('conflict: /dev/vdx is not in pool tank', out.stdout)
        out = self.zfs('t_zfs_replace tank /dev/vdf /dev/vdd ""', True, MIRROR.replace('\tlogs', '\tcache'))
        self.assertIn('/dev/vdf is a cache device', out.stdout)

    def test_a_short_name_finds_the_disk_as_zpool_lists_it(self):
        out = self.zfs('zp_find tank vdc; zp_find tank /dev/vdf; zp_find tank vdz || echo none', False)
        self.assertEqual(out.stdout.split(), ['mirror-0', 'logs', 'none'])

    def test_attach_makes_a_mirror_of_a_single_disk_and_leaves_raidz_alone(self):
        out = self.zfs('t_zfs_attach tank /dev/vdb /dev/vdd ""', True, SINGLE)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('a single disk becomes a mirror', out.stdout)
        self.assertIn('zpool attach -- tank /dev/vdb /dev/vdd', self.log())
        out = self.zfs('t_zfs_attach tank /dev/vdb /dev/vdd ""', True, RAIDZ)
        self.assertIn('/dev/vdb is in raidz1-0: attach makes a mirror of a single disk or widens a mirror', out.stdout)

    # ── md ──
    def md(self, call, apply, extra='', more=''):
        stub(self.bin, 'mdadm', MDADM)
        (self.fake / 'detail').write_text(DETAIL.format(extra=extra, more=more))
        # lsblk for the sizes of the members: each 4 GiB, twice what the array uses of them
        stub(self.bin, 'lsblk', 'echo 4294967296')
        return self.run_bash(call, apply, extra='md_path() { echo /dev/md/$1; }\n')

    def test_md_add_takes_a_spare_and_a_rerun_finds_it(self):
        out = self.md('t_md_add data /dev/vdd ""', False)
        self.assertIn('would: mdadm /dev/md/data --add /dev/vdd (as a spare)', out.stdout)
        out = self.md('t_md_add data /dev/vdd ""', True)
        self.assertIn('mdadm /dev/md/data --add /dev/vdd', self.log())
        out = self.md('t_md_add data /dev/vdd ""', True, more='       2     252       48        -      spare   /dev/vdd')
        self.assertIn('ok: /dev/vdd is in data (spare)', out.stdout)

    def test_md_add_to_a_degraded_array_rebuilds(self):
        detail = DETAIL.format(extra='', more='').replace('State : clean', 'State : clean, degraded')
        stub(self.bin, 'mdadm', MDADM)
        (self.fake / 'detail').write_text(detail)
        out = self.run_bash('t_md_add data /dev/vdd ""', False, extra='md_path() { echo /dev/md/$1; }\n')
        self.assertIn('the array is degraded: it rebuilds onto it', out.stdout)

    def test_md_replace_adds_then_replaces_and_a_rerun_takes_the_old_disk_out(self):
        out = self.md('t_md_replace data /dev/vdc /dev/vdd ""', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        lines = [l for l in self.log().splitlines() if '--add' in l or '--replace' in l]
        self.assertEqual(lines, ['mdadm /dev/md/data --add /dev/vdd', 'mdadm /dev/md/data --replace /dev/vdc --with /dev/vdd'])
        # while it copies
        out = self.md('t_md_replace data /dev/vdc /dev/vdd ""', True, extra='    Rebuild Status : 40% complete',
                      more='       2     252       48        1      spare rebuilding   /dev/vdd')
        self.assertIn('ok: copying onto /dev/vdd: Rebuild 40% complete', out.stdout)
        # done: mdadm marks the old one faulty, and the plan takes it out
        detail = DETAIL.format(extra='', more='       0     252       32        -      faulty   /dev/vdc').replace(
            '       1     252       32        1      active sync   /dev/vdc', '       2     252       48        1      active sync   /dev/vdd')
        (self.fake / 'detail').write_text(detail)
        out = self.run_bash('t_md_replace data /dev/vdc /dev/vdd ""', True, extra='md_path() { echo /dev/md/$1; }\n')
        self.assertIn('mdadm /dev/md/data --remove /dev/vdc', self.log())

    def test_md_replace_of_a_disk_that_is_not_working_says_what_to_do(self):
        out = self.md('t_md_replace data /dev/vdx /dev/vdd ""', True)
        self.assertIn('/dev/vdx is not a working member of data (not in it): add the new disk with md-add', out.stdout)

    def test_md_grow_adds_and_reshapes_and_watches_the_reshape(self):
        out = self.md('t_md_grow data /dev/vdd "" ""', False)
        self.assertIn('would: mdadm /dev/md/data --grow --raid-devices=3, after adding /dev/vdd', out.stdout)
        out = self.md('t_md_grow data /dev/vdd "" ""', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('mdadm --grow /dev/md/data --raid-devices=3', self.log())
        out = self.md('t_md_grow data /dev/vdd "" ""', True, extra='    Reshape Status : 12% complete')
        self.assertIn('ok: a reshape is running: Reshape 12% complete', out.stdout)
        out = self.md('t_md_grow data /dev/vdd "" ""', True, more='       2     252       48        2      active sync   /dev/vdd')
        self.assertIn('ok: /dev/vdd are in data', out.stdout)

    def test_md_grow_waits_for_a_degraded_array_and_refuses_raid0(self):
        stub(self.bin, 'mdadm', MDADM)
        (self.fake / 'detail').write_text(DETAIL.format(extra='', more='').replace('State : clean', 'State : clean, degraded, recovering'))
        out = self.run_bash('t_md_grow data /dev/vdd "" ""', True, extra='md_path() { echo /dev/md/$1; }\n')
        self.assertIn('data is clean, degraded, recovering: let it finish before growing it', out.stdout)
        (self.fake / 'detail').write_text(DETAIL.format(extra='', more='').replace('Raid Level : raid1', 'Raid Level : raid0'))
        out = self.run_bash('t_md_grow data /dev/vdd "" ""', True, extra='md_path() { echo /dev/md/$1; }\n')
        self.assertIn('data is raid0: this step grows', out.stdout)

    def test_md_grow_to_the_size_of_larger_disks(self):
        out = self.md('t_md_grow data "" max ""', True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('mdadm --grow /dev/md/data --size=max', self.log())
        stub(self.bin, 'lsblk', 'echo 2145386496')           # the members as large as what it uses
        out = self.run_bash('t_md_grow data "" max ""', True, extra='md_path() { echo /dev/md/$1; }\n')
        self.assertIn('ok: data uses all of its devices', out.stdout)

    # ── LUKS ──
    def luks_env(self, *keys, memory=True):
        sec = self.fake / 'secrets'
        sec.mkdir(exist_ok=True)
        for name, value in keys:
            (sec / name).write_text(value + '\n')        # as vault send-secret writes it
        return '' if not memory else 'stat() { if [[ $1 == -f ]]; then echo tmpfs; else command stat "$@"; fi; }\n'

    def fake_cryptsetup(self):
        stub(self.bin, 'cryptsetup', 'echo "cryptsetup $*" >>"$LOG"\ncase $1 in\n  isLuks) [[ -e $FAKE/luks ]] ;;\n  luksUUID) echo 1111-2222 ;;\n'
                                    '  luksFormat) cat >"$FAKE/stdin-format"; touch "$FAKE/luks" ;;\n  open) cat >"$FAKE/stdin-open" ;;\n  *) cat >/dev/null ;;\nesac')

    def test_luks_format_reads_the_key_on_stdin_and_removes_the_file(self):
        self.fake_cryptsetup()
        extra = self.luks_env(('disk-key', 'correct horse battery'))
        out = self.run_bash('t_luks_format /dev/vdd data-crypt disk-key "" 1 ""', True, extra)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual((self.fake / 'stdin-format').read_text(), 'correct horse battery', 'the key as typed, without the newline')
        self.assertEqual((self.fake / 'stdin-open').read_text(), 'correct horse battery')
        self.assertNotIn('correct horse', self.log() + out.stdout)
        self.assertIn('cryptsetup luksFormat --type luks2 --batch-mode --key-file=- /dev/vdd', self.log())
        self.assertIn('cryptsetup open --key-file=- /dev/vdd data-crypt', self.log())
        self.assertFalse((self.fake / 'secrets' / 'disk-key').exists())

    def test_luks_format_without_the_key_says_how_to_send_it_and_touches_nothing(self):
        self.fake_cryptsetup()
        out = self.run_bash('t_luks_format /dev/vdd data-crypt disk-key "" 1 ""', False, self.luks_env())
        self.assertIn('vault send-secret disk-key --host', out.stdout)
        self.assertNotIn('luksFormat', self.log())

    def test_a_key_file_that_is_not_in_memory_is_refused(self):
        self.fake_cryptsetup()
        extra = self.luks_env(('disk-key', 'x'), memory=False) + 'stat() { echo ext4; }\n'
        out = self.run_bash('t_luks_format /dev/vdd data-crypt disk-key "" 1 ""', True, extra)
        self.assertIn('is not in memory (tmpfs)', out.stdout)
        self.assertNotIn('luksFormat', self.log())

    def test_luks_format_of_a_luks_device_formats_nothing(self):
        self.fake_cryptsetup()
        (self.fake / 'luks').touch()
        out = self.run_bash('t_luks_format /dev/vdd data-crypt disk-key "" "" ""', True, self.luks_env())
        self.assertIn('ok: /dev/vdd is LUKS already (1111-2222)', out.stdout)
        self.assertNotIn('luksFormat', self.log())

    def test_crypttab_gets_one_line_by_uuid(self):
        self.fake_cryptsetup()
        (self.fake / 'luks').touch()
        tab = self.fake / 'crypttab'
        # the function writes /etc/crypttab: run it against a file of the test instead, twice
        body = 'luks_crypttab data-crypt /dev/vdd ask; luks_crypttab data-crypt /dev/vdd ask'
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=1\n' + steps_pools.BASH.replace('/etc/crypttab', str(tab)) + body],
                             capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log')})
        self.assertEqual(tab.read_text(), 'data-crypt UUID=1111-2222 none luks,nofail\n')
        self.assertIn('ok: ' + str(tab) + ' lists data-crypt', out.stdout)

    def test_luks_close_refuses_a_mounted_mapping(self):
        self.fake_cryptsetup()
        stub(self.bin, 'lsblk', 'echo /srv/data')
        mapper = self.fake / 'mapper'
        mapper.mkdir()
        (mapper / 'data-crypt').touch()
        body = steps_pools.BASH.replace('/dev/mapper/', str(mapper) + '/')
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=1\n' + body + '\nt_luks_close data-crypt'], capture_output=True, text=True, timeout=60,
                             env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log')})
        self.assertIn('is in use: mounted at /srv/data', out.stdout)
        self.assertNotIn('cryptsetup close', self.log())

    @unittest.skipUnless(shutil.which('cryptsetup'), 'needs cryptsetup')
    def test_real_cryptsetup_formats_an_image_and_adds_a_key_with_both_keys_off_the_command_line(self):
        """The real cryptsetup, on an image file: format, then a second key slot, then each key opens it (--test-passphrase needs no root).
        A cheap key derivation is added for the test, so it does not take a second of every core and a gigabyte."""
        real = shutil.which('cryptsetup')
        stub(self.bin, 'cryptsetup', f'echo "cryptsetup $*" >>"$LOG"\ncase $1 in luksFormat|luksAddKey) c=$1; shift; exec {real} "$c" --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$@" ;; esac\nexec {real} "$@"')
        img = self.d / 'disk.img'
        with open(img, 'wb') as f:
            f.truncate(20 * 2**20)
        extra = self.luks_env(('old-key', 'first key here'), ('new-key', 'second key here'))
        out = self.run_bash(f't_luks_format {img} x old-key "" "" ""', True, extra)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertTrue((self.fake / 'secrets').exists() and not (self.fake / 'secrets' / 'old-key').exists())
        self.luks_env(('old-key', 'first key here'))
        out = self.run_bash(f't_luks_add_key {img} old-key new-key', True, extra)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('a key slot for new-key', out.stdout)
        self.assertEqual(list((self.fake / 'secrets').iterdir()), [], 'both key files and the temporary one are gone')
        self.assertNotIn('key here', self.log())
        for key in ('first key here', 'second key here'):
            self.assertEqual(subprocess.run([real, 'open', '--test-passphrase', '--key-file=-', str(img)], input=key.encode(), capture_output=True).returncode, 0, key)
        # again: the new key opens it, so nothing is added
        self.luks_env(('old-key', 'first key here'), ('new-key', 'second key here'))
        out = self.run_bash(f't_luks_add_key {img} old-key new-key', True, extra)
        self.assertIn('ok: the key of new-key opens', out.stdout)
        self.luks_env(('old-key', 'wrong'), ('new-key', 'third key'))
        out = self.run_bash(f't_luks_add_key {img} old-key new-key', True, extra)
        self.assertIn('the key of old-key does not open', out.stdout)


STATUS = '''  pool: tank
 state: ONLINE
config:

\tNAME        STATE     READ WRITE CKSUM
\ttank        ONLINE       0     0     0
\t  mirror-0  ONLINE       0     0     0
\t    sdb     ONLINE       0     0     0
\t    sdc     ONLINE       0     0     0

errors: No known data errors
'''


class Checks(Db):
    """What a plan check says, from the last scan, before a script exists."""

    def setUp(self):
        super().setUp()
        lsblk = blk(('sda', 'S1', 'ext4', 'r'), ('sdb', 'S2', 'zfs_member', 'z1'), ('sdc', 'S3', 'zfs_member', 'z2'), ('sdd', 'S4', None, None),
                    ('sde', 'S5', None, None), ('sdf', 'S6', 'ext4', 'busy'))
        self.add('nas', {'collected_at': '2026-11-20T00:00:00+00:00', 'lsblk': lsblk, 'zpool_status': STATUS},
                 [('/', 'ext4', '/dev/sda1', 3, 'rw'), ('/srv/x', 'ext4', '/dev/sdf1', 1, 'rw'), ('/srv/c', 'ext4', '/dev/mapper/data-crypt', 1, 'rw')])

    def said(self, kind, **params):
        spec = changes.TYPES[kind]
        p = {f['name']: (False if f['kind'] == 'bool' else '') for f in spec['fields']}
        p.update(params)
        p.setdefault('confirm', p.get('device') or p.get('devices') or p.get('name'))
        if not p['confirm']:
            p['confirm'] = p.get('devices') or p.get('device') or p.get('name')
        r = changes.check(self.conn, changes.normalize({'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': p}]}))
        return [(i['level'], i['text']) for i in r['tasks'][0]['items']]

    def test_a_vdev_that_does_not_match_the_pool_is_critical(self):
        got = self.said('zfs-add', pool='tank', level='stripe', devices='/dev/sdd', confirm='/dev/sdd')
        self.assertIn(('crit', 'pool tank is made of a 2-way mirror and the new vdev would be a single disk: zpool add refuses a mismatched layout unless forced, '
                               'and this step never forces it'), got)
        got = self.said('zfs-add', pool='tank', level='mirror', devices='/dev/sdd /dev/sde', confirm='/dev/sdd /dev/sde')
        self.assertIn(('ok', 'the new vdev matches the pool: a 2-way mirror, like the 1 there'), got)
        self.assertFalse([t for lv, t in got if lv == 'crit'], got)

    def test_a_busy_or_missing_device_or_pool_is_critical(self):
        got = self.said('zfs-add', pool='tank', level='mirror', devices='/dev/sdd /dev/sdf', confirm='/dev/sdd /dev/sdf')
        self.assertIn(('crit', '/dev/sdf is in use: mounted at /srv/x'), got)
        got = self.said('zfs-add', pool='nope', level='mirror', devices='/dev/sdd /dev/sde', confirm='/dev/sdd /dev/sde')
        self.assertIn(('crit', 'there is no pool nope on nas'), got)

    def test_replace_and_attach(self):
        self.assertIn(('crit', '/dev/sdx is not in pool tank at the last scan'), self.said('zfs-replace', pool='tank', old='/dev/sdx', device='/dev/sdd'))
        got = self.said('zfs-replace', pool='tank', old='sdc', device='/dev/sdd')
        self.assertFalse([t for lv, t in got if lv == 'crit'], got)
        self.assertIn(('ok', 'the mirror sdb is in gets one more side'), self.said('zfs-attach', pool='tank', existing='sdb', device='/dev/sdd'))
        self.assertIn(('ok', '/dev/sdb is in pool tank already'), self.said('zfs-attach', pool='tank', existing='sdc', device='/dev/sdb'))

    def test_md_grow_needs_devices_or_max_and_confirms_by_name_for_size_only(self):
        got = self.said('md-grow', name='data', size='max', confirm='data')
        self.assertIn(('note', 'the size grows once no reshape is running, to the smallest device in the array'), got)
        with self.assertRaisesRegex(ValueError, 'type data again'):
            self.said('md-grow', name='data', size='max', confirm='/dev/sdd')
        self.assertIn(('crit', 'name the devices to grow onto, or grow to the full size of the devices it has'), self.said('md-grow', name='data', confirm='data'))

    def test_luks_names_keys_and_mounts(self):
        got = self.said('luks-format', device='/dev/sdd', name='data-crypt', secret='disk-key', crypttab='ask')
        self.assertTrue(any('vault send-secret disk-key --host nas' in t for _, t in got), got)
        self.assertIn(('crit', '/dev/sdf is in use: mounted at /srv/x'), self.said('luks-format', device='/dev/sdf', name='x', secret='k', wipe=True))
        self.assertIn(('crit', '/dev/mapper/data-crypt is mounted at /srv/c: unmount it first'), self.said('luks-close', name='data-crypt'))
        self.assertIn(('crit', 'the new key is the key it has'), self.said('luks-add-key', device='/dev/sdd', secret='k', new_secret='k'))
        self.assertIn(('crit', 'a:b is not a secret name: letters, digits, . _ and -, starting with a letter or digit, up to 64'), self.said('luks-open', device='/dev/sdd', name='x', secret='a:b'))

    def test_a_secret_name_the_plan_would_not_deliver_is_critical_in_every_step_that_reads_one(self):
        # _x passes the plan's name field, and secretstore.plan_secrets skips it: each step's check says so instead of passing
        crit = ('crit', '_x is not a secret name: letters, digits, . _ and -, starting with a letter or digit, up to 64')
        for kind, more in (('luks-open', {'device': '/dev/sdd', 'name': 'x'}), ('luks-add-key', {'device': '/dev/sdd', 'secret': 'k', 'new_secret': '_x'}),
                           ('tailscale', {}), ('cloudflare-tunnel', {'state': 'absent'}), ('pangolin-site', {'state': 'absent'}),
                           ('netbird', {}), ('openziti', {'identity': 'web-1'})):
            self.assertIn(crit, self.said(kind, **{'secret': '_x', **more}), kind)
        self.assertNotIn(crit[0], [lvl for lvl, _ in self.said('tailscale', secret='tailscale-key')])

    def test_every_device_step_is_destructive_and_gated_in_the_playbook(self):
        for kind in ('zfs-add', 'zfs-replace', 'zfs-attach', 'md-add', 'md-replace', 'md-grow', 'luks-format'):
            self.assertTrue(changes.TYPES[kind].get('destructive'), kind)
        for kind in ('luks-open', 'luks-close', 'luks-add-key'):
            self.assertFalse(changes.TYPES[kind].get('destructive'), kind)
        plan = {'name': 'p', 'tasks': [{'type': 'zfs-add', 'host': 'nas', 'params': {'pool': 'tank', 'level': 'mirror', 'devices': '/dev/sdd /dev/sde', 'confirm': '/dev/sdd /dev/sde'}},
                                       {'type': 'luks-close', 'host': 'nas', 'params': {'name': 'data-crypt'}}]}
        tasks = playbook(changes.ansible(self.conn, plan))[0]['tasks']
        self.assertEqual(tasks[0]['when'], 'storageforge_destructive | default(false) | bool')
        self.assertNotIn('when', tasks[1])
        script = changes.script(self.conn, plan)
        self.assertIn('zfs-add', script.split('CUR_DESTRUCTIVE=1 ;; ')[1].split(')')[0])
        self.assertIn('t_zfs_add', script)
        r = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_shellcheck_finds_no_errors_in_a_plan_of_every_kind(self):
        sc = shutil.which('shellcheck') or shutil.which('shellcheck', path=str(Path(os.sys.executable).parent))
        if not sc:
            self.skipTest('needs shellcheck: pip install -e ".[test]"')
        d = {'devices': '/dev/sdd /dev/sde', 'confirm': '/dev/sdd /dev/sde'}
        tasks = [('zfs-add', {'pool': 'tank', 'level': 'mirror', **d}), ('zfs-replace', {'pool': 'tank', 'old': 'sdc', 'device': '/dev/sdd', 'confirm': '/dev/sdd'}),
                 ('zfs-attach', {'pool': 'tank', 'existing': 'sdb', 'device': '/dev/sdd', 'confirm': '/dev/sdd'}), ('md-add', {'name': 'data', 'device': '/dev/sdd', 'confirm': '/dev/sdd'}),
                 ('md-replace', {'name': 'data', 'old': '/dev/sdb', 'device': '/dev/sdd', 'confirm': '/dev/sdd'}), ('md-grow', {'name': 'data', 'size': 'max', **d}),
                 ('luks-format', {'device': '/dev/sdd', 'name': 'c', 'secret': 'k', 'crypttab': 'ask', 'confirm': '/dev/sdd'}), ('luks-open', {'device': '/dev/sdd', 'name': 'c', 'secret': 'k'}),
                 ('luks-close', {'name': 'c'}), ('luks-add-key', {'device': '/dev/sdd', 'secret': 'k', 'new_secret': 'k2'})]
        script = changes.script(self.conn, {'name': 'p', 'tasks': [{'type': k, 'host': 'nas', 'params': p} for k, p in tasks]})
        r = subprocess.run([sc, '--severity=error', '-s', 'bash', '-'], input=script, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_the_playbook_task_runs_in_bash(self):
        plan = {'name': 'p', 'tasks': [{'type': 'luks-close', 'host': 'nas', 'params': {'name': 'never-open-here'}}]}
        cmd = playbook(changes.ansible(self.conn, plan))[0]['tasks'][0]['ansible.builtin.shell']['cmd']
        with tempfile.TemporaryDirectory() as d:
            stub(Path(d), 'cryptsetup', 'exit 0')
            r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=30, env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ok: never-open-here is not open', r.stdout)


if __name__ == '__main__':
    unittest.main()
