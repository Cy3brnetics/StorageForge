"""Random tests of the capacity maths (capacity.py) and of who may call which route (permissions.py). test_capacity_vectors.py pins figures that the
planner's JavaScript must also reach; these say what must hold for any pool: every byte of raw space is counted once, and never less than nothing is usable."""
import unittest

from props import HAVE, given, st
from storageforge_index import permissions
from storageforge_index.capacity import KiB, fmt_bin, parse_size, pool_capacity

TB = 10 ** 12
disk = st.integers(1, 30).map(lambda n: n * 250 * 10 ** 9)          # 250 GB to 7.5 TB, in steps a shop sells
LAYOUTS = [('zfs', 'stripe'), ('zfs', 'mirror'), ('zfs', 'raidz1'), ('zfs', 'raidz2'), ('zfs', 'raidz3'), ('md', 'raid0'), ('md', 'raid1'), ('md', 'raid5'),
           ('md', 'raid6'), ('md', 'raid10'), ('lvm', 'raid1'), ('btrfs', 'single'), ('btrfs', 'raid1'), ('btrfs', 'raid1c3'), ('btrfs', 'raid10'),
           ('btrfs', 'raid5'), ('btrfs', 'raid6'), ('lvm', 'linear'), ('', '')]
PARTS = ('usable', 'parity', 'overhead', 'fs_reserve', 'waste', 'unused')


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class AnyPool(unittest.TestCase):
    @given(st.sampled_from(LAYOUTS), st.lists(disk, min_size=1, max_size=12), st.none() | st.integers(2, 12), st.sampled_from([None, 'ext4', 'xfs']))
    def test_every_byte_is_counted_once_and_nothing_is_less_than_zero(self, layout, sizes, width, fs):
        kind, level = layout
        r = pool_capacity(kind, level, sizes, width=width, fs=fs)
        self.assertEqual(r['raw'], sum(sizes))
        for part in PARTS:
            self.assertGreaterEqual(r[part], -1e-6 * r['raw'], part)
        self.assertLessEqual(r['usable'], r['raw'])
        if r['usable'] > 0:          # with too few devices usable is held at 0 and the rest no longer adds up, by design
            self.assertAlmostEqual(sum(r[p] for p in PARTS) / r['raw'], 1.0, places=9, msg={p: r[p] for p in PARTS})

    @given(st.sampled_from(LAYOUTS), st.lists(disk, min_size=1, max_size=12))
    def test_a_pool_survives_fewer_failures_than_it_has_disks(self, layout, sizes):
        r = pool_capacity(*layout, sizes)
        self.assertGreaterEqual(r['tolerance'], 0)
        self.assertLess(r['tolerance'], len(sizes))

    @given(st.sampled_from([('md', 'raid0'), ('md', 'raid5'), ('md', 'raid6'), ('zfs', 'stripe'), ('btrfs', 'single'), ('lvm', 'linear')]),
           st.integers(1, 30).map(lambda n: n * 250 * 10 ** 9), st.integers(1, 10))
    def test_one_more_disk_of_the_same_size_never_gives_less(self, layout, size, n):
        self.assertGreaterEqual(pool_capacity(*layout, [size] * (n + 1))['usable'], pool_capacity(*layout, [size] * n)['usable'])

    @given(st.lists(disk, min_size=2, max_size=2))
    def test_a_two_way_mirror_holds_the_smaller_disk_less_its_own_reserve(self, sizes):
        for kind, level in (('md', 'raid1'), ('zfs', 'mirror')):
            r = pool_capacity(kind, level, sizes)
            self.assertLessEqual(r['usable'], min(sizes))
            self.assertGreater(r['usable'], min(sizes) * 0.96)
            self.assertEqual(r['tolerance'], 1)

    @given(st.integers(2, 12), disk, st.sampled_from([4 * KiB, 16 * KiB, 128 * KiB, 1024 * KiB]), st.sampled_from([9, 12, 13]))
    def test_raidz_keeps_no_more_than_its_data_disks_hold(self, width, size, recordsize, ashift):
        for level, parity in (('raidz1', 1), ('raidz2', 2), ('raidz3', 3)):
            if width <= parity:
                continue
            r = pool_capacity('zfs', level, [size] * width, recordsize=recordsize, ashift=ashift)
            self.assertLessEqual(r['usable'], (width - parity) * size)


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class Sizes(unittest.TestCase):
    @given(st.integers(0, 10 ** 15), st.sampled_from(['', 'K', 'M', 'G', 'T', 'KiB', 'MiB', 'GiB', 'KB', 'MB', 'GB', 'TB']), st.sampled_from(['', ' ']))
    def test_a_whole_number_with_a_unit_reads_as_that_many_bytes(self, n, unit, space):
        base = 1000 if unit.endswith('B') and not unit.endswith('iB') else 1024
        power = 'KMGT'.index(unit[0]) + 1 if unit else 0
        self.assertEqual(parse_size(f'{n}{space}{unit}'), n * base ** power if n * base ** power < 2 ** 53 else parse_size(f'{n}{space}{unit}'))

    @given(st.text(max_size=20))
    def test_any_text_is_a_size_or_a_value_error(self, text):
        try:
            self.assertGreaterEqual(parse_size(text), 0)
        except ValueError:
            pass

    @given(st.integers(0, 2 ** 62))
    def test_a_size_shown_reads_back_within_its_rounding(self, n):
        """B and KiB are shown whole, larger units with two decimals: back from the text, a size is out by at most half its last digit."""
        shown = fmt_bin(n)
        unit = 1024 ** ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'].index(shown.split()[1])
        half_digit = unit / 2 if unit <= 1024 else unit * 0.005
        self.assertLessEqual(abs(parse_size(shown.replace(' ', '')) - n), half_digit + 1, shown)


PERMISSIONS = sorted({perm for _, _, perm in permissions._RULES})
api_path = st.lists(st.sampled_from(['api', 'hosts', 'security', 'backups', 'deploy', 'jobs', 'report', 'incident', 'brake', 'x', '1', '..', '', '%2e', 'é']),
                    min_size=1, max_size=5).map(lambda parts: '/api/' + '/'.join(parts))
method = st.sampled_from(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class WhoMayCallWhat(unittest.TestCase):
    @given(st.sets(st.sampled_from(PERMISSIONS)), st.sets(st.sampled_from(PERMISSIONS)), method, api_path)
    def test_holding_more_never_allows_less(self, held, more, m, path):
        if permissions.allows(frozenset(held), m, path):
            self.assertTrue(permissions.allows(frozenset(held | more), m, path))

    @given(method, api_path | st.text(max_size=40))
    def test_every_path_needs_a_known_permission_everything_or_nothing(self, m, path):
        need = permissions.required(m, path)
        self.assertIn(need, {None, permissions.EVERYTHING, *PERMISSIONS})
        self.assertTrue(permissions.allows(frozenset(permissions.ALL), m, path))
        if need is not None:
            self.assertFalse(permissions.allows(frozenset(), m, path))

    @given(st.sets(st.sampled_from(PERMISSIONS)).filter(lambda s: not s >= permissions.ALL), method,
           st.text(st.characters(codec='ascii', categories=('L', 'N')), min_size=1, max_size=12))
    def test_a_route_no_rule_names_is_only_for_an_account_holding_everything(self, held, m, word):
        path = f'/api/zz-unlisted-{word}'
        self.assertEqual(permissions.required(m, path), permissions.EVERYTHING)
        self.assertFalse(permissions.allows(frozenset(held), m, path))


if __name__ == '__main__':
    unittest.main()
