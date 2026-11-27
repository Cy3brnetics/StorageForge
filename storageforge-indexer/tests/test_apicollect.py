"""apicollect: the one way every platform reader collects what it read, writes down what it could not, and cuts a list that holds too much."""
import unittest

from storageforge_index import apiconn
from storageforge_index.apicollect import Reading


def fails(exc):
    def fn():
        raise exc
    return fn


class Collecting(unittest.TestCase):
    def test_an_api_error_is_a_skipped_line_and_the_read_goes_on(self):
        r = Reading([('platform', 'version', {})])
        self.assertIsNone(r.call('hosts', fails(apiconn.ApiError('HTTP 500'))))
        self.assertEqual(r.call('vms', lambda: {'vms': []}), {'vms': []})
        self.assertEqual(r.result(), ([('platform', 'version', {})], ['hosts: HTTP 500']))

    def test_a_long_line_is_cut_and_a_repeated_one_kept_once(self):
        r = Reading()
        r.call('pools', fails(apiconn.ApiError('x' * 500)))
        r.skip('alerts: none')
        r.skip('alerts: none')
        _, skipped = r.result()
        self.assertEqual(len(skipped[0]), 200)
        self.assertEqual(skipped[1:], ['alerts: none'])

    def test_quiet_drops_the_line(self):
        r = Reading()
        self.assertIsNone(r.call('ceph', fails(apiconn.Refused('HTTP 403', 403)), quiet=True))
        self.assertEqual(r.result(), ([], []))

    def test_a_changed_certificate_or_a_lost_pin_fails_the_whole_read(self):
        for exc in (apiconn.CertificateChanged('changed', 'AA:BB'), apiconn.NotPinned('not accepted yet')):
            r = Reading()
            with self.assertRaises(type(exc)):
                r.call('hosts', fails(exc), quiet=True)
            self.assertEqual(r.skipped, [])

    def test_any_other_exception_is_not_caught(self):
        with self.assertRaises(KeyError):
            Reading().call('hosts', fails(KeyError('id')))


class Capping(unittest.TestCase):
    def test_counts_across_lists_and_asks_for_no_more_once_full(self):
        r = Reading()
        cap = r.cap(3, 'snapshots')
        self.assertFalse(cap.full())
        self.assertEqual(cap.take([1, 2]), [1, 2])
        self.assertEqual(r.skipped, [])
        self.assertEqual(cap.take([3, 4, 5]), [3])
        self.assertEqual(r.skipped, ['more than 3 snapshots: the rest was not read'])
        self.assertTrue(cap.full())
        self.assertEqual(cap.take([6]), [])
        self.assertEqual(r.result()[1], ['more than 3 snapshots: the rest was not read'])

    def test_exactly_full_says_nothing_until_another_list_is_due(self):
        r = Reading()
        cap = r.cap(2, 'backups')
        self.assertEqual(cap.take([1, 2]), [1, 2])
        self.assertEqual(r.skipped, [])
        self.assertTrue(cap.full())
        self.assertEqual(r.skipped, ['more than 2 backups: the rest was not read'])

    def test_a_list_cut_elsewhere_is_said_the_same_way(self):
        r = Reading()
        r.cut(10000, 'sites')
        self.assertEqual(r.result()[1], ['more than 10000 sites: the rest was not read'])


if __name__ == '__main__':
    unittest.main()
