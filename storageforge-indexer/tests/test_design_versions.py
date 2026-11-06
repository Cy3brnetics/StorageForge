"""Saved versions of a planner design (design_versions.py, roadmap 3g): saving, listing, comparing in words, restoring with the
current design kept first, deleting, the limits, who may do what, and what a backup holds. Runs on PostgreSQL too when
STORAGEFORGE_TEST_PG is set (dbfactory)."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import dbfactory

from storageforge_index import backup, design_versions as dv, graph, server, users
from storageforge_index.db import Database

PW = 'a long enough password'


def design(host='planned-01', level='raidz1', disks=('sda', 'sdb', 'sdc'), **extra):
    bp = {'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint', 'metadata': {'host': host, 'generated': '2026-11-06', 'identifiers': 'UUID'},
          'devices': [{'dev': '/dev/' + d, 'model': 'Exos', 'sizeBytes': 4 << 40, 'tier': 'mass', 'member': 'tank', 'partitions': []} for d in disks],
          'pools': [{'name': 'tank', 'type': 'zfs', 'level': level, 'tier': 'mass', 'mount': '/tank', 'members': list(disks),
                     'datasets': [{'name': 'media', 'recordsize': '1M', 'compression': 'lz4'}], 'usableBytes': 8 << 40}],
          'mounts': [], 'remotes': [], 'links': [], 'exports': [], 'protection': []}
    bp.update(extra)
    return bp


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = dbfactory.make(self, Path(self.tmp.name) / 'idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)


class Logic(Base):
    def test_a_version_is_named_timestamped_and_has_an_author(self):
        v = dv.save(self.conn, 'planned-01', design(), 'ann', note='before the move')
        self.assertEqual((v['name'], v['note'], v['author'], v['auto']), ('Version 1', 'before the move', 'ann', False))
        self.assertGreater(v['created_at'], 1_700_000_000)
        self.assertEqual(dv.save(self.conn, 'planned-01', design(), 'bob', name='Mirror plan')['name'], 'Mirror plan')
        self.assertEqual([x['name'] for x in dv.list_versions(self.conn, 'planned-01')], ['Mirror plan', 'Version 1'])      # newest first
        self.assertEqual(dv.list_versions(self.conn, 'other'), [])
        self.assertEqual(dv.get(self.conn, v['id'])['blueprint']['pools'][0]['level'], 'raidz1')

    def test_what_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'StorageBlueprint'):
            dv.save(self.conn, 'h', {'kind': 'x'}, 'ann')
        with self.assertRaisesRegex(ValueError, 'give host'):
            dv.save(self.conn, ' ', design(), 'ann')
        with self.assertRaisesRegex(ValueError, 'control character'):
            dv.save(self.conn, 'h', design(), 'ann', name='a<b>')
        with self.assertRaisesRegex(ValueError, 'longer than'):
            dv.save(self.conn, 'h', design(), 'ann', note='x' * 501)
        with self.assertRaisesRegex(ValueError, 'control character'):
            dv.save(self.conn, 'h', design(links=[{'path': '/a"b', 'kind': 'symlink'}]), 'ann')       # the checks a saved design gets
        with self.assertRaises(LookupError):
            dv.get(self.conn, 99)

    def test_a_version_has_a_size_limit(self):
        big = design(exports=[{'protocol': 'NFSv4.2', 'name': f'n{i}', 'path': '/x' * 200} for i in range(6000)])
        with self.assertRaisesRegex(ValueError, 'too large'):
            dv.save(self.conn, 'h', big, 'ann')

    def test_a_host_keeps_a_number_of_versions_and_only_automatic_ones_make_room(self):
        old = dv.MAX_VERSIONS
        dv.MAX_VERSIONS = 3
        self.addCleanup(setattr, dv, 'MAX_VERSIONS', old)
        a = dv.save(self.conn, 'h', design('h'), 'ann', auto=True)
        dv.save(self.conn, 'h', design('h'), 'ann')
        dv.save(self.conn, 'h', design('h'), 'ann')
        dv.save(self.conn, 'h', design('h'), 'ann')               # full: the automatic one goes
        names = [v['name'] for v in dv.list_versions(self.conn, 'h')]
        self.assertEqual(len(names), 3)
        self.assertNotIn(a['id'], [v['id'] for v in dv.list_versions(self.conn, 'h')])
        with self.assertRaisesRegex(ValueError, 'Delete one first'):
            dv.save(self.conn, 'h', design('h'), 'ann')           # all by hand now: nothing is dropped for the person
        self.assertEqual(len(dv.list_versions(self.conn, 'h')), 3)
        dv.save(self.conn, 'other', design('other'), 'ann')       # another host has its own room

    def test_delete(self):
        v = dv.save(self.conn, 'h', design('h'), 'ann')
        self.assertEqual(dv.delete(self.conn, v['id'])['name'], 'Version 1')
        self.assertEqual(dv.list_versions(self.conn, 'h'), [])
        with self.assertRaises(LookupError):
            dv.delete(self.conn, v['id'])


class Compare(unittest.TestCase):
    def test_the_same_design_has_nothing_to_say(self):
        r = dv.compare(design(), design())
        self.assertTrue(r['same'])
        self.assertEqual(r['changes'], [])
        self.assertIn('same things', r['summary'])

    def test_what_the_planner_works_out_or_stamps_is_not_a_change(self):
        b = design()
        b['metadata']['generated'] = '2030-01-01'
        b['pools'][0]['usableBytes'] = 1
        b['protection'] = [{'node': 'a', 'dataset': 'tank', 'status': 'ok'}]
        a = design()
        a['protection'] = [{'node': 'a', 'dataset': 'tank', 'status': 'warn'}]
        self.assertTrue(dv.compare(a, b)['same'])

    def test_it_says_what_is_in_one_and_what_differs_in_plain_words(self):
        v = design(level='raidz1', disks=('sda', 'sdb', 'sdc'))
        now = design(level='raidz2', disks=('sda', 'sdb', 'sdc', 'sdd'))
        now['pools'][0]['datasets'][0]['compression'] = 'zstd'
        now['exports'] = [{'protocol': 'NFSv4.2', 'name': 'media', 'path': '/tank/media', 'clients': '10.0.0.0/24'}]
        v['links'] = [{'path': '/srv/old', 'kind': 'symlink', 'target': '/tank/old'}]
        r = dv.compare(v, now)
        by = {(c['change'], c['kind'], c['name']): c for c in r['changes']}
        self.assertEqual(by['only_current', 'Drive', '/dev/sdd']['text'].split(' (')[0], 'Drive /dev/sdd is in the current design only')
        self.assertIn('Share media (NFSv4.2) is in the current design only', by['only_current', 'Share', 'media (NFSv4.2)']['text'])
        self.assertIn('Link /srv/old is in this version only', by['only_version', 'Link', '/srv/old']['text'])
        pool = by['different', 'Pool', 'tank']
        self.assertIn('RAID level is raidz1 in this version and raidz2 now', pool['text'])
        self.assertIn('members is sda, sdb, sdc in this version and sda, sdb, sdc, sdd now', pool['text'])
        self.assertEqual(by['different', 'Dataset', 'tank/media']['fields'], [{'field': 'compression', 'version': 'lz4', 'current': 'zstd'}])
        self.assertEqual(r['counts'], {'only_version': 1, 'only_current': 2, 'different': 2})
        self.assertEqual(r['summary'], '1 in this version only, 2 in the current design only, 2 that differ.')

    def test_sizes_are_in_words_and_a_long_list_is_cut_and_counted(self):
        a, b = design(), design()
        b['devices'][0]['sizeBytes'] = 8 << 40
        c = dv.compare(a, b)['changes'][0]
        self.assertEqual((c['fields'][0]['version'], c['fields'][0]['current']), ('4.00 TiB', '8.00 TiB'))
        many = design(links=[{'path': f'/l/{i}', 'kind': 'symlink'} for i in range(dv.MAX_CHANGES + 7)])
        r = dv.compare(many, design())
        self.assertEqual((len(r['changes']), r['truncated']), (dv.MAX_CHANGES, 7))


class Api(Base):
    def setUp(self):
        super().setUp()
        users.create(self.conn, 'root', PW, 'admin')
        self.web = server.create_app(server.App(self.db), 's' * 48)
        self.client = self.login('root')

    def login(self, name, role=None):
        if role:
            users.create(self.conn, name, PW, role)
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        return c

    def saved(self):
        return graph.stored_blueprint(self.conn, 'planned-01')

    def test_save_list_compare_restore_and_delete_through_the_routes(self):
        c = self.client
        self.assertEqual(c.put('/api/planner/design', json=design()).status_code, 200)
        r = c.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design(), 'name': 'raidz1 plan', 'note': 'first'})
        self.assertEqual(r.status_code, 201, r.json)
        first = r.json
        self.assertEqual((first['author'], first['name']), ('root', 'raidz1 plan'))
        self.assertEqual(c.put('/api/planner/design', json=design(level='raidz2')).status_code, 200)
        listed = c.get('/api/planner/versions?host=planned-01').json
        self.assertEqual([v['id'] for v in listed['versions']], [first['id']])
        self.assertNotIn('blueprint', listed['versions'][0])
        self.assertEqual(c.get(f'/api/planner/versions/{first["id"]}').json['blueprint']['pools'][0]['level'], 'raidz1')
        # against the saved design, and against the design on screen
        cmp = c.post('/api/planner/versions/compare', json={'id': first['id']}).json
        self.assertEqual((cmp['version']['name'], cmp['counts']['different']), ('raidz1 plan', 1))
        self.assertTrue(c.post('/api/planner/versions/compare', json={'id': first['id'], 'blueprint': design()}).json['same'])
        # restore: the design on screen (an unsaved edit) is kept first
        draft = design(level='raidz3', disks=('sda', 'sdb', 'sdc', 'sdd', 'sde'))
        res = c.post('/api/planner/versions/restore', json={'id': first['id'], 'current': draft})
        self.assertEqual(res.status_code, 200, res.json)
        self.assertEqual(self.saved()['pools'][0]['level'], 'raidz1')
        kept = res.json['kept']
        self.assertTrue(kept['auto'])
        self.assertIn('Before restoring raidz1 plan', kept['name'])
        self.assertEqual(c.get(f'/api/planner/versions/{kept["id"]}').json['blueprint']['pools'][0]['level'], 'raidz3')
        # and the one it replaced is not lost: restoring that brings the draft back
        back = c.post('/api/planner/versions/restore', json={'id': kept['id']})
        self.assertEqual(self.saved()['pools'][0]['level'], 'raidz3')
        self.assertTrue(back.json['kept'])
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'planner.version.%'")]
        self.assertEqual(actions.count('planner.version.restore'), 2)
        self.assertEqual(c.delete(f'/api/planner/versions/{first["id"]}').status_code, 200)
        self.assertEqual(c.get(f'/api/planner/versions/{first["id"]}').status_code, 404)
        self.assertEqual(c.delete(f'/api/planner/versions/{first["id"]}').status_code, 404)

    def test_restoring_what_a_version_already_holds_makes_no_extra_copy(self):
        c = self.client
        v = c.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).json
        res = c.post('/api/planner/versions/restore', json={'id': v['id'], 'current': design()}).json
        self.assertIsNone(res['kept'])
        self.assertEqual(len(c.get('/api/planner/versions?host=planned-01').json['versions']), 1)

    def test_a_restore_that_cannot_keep_the_current_design_does_not_happen(self):
        c = self.client
        v = c.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).json
        c.put('/api/planner/design', json=design(level='raidz2'))
        old = dv.MAX_VERSIONS
        dv.MAX_VERSIONS = 1
        self.addCleanup(setattr, dv, 'MAX_VERSIONS', old)
        r = c.post('/api/planner/versions/restore', json={'id': v['id']})
        self.assertEqual(r.status_code, 400)
        self.assertIn('Delete one first', r.json['error'])
        self.assertEqual(self.saved()['pools'][0]['level'], 'raidz2')

    def test_bad_requests(self):
        c = self.client
        self.assertEqual(c.post('/api/planner/versions', json={'host': 'h', 'blueprint': {'kind': 'x'}}).status_code, 400)
        self.assertEqual(c.post('/api/planner/versions/restore', json={'id': 'x'}).status_code, 400)
        self.assertEqual(c.post('/api/planner/versions/restore', json={'id': 12}).status_code, 404)
        self.assertEqual(c.post('/api/planner/versions/compare', json={'id': 12}).status_code, 404)
        v = c.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).json
        r = c.post('/api/planner/versions/compare', json={'id': v['id']})        # no saved design, none sent
        self.assertEqual(r.status_code, 400)
        self.assertIn('no saved design', r.json['error'])

    def test_who_may_do_what(self):
        v = self.client.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).json
        viewer = self.login('vera', 'viewer')
        self.assertEqual(viewer.get('/api/planner/versions?host=planned-01').status_code, 200)
        self.assertEqual(viewer.get(f'/api/planner/versions/{v["id"]}').status_code, 200)
        self.assertEqual(viewer.post('/api/planner/versions/compare', json={'id': v['id'], 'blueprint': design()}).status_code, 200)
        self.assertEqual(viewer.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).status_code, 403)
        self.assertEqual(viewer.post('/api/planner/versions/restore', json={'id': v['id']}).status_code, 403)
        self.assertEqual(viewer.delete(f'/api/planner/versions/{v["id"]}').status_code, 403)
        search = self.login('sam', 'search')
        self.assertEqual(search.get('/api/planner/versions?host=planned-01').status_code, 403)
        op = self.login('olive', 'operator')
        self.assertEqual(op.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': design()}).status_code, 201)
        self.assertEqual(self.web.test_client().get('/api/planner/versions?host=x').status_code, 401)

    def test_a_design_of_the_size_the_planner_saves_fits_in_a_request(self):
        big = design(exports=[{'protocol': 'NFSv4.2', 'name': f'n{i}', 'path': '/x' * 100} for i in range(3000)])
        self.assertGreater(len(json.dumps(big)), server.MAX_BODY * 100)
        self.assertEqual(self.client.post('/api/planner/versions', json={'host': 'planned-01', 'blueprint': big}).status_code, 201)

    def test_a_version_is_backed_up_with_the_essentials(self):
        self.assertIn('design_versions', backup.ESSENTIAL)
        self.assertNotIn('design_versions', backup.REBUILDABLE)
        self.assertEqual(copy.deepcopy(len(backup.ESSENTIAL)), len(set(backup.ESSENTIAL)))
