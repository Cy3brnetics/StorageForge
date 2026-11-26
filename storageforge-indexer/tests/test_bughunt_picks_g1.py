"""Picks G1: the route key needs the password in the request, and log rules go by the unit or program file, never by _COMM."""
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import logrules, server, users
from test_logrules import Db, row

PW = 'a long enough password'


class RouteKeyNeedsThePassword(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, tmp / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        users.create(conn, 'root', PW, 'admin')
        self.web = server.create_app(server.App(db), 's' * 48)

    def browser(self):
        c = self.web.test_client()
        r = c.post('/api/login', json={'username': 'root', 'password': PW, 'route_code': True})
        self.assertEqual(r.status_code, 200)
        self.assertLess(abs(r.get_json()['now'] - time.time()), 5)
        return c, r.get_json()['route_key']

    def test_a_recent_sign_in_is_not_enough_and_wrong_passwords_are_limited(self):
        c, key = self.browser()
        self.assertEqual(c.post('/api/routecode', json={}).status_code, 403, 'the password is in the request or nothing is given')
        self.assertEqual(c.post('/api/routecode', json={'password': 'wrong one'}).status_code, 403)
        self.assertEqual(c.post('/api/routecode', json={'password': PW}).get_json()['route_key'], key)
        for _ in range(8):
            r = c.post('/api/routecode', json={'password': 'wrong one'})
        self.assertEqual(r.status_code, 429, 'guesses are limited as /api/reauth limits them')


class WhoWroteTheLine(Db):
    def test_comm_is_not_the_program(self):
        self.rule(program='sshd', text='*Accepted*', min_level='info')
        self.logged(row('Accepted x', ident='logger', unit='session-3.scope', comm='sshd', priority='6'))
        self.assertEqual(self.raised(), {}, 'a process that renamed itself sshd, in a session scope')
        self.logged(row('Accepted x', ident='x', comm='sshd', priority='6'), now=2000000010.0)
        self.assertEqual(self.raised(2000000010.0), {}, 'a comm with no unit and no exe is nobody journald vouches for')

    def test_the_unit_and_else_the_program_file_are(self):
        self.rule(program='sshd', text='*Accepted*', min_level='info')
        self.logged(row('Accepted x', unit='sshd.service', comm='bash', priority='6'))
        self.assertEqual(len(self.raised()), 1)
        self.assertEqual(logrules.who_wrote({'unit': None, 'exe': '/usr/bin/sshd', 'comm': 'x', 'ident': 'y'}), ['sshd'])
        self.assertEqual(logrules.who_wrote({'unit': 'a.service', 'exe': '/usr/bin/sshd'}), ['a.service', 'a'])
        self.assertEqual(logrules.who_wrote({'ident': 'kernel'}), ['kernel'])

    def test_a_forged_systemd_line_does_not_raise_unit_failed(self):
        self.logged(*[row("x.service: Failed with result 'a'.", ident='systemd', comm='systemd', unit='session-1.scope') for _ in range(4)])
        self.assertEqual(self.raised(), {})
        self.logged(*[row("x.service: Failed with result 'a'.", ident='systemd', comm='systemd', unit='init.scope') for _ in range(4)], now=2000000100.0)
        self.assertEqual(len(self.raised(2000000100.0)), 1)


if __name__ == '__main__':
    unittest.main()
