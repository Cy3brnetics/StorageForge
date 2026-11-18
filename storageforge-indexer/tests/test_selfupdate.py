"""Releases: the check inside the application (selfupdate.py) and the script that installs one on the Docker host
(docker/update/storageforge-update). What must hold: only a release tag newer than this version is ever offered or installed; the
application's request leaves the way alerts do and says nothing about the installation; and the installer goes back when the new
release does not become healthy, and installs nothing it was told to verify and could not."""
import http.server
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import __version__, alerts, selfupdate, server, users

HERE = Path(__file__).resolve().parent.parent
SCRIPT = HERE / 'docker' / 'update' / 'storageforge-update'
PW = 'correct horse battery staple 9'
GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}


def git(cwd, *args, env=None):
    return subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True, text=True, env={'PATH': os.environ['PATH'], 'HOME': str(cwd), **GIT_ENV, **(env or {})}).stdout


def release(work, version, tag=None, sign=None):
    """Commit `version` as the tree's version and tag it."""
    (work / 'storageforge_index').mkdir(exist_ok=True)
    (work / 'storageforge_index' / '__init__.py').write_text(f"__version__ = '{version}'\n")
    (work / 'docker-compose.yml').write_text('services: {}\n')
    git(work, 'add', '-A')
    git(work, 'commit', '-q', '-m', f'release {version}')
    if sign:
        git(work, '-c', 'gpg.format=ssh', '-c', f'user.signingkey={sign}', 'tag', '-s', '-m', version, tag or f'v{version}')
    else:
        git(work, 'tag', '-a', '-m', version, tag or f'v{version}')


def reset():
    selfupdate._state.clear()
    selfupdate._state.update(latest=None, checked_at=None, error=None)


class Versions(unittest.TestCase):
    def test_versions_compare_as_numbers_and_three_parts_are_four(self):
        self.assertEqual(selfupdate.as_numbers('v0.5.4'), selfupdate.as_numbers('0.5.4.0'))
        self.assertLess(selfupdate.as_numbers('0.5.4.1'), selfupdate.as_numbers('0.5.10'))
        self.assertLess(selfupdate.as_numbers('0.5.4'), selfupdate.as_numbers('0.5.4.1'))
        for bad in ('', 'v1', '1.2', '0.5.5-rc1', '0.5.4.1.2', 'v0.5.x', '0.5.4\n', None, 5):
            with self.subTest(bad), self.assertRaises(ValueError):
                selfupdate.as_numbers(bad)

    def test_only_release_tags_are_read_from_what_a_repository_lists(self):
        sha = 'a' * 40
        lines = [f'{sha} HEAD\x00multi_ack side-band-64k', f'{sha} refs/heads/main', f'{sha} refs/heads/v9.9.9', f'{sha} refs/tags/v0.5.3', f'{sha} refs/tags/v0.5.3^{{}}',
                 f'{sha} refs/tags/v0.5.10', f'{sha} refs/tags/v0.5.4.1', f'{sha} refs/tags/v0.6.0-rc1', f'{sha} refs/tags/nightly', f'{sha} refs/tags/v1.2', f'{sha} refs/tags/xv7.0.0',
                 f'{sha} refs/tags/v8.0.0/extra']
        body = b'001e# service=git-upload-pack\n0000' + b''.join(f'{len(line) + 5:04x}{line}\n'.encode() for line in lines) + b'0000'
        self.assertEqual(selfupdate.releases(body), ['0.5.3', '0.5.4.1', '0.5.10'])
        self.assertEqual(selfupdate.releases(b'<html>refs/tags/v9.9.9</html>'), [])

    def test_an_address_that_would_show_a_password_or_is_not_http_is_refused(self):
        for bad in ('ssh://git@host/x.git', 'https://user:secret@host/x.git', 'https://token@host/x.git', 'file:///srv/x.git', 'host/x.git', 'https://host/x.git?a=b'):
            with self.subTest(bad), mock.patch.dict(os.environ, {selfupdate.SOURCE_ENV: bad}), self.assertRaises(selfupdate.UpdateCheckError):
                selfupdate.source()
        with mock.patch.dict(os.environ, {selfupdate.SOURCE_ENV: ''}):
            self.assertIsNone(selfupdate.source())


class Repository(unittest.TestCase):
    """A real repository, and what git itself advertises for it, served the way a git host serves it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        git(self.work, 'init', '-q', '-b', 'main')
        self.seen = seen = []
        case = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, dict(self.headers)))
                if not self.path.startswith('/Gabe/StorageForge.git/info/refs?service=git-upload-pack') or case.answer != 200:
                    self.send_response(case.answer if case.answer != 200 else 404)
                    self.end_headers()
                    return
                body = b'001e# service=git-upload-pack\n0000' + subprocess.run(['git', 'upload-pack', '--stateless-rpc', '--advertise-refs', str(case.work)], capture_output=True, check=True).stdout
                self.send_response(200)
                self.send_header('Content-Type', case.kind)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        self.answer, self.kind = 200, 'application/x-git-upload-pack-advertisement'
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.httpd.shutdown(), self.httpd.server_close()))
        self.url = f'http://127.0.0.1:{self.httpd.server_address[1]}/Gabe/StorageForge.git'
        env = mock.patch.dict(os.environ, {selfupdate.SOURCE_ENV: self.url})
        env.start()
        self.addCleanup(env.stop)
        reset()
        self.addCleanup(reset)

    def lan(self):
        """The test's server is on loopback, which a request from here never goes to; this stands for a server on the LAN."""
        return mock.patch.object(alerts, '_refused', lambda addr: False)

    def ahead(self):
        major = selfupdate.as_numbers(__version__)[0]
        return f'{major + 1}.0.0'

    def test_a_newer_release_is_found_and_becomes_a_notification(self):
        release(self.work, '0.0.1')
        with self.lan():
            first = selfupdate.check()
        self.assertEqual((first['latest'], first['update_available'], first['error'], first['version']), ('0.0.1', False, None, __version__))
        self.assertEqual(selfupdate.problems(), {})
        release(self.work, self.ahead())
        release(self.work, '99.0.0', tag='v99.0.0-rc1')
        with self.lan():
            second = selfupdate.check()
        self.assertEqual((second['latest'], second['update_available'], second['source']), (self.ahead(), True, '127.0.0.1'))
        kind, about, title, text, level = selfupdate.problems()['update-available']
        self.assertEqual((kind, about, level), ('update-available', 'storageforge', 'warn'))
        self.assertIn(self.ahead(), title)
        self.assertIn(__version__, text)

    def test_the_request_says_nothing_about_this_installation(self):
        release(self.work, '0.0.1')
        with self.lan():
            selfupdate.check()
        (path, headers), = self.seen
        self.assertEqual(path, '/Gabe/StorageForge.git/info/refs?service=git-upload-pack')
        sent = ' '.join(f'{k}: {v}' for k, v in headers.items())
        self.assertNotIn(__version__, sent)
        self.assertNotIn('Cookie', headers)
        self.assertNotIn('Authorization', headers)

    def test_a_loopback_address_is_never_asked(self):
        release(self.work, self.ahead())
        got = selfupdate.check()
        self.assertEqual((got['latest'], got['update_available'], self.seen), (None, False, []))
        self.assertTrue(got['error'])

    def test_a_failed_check_keeps_the_last_answer_and_says_why(self):
        release(self.work, self.ahead())
        with self.lan():
            selfupdate.check()
            for answer, kind, want in ((404, self.kind, 'HTTP 404'), (200, 'text/html', 'not a git repository'), (302, self.kind, 'HTTP 302')):
                self.answer, self.kind = answer, kind
                got = selfupdate.check()
                with self.subTest(answer=answer, kind=kind):
                    self.assertIn(want, got['error'])
                    self.assertEqual((got['latest'], got['update_available']), (self.ahead(), True), 'what was known is still known')

    def test_a_check_that_has_never_worked_is_a_notification_of_its_own(self):
        self.answer = 404
        with self.lan():
            selfupdate.check()
        self.assertEqual(list(selfupdate.problems()), ['update-check'])

    def test_with_no_address_nothing_is_asked_and_nothing_is_reported(self):
        release(self.work, self.ahead())
        with mock.patch.dict(os.environ, {selfupdate.SOURCE_ENV: ''}), self.lan():
            got = selfupdate.check()
        self.assertEqual((got['checking'], got['latest'], got['error'], self.seen, selfupdate.problems()), (False, None, None, [], {}))

    def test_the_route_answers_a_signed_in_user_and_nobody_else(self):
        release(self.work, self.ahead())
        with self.lan():
            selfupdate.check()
        db = dbfactory.make(self, f'{self.tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        users.create(conn, 'viewer', PW, 'viewer')
        client = server.create_app(server.App(db), 's' * 48).test_client()
        self.assertIn(client.get('/api/version').status_code, (401, 302))
        self.assertEqual(client.post('/api/login', json={'username': 'viewer', 'password': PW}).status_code, 200)
        answer = client.get('/api/version')
        got = answer.get_json()
        self.assertEqual(answer.status_code, 200, got)
        self.assertEqual((got['version'], got['latest'], got['update_available'], got['source']), (__version__, self.ahead(), True, '127.0.0.1'))
        self.assertIn('update-available', alerts.problems(conn))


@unittest.skipUnless(shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class Installer(unittest.TestCase):
    """The script itself, in a clone of a real repository, with a stand-in `docker` that records what it was asked and is healthy
    or not as the test says."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.upstream, self.clone, self.bin = self.tmp / 'upstream', self.tmp / 'clone', self.tmp / 'bin'
        self.upstream.mkdir()
        self.bin.mkdir()
        git(self.upstream, 'init', '-q', '-b', 'main')
        release(self.upstream, '0.5.4')
        git(self.tmp, 'clone', '-q', str(self.upstream), str(self.clone))
        git(self.clone, 'checkout', '-q', '--detach', 'v0.5.4')
        (self.bin / 'docker').write_text(f'''#!/bin/sh
version=$(sed -n "s/^__version__ = '\\(.*\\)'$/\\1/p" storageforge_index/__init__.py 2>/dev/null)
echo "$version: $*" >> {self.tmp}/calls
case "$*" in
  "compose build"*) ! grep -qx "$version" {self.tmp}/unbuildable 2>/dev/null ;;
  "compose up"*) echo "$version" > {self.tmp}/running ;;
  "compose ps -q") echo c1; echo c2 ;;
  inspect*) if grep -qx "$(cat {self.tmp}/running)" {self.tmp}/unhealthy 2>/dev/null; then echo "running unhealthy"; else echo "running healthy"; fi ;;
esac
''')
        (self.bin / 'sleep').write_text('#!/bin/sh\nexec /usr/bin/sleep 0.2\n')
        for f in self.bin.iterdir():
            f.chmod(0o755)

    def run_it(self, mode, **env):
        return subprocess.run([str(SCRIPT), mode], capture_output=True, text=True,
                              env={'PATH': f'{self.bin}:{os.environ["PATH"]}', 'HOME': str(self.tmp), 'TMPDIR': str(self.tmp), 'STORAGEFORGE_DIR': str(self.clone),
                                   'STORAGEFORGE_UPDATE_WAIT': '1', **GIT_ENV, **env})

    def calls(self):
        f = self.tmp / 'calls'
        return [line for line in f.read_text().splitlines() if 'inspect' not in line and 'ps -q' not in line] if f.exists() else []

    def here(self):
        return (self.clone / 'storageforge_index' / '__init__.py').read_text().split("'")[1]

    def test_nothing_newer_and_nothing_is_done(self):
        release(self.upstream, '0.5.3', tag='v0.5.3')
        for mode in ('check', 'apply'):
            got = self.run_it(mode)
            self.assertEqual((got.returncode, self.calls(), self.here()), (0, [], '0.5.4'), got.stderr)
            self.assertIn('this is 0.5.4, the newest release', got.stdout)

    def test_check_says_there_is_one_and_changes_nothing(self):
        release(self.upstream, '0.5.4.1')
        got = self.run_it('check')
        self.assertEqual((got.returncode, self.calls(), self.here()), (10, [], '0.5.4'), got.stderr)
        self.assertIn('0.5.4.1 is released', got.stdout)

    def test_apply_installs_the_newest_release_and_only_a_release(self):
        release(self.upstream, '0.5.4.1')
        release(self.upstream, '0.5.10')
        release(self.upstream, '0.5.5')
        release(self.upstream, '9.0.0', tag='v9.0.0-rc1')
        release(self.upstream, '9.9.9', tag='latest')
        git(self.upstream, 'commit', '-q', '--allow-empty', '-m', 'work after the release, on the branch')
        got = self.run_it('apply')
        self.assertEqual((got.returncode, self.here()), (0, '0.5.10'), got.stderr + got.stdout)
        self.assertEqual(self.calls(), ['0.5.10: compose build --quiet', '0.5.10: compose up -d --remove-orphans --quiet-pull'])
        self.assertIn("the tag's signature is not checked", got.stdout)
        again = self.run_it('apply')
        self.assertEqual((again.returncode, len(self.calls())), (0, 2), 'a second run has nothing to do')

    def test_a_release_that_is_not_healthy_is_taken_back(self):
        release(self.upstream, '0.5.5')
        (self.tmp / 'unhealthy').write_text('0.5.5\n')
        got = self.run_it('apply')
        self.assertEqual((got.returncode, self.here(), (self.tmp / 'running').read_text().strip()), (1, '0.5.4', '0.5.4'), got.stderr)
        self.assertEqual([c.split(':')[0] for c in self.calls()], ['0.5.5', '0.5.5', '0.5.4', '0.5.4'])
        self.assertIn('0.5.4 is running again', got.stderr)

    def test_a_release_that_does_not_build_is_never_started(self):
        release(self.upstream, '0.5.5')
        (self.tmp / 'unbuildable').write_text('0.5.5\n')
        got = self.run_it('apply')
        self.assertEqual((got.returncode, self.here()), (1, '0.5.4'), got.stderr)
        self.assertNotIn('0.5.5: compose up -d --remove-orphans --quiet-pull', self.calls())

    def test_hand_edits_in_the_clone_stop_it(self):
        release(self.upstream, '0.5.5')
        (self.clone / 'docker-compose.yml').write_text('services: {mine: {}}\n')
        got = self.run_it('apply')
        self.assertEqual((got.returncode, self.calls(), self.here()), (1, [], '0.5.4'))
        self.assertIn('changed by hand', got.stderr)

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'needs ssh-keygen')
    def test_with_signers_set_only_a_signed_release_is_installed(self):
        for name in ('ours', 'theirs'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(self.tmp / name)], check=True)
        signers = self.tmp / 'signers'
        signers.write_text(f'release@storageforge namespaces="git" {(self.tmp / "ours.pub").read_text()}')
        release(self.upstream, '0.5.5')
        got = self.run_it('apply', STORAGEFORGE_UPDATE_SIGNERS=str(signers))
        self.assertEqual((got.returncode, self.calls(), self.here()), (1, [], '0.5.4'), 'an unsigned tag')
        self.assertIn('not signed by a key', got.stderr)
        release(self.upstream, '0.5.6', sign=str(self.tmp / 'theirs'))
        got = self.run_it('apply', STORAGEFORGE_UPDATE_SIGNERS=str(signers))
        self.assertEqual((got.returncode, self.calls(), self.here()), (1, [], '0.5.4'), 'a tag signed by somebody else')
        release(self.upstream, '0.5.7', sign=str(self.tmp / 'ours'))
        got = self.run_it('apply', STORAGEFORGE_UPDATE_SIGNERS=str(signers))
        self.assertEqual((got.returncode, self.here()), (0, '0.5.7'), got.stderr + got.stdout)
        missing = self.run_it('apply', STORAGEFORGE_UPDATE_SIGNERS=str(self.tmp / 'nowhere'))
        self.assertEqual(missing.returncode, 0, 'nothing newer: nothing to verify')

    def test_two_at_once_and_a_folder_that_is_not_an_installation(self):
        self.assertEqual(self.run_it('apply', STORAGEFORGE_DIR=str(self.tmp)).returncode, 1)
        self.assertEqual(self.run_it('install').returncode, 1)
        import fcntl
        with open(self.tmp / f'storageforge-update.{os.getuid()}.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            got = self.run_it('check')
        self.assertEqual(got.returncode, 1)
        self.assertIn('another update is running', got.stderr)


if __name__ == '__main__':
    unittest.main()
