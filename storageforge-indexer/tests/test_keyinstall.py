"""Installing a vault key with the host's password (keyinstall.install_public_key), against a stand-in ssh-copy-id that writes down what it
was given and asks the real askpass helper for the password, as ssh does. The password is the one secret here that a person typed: it reaches
ssh through the askpass helper's environment only, never argv, a file or a log, and the scratch folder that held the public key is gone after,
whether the install worked or not. test_platform covers the routes around it with install_public_key replaced; nothing ran it before."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from storageforge_index import keyinstall

PASSWORD = 'pa ss$(id)`id`"\'\\word'
PUBLIC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample storageforge:test'

STAND_IN = r'''#!/bin/bash
# what ssh-copy-id was given, then what the askpass helper answers, then the outcome the test asked for
python3 - "$@" <<'PY'
import json, os, sys
home = os.environ.get('HOME', '')
files = sorted(os.path.relpath(os.path.join(d, f), home) for d, _, fs in os.walk(home) for f in fs) if home else []
key = sys.argv[sys.argv.index('-i') + 1]
json.dump({'argv': sys.argv[1:], 'env': dict(os.environ), 'files': files, 'home': home, 'key': open(key).read(), 'tty': os.isatty(0)}, open(os.environ['STAND_IN_LOG'] if 'STAND_IN_LOG' in os.environ else '@LOG@', 'w'))
PY
answer=$("$SSH_ASKPASS" "test@host's password: ") || answer='<askpass refused>'
printf '%s' "$answer" > '@LOG@.answer'
case "$(cat '@MODE@' 2>/dev/null)" in
  denied)   echo "/usr/bin/ssh-copy-id: INFO: attempting to log in" >&2; echo "test@host: Permission denied (publickey,password)." >&2; exit 1 ;;
  timeout)  echo "ssh: connect to host 10.0.0.9 port 22: Connection timed out" >&2; exit 255 ;;
  hang)     sleep 30 ;;
  *)        echo "Number of key(s) added: 1" ;;
esac
'''


@unittest.skipUnless(shutil.which('python3') and shutil.which('bash'), 'needs python3 and bash')
class InstallPublicKey(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.t, ignore_errors=True)
        self.bin, self.log, self.mode, self.run_dir = self.t / 'bin', self.t / 'log.json', self.t / 'mode', self.t / 'run'
        self.bin.mkdir()
        self.run_dir.mkdir()
        (self.bin / 'ssh-copy-id').write_text(STAND_IN.replace('@LOG@', str(self.log)).replace('@MODE@', str(self.mode)))
        (self.bin / 'ssh-copy-id').chmod(0o755)
        askpass = shutil.which('storageforge-askpass') or str(Path(sys.executable).parent / 'storageforge-askpass')
        if not Path(askpass).exists():
            self.skipTest('storageforge-askpass is not installed (pip install -e .)')
        (self.bin / 'storageforge-askpass').symlink_to(askpass)
        env = {'PATH': f'{self.bin}:{os.environ.get("PATH", "/usr/bin:/bin")}', 'STORAGEFORGE_RUNTIME_DIR': str(self.run_dir),
               'STORAGEFORGE_DATA_DIR': str(self.t / 'data'), 'SF_SHOULD_NOT_LEAK': 'x'}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def install(self, mode='ok', **kw):
        self.mode.write_text(mode)
        return keyinstall.install_public_key(PUBLIC, kw.get('host', '10.0.0.9'), kw.get('user', 'admin'), kw.get('password', PASSWORD), kw.get('port', 2222))

    def seen(self):
        return json.loads(self.log.read_text())

    def test_the_password_reaches_ssh_through_askpass_and_nowhere_else(self):
        self.assertEqual(self.install(), {'host': '10.0.0.9', 'user': 'admin', 'port': 2222, 'keys_added': 1})
        seen = self.seen()
        self.assertEqual((self.t / 'log.json.answer').read_text(), PASSWORD, 'askpass gave ssh the password as typed ($(...) took its newline)')
        self.assertFalse(any(PASSWORD in a for a in seen['argv']), 'never on the command line')
        self.assertFalse(any(PASSWORD in f for f in seen['files']), 'never a file name')
        self.assertEqual(seen['key'], 'restrict,pty ' + PUBLIC + '\n', 'the one file is the public key, restricted')
        self.assertEqual(seen['files'], ['key.pub'], 'and nothing else is in its folder')
        self.assertFalse(seen['tty'], 'no terminal for ssh to ask on')

    def test_ssh_is_told_to_trust_only_a_confirmed_host_key_and_to_try_the_password_once(self):
        self.install()
        argv = self.seen()['argv']
        options = {argv[i + 1] for i, a in enumerate(argv) if a == '-o'}
        for want in ('StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'PubkeyAuthentication=no', 'NumberOfPasswordPrompts=1'):
            self.assertIn(want, options)
        self.assertIn(f'UserKnownHostsFile={self.t / "data" / "ssh" / "known_hosts"}', options)
        self.assertEqual(argv[-1], 'admin@10.0.0.9')
        self.assertEqual(argv[argv.index('-p') + 1], '2222')

    def test_ssh_copy_id_gets_only_the_environment_it_needs(self):
        self.install()
        env = self.seen()['env']
        self.assertNotIn('SF_SHOULD_NOT_LEAK', env)
        self.assertEqual(env['SSH_ASKPASS_REQUIRE'], 'force')
        self.assertTrue(env['HOME'].startswith(str(self.run_dir)), 'its scratch folder is in the runtime folder, memory-backed where there is one')

    def test_the_scratch_folder_is_gone_whether_it_worked_or_not(self):
        for mode in ('ok', 'denied'):
            with self.subTest(mode):
                try:
                    self.install(mode)
                except keyinstall.InstallError:
                    pass
                self.assertFalse(Path(self.seen()['home']).exists())
                self.assertEqual(list(self.run_dir.iterdir()), [])

    def test_a_refused_password_says_so_without_ssh_copy_ids_chatter(self):
        with self.assertRaises(keyinstall.InstallError) as e:
            self.install('denied')
        self.assertIn('Permission denied', str(e.exception))
        self.assertNotIn('INFO', str(e.exception))
        self.assertNotIn(PASSWORD, str(e.exception))

    def test_a_port_nothing_answers_on_names_the_likely_firewall(self):
        with self.assertRaisesRegex(keyinstall.InstallError, 'timed out.*firewall'):
            self.install('timeout')

    def test_a_host_that_never_answers_is_given_up_on(self):
        with mock.patch.object(keyinstall, 'TIMEOUT', 1), self.assertRaisesRegex(keyinstall.InstallError, 'timed out after 1s'):
            self.install('hang')
        self.assertEqual(list(self.run_dir.iterdir()), [], 'and its folder is gone too')

    def test_what_is_refused_before_anything_runs(self):
        for kw, why in (({'password': ''}, 'password is required'), ({'host': '-oProxyCommand=id'}, 'host must be'), ({'host': 'a b'}, 'host must be'),
                        ({'user': 'root;id'}, 'plain login name'), ({'user': '-l'}, 'plain login name'), ({'port': 0}, 'port must be'), ({'port': 65536}, 'port must be')):
            with self.subTest(kw), self.assertRaisesRegex(ValueError, why):
                self.install(**kw)
        self.assertFalse(self.log.exists(), 'ssh-copy-id never ran')

    def test_without_ssh_copy_id_or_askpass_it_says_what_to_install(self):
        (self.bin / 'ssh-copy-id').unlink()
        with mock.patch('shutil.which', lambda name: None), self.assertRaisesRegex(keyinstall.InstallError, 'openssh-client'):
            self.install()
        with mock.patch('shutil.which', lambda name: None), self.assertRaisesRegex(keyinstall.InstallError, 'pip install'):
            keyinstall.askpass_path()


if __name__ == '__main__':
    unittest.main()
