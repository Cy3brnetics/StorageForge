"""The rclone-mount step (rclone.py) run for real in bash, with stand-ins for rclone, systemctl and mountpoint: the config is written
from the vault secrets into a root-only file, crypt's passwords are obscured through a pipe, the file is rewritten only when its inputs
change, and the unit mounts the encrypted remote."""
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes, rclone

HEAD = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }\n'
        'act() { echo "act: $*"; }; durable() { :; }; reload_systemd() { echo reload >> "$LOG"; }\n')

STUBS = {
    'rclone': '#!/bin/sh\ncase $1 in obscure) printf "OBS[%s]" "$(cat)" ;; version) echo "rclone v1.68.0" ;; esac\n',
    'systemctl': '#!/bin/sh\necho "systemctl $*" >> "$LOG"\ncase $1 in is-enabled|is-active) [ -e "$STATE" ] ;; enable) touch "$STATE" ;; disable) rm -f "$STATE" ;; esac\n',
    'mountpoint': '#!/bin/sh\n[ -e "$STATE" ]\n',
    'fusermount3': '#!/bin/sh\nexit 0\n',
}


class RcloneMount(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin, self.secrets, self.conf, self.units = (self.tmp / d for d in ('bin', 'secrets', 'conf', 'units'))
        for d in (self.bin, self.secrets, self.units):
            d.mkdir()
        for name, body in STUBS.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        (self.secrets / 'gdrive-rclone').write_text('client_id = 123.apps.googleusercontent.com\nclient_secret = shh\ntoken = {"access_token":"x"}\n')
        (self.secrets / 'gdrive-crypt').write_text('password = correct horse\npassword2 = battery staple\n')
        self.log = self.tmp / 'log'
        self.log.write_text('')

    def run_step(self, **over):
        p = {'name': 'gdrive', 'backend': 'drive', 'remote_path': 'Backups', 'options': 'scope=drive', 'secret': 'gdrive-rclone',
             'crypt': '1', 'crypt_secret': 'gdrive-crypt', 'filename_encryption': 'standard', 'target': str(self.tmp / 'mnt'),
             'owner': os.environ.get('USER', 'root'), 'cache': 'writes', 'state': 'present', **over}
        words = ' '.join(shlex.quote(str(p[a])) for a in rclone.ARGS)
        env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.log), 'STATE': str(self.tmp / 'up'),
               'SF_SECRET_DIR': str(self.secrets), 'SF_RCLONE_DIR': str(self.conf), 'SF_UNIT_DIR': str(self.units)}
        r = subprocess.run(['bash', '-c', HEAD + rclone.BASH + f'\nt_rclone_mount {words}\n'], env=env, capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr

    def unit(self):
        return next(self.units.iterdir()).read_text()

    def test_an_encrypted_drive_is_configured_from_the_vault_and_mounted(self):
        out = self.run_step()
        self.assertNotIn('conflict', out)
        conf = (self.conf / 'gdrive.conf').read_text()
        self.assertIn('[gdrive]\ntype = drive\nscope = drive\nclient_id = 123.apps.googleusercontent.com\nclient_secret = shh\n', conf)
        self.assertIn('[gdrive-crypt]\ntype = crypt\nremote = gdrive:Backups\nfilename_encryption = standard\ndirectory_name_encryption = true\n', conf)
        self.assertIn('password = OBS[correct horse]\npassword2 = OBS[battery staple]\n', conf, 'obscured through a pipe, never in the clear')
        self.assertNotIn('correct horse\n', conf.replace('OBS[correct horse]', ''))
        self.assertEqual(stat.S_IMODE((self.conf / 'gdrive.conf').stat().st_mode), 0o600)
        self.assertIn('mount "gdrive-crypt:"', self.unit(), 'the encrypted remote is what gets mounted')
        self.assertIn('--config', self.unit())
        self.assertIn('enable --now', self.log.read_text())

    def test_unchanged_inputs_leave_the_file_and_the_mount_alone(self):
        self.run_step()
        before = (self.conf / 'gdrive.conf').read_text()
        self.log.write_text('')
        out = self.run_step()
        self.assertEqual((self.conf / 'gdrive.conf').read_text(), before, 'obscure differs each run: the inputs decide, not the output')
        self.assertNotIn('restart', self.log.read_text())
        self.assertIn('running', out)

    def test_a_new_crypt_password_rewrites_the_config_and_remounts(self):
        self.run_step()
        (self.secrets / 'gdrive-crypt').write_text('password = new one\n')
        self.log.write_text('')
        self.run_step()
        self.assertIn('OBS[new one]', (self.conf / 'gdrive.conf').read_text())
        self.assertIn('restart', self.log.read_text())

    def test_without_its_secret_nothing_is_written(self):
        (self.secrets / 'gdrive-crypt').unlink()
        out = self.run_step()
        self.assertIn('conflict: the vault secret gdrive-crypt is not on this host', out)
        self.assertFalse((self.conf / 'gdrive.conf').exists())

    def test_without_crypt_the_plain_remote_path_is_mounted(self):
        self.run_step(crypt='', crypt_secret='')
        self.assertNotIn('[gdrive-crypt]', (self.conf / 'gdrive.conf').read_text())
        self.assertIn('mount "gdrive:Backups"', self.unit())

    def test_absent_takes_the_unit_and_config_away(self):
        self.run_step()
        out = self.run_step(state='absent')
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertFalse((self.conf / 'gdrive.conf').exists())
        self.assertIn('removed', out)


class Check(unittest.TestCase):
    def says(self, **p):
        out = []
        base = {'name': 'gdrive', 'backend': 'drive', 'target': '/mnt/g', 'secret': 's', 'state': 'present'}
        rclone._check(None, None, {'name': 'nas'}, {**base, **p}, lambda level, text: out.append((level, text)))
        return out

    def test_a_secret_in_the_options_is_refused(self):
        self.assertTrue(any(level == 'crit' and 'vault secret' in text for level, text in self.says(options='token=abc')))

    def test_crypt_without_its_secret_is_refused_and_the_loss_warned(self):
        said = self.says(crypt=True)
        self.assertTrue(any(level == 'crit' for level, _ in said))
        self.assertTrue(any('nobody can read them again' in text for _, text in said))

    def test_the_step_is_registered_with_both_secrets_delivered(self):
        from storageforge_index import secretstore
        self.assertIn('rclone-mount', changes.TYPES)
        self.assertEqual(set(secretstore.secret_fields(changes.TYPES['rclone-mount'])), {'secret', 'crypt_secret'})


if __name__ == '__main__':
    unittest.main()
