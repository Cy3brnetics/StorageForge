"""The desktop steps (steps_desktop.py) and the profiles kept on the server. What must hold: Dux's installer runs only as the
script the step names by hash, and only as the desktop's user; a profile is written as one file and one line, a configuration
the compositor refuses is taken out again, and nothing outside the user's own folder is written."""
import base64
import getpass
import hashlib
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import changes, desktop, server, steps_desktop, users
from test_desktop import PROFILE

PW = 'correct horse battery staple 9'
ME = getpass.getuser()
PRELUDE = ('set -euo pipefail; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }; later() { echo "later: $*"; }\n'
           'act() { if [[ ${APPLY:-1} == 1 ]]; then echo "changed: $*"; else echo "would: $*"; return 1; fi; }; try() { "$@"; }; doing() { :; }\n')


class Stage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin, self.home = self.tmp / 'bin', self.tmp / 'home'
        self.bin.mkdir()
        self.home.mkdir()
        self.tool('getent', f'[ "$2" = {ME} ] && echo "{ME}:x:{os.getuid()}:{os.getgid()}::{self.home}:/bin/bash"')
        self.tool('runuser', f'echo "as $2: ${{*:4}}" >> {self.tmp}/ran; shift 3; exec "$@"')          # runuser -u USER -- command
        self.env = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'T': str(self.tmp)}

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
        (self.bin / name).chmod(0o755)

    def run_bash(self, call, apply=True):
        ran = subprocess.run(['bash', '-c', PRELUDE + steps_desktop.bash() + '\n' + call], capture_output=True, text=True, env=self.env | {'APPLY': '1' if apply else '0'})
        self.assertEqual(ran.stderr, '')
        return ran.stdout


class Dux(Stage):
    INSTALLER = b'#!/bin/sh\necho "installer ran as $(id -un) with: $*" >> "$T/installed"\n'

    def setUp(self):
        super().setUp()
        import gzip
        self.gz = gzip.compress(self.INSTALLER, mtime=0)
        self.sha = hashlib.sha256(self.gz).hexdigest()
        (self.tmp / 'served.gz').write_bytes(self.gz)
        # the project's site, as far as the step asks it: the newest release, the published hash, and the installer itself
        self.tool('curl', '''out=; for a in "$@"; do url=$a; done; while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done; echo "$url" >> $T/fetched
case $url in
  */releases/latest) printf 'HTTP/2 302\\r\\nlocation: https://github.com/duxlabs-dev/dux-shell/releases/tag/v2.1.2\\r\\n';;
  *.sha256) echo "$(sha256sum < $T/served.gz | cut -d" " -f1)  duxinstall-amd64.gz";;
  *) cat $T/served.gz > "$out";;
esac''')
        self.tool('sudo', '[ "$1" = -n ] && exit ${SUDO_FAILS:-0}')
        self.tool('uname', 'echo x86_64')
        # this machine may have Dux: the step sees only the stand-ins and the plain tools it runs
        plain = self.tmp / 'plain'
        plain.mkdir()
        for name in ('bash', 'sh', 'cat', 'mktemp', 'sha256sum', 'rm', 'chmod', 'tail', 'tr', 'cut', 'id', 'env', 'grep', 'gzip', 'awk'):
            (plain / name).symlink_to(shutil.which(name))
        self.env['PATH'] = f'{self.bin}:{plain}'

    def step(self, sha=None, version='v2.1.2', apply=True, **env):
        self.env.update(env)
        return self.run_bash(f't_dux_install {ME} niri ghostty {shlex.quote(version)} {shlex.quote(self.sha if sha is None else sha)}', apply)

    def ran(self):
        f = self.tmp / 'installed'
        return f.read_text().splitlines() if f.exists() else []

    def fetched(self):
        f = self.tmp / 'fetched'
        return f.read_text().split() if f.exists() else []

    def test_the_installer_it_names_runs_once_as_the_user_with_what_was_chosen(self):
        out = self.step()
        self.assertIn(f'ok: Dux v2.1.2 is installed for {ME} with niri and ghostty', out)
        self.assertEqual(self.ran(), [f'installer ran as {ME} with: -c niri -t ghostty -y'])
        self.assertEqual(self.fetched(), ['https://github.com/duxlabs-dev/dux-shell/releases/download/v2.1.2/duxinstall-amd64.gz'], 'that one file, and not the bootstrap that would fetch the newest')
        self.assertIn(f'as {ME}: env HOME={self.home} DMS_PRIVESC=sudo', (self.tmp / 'ran').read_text())

    def test_an_installer_that_is_not_the_one_named_never_runs(self):
        (self.tmp / 'served.gz').write_bytes(self.gz + b'\0')
        out = self.step()
        self.assertIn(f'and this step names {self.sha}: it is not run', out)
        self.assertEqual(self.ran(), [])

    def test_with_no_release_or_no_hash_it_says_the_newest_and_runs_nothing(self):
        for kw in ({'sha': ''}, {'version': ''}):
            for apply in (False, True):
                out = self.step(apply=apply, **kw)
                self.assertIn(f'The newest is v2.1.2, and the project publishes {self.sha} for duxinstall-amd64.gz. Nothing runs without both', out)
        self.assertEqual(self.ran(), [])
        self.assertNotIn('https://github.com/duxlabs-dev/dux-shell/releases/download/v2.1.2/duxinstall-amd64.gz', self.fetched(), 'the installer itself is not even fetched')

    def test_a_report_fetches_and_runs_nothing(self):
        self.assertIn('would: install Dux v2.1.2', self.step(apply=False))
        self.assertEqual((self.ran(), self.fetched()), ([], []))

    def test_a_release_that_is_not_one_and_a_user_who_cannot_become_root(self):
        self.assertIn('is not a release', self.step(version='latest'))
        self.assertIn('is not a release', self.step(version='v2/../../x'))
        self.assertIn('cannot use sudo without a password', self.step(SUDO_FAILS='1'))
        self.assertEqual((self.ran(), self.fetched()), ([], []))

    def test_installed_already_and_an_account_that_is_not_there(self):
        self.tool('dms', 'true')
        self.assertIn('ok: Dux is installed (dms is here)', self.step())
        self.assertEqual(self.fetched(), [], 'nothing is fetched for a host that has it')
        self.assertIn('later: there is no account nobody-here', self.run_bash(f't_dux_install nobody-here niri ghostty v2.1.2 {self.sha}'))


class WrittenProfile(Stage):
    def setUp(self):
        super().setUp()
        self.text = {c: desktop.render(PROFILE, c) for c in desktop.COMPOSITORS}

    def step(self, compositor='niri', text=None, apply=True):
        body = base64.b64encode((self.text[compositor] if text is None else text).encode()).decode()
        return self.run_bash(f't_desktop_profile fleet {ME} {compositor} {body}', apply)

    def config(self, folder, main, text):
        d = self.home / '.config' / folder
        d.mkdir(parents=True)
        (d / main).write_text(text)
        return d

    @unittest.skipUnless(shutil.which('niri'), 'needs niri')
    def test_one_file_and_one_line_and_niri_accepts_the_whole(self):
        d = self.config('niri', 'config.kdl', 'binds {\n    Mod+T { spawn "alacritty"; }\n}\n')
        out = self.step()
        self.assertIn(f'ok: {ME} has the profile fleet for niri', out)
        self.assertEqual((d / 'storageforge.kdl').read_text(), self.text['niri'])
        self.assertEqual((d / 'config.kdl').read_text(), 'binds {\n    Mod+T { spawn "alacritty"; }\n}\n\ninclude "storageforge.kdl"\n')
        self.assertEqual((d / 'config.kdl.before-storageforge').read_text(), 'binds {\n    Mod+T { spawn "alacritty"; }\n}\n')
        self.assertEqual(subprocess.run(['niri', 'validate', '-c', str(d / 'config.kdl')], capture_output=True).returncode, 0)
        again = self.step()
        self.assertEqual(again.strip(), f'ok: {ME} has the profile fleet for niri')
        self.assertEqual((d / 'config.kdl').read_text().count('include "storageforge.kdl"'), 1)
        changed = desktop.render(PROFILE | {'binds': PROFILE['binds'][:2]}, 'niri')
        self.step(text=changed)
        self.assertEqual(((d / 'storageforge.kdl').read_text(), (d / 'config.kdl').read_text().count('include')), (changed, 1), 'a changed profile replaces the file and adds no second line')
        self.assertEqual(sorted(p.name for p in d.iterdir()), ['config.kdl', 'config.kdl.before-storageforge', 'storageforge.kdl'])

    def test_a_configuration_niri_refuses_is_taken_out_again(self):
        d = self.config('niri', 'config.kdl', 'binds {\n}\n')
        self.tool('niri', 'exit 1')
        out = self.step()
        self.assertIn('conflict: niri refuses the configuration with the profile in it: it was taken out again', out)
        self.assertEqual(((d / 'config.kdl').read_text().strip(), (d / 'storageforge.kdl').exists()), ('binds {\n}', False))

    def test_the_other_two_get_their_own_file_and_line(self):
        for compositor, folder, main, line in (('hyprland', 'hypr', 'hyprland.lua', 'require("storageforge")'), ('sway', 'sway', 'config', 'include ~/.config/sway/storageforge.conf')):
            d = self.config(folder, main, '# mine\n')
            self.assertIn(f'ok: {ME} has the profile fleet for {compositor}', self.step(compositor))
            self.assertEqual(((d / desktop.FILES[compositor]).read_text(), (d / main).read_text()), (self.text[compositor], f'# mine\n\n{line}\n'))

    @unittest.skipUnless(shutil.which('Hyprland'), 'needs Hyprland')
    def test_hyprland_accepts_its_main_file_with_the_line_in_it(self):
        d = self.config('hypr', 'hyprland.lua', 'hl.bind("SUPER + T", hl.dsp.exec_cmd("kitty"))\n')
        self.step('hyprland')
        ran = subprocess.run(['Hyprland', '--verify-config', '-c', str(d / 'hyprland.lua')], capture_output=True, text=True, timeout=60)
        self.assertIn('config ok', ran.stdout + ran.stderr, (ran.stdout + ran.stderr)[-500:])

    def test_what_stops_it_before_anything_is_written(self):
        self.assertIn('later: ', self.step())                                      # no configuration yet: the compositor or Dux writes it first
        self.assertFalse((self.home / '.config').exists())
        d = self.config('niri', 'config.kdl', 'binds {\n}\n')
        self.assertIn('would: write the profile', self.step(apply=False))
        self.assertEqual(sorted(p.name for p in d.iterdir()), ['config.kdl'])
        self.assertIn('conflict: the server has no desktop profile named fleet', self.run_bash(f"t_desktop_profile fleet {ME} niri ''"))
        elsewhere = self.tmp / 'elsewhere'
        elsewhere.mkdir()
        (elsewhere / 'config').write_text('# not the user\'s folder\n')
        (self.home / '.config' / 'sway').symlink_to(elsewhere)
        self.assertIn('is a link', self.step('sway'))
        self.assertEqual(sorted(p.name for p in elsewhere.iterdir()), ['config'], 'nothing is written through a link')


class Kept(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname) VALUES ('desk-01')")

    def test_a_profile_is_kept_whole_and_a_host_has_its_own_displays(self):
        saved = desktop.save(self.conn, PROFILE | {'hosts': {'desk-01': [{'output': 'DP-3', 'mode': '3840x2160@60', 'scale': '1.5'}]}}, 'gabe')
        self.assertEqual(desktop.get(self.conn, 'FLEET'), saved)
        self.assertIn('output "DP-3"', desktop.render(saved, 'niri', 'desk-01'))
        self.assertNotIn('output "DP-1"', desktop.render(saved, 'niri', 'desk-01'), 'its own layout, not the profile\'s as well')
        self.assertIn('output "DP-1"', desktop.render(saved, 'niri', 'desk-02'))
        desktop.save(self.conn, {'name': 'Fleet'}, 'gabe')
        self.assertEqual(list(desktop.profiles(self.conn)), ['Fleet'], 'one profile to a name, whatever its capitals')
        desktop.delete(self.conn, 'fleet', 'gabe')
        with self.assertRaises(LookupError):
            desktop.get(self.conn, 'fleet')
        for bad in ({'desk 01': []}, {'desk-01': [{'output': 'DP-1" { off }'}]}, {'desk-01': 'DP-1'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                desktop.save(self.conn, PROFILE | {'hosts': bad}, 'gabe')

    def test_the_plan_step_carries_the_profile_as_the_server_rendered_it(self):
        desktop.save(self.conn, PROFILE | {'hosts': {'desk-01': [{'output': 'DP-3'}]}}, 'gabe')
        task = {'type': 'desktop-profile', 'host': 'desk-01', 'params': {'profile': 'fleet', 'user': 'gabe', 'compositor': 'hyprland'}}
        plan = changes.normalize({'name': 'p', 'tasks': [task, {'type': 'dux-install', 'host': 'desk-01', 'params': {'user': 'gabe', 'compositor': 'niri', 'version': 'v2.1.2', 'installer_sha': 'a' * 64}}]})
        script = changes.script(self.conn, plan)
        body = base64.b64encode(desktop.render(desktop.get(self.conn, 'fleet'), 'hyprland', 'desk-01').encode()).decode()
        self.assertIn(body, script)
        self.assertIn('hl.monitor({ output = "DP-3" })', base64.b64decode(body).decode())
        said = []
        steps_desktop._check_profile(self.conn, None, {'name': 'desk-01'}, task['params'], lambda level, text: said.append((level, text)))
        self.assertIn('this host\'s own display layout', said[0][1])
        said.clear()
        steps_desktop._check_profile(self.conn, None, {'name': 'desk-01'}, task['params'] | {'profile': 'gone'}, lambda level, text: said.append((level, text)))
        self.assertEqual(said[0][0], 'crit')
        said.clear()
        steps_desktop._check_dux(self.conn, None, {'name': 'desk-01'}, {'user': 'gabe', 'compositor': 'niri'}, lambda level, text: said.append((level, text)))
        self.assertEqual([level for level, _ in said], ['crit', 'warn'], 'a step with no hash is flagged before any script is written')
        for bad in ({'compositor': 'sway'}, {'installer_sha': 'not-a-hash'}, {'terminal': 'xterm'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                changes.normalize({'name': 'p', 'tasks': [{'type': 'dux-install', 'host': 'desk-01', 'params': {'user': 'gabe', 'compositor': 'niri', 'installer_sha': 'a' * 64} | bad}]})

    def test_the_routes(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        self.assertEqual(viewer.put('/api/desktop/profiles/fleet', json=PROFILE).status_code, 403)
        self.assertEqual(admin.put('/api/desktop/profiles/fleet', json=PROFILE).status_code, 200)
        self.assertEqual(admin.put('/api/desktop/profiles/other', json=PROFILE).status_code, 400, 'a name in the body that is not the address')
        self.assertEqual(admin.put('/api/desktop/profiles/bad', json={'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'a"; rm'}]}).status_code, 400)
        listed = viewer.get('/api/desktop/profiles').get_json()
        self.assertEqual(([p['name'] for p in listed['profiles']], listed['compositors']), (['fleet'], ['niri', 'hyprland', 'sway']))
        got = viewer.get('/api/desktop/profiles/fleet/render?compositor=sway')
        self.assertEqual((got.status_code, got.mimetype, got.get_data(as_text=True)), (200, 'text/plain', desktop.render(PROFILE, 'sway')))
        self.assertEqual(viewer.get('/api/desktop/profiles/fleet/render?compositor=kwin').status_code, 400)
        self.assertEqual(viewer.get('/api/desktop/profiles/nothing/render?compositor=sway').status_code, 404)
        self.assertEqual(viewer.delete('/api/desktop/profiles/fleet').status_code, 403)
        self.assertEqual(admin.delete('/api/desktop/profiles/fleet').status_code, 200)
        self.assertEqual([r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'desktop.%' ORDER BY audit_id")], ['desktop.profile.save', 'desktop.profile.delete'])


if __name__ == '__main__':
    unittest.main()
