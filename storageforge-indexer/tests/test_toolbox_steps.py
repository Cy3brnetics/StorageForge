"""The Toolbox steps as Bash (steps_toolbox.py), with the words the catalog gives them (toolbox.install_words, remove_words), run against
stand-in podman, systemctl, package managers and curl on folders standing in for the host's: a report changes nothing; a rootless install
makes its account, subordinate ids, lingering and Quadlet unit and starts it once; a package install binds the socket to the exposure's
address; a binary is installed only when its SHA-256 is the entry's; a refused step does nothing; a removal keeps the data."""
import hashlib
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path

try:
    from test_toolbox import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import Base
from storageforge_index import changes, steps_runtime, steps_toolbox, steps_workloads, toolbox

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; durable() { :; }; later() { echo "later: $*"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
t_trash() { echo "trash: $1"; mv -- "$1" "$FAKE/trash/"; }
PROBLEMS=0 DESTRUCTIVE=1 CUR_DESTRUCTIVE=1
'''
REAL = ('bash', 'env', 'awk', 'grep', 'sed', 'cat', 'head', 'tail', 'tr', 'mktemp', 'rm', 'mkdir', 'install', 'printf', 'wc', 'cut', 'sort', 'cmp', 'diff',
        'chmod', 'mv', 'cp', 'touch', 'sync', 'ls', 'dirname', 'basename', 'stat', 'sha256sum', 'id', 'uname')

STUBS = {
    'podman': 'case $1 in --version) echo "podman version 5.4.0" ;; esac',
    # systemctl: start and restart mark a unit active, stop and disable unmark it, enable marks it enabled
    'systemctl': r'''a=("$@"); while [[ ${a[0]:-} == --user || ${a[0]:-} == -M || ${a[0]:-} == *@ ]]; do a=("${a[@]:1}"); done
u=${a[-1]:-}
case ${a[0]:-} in
  is-active) [[ -e $FAKE/active/$u ]] ;;
  is-enabled) [[ -e $FAKE/enabled/$u ]] ;;
  restart|start) touch "$FAKE/active/$u" ;;
  stop) rm -f "$FAKE/active/$u" ;;
  enable) touch "$FAKE/enabled/$u" "$FAKE/active/$u" ;;
  disable) rm -f "$FAKE/enabled/$u" "$FAKE/active/$u" ;;
  cat|daemon-reload) : ;;
esac''',
    'useradd': 'h=; while (($#)); do [[ $1 == --home-dir ]] && h=$2; shift; done; mkdir -p "$h"',
    'loginctl': ':',
    'chown': ':',
    'dpkg-query': 'grep -qx "${@: -1}" "$FAKE/installed" 2>/dev/null && echo "install ok installed"',
    'apt-cache': 'echo "  Candidate: 1.0"',
    'apt-get': 'if [[ " $* " == *" install "* ]]; then for x; do [[ $x == -* || $x == install || $x == DPkg* ]] || echo "$x" >>"$FAKE/installed"; done; fi',
    'curl': 'o=; while (($#)); do [[ $1 == -o ]] && o=$2; shift; done; cp "$FAKE/download" "$o"',
}


class Steps(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])
        d = self.tmp
        self.root, self.bin, self.real, self.fake = d / 'root', d / 'bin', d / 'real', d / 'fake'
        for p in (self.root / 'etc', self.root / 'var/lib/apt/lists', self.bin, self.real, self.fake / 'active', self.fake / 'enabled', self.fake / 'trash'):
            p.mkdir(parents=True, exist_ok=True)
        (self.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
        (self.root / 'var/lib/apt/lists/x_Packages').write_text('')
        for name in REAL:
            if shutil.which(name):
                (self.real / name).symlink_to(shutil.which(name))
        for name, body in STUBS.items():
            (self.bin / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
            (self.bin / name).chmod(0o755)
        self.paths = {toolbox.TOOLS_HOME: str(d / 'home'), '/etc/containers/systemd': str(self.root / 'etc/containers/systemd'),
                      '/etc/systemd/system/': str(self.root / 'etc/systemd/system') + '/', '/usr/local/bin/': str(self.root / 'usr/local/bin') + '/'}
        (self.root / 'usr/local/bin').mkdir(parents=True)

    def bash(self):
        text = steps_runtime.BASH + steps_workloads.BASH + steps_toolbox.BASH
        for a, b in self.paths.items():
            text = text.replace(a, b)
        return text

    def swap(self, words):
        out = []
        for w in words:
            for a, b in self.paths.items():
                w = w.replace(a, b)
            w = w.replace(toolbox.DATA_ROOT, str(self.root / 'srv/toolbox'))
            out.append(w)
        return out

    def run_fn(self, apply, fn, words):
        call = fn + ' ' + ' '.join(shlex.quote(w) for w in words)
        env = {'PATH': f'{self.bin}:{self.real}', 'FAKE': str(self.fake), 'LOG': str(self.fake / 'log'), 'RT_ROOT': str(self.root), 'HOME': str(self.tmp)}
        p = subprocess.run([str(self.real / 'bash'), '-c', HARNESS + f'APPLY={int(apply)}\n' + self.bash() + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                           capture_output=True, text=True, timeout=60, env=env)
        return p.stdout + p.stderr

    def log(self):
        p = self.fake / 'log'
        return p.read_text() if p.exists() else ''

    def install(self, apply, tool, method=None, **kw):
        pv = toolbox.preview(self.conn, 'box', tool, method, **kw)
        t = next(x for x in pv['tasks'] if x['type'] == 'tool-install')
        words = [str(t['params'].get(a) or '') for a in steps_toolbox.INSTALL_ARGS] + toolbox.install_words(self.conn, t)
        return self.run_fn(apply, 't_tool_install', self.swap(words))

    def test_rootless_container_report_then_apply_then_again(self):
        out = self.install(False, 'uptime-kuma')
        self.assertIn('would: make the account sf-uptime-kuma', out)
        self.assertIn('missing: would start uptime-kuma.service', out)
        quadlet = self.tmp / 'home/uptime-kuma/.config/containers/systemd/uptime-kuma.container'
        self.assertFalse(quadlet.exists(), 'a report writes nothing')
        self.assertNotIn('useradd', self.log())
        out = self.install(True, 'uptime-kuma')
        self.assertIn('ok: uptime-kuma.service is running', out)
        text = quadlet.read_text()
        self.assertIn('Image=docker.io/louislam/uptime-kuma:2.0.2@sha256:', text)
        self.assertIn('PublishPort=127.0.0.1:3001:3001/tcp', text)
        self.assertIn('NoNewPrivileges=true', text)
        self.assertTrue((self.root / 'srv/toolbox/uptime-kuma/data').is_dir())
        self.assertIn('sf-uptime-kuma:', (self.root / 'etc/subuid').read_text())
        log = self.log()
        self.assertIn('useradd --system --user-group --create-home', log)
        self.assertIn('loginctl enable-linger sf-uptime-kuma', log)
        self.assertIn('systemctl --user -M sf-uptime-kuma@ restart uptime-kuma.service', log)
        (self.fake / 'log').unlink()
        out = self.install(True, 'uptime-kuma')
        self.assertIn('is the unit this entry makes', out)
        self.assertNotIn('restart', self.log(), 'nothing changed, so nothing restarts')

    def test_root_quadlet_lives_in_etc(self):
        self.install(True, 'uptime-kuma', 'quadlet')
        self.assertIn('WantedBy=multi-user.target', (self.root / 'etc/containers/systemd/uptime-kuma.container').read_text())
        self.assertIn('systemctl restart uptime-kuma.service', self.log())
        self.assertNotIn('useradd', self.log())

    def test_a_refused_step_does_nothing(self):
        out = self.run_fn(True, 't_tool_install', ['uptime-kuma', 'container', 'a' * 64, '', '', '', '', 'refused', 'the catalog entry changed'])
        self.assertIn('conflict: the catalog entry changed', out)
        self.assertEqual(self.log(), '')

    def test_package_with_its_socket_bound_to_loopback(self):
        out = self.install(False, 'cockpit')
        self.assertIn('would: install cockpit with apt-get', out)
        self.assertFalse((self.root / 'etc/systemd/system/cockpit.socket.d').exists())
        out = self.install(True, 'cockpit')
        self.assertIn('ok: installed cockpit', out)
        drop = (self.root / 'etc/systemd/system/cockpit.socket.d/storageforge-listen.conf').read_text()
        self.assertEqual(drop, '[Socket]\nListenStream=\nListenStream=127.0.0.1:9090\n')
        self.assertIn('systemctl enable --now cockpit.socket', self.log())
        out = self.install(True, 'cockpit')
        self.assertIn('ok: cockpit is installed', out)
        self.assertIn('ok: cockpit.socket listens on 127.0.0.1:9090 only', out)
        out = self.install(True, 'cockpit', exposure='management', bind='10.0.0.5')
        self.assertIn('ListenStream=10.0.0.5:9090', (self.root / 'etc/systemd/system/cockpit.socket.d/storageforge-listen.conf').read_text())

    def binary_entry(self, sha):
        text = (f'format: 1\nid: tinybin\nrevision: 1\nname: Tiny\ncategory: monitoring\nsummary: A program.\ninstall:\n  methods:\n'
                f'    - kind: binary\n      name: tinybin\n      files:\n        x86_64: {{url: "https://example.org/tinybin", sha256: {sha}}}\n'
                f'        aarch64: {{url: "https://example.org/tinybin-arm", sha256: {sha}}}\n')
        toolbox.save_custom(self.conn, text, None, 'test')
        toolbox.stage(self.conn, 'box', 'tinybin', 'root', accept_unsigned=True)

    def test_a_binary_is_installed_only_with_the_sha256_of_its_entry(self):
        (self.fake / 'download').write_bytes(b'#!/bin/sh\necho tiny\n')
        good = hashlib.sha256(b'#!/bin/sh\necho tiny\n').hexdigest()
        self.binary_entry('b' * 64)
        out = self.install(True, 'tinybin')
        self.assertIn('not ' + 'b' * 64 + ': nothing was installed', out)
        self.assertFalse((self.root / 'usr/local/bin/tinybin').exists())
        self.binary_entry(good)
        out = self.install(True, 'tinybin')
        self.assertIn('installed, SHA-256 ' + good, out)
        self.assertTrue((self.root / 'usr/local/bin/tinybin').exists())

    def test_removal_takes_the_unit_and_keeps_the_data(self):
        toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        self.install(True, 'uptime-kuma')
        data = self.root / 'srv/toolbox/uptime-kuma/data'
        (data / 'kuma.db').write_text('monitors')
        toolbox.stage_remove(self.conn, 'box', 'uptime-kuma', 'test')
        t = {'host': 'box', 'type': 'tool-remove', 'params': {'tool': 'uptime-kuma', 'method': 'container'}}
        out = self.run_fn(True, 't_tool_remove', self.swap(['uptime-kuma', 'container'] + toolbox.remove_words(self.conn, t)))
        self.assertIn('its unit is gone', out)
        self.assertFalse((self.tmp / 'home/uptime-kuma/.config/containers/systemd/uptime-kuma.container').exists())
        self.assertEqual((data / 'kuma.db').read_text(), 'monitors')
        self.assertIn('its data stays', out)
        t = {'host': 'box', 'type': 'tool-data-remove', 'params': {'tool': 'uptime-kuma', 'confirm': 'uptime-kuma'}}
        out = self.run_fn(True, 't_tool_data_remove', self.swap(['uptime-kuma', 'uptime-kuma'] + toolbox.remove_words(self.conn, t, data=True)))
        self.assertIn('trash: ', out)
        self.assertFalse(data.exists())
        self.assertTrue((self.fake / 'trash/data/kuma.db').exists())

    def test_package_removal_keeps_configuration(self):
        toolbox.stage(self.conn, 'box', 'cockpit', 'test')
        self.install(True, 'cockpit')
        t = {'host': 'box', 'type': 'tool-remove', 'params': {'tool': 'cockpit', 'method': 'package'}}
        out = self.run_fn(True, 't_tool_remove', self.swap(['cockpit', 'package'] + toolbox.remove_words(self.conn, t)))
        self.assertIn('systemctl disable --now cockpit.socket', self.log())
        self.assertIn('apt-get -o DPkg::Lock::Timeout=120 remove -y -qq cockpit', self.log())
        self.assertNotIn('purge', self.log())
        self.assertFalse((self.root / 'etc/systemd/system/cockpit.socket.d/storageforge-listen.conf').exists())
        self.assertIn('configuration files stay', out)

    def test_the_whole_plan_script_is_valid_bash(self):
        got = toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        text = changes.script(self.conn, changes.get_plan(self.conn, got['plan_id']))
        p = subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == '__main__':
    unittest.main()
