"""The Toolbox steps as Bash (steps_toolbox.py), with the words the catalog gives them (toolbox.install_words, remove_words), run against
stand-in podman, systemctl, package managers and curl on folders standing in for the host's: a report changes nothing; a rootless install
makes its account, subordinate ids, lingering and Quadlet unit and starts it once; a package install binds the socket to the exposure's
address; a binary is installed only when its SHA-256 is the entry's; a refused step does nothing; a removal keeps the data."""
import hashlib
import io
import json
import tarfile
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
REAL = ('bash', 'python3', 'env', 'awk', 'grep', 'sed', 'cat', 'head', 'tail', 'tr', 'mktemp', 'rm', 'mkdir', 'install', 'printf', 'wc', 'cut', 'sort', 'cmp', 'diff',
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

    def binary_entry(self, sha, extra=""):
        text = (f'format: 1\nid: tinybin\nrevision: 1\nname: Tiny\ncategory: monitoring\nsummary: A program.\ninstall:\n  methods:\n'
                f'    - kind: binary\n      name: tinybin\n      files:\n        x86_64: {{url: "https://example.org/tinybin", sha256: {sha}{extra}}}\n'
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
        (self.root / 'usr/local/bin/tinybin-other').write_text('someone else')
        self.assertIn('StorageForge did not put it there', self.run_fn(True, 'tb_binary', ['tinybin-other', 'tinybin-other', 'https://example.org/x', good, '', '']))
        self.assertEqual((self.root / 'usr/local/bin/tinybin-other').read_text(), 'someone else')

    def serve_binary_signature(self):
        curl = self.bin / 'curl'
        curl.write_text('#!/bin/bash\no=; while (($# > 1)); do [[ $1 == -o ]] && o=$2; shift; done\n'
                        'case "$1" in *.minisig) cp "$FAKE/signature" "$o" ;; *) cp "$FAKE/download" "$o" ;; esac\n')

    @unittest.skipUnless(shutil.which('minisign'), 'needs minisign for the genuine signature check')
    def test_verifies_a_genuine_detached_publisher_signature(self):
        (self.real / 'minisign').symlink_to(shutil.which('minisign'))
        self.serve_binary_signature()
        program = self.fake / 'download'
        program.write_bytes(b'#!/bin/sh\necho tiny\n')
        key = self.fake / 'publisher.key'
        public = self.fake / 'publisher.pub'
        signature = self.fake / 'signature'
        subprocess.run(['minisign', '-GW', '-p', str(public), '-s', str(key)], check=True, capture_output=True)
        subprocess.run(['minisign', '-Sm', str(program), '-s', str(key), '-x', str(signature)], check=True, capture_output=True)
        public_key = public.read_text().splitlines()[-1]
        self.binary_entry(hashlib.sha256(program.read_bytes()).hexdigest(),
                          f', minisign: {{url: "https://example.org/tinybin.minisig", public_key: "{public_key}"}}')
        other = self.fake / 'other'
        other.write_bytes(b'different release')
        wrong_signature = self.fake / 'wrong-signature'
        subprocess.run(['minisign', '-Sm', str(other), '-s', str(key), '-x', str(wrong_signature)], check=True, capture_output=True)
        correct_signature = signature.read_bytes()
        signature.write_bytes(wrong_signature.read_bytes())
        self.assertIn('publisher signature did not verify', self.install(True, 'tinybin'))
        self.assertFalse((self.root / 'usr/local/bin/tinybin').exists())
        signature.write_bytes(correct_signature)
        out = self.install(True, 'tinybin')
        self.assertIn('minisign publisher signature verified', out)
        self.assertEqual((self.root / 'usr/local/bin/tinybin').read_bytes(), program.read_bytes())

    def test_binary_requires_its_publisher_signature_even_when_the_hash_matches(self):
        program = b'#!/bin/sh\necho tiny\n'
        key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
        self.binary_entry(hashlib.sha256(program).hexdigest(),
                          f', minisign: {{url: "https://example.org/tinybin.minisig", public_key: "{key}"}}')
        (self.fake / 'download').write_bytes(program)
        dest = self.root / 'usr/local/bin/tinybin'
        self.assertIn('minisign is needed', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        self.serve_binary_signature()
        verifier = self.bin / 'minisign'
        verifier.write_text(f'#!/bin/bash\n[[ "$1" == -Vm && "$3" == -x && "$5" == -P && "$6" == {key} ]] && '
                            'cmp "$2" "$FAKE/download" && grep -qx signed "$4"\n')
        verifier.chmod(0o755)
        signature = self.fake / 'signature'
        signature.write_text('invalid')
        self.assertIn('publisher signature did not verify', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        signature.write_text('signed')
        self.assertIn('installed, SHA-256', self.install(True, 'tinybin'))
        self.assertEqual(dest.read_bytes(), program)
        signature.write_text('invalid')
        self.assertIn('publisher signature did not verify', self.install(True, 'tinybin'))
        self.assertEqual(dest.read_bytes(), program)

    def test_cosign_binary_requires_the_bundle_and_the_catalog_public_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        program = b'#!/bin/sh\necho tiny\n'
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        public = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.binary_entry(hashlib.sha256(program).hexdigest(),
                          f', cosign: {{bundle_url: "https://example.org/tinybin.sigstore.json", public_key: {json.dumps(public)}}}')
        (self.fake / 'publisher.pub').write_text(public)
        (self.fake / 'download').write_bytes(program)
        dest = self.root / 'usr/local/bin/tinybin'
        self.assertIn('cosign is needed', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        curl = self.bin / 'curl'
        curl.write_text('#!/bin/bash\no=; while (($# > 1)); do [[ $1 == -o ]] && o=$2; shift; done\n'
                        'case "$1" in *.sigstore.json) cp "$FAKE/bundle" "$o" ;; *) cp "$FAKE/download" "$o" ;; esac\n')
        verifier = self.bin / 'cosign'
        verifier.write_text('#!/bin/bash\n[[ "$1" == verify-blob && "$2" == --bundle && "$4" == --key && "$#" == 6 ]] && '
                            'cmp "$5" "$FAKE/publisher.pub" && cmp "$6" "$FAKE/download" && grep -qx signed "$3"\n')
        verifier.chmod(0o755)
        bundle = self.fake / 'bundle'
        bundle.write_text('invalid')
        self.assertIn('cosign publisher signature did not verify', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        bundle.write_text('signed')
        self.assertIn('cosign publisher signature verified', self.install(True, 'tinybin'))
        self.assertEqual(dest.read_bytes(), program)
        bundle.write_text('invalid')
        self.assertIn('cosign publisher signature did not verify', self.install(True, 'tinybin'))
        self.assertEqual(dest.read_bytes(), program)

    def test_cosign_image_verifies_digest_before_container_or_compose_install(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.assertNotIn("'", steps_toolbox.BASH)
        key_main = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        key_side = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        (self.fake / 'main.pub').write_text(key_main)
        (self.fake / 'side.pub').write_text(key_side)
        main_img = f'docker.io/traefik/whoami:v1.10.3@sha256:{"1" * 64}'
        side_img = f'ghcr.io/example/redis:7.2@sha256:{"2" * 64}'
        entry = (
            'format: 1\nid: signedapp\nrevision: 1\nname: Signed App\ncategory: monitoring\nsummary: Signed image app.\n'
            'install:\n  methods:\n'
            f'    - kind: container\n      image: {main_img}\n      cosign: {{public_key: {json.dumps(key_main)}}}\n      ports: ["8099:80/tcp"]\n'
            f'    - kind: compose\n      image: {main_img}\n      cosign: {{public_key: {json.dumps(key_main)}}}\n      ports: ["8099:80/tcp"]\n'
            f'      sidecars:\n        - name: cache\n          image: {side_img}\n          cosign: {{public_key: {json.dumps(key_side)}}}\n'
            'requires:\n  ports: [8099/tcp]\nexposure:\n  default: loopback\n'
        )
        toolbox.save_custom(self.conn, entry, None, 'test')
        pv = toolbox.preview(self.conn, 'box', 'signedapp', method='compose')
        self.assertIn(f'Cosign verifies {main_img}', ' '.join(x['text'] for x in pv['report']))
        self.assertIn(f'Cosign verifies {side_img}', ' '.join(x['text'] for x in pv['report']))

        toolbox.stage(self.conn, 'box', 'signedapp', 'root', accept_unsigned=True)
        quadlet = self.tmp / 'home/signedapp/.config/containers/systemd/signedapp.container'
        self.assertIn('cosign is needed to verify the images before installation', self.install(True, 'signedapp'))
        self.assertFalse(quadlet.exists())

        verifier = self.bin / 'cosign'
        verifier.write_text(
            '#!/bin/bash\n'
            '[[ "$1" == verify && "$2" == --key && "$#" == 4 ]] || exit 1\n'
            'case "$4" in\n'
            f'  "docker.io/traefik/whoami@sha256:{"1" * 64}") cmp -s "$3" "$FAKE/main.pub" && grep -qx main-ok "$FAKE/cosign-state" ;;\n'
            f'  "ghcr.io/example/redis@sha256:{"2" * 64}") cmp -s "$3" "$FAKE/side.pub" && grep -qx side-ok "$FAKE/cosign-state" ;;\n'
            '  *) exit 1 ;;\n'
            'esac\n'
        )
        verifier.chmod(0o755)
        state = self.fake / 'cosign-state'
        state.write_text('none\n')
        report_out = self.install(False, 'signedapp')
        self.assertIn(f'on apply, verify {main_img} with the catalog Cosign public key', report_out)
        self.assertFalse(quadlet.exists())

        self.assertIn(f'Cosign could not verify {main_img}', self.install(True, 'signedapp'))
        self.assertFalse(quadlet.exists())

        state.write_text('main-ok\n')
        self.assertIn(f'ok: Cosign verified {main_img}', self.install(True, 'signedapp'))
        self.assertTrue(quadlet.exists())

        # Compose method verifies both main image and sidecars before writing compose files
        docker = self.bin / 'docker'
        docker.write_text('#!/bin/bash\necho "docker $*" >>"$LOG"\n[[ "$1" == compose ]] && exit 0\n')
        docker.chmod(0o755)
        compose_dir = self.root / 'srv/toolbox/signedapp/compose'
        toolbox.stage(self.conn, 'box', 'signedapp', 'root', method='compose', accept_unsigned=True)
        self.assertIn(f'Cosign could not verify {side_img}', self.install(True, 'signedapp', method='compose'))
        self.assertFalse((compose_dir / 'compose.yaml').exists())

        state.write_text('main-ok\nside-ok\n')
        out = self.install(True, 'signedapp', method='compose')
        self.assertIn(f'ok: Cosign verified {main_img}', out)
        self.assertIn(f'ok: Cosign verified {side_img}', out)
        self.assertTrue((compose_dir / 'compose.yaml').exists())

    def test_binary_archive_verifies_both_hashes_and_extracts_only_the_member(self):
        program = b'#!/bin/sh\necho tiny\n'
        digest = hashlib.sha256(program).hexdigest()
        dest = self.root / 'usr/local/bin/tinybin'
        def archive_entry(link=False, member_sha=digest):
            path = self.fake / 'download'
            with tarfile.open(path, 'w:gz') as tar:
                item = tarfile.TarInfo('release/tinybin')
                if link:
                    item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
                    tar.addfile(item)
                else:
                    item.size = len(program)
                    tar.addfile(item, io.BytesIO(program))
                sibling = tarfile.TarInfo('release/ignored')
                sibling.size = len(program)
                tar.addfile(sibling, io.BytesIO(program))
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            entry = ('format: 1\nid: tinybin\nrevision: 1\nname: Tiny\ncategory: monitoring\nsummary: A program.\n'
                     'install:\n  methods:\n    - kind: binary\n      name: tinybin\n      files:\n        x86_64:\n'
                     f'          url: https://example.org/release.tar.gz\n          sha256: {sha}\n'
                     f'          archive: {{member: release/tinybin, sha256: {member_sha}}}\n')
            toolbox.save_custom(self.conn, entry, None, 'test')
            toolbox.stage(self.conn, 'box', 'tinybin', 'root', accept_unsigned=True)

        archive_entry(link=True)
        self.assertIn('could not read archive member', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        archive_entry(member_sha='b' * 64)
        self.assertIn('nothing was installed', self.install(True, 'tinybin'))
        self.assertFalse(dest.exists())
        archive_entry()
        self.assertIn('would: download', self.install(False, 'tinybin'))
        self.assertFalse(dest.exists())
        self.assertIn('installed, SHA-256 ' + digest, self.install(True, 'tinybin'))
        self.assertEqual(dest.read_bytes(), program)
        self.assertIn('is there, SHA-256 ' + digest, self.install(True, 'tinybin'))

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
