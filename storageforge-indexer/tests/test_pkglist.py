"""Package lists: what a scan reads, what is kept of it, and the script that installs the same packages elsewhere."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import pkglist, remote

CANARY = '$(touch${IFS}/tmp/CANARY)`id`"q;x'


def section():
    s = remote.INVENTORY_SCRIPT
    return s[s.index("echo '@@pkglist'"):s.index("echo '@@access'")]


class Parse(unittest.TestCase):
    def test_apt_names_sources_and_apps(self):
        pk = pkglist.parse('distro\tubuntu\t24.04\tdebian\npm apt-get\nm\tvim\nm\tlibc6:i386\n'
                           'f\tApplication\tOrigin\nf\torg.mozilla.firefox\tflathub\ns\tcode\tclassic\n'
                           'r\t/etc/apt/sources.list\thttps://me:hunter2@repo.example.com/ubuntu?token=abc#x\ncomplete')
        self.assertEqual((pk['pm'], pk['distro'], pk['version'], pk['like'], pk['basis']), ('apt-get', 'ubuntu', '24.04', ['debian'], 'manual'))
        self.assertEqual(pk['packages'], ['libc6:i386', 'vim'])
        self.assertEqual(pk['flatpak'], [{'id': 'org.mozilla.firefox', 'origin': 'flathub'}])
        self.assertEqual(pk['snap'], [{'name': 'code', 'confinement': 'classic'}])
        self.assertEqual(pk['repos'], [{'where': '/etc/apt/sources.list', 'url': 'https://repo.example.com/ubuntu'}])
        self.assertNotIn('hunter2', json.dumps(pk))
        self.assertNotIn('token', json.dumps(pk))
        self.assertTrue(pk['complete'])

    def test_what_is_not_a_package_name_is_dropped(self):
        pk = pkglist.parse(f'pm apt-get\nm\t{CANARY}\nm\t-rf\nm\tok\nf\t{CANARY}\ts\t{CANARY}\nr\tx\tjavascript:alert(1)\nr\tx\thttps://a b/\n')
        self.assertEqual((pk['packages'], pk['flatpak'], pk['snap'], pk['repos']), (['ok'], [], [], []))
        self.assertFalse(pk['complete'])     # no end marker: the output stopped early

    def test_zypper_is_every_package_less_the_automatic_ones(self):
        pk = pkglist.parse('pm zypper\na\tvim\na\tlibfoo1\na\tgpg-pubkey\nx\tlibfoo1\ncomplete')
        self.assertEqual((pk['packages'], pk['basis']), (['vim'], 'manual'))

    def test_dnf_history_names_and_the_last_resort(self):
        pk = pkglist.parse('pm dnf\nv\tbash-5.2.26-3.fc40.x86_64\nv\tpython3-libs-3.12.1-1.fc40.x86_64\ncomplete')
        self.assertEqual((pk['packages'], pk['from_history']), (['bash', 'python3-libs'], True))
        pk = pkglist.parse('pm dnf\na\tbash\na\tgpg-pubkey\ncomplete')
        self.assertEqual((pk['packages'], pk['basis']), (['bash'], 'all'))

    def test_aur_packages_are_kept_apart(self):
        pk = pkglist.parse('pm pacman\nm\tvim\nm\tparu\no\tparu\no\tnot-explicit\ncomplete')
        self.assertEqual((pk['packages'], pk['foreign']), (['vim'], ['paru']))

    def test_compare_within_a_family_only(self):
        a = pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tvim\nm\tgit\nf\tx.y\tflathub\ncomplete')
        b = pkglist.parse('distro\tdebian\t13\npm apt-get\nm\tgit\nm\tzsh\ncomplete')
        c = pkglist.compare(a, b)
        self.assertEqual((c['comparable'], c['same_distro'], c['only_a'], c['only_b'], c['both'], c['flatpak_only_a']),
                         (True, False, ['vim'], ['zsh'], 1, ['x.y']))
        self.assertFalse(pkglist.compare(a, pkglist.parse('pm dnf\nm\tvim\n'))['comparable'])
        self.assertTrue(pkglist.compare(pkglist.parse('pm dnf\nm\tvim\n'), pkglist.parse('pm yum\nm\tvim\n'))['comparable'])


class OddSystems(unittest.TestCase):
    """Image-based, read-only and transactional systems, apt on rpm, Debian holds, backports and local debs."""
    def test_an_image_based_system_is_its_layers(self):
        import base64
        status = {'deployments': [{'booted': True, 'requested-packages': ['vim', 'htop', CANARY], 'requested-local-packages': ['tool-1.0-1.x86_64'],
                                   'container-image-reference': 'ostree-image-signed:docker://quay.io/fedora/fedora-silverblue:44'},
                                  {'booted': False, 'requested-packages': ['old']}]}
        pk = pkglist.parse('distro\tfedora\t44\nmode image\npm rpm-ostree\nO\t' + base64.b64encode(json.dumps(status).encode()).decode() + '\ncomplete')
        self.assertEqual((pk['mode'], pk['pm'], pk['packages'], pk['foreign']), ('image', 'rpm-ostree', ['htop', 'vim'], ['tool']))
        self.assertIn('fedora-silverblue:44', pk['image_ref'])
        self.assertTrue(pkglist.compare(pk, pkglist.parse('pm dnf\nm\tvim\n'))['comparable'])
        self.assertIsNone(pkglist.parse('mode image\npm rpm-ostree\nO\tnot base64!\n')['image_ref'])

    def test_a_read_only_system_brings_only_its_apps(self):
        pk = pkglist.parse('distro\tsteamos\t3.6\nmode readonly\npm pacman\nm\tlinux-neptune\nf\tcom.valvesoftware.Steam\tflathub\ncomplete')
        self.assertEqual((pk['packages'], pk['base_packages'], [f['id'] for f in pk['flatpak']]), ([], 1, ['com.valvesoftware.Steam']))

    def test_apt_on_rpm_is_its_own_family(self):
        pk = pkglist.parse('distro\taltlinux\t11\npm apt-rpm\na\tvim-console\ncomplete')
        self.assertEqual(pk['pm'], 'apt-rpm')
        self.assertFalse(pkglist.compare(pk, pkglist.parse('pm apt-get\nm\tvim\n'))['comparable'])
        self.assertFalse(pkglist.compare(pk, pkglist.parse('pm dnf\nm\tvim\n'))['comparable'])

    def test_debian_holds_backports_and_local_debs(self):
        pk = pkglist.parse('pm apt-get\nm\tvim\nm\tzfsutils-linux\nm\tmydeb\nh\tvim\nb\tzfsutils-linux\no\tmydeb\nh\tnot-manual\ncomplete')
        self.assertEqual((pk['packages'], pk['holds'], pk['backports'], pk['foreign']), (['vim', 'zfsutils-linux'], ['vim'], ['zfsutils-linux'], ['mydeb']))

    def test_base_snaps_come_with_the_apps_that_need_them(self):
        # what snap list printed on the lab's Ubuntu 22.04: core22 (base) and snapd are not installed by name
        pk = pkglist.parse('pm apt-get\ns\tcore22\tbase\ns\tsnapd\tsnapd\ns\tlxd\t-\ns\tcode\tclassic\ncomplete')
        self.assertEqual(pk['snap'], [{'name': 'code', 'confinement': 'classic'}, {'name': 'lxd', 'confinement': None}])

    def test_a_debian_cloud_image_names_its_mirrors(self):
        # Debian 12 and 13 cloud images point apt at mirror+file:/etc/apt/mirrors/*.list: the scan reads those lists
        self.assertIn('/etc/apt/mirrors/*.list', remote.INVENTORY_SCRIPT)
        pk = pkglist.parse('pm apt-get\nr\t/etc/apt/mirrors/debian.list\thttps://deb.debian.org/debian\n'
                           'r\t/etc/apt/sources.list.d/debian.sources\tmirror+file:///etc/apt/mirrors/debian.list\ncomplete')
        self.assertEqual(pk['repos'], [{'where': '/etc/apt/mirrors/debian.list', 'url': 'https://deb.debian.org/debian'}])

    def test_aur_versions_are_kept(self):
        self.assertEqual(pkglist.parse('pm pacman\nm\tparu\no\tparu\t2.0.4-1\ncomplete')['foreign_versions'], {'paru': '2.0.4-1'})


# apt-cache: every name asked about has a candidate but "nowhere", and policy alone lists a backports source
APT_CACHE = ('if [ "$1" = policy ] && [ $# -gt 1 ]; then shift; for p; do case $p in nowhere) ;; '
             '*) printf "%s:\\n  Installed: (none)\\n  Candidate: 1.0\\n" "$p" ;; esac; done; '
             'else echo " 500 http://deb.debian.org/debian trixie-backports/main amd64 Packages"; fi')


def stub(d: Path, name: str, body: str):
    p = d / name
    p.write_text('#!/bin/sh\n' + body + '\n')
    p.chmod(0o755)


class Collect(unittest.TestCase):
    """The section of the scan, run by sh with apt-mark stubbed: what it prints parses back."""
    def test_the_scan_section_reads_apt(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        stub(d, 'apt-mark', 'printf "vim\\ngit\\n"')
        stub(d, 'dpkg-query', 'printf "vim\\t2:9.1-1\\nzfsutils-linux\\t2.3.1-1~bpo12+1\\n"')
        stub(d, 'apt', 'printf "Listing...\\nmydeb/now 1.0 amd64 [installed,local]\\n"')
        pre = 'bounded() { "$@"; }\n'
        out = subprocess.run(['sh', '-c', pre + section()], capture_output=True, text=True, timeout=60,
                             env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'})
        self.assertEqual(out.returncode, 0, out.stderr)
        body = out.stdout.split('\n', 1)[1]
        pk = pkglist.parse(body)
        self.assertEqual((pk['pm'], pk['packages'], pk['complete']), ('apt-get', ['git', 'vim'], True))
        self.assertEqual(pk['mode'], 'normal')

    def test_the_section_is_one_the_parser_knows(self):
        self.assertIn('pkglist', remote.SECTIONS)


class Script(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        stub(self.d, 'apt-get', 'echo "apt-get $*" >>"$LOG"')
        stub(self.d, 'apt-cache', APT_CACHE)
        stub(self.d, 'dpkg-query', 'printf "vim\\tinstalled\\nlibc6:i386\\tinstalled\\ngone\\tnot-installed\\n"')

    def run_script(self, pk, *args):
        path = self.d / 'p.sh'
        lists = self.d / 'lists'      # apt has package lists here, as after an apt-get update
        lists.mkdir(exist_ok=True)
        (lists / 'deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages').touch()
        path.write_text(pkglist.script(pk, 'web-01', '2026-11-07').replace('/var/lib/apt/lists/', f'{lists}/'))
        return subprocess.run(['bash', str(path), *args], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log')})

    def test_a_host_with_no_package_lists_yet_leaves_names_undecided_in_a_report(self):
        path = self.d / 'fresh.sh'      # a fresh cloud image: no apt-get update yet, so no name has a candidate
        path.write_text(pkglist.script(pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tzsh\nm\tnowhere\ncomplete'), 'web-01', 'now')
                        .replace('/var/lib/apt/lists/', f'{self.d}/none/'))
        out = subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}'})
        self.assertIn('no package lists yet', out.stdout)
        self.assertNotIn('not in the package sources', out.stdout)
        self.assertIn('2 to install with apt-get', out.stdout)

    def test_tools_a_later_step_needs_are_added(self):
        path = self.d / 'also.sh'
        path.write_text(pkglist.script(pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tvim\ncomplete'), 'web-01', 'now', also=['parted', '$(id)']))
        out = subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}'})
        self.assertIn('added, as a later step of the plan needs it: parted', out.stdout)
        self.assertNotIn('$(id)', path.read_text().split('ALSO=', 1)[1].split('\n', 1)[0])

    def test_it_reports_what_is_missing_and_installs_nothing(self):
        pk = pkglist.parse(f'distro\tdebian\t12\npm apt-get\nm\tvim\nm\tlibc6:i386\nm\tgone\nm\tzsh\nm\t{CANARY}\n'
                           f'r\tx\thttps://deb.example.com/debian\ncomplete')
        out = self.run_script(pk)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('2 of 4 already installed', out.stdout)
        self.assertIn('2 to install with apt-get: gone zsh', out.stdout)
        self.assertIn('https://deb.example.com/debian', out.stdout)
        self.assertFalse((self.d / 'log').exists())
        self.assertFalse(Path('/tmp/CANARY').exists())
        self.assertIn('2 of 3 already installed', self.run_script(pk, '--skip', 'zsh').stdout)

    def test_a_name_the_sources_lack_is_said_and_not_tried(self):
        out = self.run_script(pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tzsh\nm\tnowhere\ncomplete'))
        self.assertEqual(out.returncode, 0)       # listed, and not a problem: the rest of a copy goes on (the Pi run)
        self.assertIn('missing   1 not in the package sources here', out.stdout)
        self.assertIn('1 to install with apt-get: zsh', out.stdout)

    def test_versioned_libraries_stay_behind_across_releases(self):
        # the libraries of 22.04 (libssl3, gcc-12-base) do not exist on 24.04: what needs them brings its own
        pk = pkglist.parse('distro\tubuntu\t22.04\npm apt-get\nm\tzsh\nm\tlibssl3\nm\tgcc-12-base\nm\tlibtss2-esys-3.0.2-0\nm\tlibreoffice\ncomplete')
        text = self.run_script(pk).stdout
        self.assertIn('3 versioned librar(ies) of ubuntu 22.04 left out', text)
        self.assertIn('2 to install with apt-get: libreoffice zsh', text)
        path = self.d / 'same.sh'      # the same release keeps them: a library installed on purpose may be for something unpackaged
        path.write_text(pkglist.script(pk, 'web-01', 'now').replace('. /etc/os-release 2>/dev/null || true', 'ID=ubuntu VERSION_ID=22.04'))
        same = subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}'})
        self.assertIn('5 to install with apt-get', same.stdout)

    def test_another_package_manager_is_refused(self):
        out = self.run_script(pkglist.parse('pm pacman\nm\tvim\ncomplete'))
        self.assertEqual(out.returncode, 1)
        self.assertIn('nothing is installed', out.stdout)

    @unittest.skipIf(os.geteuid() == 0, 'root may apply')
    def test_apply_needs_root(self):
        out = self.run_script(pkglist.parse('pm apt-get\nm\tzsh\ncomplete'), '--apply')
        self.assertEqual(out.returncode, 1)
        self.assertIn('--apply needs root', out.stderr)

    def test_a_hostile_source_name_stays_a_word(self):
        pk = pkglist.parse(f'pm apt-get\nm\tvim\nr\t{CANARY}\thttps://x.example/\ncomplete')
        self.assertEqual(self.run_script(pk).returncode, 0)
        self.assertFalse(Path('/tmp/CANARY').exists())


class HoldsAndBackports(unittest.TestCase):
    def test_the_report_names_both(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        stub(d, 'apt-get', 'true')
        stub(d, 'dpkg-query', 'true')
        stub(d, 'apt-cache', APT_CACHE)
        pk = pkglist.parse('pm apt-get\nm\tvim\nm\tzfsutils-linux\nh\tvim\nb\tzfsutils-linux\ncomplete')
        path = d / 'p.sh'
        path.write_text(pkglist.script(pk, 'src', 'now').replace('here_pm() {', 'here_pm() { echo apt-get; return; ')
                        .replace('. /etc/os-release 2>/dev/null || true', 'VERSION_CODENAME=trixie'))
        out = subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'})
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('1 to install with apt-get: vim', out.stdout)
        self.assertIn('would take zfsutils-linux from trixie-backports', out.stdout)
        self.assertIn('would hold vim at the installed version', out.stdout)


class NoRemovals(unittest.TestCase):
    """--apply never removes a package to make room: run as a stand-in root, with stand-in package managers."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        stub(self.d, 'rpm', 'true')
        stub(self.d, 'dpkg-query', 'true')

    def apply(self, pm, stubs, here=None):
        for name, body in stubs.items():
            stub(self.d, name, body)
        path = self.d / 'p.sh'
        # the root check is the script's own: here EUID is made 0 so --apply runs against the stand-ins
        path.write_text(pkglist.script(pkglist.parse(f'pm {pm}\nm\tnewpkg\ncomplete'), 'src', 'now').replace('[[ $EUID -ne 0 ]]', 'false')
                        .replace('here_pm() {', f'here_pm() {{ echo {here}; return; ' if here else 'here_pm() {'))
        return subprocess.run(['bash', str(path), '--apply', '--no-apps'], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log')})

    def test_apt_is_told_not_to_remove(self):
        out = self.apply('apt-get', {'apt-get': 'echo "$*" >>"$LOG"', 'apt-cache': APT_CACHE}, here='apt-get')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('install -y -qq --no-remove newpkg', (self.d / 'log').read_text())

    def test_zypper_refuses_a_removal_and_installs_nothing(self):
        dry = ('case "$*" in *--dry-run*) printf "The following package is going to be REMOVED:\\n  oldpkg\\n\\n" ;; '
               '*) echo "$*" >>"$LOG" ;; esac')
        out = self.apply('zypper', {'zypper': dry}, here='zypper')
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn('refused: installing would remove oldpkg', out.stdout)
        self.assertFalse((self.d / 'log').exists())

    def test_apk_refuses_a_purge(self):
        sim = 'case "$*" in info) ;; *--simulate*) echo "(1/1) Purging oldpkg (1.0-r0)" ;; *) echo "$*" >>"$LOG" ;; esac'
        out = self.apply('apk', {'apk': sim}, here='apk')     # this machine's own manager would be found first
        self.assertIn('refused: installing would remove oldpkg', out.stdout)
        self.assertFalse((self.d / 'log').exists())


class Routes(unittest.TestCase):
    def setUp(self):
        from storageforge_index import server, users
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        users.create(self.conn, 'alice', 'a long enough password')
        self.client = server.create_app(server.App(self.db), 's' * 48).test_client()
        a = {'collected_at': '2026-11-07T00:00:00+00:00', 'pkglist': pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tvim\nm\tgit\ncomplete')}
        b = {'pkglist': pkglist.parse('distro\tdebian\t12\npm apt-get\nm\tgit\ncomplete')}
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('a', 'a', 'scan', :a), ('b', 'b', 'scan', :b), ('old', 'old', 'scan', '{}')",
                          {'a': json.dumps(a), 'b': json.dumps(b)})

    def test_routes(self):
        self.assertEqual(self.client.get('/api/hostconfigs/packages?host=a').status_code, 401)
        self.client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        self.assertEqual(self.client.get('/api/hostconfigs/packages?host=a').json['packages'], ['git', 'vim'])
        diff = self.client.get('/api/hostconfigs/packages?host=a&against=b').json
        self.assertEqual((diff['only_a'], diff['only_b'], diff['a'], diff['b']), (['vim'], [], 'a', 'b'))
        r = self.client.get('/api/hostconfigs/packages/script?host=a')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'PKGS=(git vim)', r.data)
        for path in ('/api/hostconfigs/packages?host=old', '/api/hostconfigs/packages?host=nowhere', '/api/hostconfigs/packages/script?host=old'):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_cli(self):
        from storageforge_index import cli
        db = str(Path(self.tmp) / 'index.db')

        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = cli.main(['--db', db, 'hosts', 'packages', *args])
            return rc, out.getvalue()
        rc, out = run('a')
        self.assertEqual(rc, 0)
        self.assertIn('2 package(s) installed on purpose', out)
        rc, out = run('a', '--against', 'b')
        self.assertEqual((rc, 'only on a: vim' in out), (1, True))
        self.assertEqual(run('b', '--against', 'b')[0], 0)
        self.assertEqual(run('old')[0], 1)
        script = Path(self.tmp) / 'p.sh'
        self.assertEqual(run('a', '--script', '-o', str(script))[0], 0)
        self.assertEqual(subprocess.run(['bash', '-n', str(script)]).returncode, 0)


if __name__ == '__main__':
    unittest.main()
