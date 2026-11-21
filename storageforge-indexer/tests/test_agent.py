"""The optional agent's base (roadmap section 11.1; docs/agent.md): the setup script, storageforge-agentctl, the runtimes and
enrollment, from the controller's side.

What is real here: storageforge-agent and storageforge-agentctl, built with cargo with a release key made for the run compiled in;
the controller's signatures, made by sfagent.py and checked by the Rust programs; signatures made with ssh-keygen; the vault, the
table and the audit chain; bash running the setup script; visudo reading the sudoers line. What stands in: the host. The programs
are given a folder to treat as /, and docker, podman, lxc-create and the package manager there are scripts that write down how
they were called and start the real agent where a runtime would. RealDocker runs the same road against the real Docker with the
real image, where Docker and a registry image are at hand.

Skipped where there is no cargo."""
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import dbfactory
from storageforge_index import deploy, server, sfagent, users, vault

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'target' / 'agent-test'          # a build of its own: the release key compiled in is this folder's, not the repository's
SECRET = b'correct horse battery staple, but longer than 32'
MACHINE = '0123456789abcdef0123456789abcdef'
IMAGE = 'registry.example/storageforge-agent@sha256:' + 'a' * 64
PW = 'a long enough password'
BUILT = None


def build():
    """The agent's programs and the example plugin, built once for the run with a release key of this folder's compiled in."""
    global BUILT
    if BUILT is None and shutil.which('cargo'):
        TARGET.mkdir(parents=True, exist_ok=True)
        key = TARGET / 'release-key'
        if not key.exists():
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test-release', '-f', str(key)], check=True)
        signers = TARGET / 'release_signers'
        signers.write_text('testrelease namespaces="storageforge-plugin,storageforge-agent-image" ' + ' '.join(key.with_suffix('.pub').read_text().split()[:2]) + '\n')
        p = subprocess.run(['cargo', 'build', '--quiet', '--locked', '-j', '4', '-p', 'storageforge-agent', '--bins', '--examples'], cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, 'STORAGEFORGE_RELEASE_SIGNERS': str(signers), 'CARGO_TARGET_DIR': str(TARGET)})
        out = TARGET / 'debug'
        BUILT = out if p.returncode == 0 and (out / 'storageforge-agentctl').exists() else False
        if not BUILT:
            raise AssertionError(f'cargo is here and the agent does not build:\n{p.stderr[-2000:]}')
    return BUILT


def stub(d: Path, name: str, body: str):
    """A stand-in program. It finds the system's own tools itself: the folder it is in is all storageforge-agentctl is given to look
    for programs in, so that nothing real on this machine (its Docker, say) is taken for the host's."""
    p = d / name
    p.write_text('#!/bin/bash\nPATH=/usr/bin:/bin\n' + body + '\n')
    p.chmod(0o755)


def ssh_sign(key: Path, namespace: str, data: bytes) -> str:
    """A signature made by the real ssh-keygen, as whoever holds the release key makes one."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'data'
        f.write_bytes(data)
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-q', '-f', str(key), '-n', namespace, str(f)], check=True, capture_output=True)
        return (Path(d) / 'data.sig').read_text()


class Host:
    """A folder that stands for a host's /, with the accounts, the machine id and the programs a test gives it."""

    def __init__(self, case, runtimes=('docker',)):
        self.case = case
        self.dir = Path(tempfile.mkdtemp(prefix='sfagent-host-'))
        case.addCleanup(shutil.rmtree, self.dir, True)
        case.addCleanup(self.kill_agent)
        self.root, self.bin, self.log = self.dir / 'root', self.dir / 'bin', self.dir / 'log'
        for d in ('etc/ssh', 'etc/sudoers.d', 'root/.ssh', 'home/ana/.ssh', 'var/tmp', 'sys/block/sda', 'usr/share/lxc/config'):
            (self.root / d).mkdir(parents=True)
        self.bin.mkdir()
        (self.root / 'etc/machine-id').write_text(MACHINE + '\n')
        (self.root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\n')
        (self.root / 'etc/group').write_text('root:x:0:\ndocker:x:957:ana\nlxd:x:958:\nincus-admin:x:959:\nwheel:x:998:ana\nsystemd-journal:x:980:\n')
        (self.root / 'etc/shadow').write_text('root:!::\n')
        (self.root / 'etc/ssh/ssh_host_ed25519_key').write_text('a private host key\n')
        (self.root / 'etc/subuid').write_text('root:1000000:65536\n')
        (self.root / 'etc/subgid').write_text('root:1000000:65536\n')
        (self.root / 'usr/share/lxc/config/common.seccomp').write_text('2\n')
        self.agent_log = self.dir / 'agent.log'
        # the accounts a host makes with useradd, written into the folder's passwd and group. sfagent gets this user's own ids,
        # since whatever starts the agent here starts it as this user
        stub(self.bin, 'useradd', f'echo "useradd $*" >>{self.log}; name=${{@: -1}}; n=$(wc -l <{self.root}/etc/passwd)\n'
             f'if [[ $name == sfagent ]]; then u={os.getuid()} g={os.getgid()}; else u=$((900 + n)) g=$((900 + n)); fi\n'
             f'echo "$name:x:$u:$g::/var/lib/storageforge-agent/$name:/bin/sh" >>{self.root}/etc/passwd; echo "$name:x:$g:" >>{self.root}/etc/group')
        stub(self.bin, 'usermod', f'echo "usermod $*" >>{self.log}')
        stub(self.bin, 'userdel', f'echo "userdel $*" >>{self.log}; sed -i "/^$1:/d" {self.root}/etc/passwd {self.root}/etc/group')
        stub(self.bin, 'pgrep', 'exit 1')
        stub(self.bin, 'pkill', 'exit 0')
        stub(self.bin, 'id', f'if [[ $1 == -nG ]]; then u=$2; g=$(awk -F: -v u="$u" \'$1 == u {{print $4}}\' {self.root}/etc/passwd)\n'
             f'  awk -F: -v u="$u" -v g="$g" \'$3 == g || ("," $4 ",") ~ ("," u ",") {{printf "%s ", $1}}\' {self.root}/etc/group; echo\n'
             f'else grep -q "^$1:" {self.root}/etc/passwd; fi')
        stub(self.bin, 'gpasswd', f'echo "gpasswd $*" >>{self.log}; if [[ $1 == -a ]]; then sed -i "s/^\\($3:[^:]*:[^:]*:\\)\\(.*\\)$/\\1\\2,$2/; s/:,/:/" {self.root}/etc/group; '
             f'else sed -i "/^$3:/s/\\b$2\\b,\\?//; /^$3:/s/,$//" {self.root}/etc/group; fi')
        stub(self.bin, 'loginctl', f'echo "loginctl $*" >>{self.log}')
        stub(self.bin, 'runuser', f'echo "runuser $*" >>{self.log}; shift 3; exec "$@"')
        for name in runtimes:
            self.runtime(name)

    def runtime(self, name):
        """A stand-in for a runtime: it writes down how it was called, and where the real one would start the container it starts
        the real agent, on the three folders the container would be given."""
        agent = build() / 'storageforge-agent'
        var = self.root / 'var/lib/storageforge-agent'
        start = (f'nohup {agent} run --etc {self.root}/etc/storageforge-agent --manifest {var}/manifest --state {var}/state >>{self.agent_log} 2>&1 &\n'
                 f'echo $! >{self.dir}/agent.pid; touch {self.dir}/container')
        stop = f'if [[ -f {self.dir}/agent.pid ]]; then kill "$(cat {self.dir}/agent.pid)" 2>/dev/null; rm -f {self.dir}/agent.pid; fi'
        running = f'[[ -f {self.dir}/agent.pid ]] && kill -0 "$(cat {self.dir}/agent.pid)" 2>/dev/null'
        if name in ('docker', 'podman'):
            stub(self.bin, name, f'[[ $1 == --version ]] && {{ echo "Docker version 29.1.0, build stand-in"; exit 0; }}\necho "{name} $*" >>{self.log}\ncase $1 in\n  run) {start} ;;\n  stop) {stop} ;;\n  rm) {stop}; rm -f {self.dir}/container ;;\n'
                 f'  inspect) [[ -f {self.dir}/container ]] || exit 1; if {running}; then echo "true sha256:abc"; else echo "false sha256:abc"; fi ;;\nesac\nexit 0')
        elif name == 'lxc':
            stub(self.bin, 'lxc-create', f'echo "lxc-create $*" >>{self.log}; mkdir -p {self.root}/var/lib/lxc/storageforge-agent/rootfs; touch {self.root}/var/lib/lxc/storageforge-agent/config')
            stub(self.bin, 'lxc-start', f'echo "lxc-start $*" >>{self.log}\n{start}')
            stub(self.bin, 'lxc-stop', f'echo "lxc-stop $*" >>{self.log}\n{stop}\nexit 0')
            stub(self.bin, 'lxc-destroy', f'echo "lxc-destroy $*" >>{self.log}\n{stop}; rm -f {self.dir}/container; rm -rf {self.root}/var/lib/lxc/storageforge-agent')
            stub(self.bin, 'lxc-info', f'if {running}; then echo RUNNING; else echo STOPPED; fi')
        elif name == 'apt-get':
            # the package manager of a host with no runtime: installing podman puts the stand-in above in place
            stub(self.bin, 'apt-get', f'echo "apt-get $*" >>{self.log}; cp {self.dir}/podman.later {self.bin}/podman')
            self.runtime('podman')
            (self.bin / 'podman').rename(self.dir / 'podman.later')

    def env(self, **more):
        return {'PATH': str(self.bin), 'LC_ALL': 'C', 'STORAGEFORGE_AGENT_SETUP_ROOT': str(self.root),
                'STORAGEFORGE_AGENTCTL_ROOT': str(self.root), 'STORAGEFORGE_AGENTCTL_USER': sfagent.MANAGER, **more}

    def kill_agent(self):
        pid = self.dir / 'agent.pid'
        if pid.exists():
            try:
                os.kill(int(pid.read_text()), signal.SIGKILL)       # a process this test started, by its pid
            except (OSError, ValueError):
                pass

    def calls(self, prefix=''):
        return [line for line in (self.log.read_text().splitlines() if self.log.exists() else []) if line.startswith(prefix)]

    def agentctl(self):
        return self.root / 'usr/local/sbin/storageforge-agentctl'

    def run_setup(self, script, data=None, *args):
        # the setup is a shell script and needs the system's tools; the stand-ins come first
        return subprocess.run(['bash', '-c', script, 'setup', *args], input=data, capture_output=True, timeout=60,
                              env=self.env(PATH=f'{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin'))

    def send(self, req, **env):
        return subprocess.run([str(self.agentctl())], input=req, capture_output=True, env=self.env(**env), timeout=120)

    def group(self, group, *members):
        f = self.root / 'etc/group'
        f.write_text(''.join(f'{line.split(":")[0]}:x:{line.split(":")[2]}:{",".join(members)}\n' if line.startswith(group + ':') else line + '\n'
                             for line in f.read_text().splitlines()))


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the agent (CI builds it)')
class Base(unittest.TestCase):
    RUNTIMES = ('docker',)

    def setUp(self):
        self.out = build()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'STORAGEFORGE_DATA_DIR': str(self.tmp / 'data'),
                                         'STORAGEFORGE_AGENT_IMAGE': IMAGE, 'STORAGEFORGE_AGENT_DIR': str(self.tmp / 'agentdir')})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop('STORAGEFORGE_ENCLAVE', None)
        (self.tmp / 'agentdir/x86_64').mkdir(parents=True)
        shutil.copy(self.out / 'storageforge-agentctl', self.tmp / 'agentdir/x86_64/storageforge-agentctl')
        self.program = (self.out / 'storageforge-agentctl').read_bytes()
        self.sign_image(IMAGE)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        vault.Vault(self.db, self.conn, SECRET).init()
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, machine_id, inventory_json) VALUES ('nas', '10.0.0.3', 22, :m, :i)",
                          {'m': MACHINE, 'i': json.dumps({'packages': 'pm apt-get\ninit systemd\nprobed 1\nhave bash\nhave sudo\narch\tx86_64\n'})})
        deploy.set_access(self.conn, 'nas', 'ready', '', 'test')
        self.host = Host(self, self.RUNTIMES)
        self.setups = []

        def fake_run(db, host, script, args=(), *, kind, ref=None, data=None, **_kw):
            p = self.host.run_setup(script, data)
            self.setups.append((ref, script, p))
            return {'status': 'ok' if p.returncode == 0 else 'failed', 'exit_code': p.returncode, 'output': (p.stdout + p.stderr).decode()}

        def fake_send(_vault, _conn, _name, req, _timeout):
            p = self.host.send(req)
            return p.returncode, p.stdout, p.stderr
        for target, name, fn in ((deploy, 'run', fake_run), (sfagent, '_send', fake_send)):
            p = mock.patch.object(target, name, fn)
            p.start()
            self.addCleanup(p.stop)

    def sign_image(self, image, key=None):
        """The signature a release carries beside its image: of the digest, by the release key this build trusts."""
        sig = ssh_sign(key or TARGET / 'release-key', 'storageforge-agent-image', image.split('@')[1].encode() + b'\n')
        (self.tmp / 'agentdir/image.sig').write_text(sig)
        return sig

    def keys(self):
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:
            return sfagent.ensure_keys(v)

    def signer(self):
        self.keys()
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:
            return sfagent._signer(v)

    def setup_host(self):
        signing, login = self.keys()
        p = self.host.run_setup(sfagent.setup_script(signing, login, self.program), self.program)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return p

    def ask(self, op, signer=None, **fields):
        """One request straight to the program, signed here: (exit code, answer)."""
        req = sfagent.request(signer or self.signer(), op, fields.pop('machine', MACHINE), **fields)
        p = self.host.send(req)
        return p.returncode, json.loads(p.stdout.decode().splitlines()[-1]) if p.stdout.strip() else {}

    def install(self, **kw):
        sfagent.switch(self.conn, 'nas', True, 'test')
        return sfagent.install(self.db, 'nas', 'test', **kw)

    def audit(self):
        return [(a, o) for a, o in self.conn.all("SELECT action, outcome FROM audit_log WHERE action LIKE 'agent.%' ORDER BY audit_id")]

    def plugin(self, name='probe', needs='{}', key=None, signer='release'):
        """A plugin's signed descriptor: (bytes, signature, who signed). The program is the example plugin."""
        program = (self.out / 'examples' / 'probe').read_bytes()
        descriptor = json.dumps({'format': 1, 'name': name, 'version': '0.5.7', 'arch': os.uname().machine, 'sha256': hashlib.sha256(program).hexdigest(),
                                 'size': len(program), 'protocol': 1, 'needs': json.loads(needs)}, separators=(',', ':')).encode()
        return descriptor, ssh_sign(key or TARGET / 'release-key', 'storageforge-plugin', descriptor), signer

    def put_plugin(self, descriptor, signature):
        """What the tunnel of 11.2 will do: the plugin's three files into the agent's plugin folder."""
        name = json.loads(descriptor)['name']
        d = self.host.root / 'var/lib/storageforge-agent/state/plugins'
        d.mkdir(exist_ok=True)
        (d / f'{name}.plugin.json').write_bytes(descriptor)
        (d / f'{name}.plugin.sig').write_text(signature)
        shutil.copy(self.out / 'examples' / 'probe', d / f'{name}.plugin')

    def agent_check(self):
        var = self.host.root / 'var/lib/storageforge-agent'
        p = subprocess.run([str(self.out / 'storageforge-agent'), 'check', '--etc', str(self.host.root / 'etc/storageforge-agent'), '--manifest', str(var / 'manifest'),
                            '--state', str(var / 'state')], capture_output=True, text=True, timeout=30)
        return p.returncode, json.loads(p.stdout) if p.stdout.strip() else {}


class Setup(Base):
    """The setup script, run by bash against the stand-in host."""

    def test_it_makes_two_accounts_one_sudoers_line_and_pins_the_controller(self):
        p = self.setup_host()
        signing, login = self.keys()
        root = self.host.root
        self.assertEqual(self.host.agentctl().read_bytes(), self.program)
        self.assertEqual((root / 'etc/sudoers.d/storageforge-agentctl').read_text(),
                         'storageforge-agentctl ALL=(root) NOPASSWD: /usr/local/sbin/storageforge-agentctl ""\n', 'one line: the program, with no arguments')
        if shutil.which('visudo'):       # and sudo itself reads it as a rule
            self.assertEqual(subprocess.run(['visudo', '-cf', str(root / 'etc/sudoers.d/storageforge-agentctl')], capture_output=True).returncode, 0)
        self.assertEqual((root / 'etc/storageforge-agent/controller_signers').read_text(),
                         'controller namespaces="storageforge-agentctl,storageforge-agent-manifest" ' + ' '.join(signing.split()[:2]) + '\n')
        keys = (root / 'var/lib/storageforge-agent/ctl-home/.ssh/authorized_keys').read_text()
        self.assertEqual(keys, 'restrict,command="sudo -n /usr/local/sbin/storageforge-agentctl" ' + ' '.join(login.split()[:2]) + ' storageforge:agentctl\n')
        self.assertNotEqual(signing.split()[1], login.split()[1], 'the key that logs in signs nothing')
        made = [c.split()[-1] for c in self.host.calls('useradd')]
        self.assertEqual(made, ['sfagent', 'storageforge-agentctl'])
        self.assertTrue(all('--system' in c for c in self.host.calls('useradd')))
        self.assertIn('nologin', self.host.calls('useradd')[0], 'nobody logs in as the agent')
        self.assertEqual(oct((root / 'var/lib/storageforge-agent/state').stat().st_mode & 0o777), '0o700')
        self.assertEqual(oct((root / 'var/lib/storageforge-agent/ctl').stat().st_mode & 0o777), '0o700')
        self.assertIn('runtimes: docker', p.stdout.decode())
        # run again: nothing is made twice
        self.setup_host()
        self.assertEqual(len(self.host.calls('useradd')), 2)

    def test_the_program_is_installed_only_when_it_is_the_one_the_script_was_written_for(self):
        signing, login = self.keys()
        script = sfagent.setup_script(signing, login, self.program)
        for other in (self.program[:-1] + bytes([self.program[-1] ^ 1]), self.program + b'\0', self.program[:100], b''):
            p = self.host.run_setup(script, other)
            self.assertEqual(p.returncode, 6, p.stderr.decode())
            self.assertIn('refused: the program that arrived is not', p.stderr.decode())
        self.assertFalse(self.host.agentctl().exists())
        self.assertFalse((self.host.root / 'etc/sudoers.d/storageforge-agentctl').exists())
        self.assertEqual(self.host.calls('useradd'), [], 'nothing was made before the program was known to be right')
        # by hand, on a host with no deploy access: the program is named as an argument
        f = self.tmp / 'agentctl'
        f.write_bytes(self.program)
        self.assertEqual(self.host.run_setup(script, None, str(f)).returncode, 0)
        self.assertEqual(self.host.agentctl().read_bytes(), self.program)

    def test_a_managing_user_in_a_group_that_is_root_is_refused_with_the_reason(self):
        self.setup_host()
        signing, login = self.keys()
        for group in sfagent.ROOT_GROUPS:
            for user in (sfagent.MANAGER, sfagent.AGENT_USER):
                self.host.group(group, user)
                self.host.agentctl().unlink(missing_ok=True)
                p = self.host.run_setup(sfagent.setup_script(signing, login, self.program), self.program)
                self.assertEqual(p.returncode, 5, (group, user, p.stderr.decode()))
                self.assertIn(f'refused: {user} is in the {group} group, which is root on this host', p.stderr.decode())
                self.assertIn(f'gpasswd -d {user} {group}', p.stderr.decode())
                self.assertFalse(self.host.agentctl().exists(), 'refused before anything is installed')
                self.host.group(group)
        self.host.group('wheel', sfagent.AGENT_USER)
        p = self.host.run_setup(sfagent.setup_script(signing, login, self.program), self.program)
        self.assertEqual(p.returncode, 5)
        self.assertIn('sfagent is in the wheel group', p.stderr.decode())

    def test_another_controllers_key_is_taken_only_when_a_person_accepts_it(self):
        self.setup_host()
        signing, login = self.keys()
        other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        pinned = self.host.root / 'etc/storageforge-agent/controller_signers'
        before = pinned.read_text()
        p = self.host.run_setup(sfagent.setup_script(other, login, self.program), self.program)
        self.assertEqual(p.returncode, 7)
        self.assertIn('another controller pinned', p.stderr.decode())
        self.assertEqual(pinned.read_text(), before)
        p = self.host.run_setup(sfagent.setup_script(other, login, self.program, accept_new_key=True), self.program)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn(other.split()[1], pinned.read_text())

    def test_removing_takes_the_accounts_the_line_and_the_program_away(self):
        self.setup_host()
        p = self.host.run_setup(sfagent.remove_script())
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        root = self.host.root
        for gone in ('etc/sudoers.d/storageforge-agentctl', 'usr/local/sbin/storageforge-agentctl', 'etc/storageforge-agent', 'var/lib/storageforge-agent'):
            self.assertFalse((root / gone).exists(), gone)
        self.assertEqual([c.split()[-1] for c in self.host.calls('userdel')], [sfagent.MANAGER, sfagent.AGENT_USER])

    def test_the_scripts_hold_no_odd_quote_and_no_secret(self):
        signing, login = self.keys()
        for script in (sfagent.setup_script(signing, login, self.program), sfagent.remove_script()):
            self.assertEqual([line for line in script.splitlines() if line.count("'") % 2], [])
            self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
            self.assertNotIn('PRIVATE KEY', script)
            self.assertNotIn(SECRET.decode(), script)


class Requests(Base):
    """What storageforge-agentctl acts on, and what it refuses: the real program, asked directly."""

    def setUp(self):
        super().setUp()
        self.setup_host()

    def test_it_takes_a_signed_request_on_stdin_and_nothing_else(self):
        self.assertEqual(self.ask('preflight')[0], 0)
        ctl = str(self.host.agentctl())
        p = subprocess.run([ctl, 'status'], input=b'', capture_output=True, env=self.host.env())
        self.assertEqual(p.returncode, 97)
        self.assertIn('takes no arguments', p.stderr.decode())
        for words in (['docker', 'ps'], ['--', 'sh'], ['-c', 'id']):
            self.assertEqual(subprocess.run([ctl, *words], input=b'', capture_output=True, env=self.host.env()).returncode, 97)
        # run by someone who is not root, on a real host: it has nothing to act with and says so
        bare = {'PATH': str(self.host.bin)}
        p = subprocess.run([ctl], input=sfagent.request(self.signer(), 'status', MACHINE), capture_output=True, env=bare)
        self.assertEqual(p.returncode, 97)
        self.assertIn('runs as root, through sudo', p.stderr.decode())
        for junk in (b'', b'hello\n', b'STORAGEFORGE-RUN 1\n2\n2\n{}{}', b'STORAGEFORGE-AGENTCTL 1\n99999999\n10\n', b'\x00' * 4096):
            p = self.host.send(junk)
            self.assertEqual(p.returncode, 97, junk[:30])
            self.assertEqual(json.loads(p.stdout)['error'], 'request')
        self.assertEqual(self.host.calls('docker'), [], 'no runtime was touched')

    def test_only_this_controller_this_machine_now_and_once(self):
        signer = self.signer()
        other = ed25519.Ed25519PrivateKey.generate()
        self.assertEqual(self.ask('status', signer=other)[0], 97)
        rc, got = self.ask('status', machine='f' * 32)
        self.assertEqual((rc, got['error']), (97, 'request'))
        self.assertIn('another machine', got['why'])
        for when in (time.time() - 3600, time.time() + 3600):
            p = self.host.send(sfagent.request(signer, 'status', MACHINE, now=when))
            self.assertEqual(p.returncode, 97)
            self.assertIn('too old, or the clocks differ', p.stderr.decode())
        req = sfagent.request(signer, 'status', MACHINE)
        self.assertEqual(self.host.send(req).returncode, 0)
        again = self.host.send(req)
        self.assertEqual(again.returncode, 97)
        self.assertIn('already used', again.stderr.decode())
        # a signature of the controller's made for something else: a manifest, a deploy
        payload = json.dumps({'op': 'status', 'machine': MACHINE, 'issued': int(time.time()), 'nonce': 'ab' * 16}, separators=(',', ':')).encode()
        for namespace in (sfagent.NS_MANIFEST, deploy.NAMESPACE):
            sig = deploy.sshsig(signer, payload, namespace).encode()
            p = self.host.send(f'STORAGEFORGE-AGENTCTL 1\n{len(payload)}\n{len(sig)}\n'.encode() + payload + sig)
            self.assertEqual(p.returncode, 97, namespace)
            self.assertIn('not signed by this host\'s controller', p.stderr.decode())

    def test_what_is_not_an_agent_operation_is_refused_even_signed(self):
        signer = self.signer()

        def signed(body):
            payload = json.dumps({'machine': MACHINE, 'issued': int(time.time()), 'nonce': os.urandom(16).hex(), **body}, separators=(',', ':')).encode()
            sig = deploy.sshsig(signer, payload, sfagent.NS_REQUEST).encode()
            p = self.host.send(f'STORAGEFORGE-AGENTCTL 1\n{len(payload)}\n{len(sig)}\n'.encode() + payload + sig)
            return p.returncode, json.loads(p.stdout)
        for body in ({'op': 'exec', 'argv': ['id']}, {'op': 'run'}, {'op': 'shell'}, {'op': 'status', 'command': 'id'}, {'op': 'status', 'script': 'id'},
                     {'op': 'enroll', 'image': 'storageforge-agent:latest', 'image_signature': 's'}, {'op': 'enroll', 'image': IMAGE, 'image_signature': 's', 'privileged': True},
                     {'op': 'enroll', 'image': '--privileged@sha256:' + 'a' * 64, 'image_signature': 's'}, {'op': 'enroll', 'image': IMAGE},
                     {'op': 'stop', 'image': IMAGE}, {'op': 'apply'}):
            rc, got = signed(body)
            self.assertEqual((rc, got['ok'], got['error']), (97, False, 'request'), body)
        self.assertEqual(self.host.calls('docker'), [])
        with self.assertRaises(ValueError):
            sfagent.request(signer, 'exec', MACHINE)

    def test_the_managing_user_in_docker_lxd_or_incus_admin_is_refused_at_every_request(self):
        for group in sfagent.ROOT_GROUPS:
            self.host.group(group, 'ana', sfagent.MANAGER)
            for op in ('preflight', 'status', 'stop'):
                rc, got = self.ask(op)
                self.assertEqual((rc, got['error']), (97, 'root-group'), (group, op))
                self.assertIn(f'{sfagent.MANAGER} is in the {group} group, which is root on this host', got['why'])
            self.host.group(group, 'ana')
        self.assertEqual(self.ask('preflight')[0], 0)
        # and the agent's own account in a group that gives root
        self.host.group('wheel', sfagent.AGENT_USER)
        rc, got = self.ask('preflight')
        self.assertEqual((rc, got['error']), (97, 'account'))

    def test_a_host_that_was_never_set_up_answers_nothing(self):
        bare = Host(self)
        (bare.root / 'usr/local/sbin').mkdir(parents=True)
        shutil.copy(self.out / 'storageforge-agentctl', bare.agentctl())
        p = bare.send(sfagent.request(self.signer(), 'status', MACHINE))
        self.assertEqual(p.returncode, 97)
        self.assertIn('no controller pinned', p.stderr.decode())


class Lifecycle(Base):
    """Enrollment and the lifecycle, from sfagent.py through the real programs, with Docker standing in."""

    def test_enrolling_pins_the_key_the_agent_made_and_gives_the_container_nothing(self):
        got = self.install()
        self.assertEqual((got['state'], got['runtime']), ('running', 'docker'))
        row = sfagent.get(self.conn, 'nas')
        public = (self.host.root / 'var/lib/storageforge-agent/state/agent_key.pub').read_text().strip()
        self.assertEqual(row['public_key'], public, 'the key the agent itself made')
        said = subprocess.run(['ssh-keygen', '-lf', str(self.host.root / 'var/lib/storageforge-agent/state/agent_key.pub')], capture_output=True, text=True).stdout.split()[1]
        self.assertEqual(row['fingerprint'], said, 'the fingerprint ssh-keygen shows')
        self.assertEqual(oct((self.host.root / 'var/lib/storageforge-agent/state/agent_key').stat().st_mode & 0o777), '0o600')
        self.assertEqual((row['state'], row['counter'], row['image']), ('running', 1, IMAGE))
        self.assertEqual(self.audit(), [('agent.enroll', 'ok'), ('agent.apply', 'ok')])
        self.assertEqual([ref for ref, *_ in self.setups], ['setup'])
        runs = self.host.calls('docker run')
        self.assertEqual(len(runs), 2, 'once to enroll, and again for the first manifest')
        uid, gid = os.getuid(), os.getgid()
        for must in ('--read-only', '--cap-drop ALL', '--security-opt no-new-privileges', f'--user {uid}:{gid}', '--network none', f'{IMAGE} run',
                     f'type=bind,src={self.host.root}/etc/storageforge-agent,dst=/etc/storageforge-agent,readonly'):
            self.assertIn(must, runs[-1])
        for never in ('--privileged', 'docker.sock', '--cap-add', '--pid ', '--device', '/host', '--group-add'):
            self.assertNotIn(never, runs[-1])
        self.assertIn(f'docker pull --quiet {IMAGE}', self.host.calls('docker pull'))
        # the agent has the manifest and runs nothing: there is no plugin in it
        rc, report = self.agent_check()
        self.assertEqual((rc, report['counter'], report['plugins'], report['agent']), (0, 1, [], row['fingerprint']))
        # the answer of a host is checked for what it is: this one is from the real program
        status = sfagent.lifecycle(self.db, 'nas', 'status', 'test')
        self.assertEqual((status['running'], status['key_matches'], status['counter'], status['runtime']), (True, True, 1, 'docker'))

    def test_it_is_off_until_switched_on_and_a_second_agent_is_not_enrolled_over_the_first(self):
        with self.assertRaisesRegex(sfagent.AgentError, 'switched off for nas'):
            sfagent.install(self.db, 'nas', 'test')
        self.assertEqual(self.setups, [], 'nothing reached the host')
        self.assertEqual([a['state'] for a in sfagent.view(self.conn)], ['off'])
        self.install()
        with self.assertRaisesRegex(sfagent.AgentError, 'enrolled already'):
            sfagent.install(self.db, 'nas', 'test')
        with self.assertRaisesRegex(sfagent.AgentError, 'remove it before switching'):
            sfagent.switch(self.conn, 'nas', False, 'test')
        # asked directly, the program says the same
        rc, got = self.ask('enroll', image=IMAGE, image_signature=self.sign_image(IMAGE))
        self.assertEqual((rc, got['error']), (97, 'enrolled'))

    def test_stopped_stays_stopped_started_is_made_again_and_removed_forgets_the_key(self):
        self.install()
        fp = sfagent.get(self.conn, 'nas')['fingerprint']
        self.assertEqual(sfagent.lifecycle(self.db, 'nas', 'stop', 'test')['state'], 'stopped')
        self.assertEqual(self.host.calls('docker update'), ['docker update --restart no storageforge-agent'], 'its restart policy is taken off before it is stopped')
        self.assertFalse(sfagent.lifecycle(self.db, 'nas', 'status', 'test')['running'])
        n = len(self.host.calls('docker run'))
        self.assertEqual(sfagent.lifecycle(self.db, 'nas', 'start', 'test')['state'], 'running')
        self.assertEqual(len(self.host.calls('docker run')), n + 1)
        self.assertTrue(sfagent.lifecycle(self.db, 'nas', 'status', 'test')['running'])
        got = sfagent.remove(self.db, 'nas', 'test')
        self.assertEqual((got['state'], got['problems']), ('removed', []))
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual((row['fingerprint'], row['public_key'], row['counter']), (None, None, 1), 'the key is forgotten and the counter is kept')
        self.assertFalse((self.host.root / 'var/lib/storageforge-agent').exists())
        self.assertFalse((self.host.root / 'etc/sudoers.d/storageforge-agentctl').exists())
        self.assertIn(('agent.remove', 'ok'), self.audit())
        # enrolled again it is another agent, with another key, and its manifests go on counting
        self.install()
        row = sfagent.get(self.conn, 'nas')
        self.assertNotEqual(row['fingerprint'], fp)
        self.assertEqual(row['counter'], 2)

    def test_a_plugin_gets_what_its_signed_descriptor_declares_and_secrets_are_masked(self):
        self.install()
        descriptor, signature, by = self.plugin(needs='{"mounts":["/etc","/proc"],"namespaces":["pid"]}')
        got = sfagent.apply(self.db, 'nas', [(descriptor, signature, by)], actor='test')
        self.assertEqual((got['counter'], got['runtime']), (2, 'docker'))
        # the files come after the manifest that names them, as through the tunnel: before it, an agent takes them for tampering
        self.put_plugin(descriptor, signature)
        run = self.host.calls('docker run')[-1]
        root = self.host.root
        for must in (f'type=bind,src={root}/etc,dst=/host/etc,readonly,bind-recursive=disabled', f'type=bind,src={root}/proc,dst=/host/proc,readonly,bind-recursive=disabled',
                     '--pid host', '--network none', '--cap-drop ALL', '--tmpfs /host/etc/sudoers.d:ro,size=4k,mode=000',
                     'type=bind,src=/dev/null,dst=/host/etc/shadow,readonly', 'type=bind,src=/dev/null,dst=/host/etc/ssh/ssh_host_ed25519_key,readonly'):
            self.assertIn(must, run)
        self.assertNotIn('--cap-add', run)
        # and the agent, given the files, loads it: signed by the release key this build trusts (a signature ssh-keygen made)
        rc, report = self.agent_check()
        self.assertEqual((rc, report['counter'], [(p['name'], p['loaded']) for p in report['plugins']]), (0, 2, [('probe', True)]), report)
        self.assertEqual(self.audit()[-1], ('agent.apply', 'ok'))
        # a plugin taken out again takes its privileges with it
        sfagent.apply(self.db, 'nas', [], actor='test')
        self.assertNotIn('/host', self.host.calls('docker run')[-1])
        self.assertNotIn('--pid host', self.host.calls('docker run')[-1])

    def test_a_manifest_cannot_give_more_than_the_signer_declared_and_only_release_keys_make_code_official(self):
        self.install()
        row = sfagent.get(self.conn, 'nas')
        signer = self.signer()
        n = len(self.host.calls('docker run'))

        def apply(entries, sent, counter=5):
            text, sig = sfagent.manifest(signer, row['fingerprint'], MACHINE, counter, IMAGE, entries)
            return self.ask('apply', manifest=text, manifest_signature=sig, image_signature=self.sign_image(IMAGE), plugins=sent)
        descriptor, signature, _ = self.plugin(needs='{"mounts":["/srv"]}')
        entry = sfagent.plugin_entry(descriptor, 'release')
        sent = [{'descriptor': descriptor.decode(), 'signature': signature}]
        # the controller writes more into the manifest than the plugin's signer declared: the whole of /, a capability
        for more in ({'mounts': ['/']}, {'mounts': ['/srv'], 'capabilities': ['SYS_ADMIN']}, {}):
            rc, got = apply([entry | {'needs': more}], sent)
            self.assertEqual((rc, got['error']), (97, 'plugin'), more)
            self.assertIn('other privileges than its signed descriptor declares', got['why'])
        # the controller signs a descriptor itself, or sends one nobody signed
        own = deploy.sshsig(signer, descriptor, 'storageforge-plugin')
        for bad in (own, '', signature.replace('A', 'B', 1)):
            rc, got = apply([entry], [{'descriptor': descriptor.decode(), 'signature': bad}])
            self.assertEqual((rc, got['error']), (97, 'plugin'), bad[:40])
            self.assertIn('not signed by a release key', got['why'])
        # an operator's plugin on a host whose operator trusts no key of their own
        rc, got = apply([entry | {'signer': 'operator'}], sent)
        self.assertEqual((rc, got['error']), (97, 'plugin'))
        self.assertIn('not signed by an operator key of this host', got['why'])
        # a descriptor changed after it was signed, one that did not come, and one too many
        changed = descriptor.replace(b'/srv', b'/etc')
        rc, got = apply([sfagent.plugin_entry(changed, 'release')], [{'descriptor': changed.decode(), 'signature': signature}])
        self.assertEqual((rc, got['error']), (97, 'plugin'))
        self.assertEqual(apply([entry], [])[1]['error'], 'plugin')
        other, other_sig, _ = self.plugin(name='other')
        self.assertEqual(apply([entry], sent + [{'descriptor': other.decode(), 'signature': other_sig}])[1]['error'], 'plugin')
        # what no descriptor can ask for at all, even signed by the release key
        for needs in ('{"mounts":["/run/docker.sock"]}', '{"mounts":["/root/.ssh"]}', '{"mounts":["/dev/sda"]}', '{"capabilities":["SYS_MODULE"]}', '{"privileged":true}'):
            d, s, _ = self.plugin(needs=needs)
            rc, got = apply([{'name': 'probe', 'descriptor': hashlib.sha256(d).hexdigest(), 'signer': 'release', 'needs': json.loads(needs)}], [{'descriptor': d.decode(), 'signature': s}])
            self.assertEqual(rc, 97, needs)
        self.assertEqual(len(self.host.calls('docker run')), n, 'no container was made for any of it')
        self.assertEqual(self.ask('status')[1]['counter'], 1, 'and no counter moved')
        # the operator puts a key of their own on the host, by hand: then their plugin is taken, on that host
        operator = self.tmp / 'operator-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(operator)], check=True)
        (self.host.root / 'etc/storageforge-agent/operator_signers').write_text('me namespaces="storageforge-plugin" ' + operator.with_suffix('.pub').read_text())
        d, s, _ = self.plugin(name='mine', key=operator)
        rc, got = apply([sfagent.plugin_entry(d, 'operator')], [{'descriptor': d.decode(), 'signature': s}])
        self.assertEqual((rc, got.get('plugins')), (0, ['mine']), got)

    def test_an_old_manifest_played_back_and_a_manifest_for_another_host_are_refused(self):
        self.install()
        row = sfagent.get(self.conn, 'nas')
        signer = self.signer()
        image_sig = self.sign_image(IMAGE)

        def apply(counter, fp=row['fingerprint'], machine=MACHINE, now=None):
            text, sig = sfagent.manifest(signer, fp, machine, counter, IMAGE, [], now=now)
            return self.ask('apply', manifest=text, manifest_signature=sig, image_signature=image_sig), (text, sig)
        (rc, got), third = apply(3)
        self.assertEqual((rc, got['counter']), (0, 3))
        fourth = time.time()
        (rc, got), _ = apply(4, now=fourth)
        self.assertEqual(rc, 0)
        # the third again, with its good signature, in a new request
        rc, got = self.ask('apply', manifest=third[0], manifest_signature=third[1], image_signature=image_sig)
        self.assertEqual((rc, got['error']), (97, 'manifest'))
        self.assertIn('old one played back', got['why'])
        (rc, got), _ = apply(4, now=fourth)
        self.assertEqual(rc, 0, 'the very same manifest again is the same manifest')
        (rc, got), _ = apply(4, now=time.time() - 30)
        self.assertEqual(rc, 97, 'another manifest under a counter that was used')
        (rc, got), _ = apply(9, now=time.time() - 7200)
        self.assertIn('not signed a moment ago', got['why'])
        (rc, got), _ = apply(9, fp='SHA256:' + 'A' * 43)
        self.assertIn('another agent\'s key', got['why'])
        other = '1' * 32
        text, sig = sfagent.manifest(signer, row['fingerprint'], other, 9, IMAGE, [])
        rc, got = self.ask('apply', manifest=text, manifest_signature=sig, image_signature=image_sig)
        self.assertIn('another machine', got['why'])
        self.assertEqual(self.ask('status')[1]['counter'], 4)
        # the agent keeps a count of its own: a file put back by hand in its manifest folder is refused there too
        d = self.host.root / 'var/lib/storageforge-agent/manifest'
        seen = self.host.root / 'var/lib/storageforge-agent/state/manifest.seen'
        for _ in range(100):             # the agent that was started for the fourth writes its counter down as it starts
            if seen.exists() and seen.read_text().startswith('4 '):
                break
            time.sleep(0.05)
        self.assertTrue(seen.read_text().startswith('4 '))
        self.host.kill_agent()
        (d / 'manifest.json').write_text(third[0])
        (d / 'manifest.json.sig').write_text(third[1])
        rc, report = self.agent_check()
        self.assertEqual(rc, 1)
        self.assertIn('old one played back', report['problems'][0])
        # and storageforge-agentctl does not start a container for it
        rc, got = self.ask('start')
        self.assertEqual((rc, got['error']), (97, 'manifest'))

    def test_only_an_image_the_release_key_signed_is_run_whatever_the_controller_says(self):
        """The controller names the image, and a controller that was taken over would name its own. storageforge-agentctl runs none
        whose digest a release key did not sign, or a key the operator put on that host."""
        sfagent.switch(self.conn, 'nas', True, 'test')
        other = 'registry.example/storageforge-agent@sha256:' + 'b' * 64
        signer = self.signer()
        self.setup_host()
        good = self.sign_image(IMAGE)
        mine = self.tmp / 'not-the-release-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(mine)], check=True)
        for image, signature in ((other, good),                                                  # another image under the good image's signature
                                 (IMAGE, deploy.sshsig(signer, IMAGE.split('@')[1].encode() + b'\n', 'storageforge-agent-image')),     # signed by the controller itself
                                 (IMAGE, ssh_sign(mine, 'storageforge-agent-image', IMAGE.split('@')[1].encode() + b'\n')),           # by a key nobody trusts
                                 (IMAGE, ssh_sign(TARGET / 'release-key', 'storageforge-plugin', IMAGE.split('@')[1].encode() + b'\n')),   # by the release key, for another use
                                 (IMAGE, 'not a signature')):
            rc, got = self.ask('enroll', image=image, image_signature=signature)
            self.assertEqual((rc, got['error']), (97, 'image'), (image, signature[:40]))
            self.assertIn('not signed by a release key or by an operator key of this host', got['why'])
        self.assertEqual(self.host.calls('docker'), [], 'nothing was fetched')
        # the same through sfagent.py, with the controller set to an image its signature file is not for
        (self.tmp / 'agentdir/image.sig').write_text(good)
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': other}), self.assertRaisesRegex(sfagent.AgentError, 'not signed by a release key'):
            sfagent.install(self.db, 'nas', 'test')
        (self.tmp / 'agentdir/image.sig').unlink()
        with self.assertRaisesRegex(sfagent.AgentError, 'no signature of the agent image'):
            sfagent.install(self.db, 'nas', 'test')
        self.sign_image(IMAGE)
        self.conn.execute("UPDATE agents SET state = 'on' WHERE host = 'nas'")
        self.assertEqual(sfagent.install(self.db, 'nas', 'test')['state'], 'running')
        # an enrolled agent is not moved to another image by a manifest either
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': other}), self.assertRaisesRegex(sfagent.AgentError, 'not signed by a release key'):
            sfagent.apply(self.db, 'nas', [], actor='test')
        self.assertNotIn(other, ' '.join(self.host.calls('docker')))
        # but to one that is signed it is: that is an update
        self.sign_image(other)
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': other}):
            sfagent.apply(self.db, 'nas', [], actor='test')
        self.assertIn(f'{other} run', self.host.calls('docker run')[-1])
        self.assertEqual(sfagent.get(self.conn, 'nas')['image'], other)

    def test_what_a_host_answers_is_checked_before_it_is_believed(self):
        sfagent.switch(self.conn, 'nas', True, 'test')
        for answer in (b'', b'not json', b'[]', b'{"ok":"yes"}', b'x' * (sfagent.MAX_REPLY + 1)):
            with self.assertRaises(sfagent.AgentError):
                sfagent.read_reply(answer)
        real_send = sfagent._send

        def lying(v, conn, name, req, timeout):
            rc, out, err = real_send(v, conn, name, req, timeout)
            got = json.loads(out)
            if got.get('op') == 'enroll':        # the host says another key than the agent made, in a shape no key has
                got['public_key'] = 'ssh-ed25519 AAAA$(id) storageforge-agent'
                got['fingerprint'] = 'SHA256:what-the-host-would-like'
            return rc, json.dumps(got).encode(), err
        with mock.patch.object(sfagent, '_send', lying), self.assertRaisesRegex(sfagent.AgentError, 'not an agent key'):
            sfagent.install(self.db, 'nas', 'test')
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual((row['state'], row['fingerprint']), ('failed', None))
        self.assertEqual(self.audit()[-1], ('agent.install', 'failed'))


class NoRuntime(Base):
    """A host with no container runtime gets Podman, after the user is told."""
    RUNTIMES = ('apt-get',)

    def test_the_user_is_told_first_and_nothing_is_installed_until_they_say_so(self):
        got = self.install()
        self.assertEqual(got['state'], 'needs-podman')
        self.assertIn('Podman will be installed', got['message'])
        self.assertEqual(self.host.calls('apt-get'), [])
        self.assertEqual(sfagent.get(self.conn, 'nas')['state'], 'needs-podman')
        self.assertIsNone(sfagent.get(self.conn, 'nas')['fingerprint'])
        # asked directly without the word, the program refuses too
        rc, answer = self.ask('enroll', image=IMAGE, image_signature=self.sign_image(IMAGE))
        self.assertEqual((rc, answer['error']), (97, 'no-runtime'))
        got = sfagent.install(self.db, 'nas', 'test', install_podman=True)
        self.assertEqual((got['state'], got['runtime']), ('running', 'podman-rootless'))
        self.assertIn('Podman was installed', got['notes'])
        self.assertEqual(self.host.calls('apt-get'), ['apt-get install -y --no-install-recommends podman uidmap'])
        # under Podman it runs without root: sfagent runs podman itself, and is itself inside
        runs = [c for c in self.host.calls('podman run')]
        self.assertTrue(runs)
        for must in ('--userns keep-id', '--cap-drop ALL', '--read-only', '--restart always', f'--user {os.getuid()}:{os.getgid()}'):
            self.assertIn(must, runs[-1])
        self.assertTrue(all(c.startswith('runuser -u sfagent -- env HOME=') for c in self.host.calls('runuser')))
        self.assertEqual(len(self.host.calls('runuser')), len(self.host.calls('podman')), 'every podman call was made as sfagent')
        self.assertIn(f'sfagent:1065536:65536', (self.host.root / 'etc/subuid').read_text())
        self.assertEqual(self.host.calls('loginctl'), ['loginctl enable-linger sfagent'] * 2)

    def test_a_plugin_that_reads_the_journal_puts_sfagent_in_that_group_and_out_again(self):
        self.install(install_podman=True)
        descriptor, signature, by = self.plugin(needs='{"groups":["systemd-journal"],"mounts":["/var/log/journal"]}')
        sfagent.apply(self.db, 'nas', [(descriptor, signature, by)], actor='test')
        self.assertEqual(self.host.calls('gpasswd'), ['gpasswd -a sfagent systemd-journal'])
        self.assertIn('--group-add keep-groups', self.host.calls('podman run')[-1])
        sfagent.apply(self.db, 'nas', [], actor='test')
        self.assertEqual(self.host.calls('gpasswd')[-1], 'gpasswd -d sfagent systemd-journal', 'a group no plugin reads as any more is given back')
        # a capability cannot be had without root: for that plugin Podman is run as root, and only then
        descriptor, signature, by = self.plugin(needs='{"capabilities":["SYS_RAWIO"],"devices":["disks"]}')
        n = len(self.host.calls('podman run'))
        got = sfagent.apply(self.db, 'nas', [(descriptor, signature, by)], actor='test')
        self.assertEqual(got['runtime'], 'podman', 'the disks plugin takes Podman as root, and the process inside is still sfagent')
        run = self.host.calls('podman run')[-1]
        self.assertIn('--cap-add SYS_RAWIO', run)
        self.assertIn('--device /dev/sda:/dev/sda:r', run)
        self.assertIn(f'--user {os.getuid()}:{os.getgid()}', run)
        self.assertNotIn('keep-id', run)
        self.assertGreater(len(self.host.calls('podman run')), n)


class LxcOnly(Base):
    """A host with LXC and no Docker or Podman gets the agent in LXC, and is never asked to take Podman."""
    RUNTIMES = ('lxc',)

    def test_the_agent_runs_unprivileged_in_lxc_and_podman_is_not_offered(self):
        got = self.install()
        self.assertEqual((got['state'], got['runtime']), ('running', 'lxc'))
        self.assertEqual(self.host.calls('apt-get') + self.host.calls('podman'), [])
        conf = (self.host.root / 'var/lib/storageforge-agent/ctl/lxc.conf').read_text()
        uid, gid = os.getuid(), os.getgid()
        for must in (f'lxc.idmap = u 10003 {uid} 1', f'lxc.idmap = g 10003 {gid} 1', 'lxc.idmap = u 0 1000000 10003', 'lxc.rootfs.options = ro', 'lxc.cap.keep = none',
                     'lxc.no_new_privs = 1', 'lxc.apparmor.allow_nesting = 0', 'lxc.net.0.type = empty', 'lxc.init.uid = 10003',
                     f'lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp'):
            self.assertIn(must, conf)
        self.assertIn(f'lxc-create -n storageforge-agent -f {self.host.root}/var/lib/storageforge-agent/ctl/lxc.conf -t oci -- --url docker://{IMAGE}', self.host.calls('lxc-create'))
        self.assertTrue(sfagent.lifecycle(self.db, 'nas', 'status', 'test')['running'])
        # a plugin LXC cannot serve is refused with the reason, and the agent that runs is left as it is
        descriptor, signature, by = self.plugin(needs='{"capabilities":["SYS_ADMIN"],"mounts":["/"]}')
        with self.assertRaisesRegex(sfagent.AgentError, 'unprivileged LXC container cannot be given'):
            sfagent.apply(self.db, 'nas', [(descriptor, signature, by)], actor='test')
        self.assertTrue(sfagent.lifecycle(self.db, 'nas', 'status', 'test')['running'])
        # one it can: the mount read-only, one filesystem, with the secrets masked
        descriptor, signature, by = self.plugin(needs='{"mounts":["/etc"]}')
        sfagent.apply(self.db, 'nas', [(descriptor, signature, by)], actor='test')
        conf = (self.host.root / 'var/lib/storageforge-agent/ctl/lxc.conf').read_text()
        self.assertIn(f'lxc.mount.entry = {self.host.root}/etc host/etc none bind,ro 0 0', conf)
        self.assertIn('lxc.mount.entry = /dev/null host/etc/shadow none bind,ro 0 0', conf)
        self.assertTrue((self.host.root / 'var/lib/lxc/storageforge-agent/rootfs/host/etc').is_dir())
        sfagent.lifecycle(self.db, 'nas', 'stop', 'test')
        self.assertIn('lxc.start.auto = 0', (self.host.root / 'var/lib/lxc/storageforge-agent/config').read_text())


class Store(unittest.TestCase):
    """The table and the routes, on SQLite and PostgreSQL. Nothing here reaches a host or needs the programs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'STORAGEFORGE_DATA_DIR': str(self.tmp / 'data')})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop('STORAGEFORGE_AGENT_IMAGE', None)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        vault.Vault(self.db, self.conn, SECRET).init()
        for name in ('nas', 'pc'):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, machine_id, inventory_json) VALUES (:h, :h, 22, :m, '{}')", {'h': name, 'm': MACHINE})
        users.create(self.conn, 'root', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self, name='root'):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        return c

    def test_the_switch_is_off_by_default_and_per_host(self):
        self.assertEqual([(a['host'], a['enabled'], a['state']) for a in sfagent.view(self.conn)], [('nas', False, 'off'), ('pc', False, 'off')])
        self.assertEqual(sfagent.switch(self.conn, 'nas', True, 'test')['state'], 'on')
        self.assertEqual([(a['host'], a['enabled']) for a in sfagent.view(self.conn)], [('nas', True), ('pc', False)])
        self.assertEqual(sfagent.switch(self.conn, 'nas', False, 'test')['state'], 'off')
        with self.assertRaises(LookupError):
            sfagent.switch(self.conn, 'nowhere', True, 'test')
        self.conn.execute("INSERT INTO network_devices (name, platform, address, port, created_at) VALUES ('pc', 'routeros', '10.0.0.9', 22, 1)")
        with self.assertRaisesRegex(sfagent.AgentError, 'stay agentless'):
            sfagent.switch(self.conn, 'pc', True, 'test')

    def test_the_counter_only_goes_up_and_a_manifest_names_one_agent_on_one_machine(self):
        key = ed25519.Ed25519PrivateKey.generate()
        text, sig = sfagent.manifest(key, 'SHA256:' + 'A' * 43, MACHINE, 3, IMAGE, [{'name': 'b', 'descriptor': 'd' * 64, 'signer': 'release', 'needs': {}},
                                                                                     {'name': 'a', 'descriptor': 'e' * 64, 'signer': 'release', 'needs': {}}], now=1000)
        body = json.loads(text)
        self.assertEqual((body['counter'], body['issued'], body['machine'], [p['name'] for p in body['plugins']]), (3, 1000, MACHINE, ['a', 'b']))
        # the signature is one ssh-keygen accepts, in the manifest's own namespace and no other
        pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        (self.tmp / 'signers').write_text(sfagent.signers_line(pub) + '\n')
        (self.tmp / 'sig').write_text(sig)

        def verify(namespace):
            return subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(self.tmp / 'signers'), '-I', 'controller', '-n', namespace, '-s', str(self.tmp / 'sig')],
                                  input=text.encode(), capture_output=True).returncode
        self.assertEqual(verify(sfagent.NS_MANIFEST), 0)
        self.assertNotEqual(verify(sfagent.NS_REQUEST), 0)
        for bad in (lambda: sfagent.manifest(key, 'SHA256:x', MACHINE, 0, IMAGE, []), lambda: sfagent.manifest(key, 'SHA256:x', 'host', 1, IMAGE, []),
                    lambda: sfagent.manifest(key, 'SHA256:x', MACHINE, 1, 'storageforge-agent:latest', [])):
            with self.assertRaises(ValueError):
                bad()
        entry = sfagent.plugin_entry(b'{"name":"logs","needs":{"mounts":["/var/log/journal"]}}', 'release')
        self.assertEqual((entry['name'], entry['needs']), ('logs', {'mounts': ['/var/log/journal']}))
        for descriptor, signer in ((b'{"name":"logs"}', 'controller'), (b'{"name":"../x"}', 'release'), (b'[]', 'release')):
            with self.assertRaises(ValueError):
                sfagent.plugin_entry(descriptor, signer)

    def test_the_image_is_named_by_digest_or_not_at_all(self):
        with self.assertRaisesRegex(sfagent.AgentError, 'STORAGEFORGE_AGENT_IMAGE is not set'):
            sfagent.agent_image()
        for bad in ('storageforge-agent:latest', 'storageforge-agent', '--privileged@sha256:' + 'a' * 64, 'x@sha256:abc'):
            with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': bad}), self.assertRaises(sfagent.AgentError):
                sfagent.agent_image()
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': IMAGE}):
            self.assertEqual(sfagent.agent_image(), IMAGE)
        with self.assertRaisesRegex(sfagent.AgentError, 'x86_64 and arm64'):
            sfagent.agentctl_program('riscv64')

    def test_the_routes_take_an_admin_and_a_fresh_password_and_are_audited(self):
        c = self.client()
        got = c.get('/api/agents').get_json()
        self.assertEqual([(a['host'], a['state']) for a in got['agents']], [('nas', 'off'), ('pc', 'off')])
        self.assertIsNone(got['image'])
        r = c.put('/api/agents/nas', json={'enabled': True})
        self.assertEqual((r.status_code, r.get_json()['state']), (200, 'on'))
        self.assertIn('last scan found no Docker or Podman', r.get_json()['hint']['text'])
        self.assertEqual(c.put('/api/agents/nowhere', json={'enabled': True}).status_code, 404)
        # installing: refused here, before anything is started, for what can be known here
        r = c.post('/api/agents/pc/install', json={})
        self.assertEqual(r.status_code, 409)
        self.assertIn('switched off for pc', r.get_json()['error'])
        r = c.post('/api/agents/nas/install', json={})
        self.assertIn('no deploy access yet', r.get_json()['error'])
        deploy.set_access(self.conn, 'nas', 'ready', '', 'test')
        r = c.post('/api/agents/nas/install', json={})
        self.assertIn('STORAGEFORGE_AGENT_IMAGE is not set', r.get_json()['error'])
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_IMAGE': IMAGE, 'STORAGEFORGE_AGENT_DIR': str(self.tmp)}):
            self.assertIn('no signature of the agent image', c.post('/api/agents/nas/install', json={}).get_json()['error'])
        r = c.post('/api/agents/nas/status', json={})
        self.assertEqual(r.status_code, 409)
        self.assertIn('no agent enrolled', r.get_json()['error'])
        self.assertEqual(c.delete('/api/agents/pc').status_code, 409)
        actions = [a for (a,) in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'agent.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['agent.switch', 'agent.status'])
        # a stale password is asked for again, and a viewer may look and not touch
        with c.session_transaction() as s:
            s['auth_at'] = 0
        self.assertTrue(c.put('/api/agents/nas', json={'enabled': False}).get_json().get('reauth'))
        v = self.client('viewer')
        self.assertEqual(v.get('/api/agents').status_code, 200)
        for method, path in (('PUT', '/api/agents/nas'), ('POST', '/api/agents/nas/install'), ('POST', '/api/agents/nas/stop'), ('DELETE', '/api/agents/nas')):
            self.assertEqual(v.open(path, method=method, json={}).status_code, 403, path)

    def test_a_request_is_what_the_program_reads(self):
        key = ed25519.Ed25519PrivateKey.generate()
        req = sfagent.request(key, 'enroll', MACHINE, now=1000, nonce='ab' * 16, image=IMAGE, install_podman=False)
        head, plen, slen, rest = req.split(b'\n', 3)
        self.assertEqual(head, b'STORAGEFORGE-AGENTCTL 1')
        payload, sig = rest[:int(plen)], rest[int(plen):]
        self.assertEqual(len(sig), int(slen))
        self.assertEqual(json.loads(payload), {'op': 'enroll', 'machine': MACHINE, 'issued': 1000, 'nonce': 'ab' * 16, 'image': IMAGE})
        for bad in (lambda: sfagent.request(key, 'status', 'nas'), lambda: sfagent.request(key, 'status', MACHINE, nonce='x')):
            with self.assertRaises(ValueError):
                bad()
        self.assertEqual(sfagent.fingerprint('ssh-ed25519 ' + base64.b64encode(b'\0' * 51).decode()), 'SHA256:' + base64.b64encode(hashlib.sha256(b'\0' * 51).digest()).decode().rstrip('='))


def registry_image():
    """A registry image that is already on this machine, or None: a test pulls nothing from the internet."""
    if not shutil.which('docker'):
        return None
    for name in ('registry:2', 'registry:3'):
        if subprocess.run(['docker', 'image', 'inspect', name], capture_output=True).returncode == 0:
            return name
    return None


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the agent (CI builds it)')
@unittest.skipUnless(registry_image(), 'needs Docker and a registry image that is already here (docker pull registry:2)')
class RealDocker(Base):
    """The same road with nothing standing in for the runtime: the real Docker, the agent's real image from the Dockerfile's `agent`
    stage, pulled by its digest from a registry started for the test. The containers and the image it makes are removed after."""
    RUNTIMES = ()

    def setUp(self):
        super().setUp()
        tag = f'sfagent-test-{os.getpid()}'
        self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', 'storageforge-agent', tag], capture_output=True))
        p = subprocess.run(['docker', 'build', '-q', '--target', 'agent', '-t', tag, str(ROOT)], capture_output=True, text=True, timeout=1500)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.addCleanup(lambda: subprocess.run(['docker', 'image', 'rm', '-f', tag], capture_output=True))
        subprocess.run(['docker', 'run', '-d', '--name', tag, '-p', '127.0.0.1::5000', registry_image()], check=True, capture_output=True)
        port = subprocess.run(['docker', 'port', tag, '5000/tcp'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1]
        remote = f'127.0.0.1:{port}/storageforge-agent'
        self.addCleanup(lambda: subprocess.run(['docker', 'image', 'rm', '-f', remote], capture_output=True))
        subprocess.run(['docker', 'tag', tag, remote], check=True)
        for _ in range(50):
            p = subprocess.run(['docker', 'push', '-q', remote], capture_output=True, text=True)
            if p.returncode == 0:
                break
            time.sleep(0.2)
        self.assertEqual(p.returncode, 0, p.stderr)
        digest = subprocess.run(['docker', 'image', 'inspect', '--format', '{{index .RepoDigests 0}}', remote], capture_output=True, text=True).stdout.strip()
        self.image = digest
        self.assertRegex(self.image, sfagent.IMAGE_RE.pattern)
        self.addCleanup(lambda: subprocess.run(['docker', 'image', 'rm', '-f', self.image], capture_output=True))
        os.environ['STORAGEFORGE_AGENT_IMAGE'] = self.image
        self.sign_image(self.image)
        # the real docker, and nothing else that could be taken for a runtime
        (self.host.bin / 'docker').symlink_to(shutil.which('docker'))
        # the image carries a program built with the repository's signers, which trust no key yet; the checks from outside go on

    def inspect(self, fmt):
        return subprocess.run(['docker', 'inspect', '--format', fmt, 'storageforge-agent'], capture_output=True, text=True).stdout.strip()

    def test_the_real_image_runs_as_sfagent_read_only_with_no_capability_and_no_network(self):
        got = self.install()
        self.assertEqual((got['state'], got['runtime']), ('running', 'docker'))
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual(row['public_key'], (self.host.root / 'var/lib/storageforge-agent/state/agent_key.pub').read_text().strip())
        self.assertEqual(self.inspect('{{.State.Running}} {{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}}'),
                         f'true {os.getuid()}:{os.getgid()} true none false')
        self.assertEqual(self.inspect('{{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}} {{.HostConfig.SecurityOpt}}'), '[ALL] [] [no-new-privileges]')
        self.assertEqual(self.inspect('{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.PidMode}}'), 'unless-stopped|', 'its own process table, not the host\'s')
        mounts = json.loads(self.inspect('{{json .Mounts}}'))
        self.assertEqual(sorted((m['Destination'], m['RW']) for m in mounts),
                         [('/etc/storageforge-agent', False), ('/var/lib/storageforge-agent/manifest', False), ('/var/lib/storageforge-agent/state', True)])
        self.assertNotIn('docker.sock', json.dumps(mounts))
        # the process, as the kernel has it: not root, no capability at all, and it cannot gain any
        pid = self.inspect('{{.State.Pid}}')
        status = Path(f'/proc/{pid}/status').read_text()
        fields = dict(line.split(':\t', 1) for line in status.splitlines() if ':\t' in line)
        self.assertEqual(fields['Uid'].split()[0], str(os.getuid()))
        self.assertEqual((int(fields['CapEff'], 16), int(fields['CapPrm'], 16), int(fields['CapBnd'], 16), fields['NoNewPrivs']), (0, 0, 0, '1'))
        logs = ''
        for _ in range(50):
            logs = subprocess.run(['docker', 'logs', 'storageforge-agent'], capture_output=True, text=True).stderr
            if 'manifest 1' in logs:
                break
            time.sleep(0.1)
        self.assertIn('manifest 1: 0 of 0 plugins loaded', logs)
        # nothing was written into the container but its state folder
        self.assertEqual(subprocess.run(['docker', 'diff', 'storageforge-agent'], capture_output=True, text=True).stdout.strip(), '')
        # there is no shell and no other program in it to run
        for program in ('sh', '/bin/sh', 'ls', 'ssh'):
            self.assertNotEqual(subprocess.run(['docker', 'exec', 'storageforge-agent', program, '-c', 'true'], capture_output=True).returncode, 0, program)
        # a plugin's mount, by the real runtime: read-only, one filesystem, the secrets under it masked
        (self.host.root / 'etc/storageforge-agent/operator_signers').write_text('me namespaces="storageforge-plugin" ' + (TARGET / 'release-key.pub').read_text())
        descriptor, signature, _ = self.plugin(needs='{"mounts":["/etc"]}')
        sfagent.apply(self.db, 'nas', [(descriptor, signature, 'operator')], actor='test')
        mounts = {m['Destination']: m for m in json.loads(self.inspect('{{json .Mounts}}'))}
        self.assertEqual((mounts['/host/etc']['RW'], mounts['/host/etc']['Source']), (False, str(self.host.root / 'etc')))
        self.assertEqual(mounts['/host/etc/shadow']['Source'], '/dev/null')
        self.assertEqual(mounts['/host/etc/ssh/ssh_host_ed25519_key']['Source'], '/dev/null')
        self.assertIn('/host/etc/sudoers.d', json.loads(self.inspect('{{json .HostConfig.Tmpfs}}')))
        self.assertEqual(self.inspect('{{.State.Running}}'), 'true')
        # stopped, it stays stopped; removed, it is gone
        sfagent.lifecycle(self.db, 'nas', 'stop', 'test')
        self.assertEqual(self.inspect('{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}'), 'false no')
        self.assertFalse(sfagent.lifecycle(self.db, 'nas', 'status', 'test')['running'])
        sfagent.lifecycle(self.db, 'nas', 'start', 'test')
        self.assertEqual(self.inspect('{{.State.Running}}'), 'true')
        sfagent.remove(self.db, 'nas', 'test')
        self.assertEqual(subprocess.run(['docker', 'inspect', 'storageforge-agent'], capture_output=True).returncode, 1)


if __name__ == '__main__':
    unittest.main()
