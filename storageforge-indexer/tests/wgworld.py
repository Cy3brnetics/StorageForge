"""Real WireGuard for the tests, without root: a small site of machines that are network namespaces on one LAN.

Every machine is a network namespace inside one user namespace, with an `eth0` on a bridge that stands for the LAN and a folder of
its own that stands for /etc/wireguard. `wg`, `ip` and `wg-quick` are the real ones and so is the kernel's WireGuard, so a key that
is wrong, a peer that is missing or an address on the wrong key stops the traffic here as it would between real hosts.

    WORKS                      whether this machine can do it at all (the tools, and WireGuard in the kernel)
    Machines(case, hosts)      hosts: [(name, LAN address)]
      .run(name, script)       bash on that machine
      .step(task)              one plan task on its host: the step function exactly as the plan script has it
      .reading(name)           what a scan's WireGuard lines read there, parsed as a scan parses them
      .ping(name, address)     whether that machine reaches the address
      .private_keys()          every private key any machine holds, to look for where none may be
"""
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from storageforge_index import changes, inframeasure, steps_infra

USERNS = ['unshare', '--user', '--map-root-user']
PRELUDE = ('ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }; doing() { echo "changed: $*"; }; missing() { echo "missing: $*"; }\n'
           'act() { if ((!APPLY)); then missing "would: $*"; return 1; fi; doing "$*"; }; try() { "$@" || { conflict "failed: $*" >&2; return 1; }; }; durable() { :; }\n')
# the lines a scan runs for WireGuard, taken from the scan's own script
READ = 'try() { timeout 30 "$@" 2>/dev/null || :; }; has() { command -v "$1" >/dev/null; }\n' + re.search(r'^sec wireguard\n(.*?)^sec ', inframeasure.BODY, re.M | re.S)[1]


def tool(name):
    return shutil.which(name)


def _works() -> bool:
    if not all(tool(t) for t in ('wg', 'wg-quick', 'ip', 'unshare', 'nsenter', 'ping')):
        return False
    try:
        return subprocess.run(USERNS + ['--net', 'sh', '-c', 'ip link add sf0 type wireguard && wg show sf0 public-key && ip link add br0 type bridge && ip link add v0 type veth peer name v1'],
                              capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


WORKS = _works()
NEEDS = 'needs wg, wg-quick, ip, ping, unshare and nsenter, and WireGuard, bridges and veth pairs in the kernel'


class Machines:
    """wg-quick is called through two lines that hand it the file in the machine's own folder, and systemctl through four that call
    wg-quick, because neither /etc/wireguard nor the system manager can be used from a test."""

    def __init__(self, case, hosts):
        self.case, self.root = case, Path(tempfile.mkdtemp())
        case.addCleanup(shutil.rmtree, self.root, True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'wg-quick').write_text(f'#!/bin/bash\ncase $1 in up|down|save) exec {tool("wg-quick")} "$1" "$SF_WG_DIR/$2.conf";; esac\n')
        (self.bin / 'systemctl').write_text('#!/bin/bash\nunit=${@: -1}; iface=${unit#wg-quick@}\ncase "$1" in enable) wg-quick up "$iface";; disable|stop) wg-quick down "$iface";; esac\n')
        for f in self.bin.iterdir():
            f.chmod(0o755)
        self.holders, self.said, self.lan_of = {}, [], {}
        self.world = self._hold(USERNS + ['sleep', '900'])
        self.holders['(lan)'] = self._hold(self._in(self.world, net=False) + ['unshare', '--net', 'sleep', '900'])
        self._must(self.run('(lan)', 'ip link add br0 type bridge && ip link set br0 up'))
        for name, address in hosts:
            self.add(name, address)

    def _hold(self, argv):
        """A process that holds a namespace open. It is ready when it has become the sleep: before that it is still on its way in."""
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.case.addCleanup(p.wait)
        self.case.addCleanup(p.kill)
        for _ in range(100):
            try:
                if Path(f'/proc/{p.pid}/comm').read_text().strip() == 'sleep':
                    return p
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError('the namespace did not come up')

    @staticmethod
    def _in(holder, net=True):
        return ['nsenter', '-t', str(holder.pid), '--user', *(['--net'] if net else []), '--preserve-credentials']

    def _must(self, ran):
        self.case.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        return ran

    def add(self, name, address):
        """A machine on the LAN at that address."""
        self.holders[name] = self._hold(self._in(self.world, net=False) + ['unshare', '--net', 'sleep', '900'])
        self.lan_of[name] = address
        port = f'v{len(self.lan_of)}'
        self._must(self.run('(lan)', f'ip link add {port} type veth peer name eth0 netns /proc/{self.holders[name].pid}/ns/net && ip link set {port} master br0 up'))
        self._must(self.run(name, f'ip link set lo up && ip addr add {shlex.quote(address)}/24 dev eth0 && ip link set eth0 up'))

    def keys(self, name) -> Path:
        return self.root / name / 'wireguard'

    def run(self, name, script, **env):
        ran = subprocess.run(self._in(self.holders[name]) + ['bash', '-c', script], capture_output=True, text=True, timeout=60,
                             env={'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_WG_DIR': str(self.keys(name)), **env})
        self.said.append(ran.stdout + ran.stderr)
        return ran

    def step(self, task, apply=True) -> str:
        """Run one plan task on its host: the step function as the plan script has it, with the words the plan would give it."""
        t = changes.normalize({'name': 'p', 'tasks': [task]})['tasks'][0]
        fn = 't_' + t['type'].replace('-', '_')
        body = re.search(rf'^{fn}\(\) \{{.*?^\}}$', steps_infra.BASH, re.M | re.S)[0]
        call = ' '.join(shlex.quote(str(t['params'].get(a) or '')) for a in changes.ARGS[t['type']])
        ran = self.run(t['host'], f'set -euo pipefail\nAPPLY={int(apply)}\n{PRELUDE}{body}\n{fn} {call}\n')
        self.case.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        return ran.stdout

    def reading(self, name) -> list:
        return inframeasure.parse_wireguard(self.run(name, READ).stdout.splitlines())

    def ping(self, name, address) -> bool:
        return self.run(name, f'ping -c 1 -W 1 {shlex.quote(address)}').returncode == 0

    def private_keys(self) -> set:
        """Every private key on any machine: the key files, and any a configuration file holds."""
        found = set()
        for f in self.root.glob('*/wireguard/*'):
            text = f.read_text()
            found |= {text.strip()} if '.key' in f.name or f.name == 'by-hand' else set(re.findall(r'^PrivateKey\s*=\s*(\S+)', text, re.M))
        return {k for k in found if k}
