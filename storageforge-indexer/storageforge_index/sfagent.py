"""The controller's side of the optional agent (roadmap section 11.1; the programs are agent/, in Rust; docs/agent.md).

    controller ──signed deploy, once──► host: the setup script, with storageforge-agentctl on its stdin
        accounts sfagent (the agent) and storageforge-agentctl (who manages it), one sudoers line, the controller's key pinned
    controller ──ssh storageforge-agentctl@host──► sudo -n /usr/local/sbin/storageforge-agentctl   (whatever ssh asks for)
        a signed request on stdin: preflight, enroll, apply, start, stop, restart, status, remove. One line of JSON comes back.
    vault: storageforge-agentctl       (ed25519) logs in as storageforge-agentctl, which can start nothing but that program
    vault: storageforge-agent-signing  (ed25519) signs each request and each host's manifest, in two namespaces
    no key here signs code: plugins and the agent's image are signed by the release key (or an operator's own, kept off the
    controller), and the controller only carries those signatures

SSH stays the base. The agent is switched on per host and is off unless someone switched it on; a host without it keeps every
feature. Setting it up goes through the deploy access the host already has, which is the pinned SSH connection, and the agent's
public key is read back over that same connection and pinned here. From then on only that key is the agent of that host.

What is built here is the lifecycle, enrollment, and what the tunnel needs from the web app's side: `apply` names the receiver the
agent dials (its address and its key, which the host pins) in the signed request, and leaves the signed manifest and the signed
plugin descriptors in agent_deliveries, where the receiver (agentreceiver.py, a process of its own) hands them to the agent at the
start of every session. The web app never speaks to an agent: it signs, and the agent checks.

Everything a host answers is a claim. It is read as one line of JSON of limited size, every field is checked for its shape before
it is stored, the fingerprint of the agent's key is worked out here and never taken from the answer, and text from a host
reaches a page only through the UI's own escaping.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import agenttunnel, deploy
from .db import Database
from .remote import REFUSE_APPLIANCE, Transport, child_env
from .runner import connect_address, ephemeral_agent, known_hosts_path
from .vault import AuditLog, EnclaveKey, Vault, actor_name

SIGNING_KEY = 'storageforge-agent-signing'
LOGIN_KEY = 'storageforge-agentctl'
MANAGER = 'storageforge-agentctl'               # the account that manages the agent over SSH; never in docker, lxd or incus-admin
AGENT_USER = 'sfagent'                          # the account the agent runs as
AGENTCTL = '/usr/local/sbin/storageforge-agentctl'
NS_REQUEST = 'storageforge-agentctl'
NS_MANIFEST = 'storageforge-agent-manifest'
ROOT_GROUPS = ('docker', 'lxd', 'incus-admin')   # root on a host by another name
RUNTIMES = ('docker', 'podman-rootless', 'podman', 'lxc', 'incus', 'pct')
OPS = ('preflight', 'enroll', 'apply', 'start', 'stop', 'restart', 'status', 'remove')
STATES = ('off', 'on', 'needs-podman', 'running', 'stopped', 'removed', 'failed')
MAX_REPLY = 64 * 1024
REFUSED = 97                                    # storageforge-agentctl's exit code for a request it would not act on
IMAGE_RE = re.compile(r'[a-z0-9][a-z0-9._:/-]{0,199}@sha256:[0-9a-f]{64}')
PUBLIC_RE = re.compile(r'ssh-ed25519 ([A-Za-z0-9+/]{68}) storageforge-agent')
MACHINE_RE = re.compile(r'[0-9a-f]{32}')
PODMAN_NOTICE = ('This host has no container runtime. The agent needs one, so Podman will be installed with the host\'s own package '
                 'manager, and the agent will run under it without root. Nothing is installed until you say so: start the '
                 'install again with Podman allowed.')


class AgentError(RuntimeError):
    """Something the agent's setup could not do. code is storageforge-agentctl's own word for it where it gave one."""

    def __init__(self, text: str, code: str | None = None):
        super().__init__(text)
        self.code = code


# ── what goes on the host ───────────────────────────────────────────
# No apostrophes: the script text is checked for values that could end a quoted word. The values put in are the quoted ones below.
# The program arrives on stdin (a signed deploy) or is named as the first argument (by hand), and is installed only when it is the
# one this script was written for, by size and sha256.
SETUP = r"""set -euo pipefail
export LC_ALL=C
R=
if ((EUID != 0)); then     # only the unit tests, which give it a folder to treat as /: as root neither variable is read
  R=${STORAGEFORGE_AGENT_SETUP_ROOT:?this setup runs as root}
else
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
fi
%(refuse)s
M=%(manager)s A=%(agent)s BIN=%(agentctl)s
SIZE=%(size)s SHA=%(sha)s ACCEPT=%(accept)s
refuse() { local code=$1; shift; echo "refused: $*" >&2; exit "$code"; }
own() { if ((EUID == 0)); then chown "$@"; fi; }
groups_of() { id -nG "$1" 2>/dev/null | tr " " "\n"; }
for c in useradd usermod install sha256sum visudo id mktemp head wc; do
  command -v "$c" >/dev/null 2>&1 || { echo "$c is missing: the agent needs a full userland and sudo (on Alpine: apk add shadow coreutils sudo)" >&2; exit 3; }
done
# The user that manages the agent must not hold a runtime by another road: these groups are root on this host, and then the one
# sudoers line below limits nothing. Checked before anything is made.
for u in "$M" "$A"; do
  if id "$u" >/dev/null 2>&1; then
    for g in %(root_groups)s; do
      if groups_of "$u" | grep -qx "$g"; then
        refuse 5 "$u is in the $g group, which is root on this host. Take it out of that group (gpasswd -d $u $g) and set the agent up again"
      fi
    done
  fi
done
if id "$A" >/dev/null 2>&1; then
  for g in sudo wheel admin root; do
    if groups_of "$A" | grep -qx "$g"; then refuse 5 "$A is in the $g group. The agent runs as an account that can become nothing else"; fi
  done
fi
tmp=$(mktemp)
trap "rm -f \"$tmp\"" EXIT
if [[ -n ${1:-} ]]; then head -c $((SIZE + 1)) -- "$1" >"$tmp"; else head -c $((SIZE + 1)) >"$tmp"; fi
[[ $(wc -c <"$tmp") -eq $SIZE ]] || refuse 6 "the program that arrived is not the size this setup was written for"
[[ $(sha256sum <"$tmp" | cut -c1-64) == "$SHA" ]] || refuse 6 "the program that arrived is not the one this setup was written for"
# the pinned controller: a key that changes is taken only when a person said so
signers=$R/etc/storageforge-agent/controller_signers
line=%(signers)s
if [[ -s $signers && $(cat "$signers") != "$line" && $ACCEPT != yes ]]; then
  refuse 7 "this host has another controller pinned for its agent. A key that changes is taken only when a person accepts it: set the agent up again with the new key accepted, or remove the agent first"
fi
nologin=/usr/sbin/nologin; [[ -x $nologin ]] || nologin=/sbin/nologin
if ! id "$A" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/storageforge-agent/home --shell "$nologin" --comment "StorageForge agent" "$A"
  echo "created user $A"
fi
if ! id "$M" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/storageforge-agent/ctl-home --shell /bin/sh --comment "StorageForge agent control" "$M"
  echo "created user $M"
fi
usermod -p "*" "$M"            # no password, but not locked: sshd without PAM refuses key logins to locked accounts
install -d -m 0755 "$R/etc/storageforge-agent" "$R/var/lib/storageforge-agent" "$R/var/lib/storageforge-agent/manifest" "$R/usr/local/sbin"
install -d -m 0700 "$R/var/lib/storageforge-agent/ctl" "$R/var/lib/storageforge-agent/state" "$R/var/lib/storageforge-agent/home"
install -d -m 0755 "$R/var/lib/storageforge-agent/ctl-home" "$R/var/lib/storageforge-agent/ctl-home/.ssh"
own root:root "$R/etc/storageforge-agent" "$R/var/lib/storageforge-agent" "$R/var/lib/storageforge-agent/manifest" "$R/var/lib/storageforge-agent/ctl" \
  "$R/var/lib/storageforge-agent/ctl-home" "$R/var/lib/storageforge-agent/ctl-home/.ssh"
own "$A:$A" "$R/var/lib/storageforge-agent/state" "$R/var/lib/storageforge-agent/home"
printf "%%s\n" "$line" >"$signers.new"
chmod 0644 "$signers.new"; own root:root "$signers.new"; mv "$signers.new" "$signers"
install -m 0755 "$tmp" "$R$BIN.new"
own root:root "$R$BIN.new"; mv "$R$BIN.new" "$R$BIN"
# the key that logs in can start storageforge-agentctl and nothing else, whatever ssh asks for
keys=$R/var/lib/storageforge-agent/ctl-home/.ssh/authorized_keys
printf "restrict,command=\"sudo -n %%s\" %%s\n" "$BIN" %(login)s >"$keys.new"
chmod 0644 "$keys.new"; own root:root "$keys.new"; mv "$keys.new" "$keys"
# the one sudoers line: this program, with no arguments, and nothing else
sudo_tmp=$(mktemp)
printf "%%s ALL=(root) NOPASSWD: %%s \"\"\n" "$M" "$BIN" >"$sudo_tmp"
visudo -cf "$sudo_tmp" >/dev/null || { rm -f "$sudo_tmp"; echo "visudo rejected the sudoers rule" >&2; exit 4; }
[[ -d $R/etc/sudoers.d ]] || install -d -m 0750 "$R/etc/sudoers.d"
install -m 0440 "$sudo_tmp" "$R/etc/sudoers.d/storageforge-agentctl"
own root:root "$R/etc/sudoers.d/storageforge-agentctl"
rm -f "$sudo_tmp"
found=
for c in docker podman pct incus lxc-create; do if command -v "$c" >/dev/null 2>&1; then found="$found $c"; fi; done
echo "runtimes:${found:- none}"
echo "the agent can be enrolled: $M may only run $BIN, and that takes only requests this controller signed"
"""

REMOVE = r"""set -euo pipefail
export LC_ALL=C
R=
if ((EUID != 0)); then R=${STORAGEFORGE_AGENT_SETUP_ROOT:?this runs as root}; else export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; fi
M=%(manager)s A=%(agent)s BIN=%(agentctl)s
rm -f "$R/etc/sudoers.d/storageforge-agentctl" "$R$BIN"
for u in "$M" "$A"; do
  if id "$u" >/dev/null 2>&1; then
    # a login outlives its request by a moment, and userdel refuses while a process of the account is alive
    for _ in 1 2 3 4 5; do pgrep -u "$u" >/dev/null 2>&1 || break; sleep 1; done
    pkill -KILL -u "$u" 2>/dev/null || true
    if command -v loginctl >/dev/null 2>&1; then loginctl disable-linger "$u" 2>/dev/null || true; fi
    userdel "$u" 2>/dev/null || true
  fi
done
rm -rf "$R/etc/storageforge-agent" "$R/var/lib/storageforge-agent"
echo "the agent and everything set up for it are gone from this host"
"""


def signers_line(signing_pub: str) -> str:
    """The controller's key as the host pins it: the one key requests and manifests are checked against, each in its namespace."""
    return f'controller namespaces="{NS_REQUEST},{NS_MANIFEST}" ' + ' '.join(signing_pub.split()[:2])


def setup_script(signing_pub: str, login_pub: str, program: bytes, accept_new_key: bool = False) -> str:
    q = shlex.quote
    return SETUP % {'refuse': REFUSE_APPLIANCE, 'manager': q(MANAGER), 'agent': q(AGENT_USER), 'agentctl': q(AGENTCTL),
                    'size': q(str(len(program))), 'sha': q(hashlib.sha256(program).hexdigest()), 'accept': q('yes' if accept_new_key else 'no'),
                    'root_groups': ' '.join(q(g) for g in ROOT_GROUPS), 'signers': q(signers_line(signing_pub)),
                    'login': q(' '.join(login_pub.split()[:2]) + ' storageforge:agentctl')}


def remove_script() -> str:
    q = shlex.quote
    return REMOVE % {'manager': q(MANAGER), 'agent': q(AGENT_USER), 'agentctl': q(AGENTCTL)}


# ── keys and signatures ─────────────────────────────────────────────
def ensure_keys(vault: Vault) -> tuple[str, str]:
    """The signing and login keys, made on first use. Returns their public lines."""
    have = {k['name'] for k in vault.list_keys()}
    if SIGNING_KEY not in have:
        vault.generate_key(SIGNING_KEY, comment='storageforge:agent-signing')
    if LOGIN_KEY not in have:
        vault.generate_key(LOGIN_KEY, comment='storageforge:agentctl')
    return vault.public_key(SIGNING_KEY), vault.public_key(LOGIN_KEY)


def _signer(vault: Vault):
    kid = vault.conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': SIGNING_KEY})
    if kid is None:
        raise AgentError('no agent signing key yet: set the agent up on a host first')
    buf = vault.decrypt_key(kid, 'sign')
    if isinstance(buf, EnclaveKey):
        return buf                       # it signs inside the enclave: sshsig needs only public_key() and sign()
    try:
        return serialization.load_ssh_private_key(bytes(buf.view()), None)
    finally:
        buf.wipe()


def fingerprint(public_line: str) -> str:
    """SHA256:... of an OpenSSH public key line, as ssh-keygen -l shows it. Worked out here, never taken from a host."""
    blob = base64.b64decode(public_line.split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def request(signer, op: str, machine: str, now: float | None = None, nonce: str | None = None, **fields) -> bytes:
    """The bytes storageforge-agentctl reads from stdin: one signed request for one machine, usable once."""
    if op not in OPS:
        raise ValueError(f'{op} is not an agent operation')
    if not MACHINE_RE.fullmatch(machine or ''):
        raise ValueError('bad machine id')
    nonce = nonce or secrets.token_hex(16)
    if not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('bad nonce')
    body = {'op': op, 'machine': machine, 'issued': int(now or time.time()), 'nonce': nonce}
    body.update({k: v for k, v in fields.items() if v not in (None, False, [])})
    payload = json.dumps(body, separators=(',', ':')).encode()
    sig = deploy.sshsig(signer, payload, NS_REQUEST).encode()
    return f'STORAGEFORGE-AGENTCTL 1\n{len(payload)}\n{len(sig)}\n'.encode() + payload + sig


def plugin_entry(descriptor: bytes, signer: str) -> dict:
    """A manifest's entry for a plugin, from its signed descriptor: its name, the descriptor's hash, who signed it (release or
    operator), and the needs the descriptor declares, word for word. The agent and storageforge-agentctl both refuse a manifest that
    gives a plugin anything else. The controller holds no key that makes a descriptor: it only carries them."""
    if signer not in ('release', 'operator'):
        raise ValueError('a plugin is signed by the release key or by an operator key')
    d = json.loads(descriptor)
    if not isinstance(d, dict) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', str(d.get('name') or '')) or not isinstance(d.get('needs', {}), dict):
        raise ValueError('not a plugin descriptor')
    return {'name': d['name'], 'descriptor': hashlib.sha256(descriptor).hexdigest(), 'signer': signer, 'needs': d.get('needs', {})}


def manifest(signer, agent_fingerprint: str, machine: str, counter: int, image: str, entries: list[dict],
             now: float | None = None) -> tuple[str, str]:
    """A host's manifest and the controller's signature of it: which plugins, at which hashes, with which needs, for the agent
    with this key on this machine, with the time and a counter that only goes up."""
    if not IMAGE_RE.fullmatch(image):
        raise ValueError('the agent image is named by its digest: name@sha256:...')
    if not MACHINE_RE.fullmatch(machine or '') or counter < 1:
        raise ValueError('a manifest names a machine, and its counter starts at 1')
    body = {'format': 1, 'agent': agent_fingerprint, 'machine': machine, 'counter': counter, 'issued': int(now or time.time()),
            'image': image, 'plugins': sorted(entries, key=lambda e: e['name'])}
    text = json.dumps(body, separators=(',', ':'))
    return text, deploy.sshsig(signer, text.encode(), NS_MANIFEST)


# ── the tunnel ──────────────────────────────────────────────────────
def _address(host: str, port: int) -> str:
    """host:port with host as an address: a name is looked up here, on the controller, so that the agent looks nothing up and the
    host's firewall rule can name the one address it may reach."""
    import ipaddress
    import socket
    try:
        ip = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0])
        except (OSError, IndexError, ValueError):
            raise AgentError(f'the agent endpoint {host} does not resolve to an address') from None
    if ip.is_unspecified or ip.is_multicast:
        raise AgentError(f'{ip} is not an address an agent can dial')
    return f'[{ip}]:{port}' if ip.version == 6 else f'{ip}:{port}'


def endpoint_for(conn, name: str) -> str | None:
    """Where this host's agent dials the receiver. Over the StorageForge network when the host and the controller are peers on it
    (the controller's address there, STORAGEFORGE_AGENT_PORT), else STORAGEFORGE_AGENT_ENDPOINT (host:port: the controller's LAN
    address, or the public address where remote nodes reach the tunnel container's machine). None when neither: then the agent gets
    no tunnel and reports nothing."""
    from . import sfnet, sfnetwork
    port = int(os.environ.get('STORAGEFORGE_AGENT_PORT', '').strip() or agenttunnel.DEFAULT_PORT)
    try:
        if sfnetwork.route(conn, name) is not None:
            network = sfnetwork.load(conn)
            me = sfnet.member(network, network['controller'])
            return _address(str(me['address']).split('/')[0], port)
    except AgentError:
        raise
    except Exception:
        pass                            # the network is one way of several: nothing about it may stop an apply
    configured = os.environ.get('STORAGEFORGE_AGENT_ENDPOINT', '').strip()
    if not configured:
        return None
    host, sep, p = configured.rpartition(':')
    if not sep or not p.isdigit() or not 0 < int(p) < 65536:
        raise AgentError('STORAGEFORGE_AGENT_ENDPOINT is host:port, where agents reach the receiver')
    return _address(host, int(p))


def tunnel_for(conn, name: str) -> dict | None:
    """The receiver an agent's tunnel dials and pins, as the signed request carries it, or None when there is no receiver yet."""
    key = agenttunnel.receiver_public()
    endpoint = endpoint_for(conn, name) if key else None
    return {'endpoint': endpoint, 'key': key} if key and endpoint else None


def save_delivery(conn, name: str, fp: str, counter: int, text: str, sig: str, plugins: list[tuple[bytes, str, str]], tunnel: bool = True):
    """What the receiver hands this host's agent from its next session on. With a tunnel, each plugin's program has to be in the
    release's folder as its descriptor names it, or the apply stops here, before the host is asked to make a container for it."""
    sent = [{'descriptor': d.decode(), 'signature': s} for d, s, _kind in plugins]
    for p in sent if tunnel else []:
        try:
            agenttunnel.program_of(p['descriptor'])
        except (OSError, ValueError, agenttunnel.TunnelError) as exc:
            raise AgentError(str(exc)) from None
    conn.execute('DELETE FROM agent_deliveries WHERE host = :h', {'h': name})
    conn.execute("""INSERT INTO agent_deliveries (host, fingerprint, counter, manifest, signature, plugins_json, updated_at)
                    VALUES (:h, :f, :c, :m, :s, :p, :t)""",
                 {'h': name, 'f': fp, 'c': counter, 'm': text, 's': sig, 'p': json.dumps(sent), 't': int(time.time())})


# ── what the controller is configured with ──────────────────────────
def agent_image() -> str:
    """The agent's image, by digest, from STORAGEFORGE_AGENT_IMAGE. There is no default: a tag can be moved to other bytes, and the
    digest is what ties what runs on a host to the image that was scanned and signed."""
    image = os.environ.get('STORAGEFORGE_AGENT_IMAGE', '').strip()
    if not image:
        raise AgentError('STORAGEFORGE_AGENT_IMAGE is not set: name the agent image by its digest (registry/storageforge-agent@sha256:...)')
    if not IMAGE_RE.fullmatch(image):
        raise AgentError('STORAGEFORGE_AGENT_IMAGE does not name an image by its digest (registry/storageforge-agent@sha256:...)')
    return image


def image_signature() -> str:
    """The signature of the agent image's digest, from the file STORAGEFORGE_AGENT_IMAGE_SIG names (image.sig in
    STORAGEFORGE_AGENT_DIR if it names none). It is made with the release key, or with a key the operator put on their hosts
    (docs/agent.md), and is not secret. The controller carries it and cannot make it: storageforge-agentctl runs no image without
    one, so a controller that was taken over cannot have another image run on a host."""
    path = os.environ.get('STORAGEFORGE_AGENT_IMAGE_SIG', '').strip() or str(Path(os.environ.get('STORAGEFORGE_AGENT_DIR', '').strip() or '.') / 'image.sig')
    try:
        text = Path(path).read_text()
    except OSError:
        raise AgentError(f'no signature of the agent image at {path}: the release has one beside the image, and STORAGEFORGE_AGENT_IMAGE_SIG names it') from None
    if len(text) > 4096 or 'BEGIN SSH SIGNATURE' not in text:
        raise AgentError(f'{path} is not an SSH signature')
    return text


def agentctl_program(arch: str) -> bytes:
    """storageforge-agentctl for a kind of machine, from STORAGEFORGE_AGENT_DIR (the image has it; agent/build.sh makes it)."""
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(arch, arch)
    if arch not in ('x86_64', 'aarch64'):
        raise AgentError(f'the agent is built for x86_64 and arm64, and this host is {arch or "of a kind the scan did not tell"}')
    folder = os.environ.get('STORAGEFORGE_AGENT_DIR', '').strip()
    path = Path(folder) / arch / 'storageforge-agentctl' if folder else None
    if not path or not path.is_file():
        raise AgentError('STORAGEFORGE_AGENT_DIR has no storageforge-agentctl for ' + arch + ': build it with agent/build.sh')
    data = path.read_bytes()
    if not data.startswith(b'\x7fELF') or len(data) > 16 * 1024 * 1024:
        raise AgentError(f'{path} is not the program')
    return data


def host_arch(conn, name: str) -> str:
    """The machine a host is, from its last scan (uname -m)."""
    inv = conn.scalar('SELECT inventory_json FROM hosts WHERE hostname = :h', {'h': name})
    inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
    for line in str(inv.get('packages') or '').splitlines():       # the package survey ends with it: arch<TAB>x86_64
        if line.startswith('arch\t'):
            return line.split('\t', 1)[1].strip()
    return ''


def runtime_hint(conn, name: str) -> dict:
    """What the last scan says about a runtime on the host, to tell the user before anything runs. Only a hint: the answer that
    counts is storageforge-agentctl's own, read on the host when the agent is set up."""
    rows = conn.all("""SELECT d.engine FROM docker_hosts d JOIN hosts h ON h.host_id = d.host_id WHERE h.hostname = :h""", {'h': name})
    engines = sorted({str(r[0] or '').split()[0].lower() for r in rows if r[0]})
    return {'known': engines, 'text': (f'the last scan found {" and ".join(engines)}' if engines else
                                       'the last scan found no Docker or Podman: if the host has LXC the agent runs there, and if it has '
                                       'no runtime at all you will be asked before Podman is installed')}


# ── the table ───────────────────────────────────────────────────────
COLUMNS = ('host', 'enabled', 'state', 'public_key', 'fingerprint', 'runtime', 'image', 'counter', 'manifest_sha', 'detail',
           'enrolled_at', 'updated_at', 'updated_by', 'receiver_key', 'endpoint')


def get(conn, name: str) -> dict | None:
    rows = conn.all(f'SELECT {", ".join(COLUMNS)} FROM agents WHERE host = :h', {'h': name})
    return dict(zip(COLUMNS, rows[0])) | {'enabled': bool(rows[0][1])} if rows else None


def view(conn) -> list[dict]:
    """Every host with its agent's state. A host that was never switched on is `off`."""
    rows = conn.all(f"""SELECT h.hostname, {", ".join("a." + c for c in COLUMNS[1:])} FROM hosts h
                        LEFT JOIN agents a ON a.host = h.hostname ORDER BY h.hostname""")
    out = []
    for r in rows:
        d = dict(zip(COLUMNS, r))
        out.append(d | {'enabled': bool(d['enabled']), 'state': d['state'] or 'off', 'counter': d['counter'] or 0, 'public_key': None,
                        'deploy_ready': deploy.ready(conn, d['host'])})
    return out


def _save(conn, name: str, actor: str, **fields):
    if 'state' in fields and fields['state'] not in STATES:
        raise ValueError(f'not an agent state: {fields["state"]}')
    if 'detail' in fields:
        fields['detail'] = str(fields['detail'] or '')[-2000:]
    fields |= {'updated_at': int(time.time()), 'updated_by': actor}
    if get(conn, name) is None:
        conn.execute("INSERT INTO agents (host, enabled, state, counter, updated_at, updated_by) VALUES (:h, 0, 'off', 0, :t, :a)",
                     {'h': name, 't': fields['updated_at'], 'a': actor})
    sets = ', '.join(f'{k} = :{k}' for k in fields)
    conn.execute(f'UPDATE agents SET {sets} WHERE host = :host_name', fields | {'host_name': name})


def switch(conn, host: str, on: bool, actor: str) -> dict:
    """The per-host switch. On says the agent may be set up on this host; it does nothing on the host by itself. Off is refused
    while an agent is enrolled there: remove it first, so that no agent is left running that the controller no longer counts."""
    name = deploy.canonical(conn, host)
    if not conn.scalar('SELECT count(*) FROM hosts WHERE hostname = :h', {'h': name}):
        raise LookupError(f'no host {host}')
    if conn.scalar('SELECT count(*) FROM network_devices WHERE name = :n', {'n': name}):
        raise AgentError(f'{name} is a network device: routers, firewalls, switches and appliances stay agentless')
    row = get(conn, name)
    if not on and row and row['state'] in ('running', 'stopped'):
        raise AgentError(f'{name} has an agent enrolled: remove it before switching the agent off for this host')
    _save(conn, name, actor, enabled=1 if on else 0, state='on' if on else 'off', **({} if on else {'detail': ''}))
    return get(conn, name)


# ── talking to storageforge-agentctl ────────────────────────────────
def read_reply(out: bytes) -> dict:
    """The one line of JSON storageforge-agentctl prints. Anything else is not an answer."""
    lines = [line for line in out[-MAX_REPLY:].decode('utf-8', 'replace').splitlines() if line.strip()]
    try:
        reply = json.loads(lines[-1]) if lines and len(out) <= MAX_REPLY else None
    except ValueError:
        reply = None
    if not isinstance(reply, dict) or not isinstance(reply.get('ok'), bool):
        raise AgentError('the host answered something that is not an answer of storageforge-agentctl')
    return reply


def _send(vault: Vault, conn, name: str, req: bytes, timeout: int) -> tuple[int, bytes, bytes]:
    """One request over ssh as the managing account, with its key from the vault and the host key that is pinned."""
    addr = connect_address(conn, name)
    port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or 22
    kid = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': LOGIN_KEY})
    if kid is None:
        raise AgentError('no agent login key yet: set the agent up on a host first')
    with ephemeral_agent(vault.decrypt_key(kid, 'deploy'), ttl=timeout + 60) as sock:
        t = Transport(host=addr, user=MANAGER, port=port, agent_sock=sock, known_hosts=str(known_hosts_path()), isolated=True, strict=True)
        try:
            # the account can start one program whatever is asked for here, so what is asked for is its name
            p = subprocess.run(t.argv('storageforge-agentctl'), input=req, capture_output=True, timeout=timeout, env=child_env())
        finally:
            t.close()
    return p.returncode, p.stdout, p.stderr


def call(db: Database, host: str, op: str, *, timeout: int = 900, group_id: str | None = None, actor: str | None = None, **fields) -> dict:
    """One signed request to a host's storageforge-agentctl; returns its answer. Raises AgentError when it refused or failed, with
    its reason. With group_id the request is recorded as a run of that group, as a deploy is, so the UI can show it."""
    conn = db.connect()
    run_id, status, text = None, 'failed', ''
    try:
        name = deploy.canonical(conn, host)
        machine = deploy._machine(conn, name)
        if not machine:
            raise AgentError(f'{name} has no machine id on record: scan it first, so that requests can be signed for that machine only')
        if group_id:
            run_id = conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at)
                                    VALUES (:g, :h, 'agent', :r, 'apply', 'running', :a, :t) RETURNING run_id""",
                                 {'g': group_id, 'h': name, 'r': op, 'a': actor or actor_name(), 't': int(time.time())})
        try:
            with Vault(db, conn).unlock() as v:
                rc, out, err = _send(v, conn, name, request(_signer(v), op, machine, **fields), timeout)
        except subprocess.TimeoutExpired:
            raise AgentError(f'{name} did not answer {op} in {timeout} seconds') from None
        try:
            reply = read_reply(out)
        except AgentError:
            tail = deploy.ssh_failure(err.decode('utf-8', 'replace')) if rc == 255 else err.decode('utf-8', 'replace')[-500:].strip()
            raise AgentError(f'{name}: {op} got no answer ({tail or "exit " + str(rc)})') from None
        text = json.dumps(reply)[:4000]
        if rc != 0 or not reply['ok']:
            raise AgentError(f'{name}: {str(reply.get("why") or "refused")[:500]}', str(reply.get('error') or '')[:40] or None)
        status = 'ok'
        return reply
    except AgentError as exc:
        text = text or str(exc)
        raise
    finally:
        if run_id:
            conn.execute('UPDATE deploy_runs SET status = :s, output = :o, finished_at = :f WHERE run_id = :r',
                         {'s': status, 'o': text, 'f': int(time.time()), 'r': run_id})
        conn.close()


def _audit(db, conn, actor: str, action: str, outcome: str, name: str, fp: str | None, detail: dict):
    with Vault(db, conn).unlock() as v:
        AuditLog(db, conn, v.audit_key).append(actor, action, outcome, name, fp, detail)


def _runtime(reply: dict) -> str | None:
    return reply.get('runtime') if reply.get('runtime') in RUNTIMES else None


# ── the lifecycle ───────────────────────────────────────────────────
def install(db: Database, host: str, actor: str | None = None, install_podman: bool = False, accept_new_key: bool = False,
            group_id: str | None = None) -> dict:
    """Set the agent up on a host and enroll it: the setup through the host's deploy access, then storageforge-agentctl makes the
    container, the agent makes its key, and the public half is read back and pinned. A host with no container runtime is not
    touched further until install_podman says the user was told Podman will be installed."""
    actor = actor or actor_name()
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = get(conn, name)
        if not row or not row['enabled']:
            raise AgentError(f'the agent is switched off for {name}: switch it on for this host first')
        if row['state'] in ('running', 'stopped'):
            raise AgentError(f'{name} has an agent enrolled already: remove it before enrolling another')
        if not deploy.ready(conn, name):
            raise AgentError(f'{name} has no deploy access yet, and the agent is set up through it: set up deploy access first')
        image, image_sig, program = agent_image(), image_signature(), agentctl_program(host_arch(conn, name))
        with Vault(db, conn).unlock() as v:
            signing_pub, login_pub = ensure_keys(v)
        try:
            r = deploy.run(db, name, setup_script(signing_pub, login_pub, program, accept_new_key), kind='agent', ref='setup', mode='apply',
                           actor=actor, group_id=group_id, data=program)
            if r['status'] != 'ok':
                raise AgentError(f'{name}: the setup did not finish: ' + (r['output'] or '').strip()[-600:])
            pre = call(db, name, 'preflight', group_id=group_id, actor=actor, timeout=120)
            runtimes = [x for x in pre.get('runtimes') or [] if x in ('docker', 'podman', 'pct', 'incus', 'lxc')]
            if not runtimes and not install_podman:
                _save(conn, name, actor, state='needs-podman', detail=PODMAN_NOTICE)
                return {'host': name, 'state': 'needs-podman', 'message': PODMAN_NOTICE}
            got = call(db, name, 'enroll', group_id=group_id, actor=actor, image=image, image_signature=image_sig,
                       install_podman=bool(install_podman and not runtimes))
            public = str(got.get('public_key') or '')
            if not PUBLIC_RE.fullmatch(public):
                raise AgentError(f'{name}: what came back from the enrollment is not an agent key')
            fp = fingerprint(public)
            _save(conn, name, actor, public_key=public, fingerprint=fp, runtime=_runtime(got), image=image, enrolled_at=int(time.time()), manifest_sha=None)
            _audit(db, conn, actor, 'agent.enroll', 'ok', name, fp, {'runtime': _runtime(got), 'image': image, 'podman_installed': bool(install_podman and not runtimes)})
            applied = apply(db, name, [], actor=actor, group_id=group_id)
        except Exception as exc:
            _save(conn, name, actor, state='failed', detail=str(exc))
            _audit(db, conn, actor, 'agent.install', 'failed', name, None, {'error': str(exc)[:500]})
            raise
        return {'host': name, 'state': 'running', 'fingerprint': fp, 'runtime': applied['runtime'], 'notes': [str(n)[:300] for n in (got.get('notes') or [])][:10]}
    finally:
        conn.close()


def apply(db: Database, host: str, plugins: list[tuple[bytes, str, str]], actor: str | None = None, group_id: str | None = None,
          accept_new_key: bool = False) -> dict:
    """Sign a new manifest for a host and have its container made again for it. plugins: (descriptor bytes, its signature, 'release'
    or 'operator') for each plugin the host is to run; with none the agent runs and has nothing to do. The counter goes up by one
    for every manifest signed, whether the host took it or not, and never comes down.

    With a receiver running, the request also names it (tunnel_for), and the manifest and plugins are left for it to deliver. A
    receiver key other than the one the host pinned is sent only with accept_new_key, which a person gives.

    SEAM (roadmap 11.2, "Privilege needs a person"): whoever calls this with a plugin that declares a need has to have asked an
    admin with a fresh password first. Nothing calls it with plugins yet."""
    actor = actor or actor_name()
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = get(conn, name)
        if not row or not row['enabled'] or not row['fingerprint']:
            raise AgentError(f'{name} has no agent enrolled')
        machine = deploy._machine(conn, name)
        image, image_sig = agent_image(), image_signature()      # the image this controller is set to now: applying is also how an agent is updated
        entries = [plugin_entry(descriptor, signer) for descriptor, _sig, signer in plugins]
        tunnel = tunnel_for(conn, name)
        new_key = bool(tunnel and row.get('receiver_key') and row['receiver_key'] != tunnel['key'])
        if new_key and not accept_new_key:
            raise AgentError(f'{name} pinned another receiver key for its tunnel than this receiver has: the receiver was set up again, '
                             'or something else holds its folder. Accept the new key for this host if you made it', 'tunnel-key')
        conn.execute('UPDATE agents SET counter = counter + 1 WHERE host = :h', {'h': name})
        counter = conn.scalar('SELECT counter FROM agents WHERE host = :h', {'h': name})
        with Vault(db, conn).unlock() as v:
            text, sig = manifest(_signer(v), row['fingerprint'], machine, counter, image, entries)
        sent = [{'descriptor': descriptor.decode(), 'signature': s} for descriptor, s, _signer_kind in plugins]
        save_delivery(conn, name, row['fingerprint'], counter, text, sig, plugins, tunnel=tunnel is not None)
        try:
            got = call(db, name, 'apply', group_id=group_id, actor=actor, manifest=text, manifest_signature=sig, image_signature=image_sig, plugins=sent,
                       tunnel=tunnel, accept_new_tunnel_key=new_key)
        except AgentError as exc:
            _audit(db, conn, actor, 'agent.apply', 'failed', name, row['fingerprint'], {'counter': counter, 'error': str(exc)[:500]})
            raise
        sha = hashlib.sha256(text.encode()).hexdigest()
        _save(conn, name, actor, state='running', runtime=_runtime(got), manifest_sha=sha, image=image, detail='',
              **({'receiver_key': tunnel['key'], 'endpoint': tunnel['endpoint']} if tunnel else {}))
        _audit(db, conn, actor, 'agent.apply', 'ok', name, row['fingerprint'],
               {'counter': counter, 'manifest': sha, 'plugins': [e['name'] for e in entries], 'needs': got.get('needs') if isinstance(got.get('needs'), dict) else {},
                'tunnel': tunnel['endpoint'] if tunnel else None, 'new_receiver_key': new_key})
        return {'host': name, 'state': 'running', 'counter': counter, 'manifest': sha, 'runtime': _runtime(got), 'tunnel': tunnel['endpoint'] if tunnel else None}
    finally:
        conn.close()


def lifecycle(db: Database, host: str, verb: str, actor: str | None = None) -> dict:
    """start, stop, restart or status of a host's agent, through storageforge-agentctl."""
    if verb not in ('start', 'stop', 'restart', 'status'):
        raise ValueError(f'not something an agent is asked: {verb}')
    actor = actor or actor_name()
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = get(conn, name)
        if not row or not row['fingerprint']:
            raise AgentError(f'{name} has no agent enrolled')
        got = call(db, name, verb, actor=actor, timeout=300)
        if verb == 'status':
            # what the host says, beside what is pinned here: a key that is not the pinned one is said, never taken
            theirs = str(got.get('fingerprint') or '')[:64]
            out = {'host': name, 'state': row['state'], 'running': got.get('running') is True, 'runtime': _runtime(got),
                   'counter': got.get('counter') if isinstance(got.get('counter'), int) else None, 'pinned': row['fingerprint'],
                   'key_matches': theirs == row['fingerprint'], 'enrolled_there': got.get('enrolled') is True}
            return out
        state = 'stopped' if verb == 'stop' else 'running'
        _save(conn, name, actor, state=state, **({'runtime': _runtime(got)} if _runtime(got) else {}))
        _audit(db, conn, actor, f'agent.{verb}', 'ok', name, row['fingerprint'], {})
        return {'host': name, 'state': state}
    finally:
        conn.close()


def remove(db: Database, host: str, actor: str | None = None, group_id: str | None = None) -> dict:
    """Take the agent off a host: its container and its key through storageforge-agentctl, then the accounts, the sudoers line and
    the program through the host's deploy access. The key pinned here is forgotten first, which no host can undo: whatever is
    left there afterwards is no agent of this controller."""
    actor = actor or actor_name()
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = get(conn, name)
        if not row:
            raise AgentError(f'{name} has no agent')
        fp = row['fingerprint']
        _save(conn, name, actor, state='removed', public_key=None, fingerprint=None, manifest_sha=None, runtime=None, detail='', receiver_key=None, endpoint=None)
        conn.execute('DELETE FROM agent_deliveries WHERE host = :h', {'h': name})
        _audit(db, conn, actor, 'agent.remove', 'ok', name, fp, {})
        problems = []
        try:
            call(db, name, 'remove', group_id=group_id, actor=actor, timeout=300)
        except AgentError as exc:
            problems.append(str(exc))
        if deploy.ready(conn, name):
            r = deploy.run(db, name, remove_script(), kind='agent', ref='remove', mode='apply', actor=actor, group_id=group_id)
            if r['status'] != 'ok':
                problems.append((r['output'] or '').strip()[-400:])
        else:
            problems.append('the host has no deploy access any more: the accounts and the sudoers line are still there')
        if problems:
            _save(conn, name, actor, detail='removed here; on the host: ' + '; '.join(problems))
        return {'host': name, 'state': 'removed', 'problems': problems}
    finally:
        conn.close()


def start_install(db: Database, host: str, actor: str, install_podman: bool = False, accept_new_key: bool = False) -> str:
    """install() in a background thread: pulling an image, or installing Podman, takes longer than a web request should. Returns the
    group id, which the UI polls as it polls a deploy."""
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = get(conn, name)
        if row and row['enabled'] and row['state'] in ('needs-podman', 'failed', 'removed'):
            _save(conn, name, actor, state='on', detail='')      # so that whoever polls sees this install's end, not the last one's
    finally:
        conn.close()
    return deploy.start_task(db, name, 'agent', 'install', actor,
                             lambda gid: install(db, name, actor, install_podman=install_podman, accept_new_key=accept_new_key, group_id=gid))
