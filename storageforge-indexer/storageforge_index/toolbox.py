"""The Toolbox catalog engine (roadmap section 4.1; docs/toolbox.md): entries as signed data, the override layer, install methods in
order of safety, risk labels, and staging an install or a removal as a change plan.

An entry is YAML, data and never code. What it can make a host run is bounded by the step kinds it becomes (steps_toolbox.py) and the
field checks of those kinds: an image pinned by digest, packages by name from the host's own sources, a binary by its SHA-256, a few
named step kinds with checked parameters. The probes adapters run are in the code (tbadapters.py), never in an entry.

Trust, in three sources:
  official   the catalog that ships in the package (catalog/*.yaml, listed with their SHA-256 in catalog/catalog.json). With the release
             key's signature on that manifest (catalog.json.sig, ssh-keygen -Y sign -n storageforge-catalog) it is release-signed;
             without one it is packaged, as trusted as the code it came with. A manifest signature that fails, or a file that is not
             the one the manifest lists, is refused. An update of the official catalog can be taken later from a file, only signed by
             the release key and only with a higher serial: there is no release key in catalog/release_signers yet, so none can be.
  custom     an operator's own entry, signed on the operator's machine with ssh-keygen -Y sign -n storageforge-catalog. The controller
             holds the public keys (toolbox_signers) and only verifies: the private key is never on it. An unsigned custom entry can
             be staged only by someone with hosts.command who accepts it for that host behind a fresh password, and the page says so.
Every read checks again, so a row changed in the database, or a file changed in the package, is refused rather than run.

When a plan is turned into a script, each tool step is checked once more against the catalog as it is then (install_words): the
entry must still be trusted, still be the one the step was staged from (its SHA-256), with the same override. A plan edited by hand
to point at another image or package list has nothing to carry it: the step takes its values from the entry, not from the plan.
"""
from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from .db import Conn

FORMAT = 1
NAMESPACE = 'storageforge-catalog'
CATALOG_DIR = Path(__file__).resolve().parent / 'catalog'
RELEASE_SIGNERS = CATALOG_DIR / 'release_signers'
TOOLS_HOME = '/var/lib/storageforge-tools'       # the home of each rootless tool's own account
DATA_ROOT = '/srv/toolbox'                       # where a tool's volumes are kept on the host, one folder each
MAX_ENTRY = 64 << 10

CATEGORIES = ('panel', 'vpn', 'access', 'identity', 'proxy', 'dns', 'detection', 'monitoring', 'backup', 'secrets', 'provisioning', 'storage', 'offline')
# safest first: a rootless container under an account of its own, the distribution's package, a binary checked by its SHA-256, then
# a container run by root's Podman (Quadlet) or a compose stack, where the engine itself runs as root
METHODS = ('container', 'package', 'binary', 'quadlet', 'compose')
METHOD_LABEL = {'container': 'rootless container (Podman, Quadlet, its own account)', 'package': 'distribution package',
                'binary': 'binary checked by its SHA-256', 'quadlet': 'container run by root (Podman Quadlet)', 'compose': 'compose stack (Docker or Podman, as root)'}
GUI_LEVELS = ('none', 'link', 'sso-link', 'status', 'status+actions', 'full')
EXPOSURES = ('loopback', 'management', 'any')
PMS = ('apt', 'dnf', 'zypper', 'pacman')
CAPS = ('NET_BIND_SERVICE', 'NET_ADMIN', 'NET_RAW', 'CHOWN', 'SETUID', 'SETGID', 'DAC_OVERRIDE', 'FOWNER', 'KILL')
# the step kinds an entry may add beside its install, with values from the entry's inputs; each is checked as any plan step is
ENTRY_STEPS = ('wg-interface', 'wg-peer', 'unit-state', 'nebula', 'cloudflare-tunnel', 'ssh-ca-trust', 'chrony-nts')    # kept short on purpose: each is a way an entry reaches a host
# what each risk label means, and what lessens it. Shown in the report before anything is staged
RISKS = {
    'docker-socket': ('mounts the Docker socket', 'root on the host in effect', 'use a socket proxy that allows only what it needs'),
    'privileged': ('privileged', 'the container can do what root on the host can', 'none: StorageForge refuses privileged entries'),
    'host-network': ('host network', 'it listens on every address the host has, past the container network', 'bind its ports to one address, and fence them'),
    'publishes-80-443': ('publishes 80/443', 'it takes the web ports, which another tool may want', 'put it behind the reverse proxy instead'),
    'runs-as-root': ('runs as root', 'a flaw in it is a flaw in root', 'the rootless container method where the entry has one'),
    'holds-credentials': ('holds credentials', 'it keeps passwords, keys or tokens of its own', 'back up its data with the rest of the vault, and keep it off the internet'),
    'internet-listener': ('listens on the internet', 'anyone who can reach the host can reach it', 'keep it on loopback or the management network, or fence it to known addresses'),
    'net-admin': ('changes the network', 'it can change interfaces, routes and firewall rules', 'none: it is what the tool is for'),
    'engine-socket': ('runs containers', 'it holds the rootless Podman socket of its own account, so it can run any container as that account, '
                      'and SELinux does not separate it from that socket', 'none for root: the account owns nothing else, and root containers stay out of its reach'),
}
# what an entry says of itself beyond its risks: shown beside it in the catalog and in the report. An entry labelled non-commercial is
# never part of a bundle or a role profile's defaults: someone chooses it, knowing its licence
LABELS = {
    'outside-account': 'needs an account with an outside service, made by you there',
    'outside-service': 'talks to a service run by someone else for part of what it does',
    'non-commercial': 'its licence does not allow commercial use of some of it: read the licence before you use it at work',
    'source-available': 'its licence is not an open-source one: read what it allows',
    'not-a-default': 'never installed as part of a bundle or a role profile: choose it yourself',
}
LAB_PASSED: set[str] = set()     # tools with a passing run of the toolbox tier (tests/lab): none yet, so every entry is not lab-tested

ID = re.compile(r'[a-z0-9][a-z0-9-]{1,40}')
IMAGE = re.compile(r'[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)+:[A-Za-z0-9._-]{1,64}@sha256:[0-9a-f]{64}')
PORT = re.compile(r'(\d{1,5}):(\d{1,5})/(tcp|udp)')
PORT_DECL = re.compile(r'(\d{1,5})/(tcp|udp)')
CPATH = re.compile(r'/[A-Za-z0-9._/-]{0,200}')
ENV_KEY = re.compile(r'[A-Z][A-Za-z0-9_]{0,63}')        # Pi-hole reads FTLCONF_dns_listeningMode: the case is part of the name
ENV_VALUE = re.compile(r'[A-Za-z0-9 ._:/@+=,-]{0,200}')       # no %: systemd would expand it in a unit file
ARG = re.compile(r'[A-Za-z0-9._:/=@,+-]{1,200}')                # a word of a container's command: no space, no quote, no %, no $
FILE_NAME = re.compile(r'[a-z][a-z0-9_.-]{0,40}')
MAX_FILE = 8 << 10
PKG = re.compile(r'[a-z0-9][a-z0-9+._-]{0,99}')
UNIT = re.compile(r'[A-Za-z0-9_.@-]{1,120}\.(service|socket|timer)')
HTTPS = re.compile(r'https://[A-Za-z0-9.-]+(:\d{1,5})?/[A-Za-z0-9._~/%+-]{0,300}')
HEALTH = re.compile(r'(https?)://127\.0\.0\.1:(\d{1,5})(/[A-Za-z0-9._/-]{0,100})?')
URL_TEMPLATE = re.compile(r'(https?)://\{host\}(:\{port\}|:\d{1,5})?(/[A-Za-z0-9._/{}-]{0,100})?')
WORDS = re.compile(r'[^\0\r\x1b]{0,400}')
SECRETISH = re.compile(r'(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credentials?)', re.I)
SIGNER_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,63}')
KEY_LINE = re.compile(r'(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/]{40,800}={0,3}')


class CatalogError(ValueError):
    pass


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def normal_text(text: str) -> str:
    """The bytes that are signed: LF line ends and one newline at the end, whatever a browser or an editor did to them."""
    text = (text or '').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')
    return text + '\n'


# ── the entry schema ────────────────────────────────────────────────
def _str(v, problems, where, rx=None, required=True, limit=200):
    if v is None or v == '':
        if required:
            problems.append(f'{where} is required')
        return ''
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        problems.append(f'{where} is a word or a sentence')
        return ''
    v = str(v)
    if len(v) > limit or '\n' in v:
        problems.append(f'{where} is one line of up to {limit} characters')
        return ''
    if rx is not None and not rx.fullmatch(v):
        problems.append(f'{where} {v!r} is not valid')
        return ''
    return v


def _list(v, problems, where):
    if v is None:
        return []
    if not isinstance(v, list):
        problems.append(f'{where} is a list')
        return []
    return v


def _map(v, problems, where):
    if v is None:
        return {}
    if not isinstance(v, dict):
        problems.append(f'{where} is a mapping')
        return {}
    return v


def _qualified_image(image: str) -> bool:
    registry = image.split('/', 1)[0]
    return bool(IMAGE.fullmatch(image) and ('.' in registry or ':' in registry or registry == 'localhost'))


def _container(m: dict, i: int, volumes: list, problems: list, secret_files: frozenset = frozenset(),
               secret_uris: frozenset = frozenset(), sidecar: str = '') -> dict:
    where = f'install.methods[{i}] ({m.get("kind")})' + (f' sidecar {sidecar}' if sidecar else '')
    out = {'kind': m['kind'], 'image': _str(m.get('image'), problems, f'{where} image', IMAGE, limit=300)}
    if m.get('image') and not out['image'] and isinstance(m.get('image'), str) and '@sha256:' not in m['image']:
        problems.append(f'{where}: the image is pinned by digest (name:tag@sha256:...), so an update cannot bring anything else')
    if 'cosign' in m:
        meta = _map(m['cosign'], problems, f'{where} cosign')
        out['cosign_key'] = _cosign_key(meta.get('public_key'), problems, f'{where} cosign.public_key')
        if out['image'] and not _qualified_image(out['image']):
            problems.append(f'{where}: Cosign needs an image with an explicit registry host')
    out['ports'] = []
    for p in _list(m.get('ports'), problems, f'{where} ports'):
        mm = PORT.fullmatch(str(p))
        if not mm or not (0 < int(mm[1]) < 65536 and 0 < int(mm[2]) < 65536):
            problems.append(f'{where}: a port is host-port:container-port/tcp or /udp ({p!r} is not); the address it binds to comes from the exposure')
            continue
        out['ports'].append({'host': int(mm[1]), 'container': int(mm[2]), 'proto': mm[3]})
    out['volumes'] = {}
    for name, target in _map(m.get('volumes'), problems, f'{where} volumes').items():
        if str(name) not in volumes:
            problems.append(f'{where}: the volume {name} is not in requires.volumes')
        elif not isinstance(target, str) or not CPATH.fullmatch(target) or '..' in target.split('/'):
            problems.append(f'{where}: the volume {name} is mounted at an absolute path in the container')
        else:
            out['volumes'][str(name)] = target
    out['env'] = {}
    for k, v in _map(m.get('env'), problems, f'{where} env').items():
        if not ENV_KEY.fullmatch(str(k)) or not isinstance(v, (str, int)) or isinstance(v, bool) or not ENV_VALUE.fullmatch(str(v)):
            problems.append(f'{where}: env {k} is NAME: value, in letters, digits and . _ : / @ + = , - only')
        elif SECRETISH.search(str(k)) and not ((str(k).endswith('_FILE') and str(v) in secret_files) or str(v) in secret_uris):
            problems.append(f'{where}: env {k} looks like a secret (or points at {v}, which is not one of the secrets the entry declares): '
                            'declare it under secrets, and it reaches the container as a file (/run/secrets/<entry>/<name>, or file:// before it)')
        else:
            out['env'][str(k)] = str(v)
    out['caps'] = []
    for c in _list(m.get('caps_add'), problems, f'{where} caps_add'):
        if c not in CAPS:
            problems.append(f'{where}: the capability {c} is not one an entry may add ({", ".join(CAPS)})')
        else:
            out['caps'].append(c)
    net = m.get('network') or 'bridge'
    if net not in ('bridge', 'host'):
        problems.append(f'{where}: network is bridge or host')
    out['network'] = net
    if m.get('privileged'):
        problems.append(f'{where}: privileged containers are refused')
    for key in ('socket', 'devices', 'pid', 'ipc', 'security_opt'):
        if m.get(key):
            problems.append(f'{where}: {key} is not something an entry may ask for')
    out['read_only'] = bool(m.get('read_only'))
    out['drop_caps'] = m.get('drop_caps') == 'all'
    out['user'] = _str(m.get('user'), problems, f'{where} user', re.compile(r'\d{1,10}(:\d{1,10})?'), required=False)
    # the uid the image runs as, when it is not root: its folders are given to it (Podman's U option; chown for a compose stack)
    out['volume_owner'] = _str(m.get('volume_owner'), problems, f'{where} volume_owner', re.compile(r'[1-9]\d{0,9}'), required=False)
    out['args'] = []
    raw_cmd = m.get('args') if m.get('args') is not None else m.get('command')
    cmd_where = 'args' if m.get('command') is None else 'command'
    for a in _list(raw_cmd, problems, f'{where} {cmd_where}')[:20]:
        if not isinstance(a, (str, int)) or isinstance(a, bool) or not ARG.fullmatch(str(a)):
            problems.append(f'{where}: args are words (a word of the command, one word of letters, digits and . _ : / = @ , + -; {a!r} is not: no spaces, no shell)')
        else:
            out['args'].append(str(a))
    out['command'] = out['args']
    out['files'] = {}
    for name, f in list(_map(m.get('files'), problems, f'{where} files').items())[:6]:
        f = f if isinstance(f, dict) else {}
        target, body = f.get('path'), f.get('text')
        if not FILE_NAME.fullmatch(str(name)):
            problems.append(f'{where}: a file is named in lower-case letters, digits and . _ -')
        elif not isinstance(target, str) or not CPATH.fullmatch(target) or '..' in target.split('/'):
            problems.append(f'{where}: the file {name} is mounted at an absolute path in the container')
        elif not isinstance(body, str) or len(body.encode()) > MAX_FILE or re.search(r'[\0\r\x1b]', body):
            problems.append(f'{where}: the file {name} is text of up to {MAX_FILE >> 10} KiB')
        elif re.search(r'(?im)^\s*[a-z_]*(password|secret|token)\s*[=:]\s*["\']?[A-Za-z0-9+/]{12,}', body):
            problems.append(f'{where}: the file {name} looks like it holds a secret: declare it under secrets, and point the file at /run/secrets')
        else:
            out['files'][str(name)] = {'path': target, 'text': body}
    # a panel that manages containers gets the rootless Podman socket of its own account: never root's, never Docker's
    sock = m.get('engine_socket')
    out['engine_socket'] = sock == 'own' and m['kind'] == 'container' and not sidecar
    if sock is not None and not out['engine_socket']:
        problems.append(f'{where}: engine_socket is own, and only for the rootless container method: the socket of its own account, not root\'s')
    out['sidecars'] = []
    if not sidecar:
        names = set()
        for j, sc in enumerate(_list(m.get('sidecars'), problems, f'{where} sidecars')[:6]):
            sc = sc if isinstance(sc, dict) else {}
            name = _str(sc.get('name'), problems, f'{where} sidecars[{j}] name', re.compile(r'[a-z][a-z0-9-]{0,20}'))
            if m['kind'] != 'compose':
                problems.append(f'{where}: sidecars are for the compose method, which runs the tool and them as one stack')
                break
            if not name or name in names:
                problems.append(f'{where}: each sidecar has a name of its own')
                continue
            names.add(name)
            if sc.get('ports'):
                problems.append(f'{where} sidecar {name}: a sidecar publishes no port; the tool reaches it by its name inside the stack')
            got = _container({**{k: v for k, v in sc.items() if k not in ('name', 'ports')}, 'kind': 'compose'},
                             i, volumes, problems, secret_files, secret_uris, sidecar=name)
            out['sidecars'].append({**got, 'name': name})
        if out['sidecars']:
            images = [out, *out['sidecars']]
            if any('cosign_key' in image for image in images) and not all(image.get('cosign_key') for image in images):
                problems.append(f'{where}: Cosign verification requires a publisher key for the main image and every sidecar')
    elif m.get('sidecars'):
        problems.append(f'{where}: a sidecar has no sidecars of its own')
    return out


def _package(m: dict, i: int, problems: list) -> dict:
    where = f'install.methods[{i}] (package)'
    pk = _map(m.get('packages'), problems, f'{where} packages')
    out = {'kind': 'package', 'packages': {}}
    for pm, names in pk.items():
        if pm not in PMS:
            problems.append(f'{where}: packages are given for {", ".join(PMS)} ({pm} is not one)')
            continue
        good = [n for n in _list(names, problems, f'{where} packages.{pm}') if isinstance(n, str) and PKG.fullmatch(n)]
        if len(good) != len(names or []):
            problems.append(f'{where}: a package name in packages.{pm} is not valid')
        if good:
            out['packages'][pm] = good
    if not out['packages']:
        problems.append(f'{where} names no package')
    out['units'] = [u for u in _list(m.get('units'), problems, f'{where} units') if isinstance(u, str) and UNIT.fullmatch(u)]
    if len(out['units']) != len(m.get('units') or []):
        problems.append(f'{where}: a unit is name.service, name.socket or name.timer')
    sock = _map(m.get('socket'), problems, f'{where} socket')
    out['socket'] = None
    if sock:
        unit, port = str(sock.get('unit') or ''), sock.get('port')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,120}\.socket', unit) or not isinstance(port, int) or not 0 < port < 65536:
            problems.append(f'{where}: socket is {{unit: name.socket, port: N}}, the socket whose address the exposure sets')
        else:
            out['socket'] = {'unit': unit, 'port': port}
    return out


def _cosign_key(value, problems: list, where: str) -> str:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    if isinstance(value, str) and len(value) <= 4096:
        text = value.strip()
        if re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----', text):
            try:
                key = serialization.load_pem_public_key(text.encode('ascii'))
                return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
            except (ValueError, UnsupportedAlgorithm):
                pass
    problems.append(f'{where} must be a PEM public key')
    return ''


def _binary(m: dict, i: int, problems: list) -> dict:
    where = f'install.methods[{i}] (binary)'
    out = {'kind': 'binary', 'name': _str(m.get('name'), problems, f'{where} name', re.compile(r'[a-z0-9][a-z0-9._-]{0,60}')), 'files': {}}
    for arch, f in _map(m.get('files'), problems, f'{where} files').items():
        f = f if isinstance(f, dict) else {}
        if arch not in ('x86_64', 'aarch64'):
            problems.append(f'{where}: files are given for x86_64 and aarch64 ({arch} is not one)')
            continue
        url = _str(f.get('url'), problems, f'{where} files.{arch}.url', HTTPS, limit=400)
        sha = _str(f.get('sha256'), problems, f'{where} files.{arch}.sha256', re.compile(r'[0-9a-f]{64}'))
        if url and sha:
            out['files'][arch] = {'url': url, 'sha256': sha}
        if 'archive' in f:
            archive = _map(f['archive'], problems, f'{where} files.{arch}.archive')
            member = _str(archive.get('member'), problems, f'{where} files.{arch}.archive.member',
                          re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*'), limit=255)
            if member and any(part in ('.', '..') for part in member.split('/')):
                problems.append(f'{where}: archive member must be a relative path without dot segments')
            member_sha = _str(archive.get('sha256'), problems, f'{where} files.{arch}.archive.sha256', re.compile(r'[0-9a-f]{64}'))
            if url and sha and member and member_sha:
                out['files'][arch]['archive'] = {'member': member, 'sha256': member_sha}
        if 'minisign' in f:
            meta = f'{where} files.{arch}.minisign'
            sig = _map(f['minisign'], problems, meta)
            signature_url = _str(sig.get('url'), problems, f'{meta}.url', HTTPS, limit=400)
            # Base64 of the 42-byte Ed header, key ID and Ed25519 public key.
            public_key = _str(sig.get('public_key'), problems, f'{meta}.public_key',
                              re.compile(r'RW[QRST][A-Za-z0-9+/]{53}'))
            if url and sha and signature_url and public_key:
                out['files'][arch]['minisign'] = {'url': signature_url, 'public_key': public_key}
        if 'cosign' in f:
            meta = f'{where} files.{arch}.cosign'
            bundle = _map(f['cosign'], problems, meta)
            bundle_url = _str(bundle.get('bundle_url'), problems, f'{meta}.bundle_url', HTTPS, limit=400)
            public_key = _cosign_key(bundle.get('public_key'), problems, f'{meta}.public_key')
            if 'minisign' in f:
                problems.append(f'{where} files.{arch} must choose one publisher signature format')
            if url and sha and bundle_url and public_key:
                out['files'][arch]['cosign'] = {'url': bundle_url, 'public_key': public_key}
    if not out['files']:
        problems.append(f'{where} has no file to download')
    if m.get('archive'):
        problems.append(f'{where}: put archive metadata under each file in files.<architecture>.archive')
    return out


def load_entry(text: str) -> tuple[dict | None, list[str]]:
    """The entry checked against the schema: (entry, []) or (None or a partial entry, the problems). Never raises on what it is given."""
    problems: list[str] = []
    if not isinstance(text, str) or not text.strip():
        return None, ['the entry is empty']
    if len(text.encode()) > MAX_ENTRY:
        return None, [f'an entry is at most {MAX_ENTRY >> 10} KiB']
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, [f'not YAML: {str(exc).splitlines()[0][:200]}']
    if not isinstance(raw, dict):
        return None, ['an entry is a YAML mapping']
    known = {'format', 'id', 'revision', 'name', 'app_version', 'category', 'summary', 'homepage', 'license', 'install', 'inputs', 'steps', 'requires',
             'exposure', 'secrets', 'firewall', 'mac', 'health', 'backup', 'gui', 'upgrade', 'risk', 'compliance', 'notes', 'labels', 'outside', 'storage'}
    for k in raw:
        if k not in known:
            problems.append(f'{k} is not a field of an entry')
    if raw.get('format') != FORMAT:
        problems.append(f'format is {FORMAT}')
    e = {'format': FORMAT, 'id': _str(raw.get('id'), problems, 'id', ID), 'name': _str(raw.get('name'), problems, 'name', WORDS, limit=80),
         'app_version': _str(raw.get('app_version'), problems, 'app_version', WORDS, required=False, limit=60) or '',
         'summary': _str(raw.get('summary'), problems, 'summary', WORDS, limit=300), 'notes': _str(raw.get('notes'), problems, 'notes', WORDS, required=False, limit=400) or '',
         'homepage': _str(raw.get('homepage'), problems, 'homepage', HTTPS, required=False, limit=300) or '',
         'license': _str(raw.get('license'), problems, 'license', re.compile(r'[A-Za-z0-9.+-]{1,40}'), required=False) or ''}
    rev = raw.get('revision')
    if not isinstance(rev, int) or isinstance(rev, bool) or not 0 < rev < 1_000_000:
        problems.append('revision is a whole number from 1, raised with every change to the entry')
        rev = 0
    e['revision'] = rev
    e['category'] = raw.get('category') if raw.get('category') in CATEGORIES else ''
    if not e['category']:
        problems.append(f'category is one of {", ".join(CATEGORIES)}')
    req = _map(raw.get('requires'), problems, 'requires')
    volumes = [str(v) for v in _list(req.get('volumes'), problems, 'requires.volumes') if isinstance(v, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', v)]
    if len(volumes) != len(req.get('volumes') or []):
        problems.append('requires.volumes are short lower-case names')
    ports = []
    for p in _list(req.get('ports'), problems, 'requires.ports'):
        mm = PORT_DECL.fullmatch(str(p))
        if not mm:
            problems.append(f'requires.ports: {p!r} is not port/tcp or port/udp')
        else:
            ports.append({'port': int(mm[1]), 'proto': mm[2]})
    e['requires'] = {'ports': ports, 'volumes': volumes}
    from . import tbstorage
    e['storage'] = tbstorage.load_storage(raw.get('storage'), volumes, problems)     # where a storage-facing app's data goes (tbstorage.py)
    methods = []
    rid = str(raw.get('id') or '')
    snames = [s['name'] for s in (raw.get('secrets') or []) if isinstance(s, dict) and isinstance(s.get('name'), str)]
    secret_files = frozenset(f'/run/secrets/{rid}/{n}' for n in snames)
    secret_uris = frozenset(f'file:///run/secrets/{rid}/{n}' for n in snames)
    inst = _map(raw.get('install'), problems, 'install')
    for i, m in enumerate(_list(inst.get('methods'), problems, 'install.methods')):
        if not isinstance(m, dict) or m.get('kind') not in METHODS:
            problems.append(f'install.methods[{i}]: kind is one of {", ".join(METHODS)}')
            continue
        if any(x['kind'] == m['kind'] for x in methods):
            problems.append(f'install.methods[{i}]: {m["kind"]} is given twice')
            continue
        if m['kind'] in ('package', 'binary') and 'cosign' in m:
            problems.append(f'install.methods[{i}]: cosign is for an image, or under files.<architecture> for a binary')
        methods.append(_container(m, i, volumes, problems, secret_files, secret_uris) if m['kind'] in ('container', 'quadlet', 'compose') else
                       _package(m, i, problems) if m['kind'] == 'package' else _binary(m, i, problems))
    if not methods:
        problems.append('install.methods names at least one way to install it')
    e['methods'] = sorted(methods, key=lambda m: METHODS.index(m['kind']))
    for m in e['methods']:
        # what an entry may switch on, or install in /usr/local/bin, is its own: a unit named after its packages or itself, a program named
        # after itself. Never debug-shell.service, never a sudo that shadows the real one
        if any(sc['name'] == e['id'] for sc in m.get('sidecars', [])):
            problems.append(f'install.methods: sidecars cannot use the main service name {e["id"]}')
        own = {e['id'], *(n for names in (m.get('packages') or {}).values() for n in names)}
        for u in (m.get('units') or []) + ([m['socket']['unit']] if m.get('socket') else []):
            # chronyd.service and smartd.service: a daemon named after its package with a d, as Fedora and Arch name them
            if not any(u == o or u.startswith(o + '.') or u.startswith(o + '-') or u.startswith(o + '@') or u.startswith(o + 'd.') for o in own):
                problems.append(f'install.methods: the unit {u} is not named after {e["id"]} or one of its packages')
        if m['kind'] == 'binary' and m.get('name') and e['id'] and not (m['name'] == e['id'] or m['name'].startswith(e['id'] + '-')):
            problems.append(f'install.methods (binary): the program is named {e["id"]} or {e["id"]}-something, so it cannot stand in for another')
    from . import changes
    e['inputs'] = []
    for i, inp in enumerate(_list(raw.get('inputs'), problems, 'inputs')):
        inp = inp if isinstance(inp, dict) else {}
        name = _str(inp.get('name'), problems, f'inputs[{i}] name', re.compile(r'[a-z][a-z0-9_]{0,30}'))
        kind = inp.get('kind')
        if kind not in changes.CHECKS:
            problems.append(f'inputs[{i}]: kind is a field kind of plan steps (iface, cidr, port, name, word, ...)')
            continue
        default = '' if inp.get('default') is None else str(inp.get('default'))
        if default and not changes.CHECKS[kind].fullmatch(default):
            problems.append(f'inputs[{i}]: the default {default!r} is not a valid {kind}')
        e['inputs'].append({'name': name, 'kind': kind, 'label': _str(inp.get('label'), problems, f'inputs[{i}] label', WORDS, limit=80), 'default': default})
    names = {x['name'] for x in e['inputs']}
    e['steps'] = []
    for i, st in enumerate(_list(raw.get('steps'), problems, 'steps')):
        st = st if isinstance(st, dict) else {}
        kind = st.get('type')
        if kind not in ENTRY_STEPS:
            problems.append(f'steps[{i}]: type is one of {", ".join(ENTRY_STEPS)}')
            continue
        fields = {f['name'] for f in changes.TYPES.get(kind, {}).get('fields', [])}
        params = {}
        for k, v in _map(st.get('params'), problems, f'steps[{i}] params').items():
            v = str(v)
            if k not in fields:
                problems.append(f'steps[{i}]: {kind} has no field {k}')
            elif any(ref not in names for ref in re.findall(r'\{([a-z0-9_]+)\}', v)):
                problems.append(f'steps[{i}]: {k} names an input the entry does not have')
            elif len(v) > 200 or '\n' in v:
                problems.append(f'steps[{i}]: {k} is one line')
            else:
                params[k] = v
        e['steps'].append({'type': kind, 'params': params})
    exp = _map(raw.get('exposure'), problems, 'exposure')
    e['exposure'] = {'default': exp.get('default') or 'loopback', 'public_optional': bool(exp.get('public_optional')), 'behind': str(exp.get('behind') or '')}
    if e['exposure']['default'] not in EXPOSURES:
        problems.append(f'exposure.default is one of {", ".join(EXPOSURES)}')
    e['secrets'] = []
    for i, s in enumerate(_list(raw.get('secrets'), problems, 'secrets')):
        s = s if isinstance(s, dict) else {}
        e['secrets'].append({'name': _str(s.get('name'), problems, f'secrets[{i}] name', re.compile(r'[a-z][a-z0-9_-]{0,40}')),
                             'kind': s.get('kind') if s.get('kind') in ('password', 'token', 'hex', 'pin') else 'password'})
    health = raw.get('health')
    e['health'] = None
    if isinstance(health, dict):
        url = _str(health.get('url'), problems, 'health.url', HEALTH, limit=150)
        expect = health.get('expect', 200)
        if not isinstance(expect, int) or not 100 <= expect < 600:
            problems.append('health.expect is an HTTP status')
        elif url:
            e['health'] = {'url': url, 'expect': expect}
    elif health not in (None, 'none'):
        problems.append('health is {url: http://127.0.0.1:PORT/..., expect: 200}, or none: only loopback is checked')
    bk = _map(raw.get('backup'), problems, 'backup')
    e['backup'] = {'paths': [str(p) for p in _list(bk.get('paths'), problems, 'backup.paths') if isinstance(p, str) and (p in volumes or CPATH.fullmatch(p))],
                   'consistency': bk.get('consistency') if bk.get('consistency') in ('stop-snapshot', 'live', 'dump') else 'live'}
    gui = _map(raw.get('gui'), problems, 'gui')
    native = gui.get('native')
    e['gui'] = {'native': None, 'level': 'none', 'adapter': None, 'api': None}
    if isinstance(native, dict):
        tpl = _str(native.get('url_template'), problems, 'gui.native.url_template', URL_TEMPLATE, limit=150)
        port = native.get('port')
        if port is not None and (not isinstance(port, int) or not 0 < port < 65536):
            problems.append('gui.native.port is a port number')
            port = None
        sso = native.get('sso') or 'none'
        if sso not in ('none', 'oidc', 'forward-auth'):
            problems.append('gui.native.sso is none, oidc or forward-auth')
        # where an identity provider sends a browser back after signing in, as a path of the tool's own address
        redirect = _str(native.get('oidc_redirect'), problems, 'gui.native.oidc_redirect', re.compile(r'/[A-Za-z0-9._/-]{0,100}'), required=False) or ''
        if redirect and sso != 'oidc':
            problems.append('gui.native.oidc_redirect is for sso: oidc')
        if tpl:
            e['gui']['native'] = {'url_template': tpl, 'port': port, 'sso': sso, 'oidc_redirect': redirect}
            e['gui']['level'] = 'link'
    elif native not in (None, 'none'):
        problems.append('gui.native is {url_template, port, sso}, or none')
    panel = _map(gui.get('panel'), problems, 'gui.panel')
    if panel:
        level = panel.get('level') or 'status'
        if level not in GUI_LEVELS:
            problems.append(f'gui.panel.level is one of {", ".join(GUI_LEVELS)}')
        else:
            e['gui']['level'] = level
        from . import tbadapters
        adapter = panel.get('adapter')
        if adapter is not None and adapter not in tbadapters.ADAPTERS:
            problems.append(f'gui.panel.adapter: there is no adapter {adapter} in this version of StorageForge ({", ".join(sorted(tbadapters.ADAPTERS))})')
        else:
            e['gui']['adapter'] = adapter
        api = panel.get('api')
        if api is not None:
            from . import apiconn
            if api not in apiconn.KINDS:
                problems.append(f'gui.panel.api names a platform connection kind ({", ".join(sorted(apiconn.KINDS))})')
            else:
                e['gui']['api'] = api
    if e['gui']['level'] in ('status', 'status+actions', 'full') and not (e['gui']['adapter'] or e['gui']['api']):
        problems.append(f'gui.panel.level {e["gui"]["level"]} needs an adapter or a platform connection kind (api) to read the status from')
    up = _map(raw.get('upgrade'), problems, 'upgrade')
    e['upgrade'] = {'strategy': up.get('strategy') or 'recreate', 'rollback_on_unhealthy': bool(up.get('rollback_on_unhealthy'))}
    e['declared_risks'] = []
    for r in _list(raw.get('risk'), problems, 'risk'):
        if r not in RISKS:
            problems.append(f'risk: {r} is not a known label ({", ".join(RISKS)})')
        else:
            e['declared_risks'].append(r)
    e['compliance'] = [str(c)[:60] for c in _list(raw.get('compliance'), problems, 'compliance')][:20]
    e['labels'] = []
    for lb in _list(raw.get('labels'), problems, 'labels'):
        if lb not in LABELS:
            problems.append(f'labels: {lb} is not a known label ({", ".join(LABELS)})')
        elif lb not in e['labels']:
            e['labels'].append(lb)
    if 'non-commercial' in e['labels'] and 'not-a-default' not in e['labels']:
        e['labels'].append('not-a-default')
    e['outside'] = _str(raw.get('outside'), problems, 'outside', WORDS, required=False, limit=200) or ''
    if e['outside'] and not {'outside-account', 'outside-service'} & set(e['labels']):
        problems.append('outside says what outside account or service it needs: label it outside-account or outside-service too')
    mac = _map(raw.get('mac'), problems, 'mac')
    e['mac'] = {k: str(mac[k])[:200] for k in ('selinux', 'apparmor', 'notes') if mac.get(k)}
    fw = _map(raw.get('firewall'), problems, 'firewall')
    e['firewall'] = [{'port': str(a.get('port'))[:40], 'from': str(a.get('from') or 'management')[:40]} for a in _list(fw.get('allow'), problems, 'firewall.allow') if isinstance(a, dict)]
    return e, problems


def risks(e: dict, method: str | None = None, exposure: str | None = None) -> list[dict]:
    """Risk labels, the entry's own and those its methods and exposure show, each with what it means and what lessens it."""
    found = set(e.get('declared_risks') or [])
    exposure = exposure or e['exposure']['default']
    for m in e['methods']:
        if method and m['kind'] != method:
            continue
        if m['kind'] in ('package', 'binary', 'quadlet', 'compose') and (not m.get('user') or m['user'].split(':')[0] == '0'):
            found.add('runs-as-root')
        if m.get('engine_socket'):
            found.add('engine-socket')
        for part in (m, *(m.get('sidecars') or [])):
            if part.get('network') == 'host':
                found.add('host-network')
            if 'NET_ADMIN' in (part.get('caps') or []):
                found.add('net-admin')
        if any(p['host'] in (80, 443) for p in m.get('ports') or []):
            found.add('publishes-80-443')
    if e.get('secrets'):
        found.add('holds-credentials')
    if exposure == 'any':
        found.add('internet-listener')
    return [{'label': k, 'title': RISKS[k][0], 'means': RISKS[k][1], 'mitigation': RISKS[k][2]} for k in RISKS if k in found]


# ── signatures ──────────────────────────────────────────────────────
@functools.lru_cache(maxsize=512)
def _verify_cached(data: bytes, armored: str, signers: str) -> str | None:
    """The principal of `signers` (an allowed-signers text) whose key made `armored` over `data` in NAMESPACE, or None."""
    if not armored.strip() or not signers.strip():
        return None
    with tempfile.TemporaryDirectory(prefix='sftb-') as d:
        sf, sig = os.path.join(d, 'signers'), os.path.join(d, 'm.sig')
        Path(sf).write_text(signers)
        Path(sig).write_text(armored)
        try:
            found = subprocess.run(['ssh-keygen', '-Y', 'find-principals', '-f', sf, '-s', sig, '-n', NAMESPACE], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None
        for principal in found.stdout.split():
            try:
                ok = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', sf, '-I', principal, '-n', NAMESPACE, '-s', sig], input=data, capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                return None
            if ok.returncode == 0:
                return principal
    return None


def verify(data: str | bytes, armored: str | None, signers: str) -> str | None:
    if not armored or len(armored) > 8192 or '-----BEGIN SSH SIGNATURE-----' not in armored:
        return None
    return _verify_cached(data.encode() if isinstance(data, str) else data, armored.strip() + '\n', signers)


def _signer_lines(keys: list[tuple[str, str]]) -> str:
    return ''.join(f'{name} namespaces="{NAMESPACE}" {key}\n' for name, key in keys)


def release_signers() -> str:
    """The allowed-signers lines of the release key, from the package. Comments and blank lines are left out."""
    try:
        text = RELEASE_SIGNERS.read_text()
    except OSError:
        return ''
    return ''.join(line + '\n' for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#'))


def operator_signers(conn: Conn) -> str:
    return _signer_lines([(r[0], r[1]) for r in conn.all('SELECT name, public_key FROM toolbox_signers ORDER BY name')])


def fingerprint(key_line: str) -> str:
    with tempfile.NamedTemporaryFile('w', suffix='.pub') as f:
        f.write(key_line + '\n')
        f.flush()
        p = subprocess.run(['ssh-keygen', '-l', '-f', f.name], capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        raise CatalogError('ssh-keygen does not read that as a public key')
    return p.stdout.split()[1]


def signers(conn: Conn) -> list[dict]:
    return [{'name': r[0], 'public_key': r[1], 'fingerprint': r[2], 'added_at': r[3], 'added_by': r[4]}
            for r in conn.all('SELECT name, public_key, fingerprint, added_at, added_by FROM toolbox_signers ORDER BY name')]


def add_signer(conn: Conn, name: str, key: str, actor: str) -> dict:
    name, key = (name or '').strip(), ' '.join((key or '').split()[:2])
    if not SIGNER_NAME.fullmatch(name):
        raise CatalogError('a signer is named in letters, digits and . _ @ -')
    if not KEY_LINE.fullmatch(key):
        raise CatalogError('give the public key as one line: ssh-ed25519 AAAA... (the private key stays where it is)')
    fp = fingerprint(key)
    if conn.scalar('SELECT 1 FROM toolbox_signers WHERE name = :n OR public_key = :k', {'n': name, 'k': key}):
        raise CatalogError('that name or that key is already a signer')
    conn.execute('INSERT INTO toolbox_signers (name, public_key, fingerprint, added_at, added_by) VALUES (:n, :k, :f, :t, :a)',
                 {'n': name, 'k': key, 'f': fp, 't': int(time.time()), 'a': actor[:60]})
    return {'name': name, 'public_key': key, 'fingerprint': fp}


def remove_signer(conn: Conn, name: str) -> bool:
    return bool(conn.execute('DELETE FROM toolbox_signers WHERE name = :n', {'n': name}).rowcount)


def sign_command(tool_id: str) -> str:
    """What the operator runs on their own machine, where the key is: the controller only verifies what comes back."""
    return f'ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n {NAMESPACE} {tool_id}.yaml    # writes {tool_id}.yaml.sig: paste it here'


# ── the official catalog ────────────────────────────────────────────
def manifest_of(entries: dict[str, str], serial: int) -> str:
    """The manifest that is signed: format, serial and each entry's SHA-256, as compact sorted JSON."""
    return json.dumps({'format': FORMAT, 'name': 'official', 'serial': int(serial), 'entries': {k: sha256(v) for k, v in sorted(entries.items())}},
                      sort_keys=True, separators=(',', ':')) + '\n'


def _official_from(manifest: str, sig: str | None, texts: dict[str, str], origin: str) -> dict:
    """One official catalog: its serial, how it is trusted, and its entries. A file that is not the one the manifest lists is refused,
    and with a release key in the package, so is a manifest it did not sign."""
    try:
        man = json.loads(manifest)
        serial, listed = int(man['serial']), dict(man['entries'])
    except (ValueError, KeyError, TypeError):
        return {'serial': -1, 'state': 'refused', 'why': f'the {origin} catalog manifest cannot be read', 'entries': {}}
    keys = release_signers()
    principal = verify(manifest, sig, keys) if keys else None
    if principal:
        state, why = 'release-signed', 'signed by the release key'
    elif keys:
        return {'serial': serial, 'state': 'refused', 'why': f'the {origin} catalog is not signed by the release key: nothing in it is offered', 'entries': {}}
    elif origin == 'packaged':
        state, why = 'packaged', 'came in the package with this version; there is no release key in it yet to sign the catalog'
    else:
        return {'serial': serial, 'state': 'refused', 'why': 'no release key is in this version, so no catalog update can be taken', 'entries': {}}
    entries = {}
    for tid, digest in listed.items():
        text = texts.get(tid)
        if text is None or sha256(text) != digest:
            entries[tid] = {'text': text or '', 'sha256': sha256(text) if text else '', 'state': 'refused',
                            'why': f'{tid} is not the file the {origin} manifest lists: it was changed after the catalog was made'}
        else:
            entries[tid] = {'text': text, 'sha256': digest, 'state': state, 'why': why}
    return {'serial': serial, 'state': state, 'why': why, 'entries': entries}


def packaged() -> dict:
    try:
        manifest = (CATALOG_DIR / 'catalog.json').read_text()
    except OSError:
        return {'serial': -1, 'state': 'refused', 'why': 'the package has no catalog manifest', 'entries': {}}
    try:
        sig = (CATALOG_DIR / 'catalog.json.sig').read_text()
    except OSError:
        sig = None
    texts = {}
    for f in sorted(CATALOG_DIR.glob('*.yaml')):
        try:
            texts[f.stem] = f.read_text()
        except (OSError, UnicodeError):
            continue  # the manifest verification below refuses unreadable entries
    return _official_from(manifest, sig, texts, 'packaged')


def official(conn: Conn) -> dict:
    """The official catalog in use: the packaged one, or an update taken since with a higher serial."""
    pk = packaged()
    rows = conn.all("SELECT id, spec_yaml, signature, manifest_json, serial FROM toolbox_catalog WHERE source = 'official' ORDER BY id")
    if rows:
        upd = _official_from(rows[0][3] or '', rows[0][2], {r[0]: r[1] for r in rows}, 'updated')
        if upd['state'] != 'refused' and upd['serial'] > pk['serial']:
            return upd | {'origin': 'update'}
    return pk | {'origin': 'package'}


def take_update(conn: Conn, manifest: str, signature: str, texts: dict[str, str], actor: str) -> dict:
    """An update of the official catalog: every entry valid, the manifest signed by the release key, its serial above the one in use."""
    if not isinstance(texts, dict) or not texts:
        raise CatalogError('the update has no entries')
    texts = {str(k): normal_text(v) for k, v in texts.items() if isinstance(v, str)}
    got = _official_from(manifest or '', signature, texts, 'updated')
    if got['state'] == 'refused':
        raise CatalogError(got['why'])
    bad = [e['why'] for e in got['entries'].values() if e['state'] == 'refused']
    if bad or set(got['entries']) != set(texts):
        raise CatalogError(bad[0] if bad else 'the update carries entries its manifest does not list')
    now = official(conn)
    if got['serial'] <= now['serial']:
        raise CatalogError(f'the update has serial {got["serial"]}, and the catalog in use has {now["serial"]}: an older catalog is not taken back')
    parsed = {}
    for tid, text in texts.items():
        e, problems = load_entry(text)
        if problems or e['id'] != tid:
            raise CatalogError(f'{tid}: ' + ('; '.join(problems[:3]) if problems else 'the file name and the id differ'))
        parsed[tid] = e
    t = int(time.time())
    with conn.tx():
        conn.execute("DELETE FROM toolbox_catalog WHERE source = 'official'")
        for tid, text in texts.items():
            conn.execute("""INSERT INTO toolbox_catalog (source, id, revision, category, spec_yaml, sha256, signature, signed_by, manifest_json, serial, added_at, added_by)
                            VALUES ('official', :i, :r, :c, :y, :s, :sig, 'release', :m, :n, :t, :a)""",
                         {'i': tid, 'r': parsed[tid]['revision'], 'c': parsed[tid]['category'], 'y': text, 's': sha256(text), 'sig': signature,
                          'm': manifest, 'n': got['serial'], 't': t, 'a': actor[:60]})
    return {'serial': got['serial'], 'entries': sorted(texts)}


# ── custom entries ──────────────────────────────────────────────────
def custom_rows(conn: Conn) -> list[dict]:
    return [{'id': r[0], 'text': r[1], 'sha256': r[2], 'signature': r[3], 'signed_by': r[4], 'added_at': r[5], 'added_by': r[6]}
            for r in conn.all("SELECT id, spec_yaml, sha256, signature, signed_by, added_at, added_by FROM toolbox_catalog WHERE source = 'custom' ORDER BY id")]


def _custom_trust(conn: Conn, text: str, sig: str | None, keys: str | None = None) -> tuple[str, str, str | None]:
    if not sig:
        return 'unsigned', 'not signed: it can be staged only by someone who may run commands as root, who accepts it for each host', None
    principal = verify(text, sig, operator_signers(conn) if keys is None else keys)
    if principal:
        return 'operator-signed', f'signed by {principal}, an operator key', principal
    return 'refused', 'its signature is not one of the operator keys over this text: it was changed after it was signed, or signed by another key', None


def save_custom(conn: Conn, text: str, signature: str | None, actor: str) -> dict:
    text = normal_text(text)
    e, problems = load_entry(text)
    if problems:
        raise CatalogError('; '.join(problems[:6]))
    if e['id'] in official(conn)['entries']:
        raise CatalogError(f'{e["id"]} is an official entry: a custom entry takes a name of its own (an override changes ports, volumes and exposure)')
    state, why, principal = _custom_trust(conn, text, (signature or '').strip() or None)
    if state == 'refused':
        raise CatalogError(why)
    t = int(time.time())
    params = {'i': e['id'], 'r': e['revision'], 'c': e['category'], 'y': text, 's': sha256(text), 'sig': (signature or '').strip() or None,
              'b': principal, 't': t, 'a': actor[:60]}
    with conn.tx():
        conn.execute("DELETE FROM toolbox_catalog WHERE source = 'custom' AND id = :i", params)
        conn.execute("""INSERT INTO toolbox_catalog (source, id, revision, category, spec_yaml, sha256, signature, signed_by, added_at, added_by)
                        VALUES ('custom', :i, :r, :c, :y, :s, :sig, :b, :t, :a)""", params)
    return {'id': e['id'], 'sha256': params['s'], 'state': state, 'why': why}


def sign_custom(conn: Conn, tool_id: str, signature: str) -> dict:
    """The signature made on the operator's machine, checked here and kept with the entry. Nothing is signed on the controller."""
    row = next((r for r in custom_rows(conn) if r['id'] == tool_id), None)
    if not row:
        raise LookupError(f'no custom entry {tool_id}')
    state, why, principal = _custom_trust(conn, row['text'], (signature or '').strip() or None)
    if state != 'operator-signed':
        raise CatalogError(why if state == 'refused' else 'paste the signature ssh-keygen wrote (the .sig file)')
    conn.execute("UPDATE toolbox_catalog SET signature = :s, signed_by = :b WHERE source = 'custom' AND id = :i",
                 {'s': signature.strip(), 'b': principal, 'i': tool_id})
    return {'id': tool_id, 'state': state, 'why': why}


def remove_custom(conn: Conn, tool_id: str) -> bool:
    return bool(conn.execute("DELETE FROM toolbox_catalog WHERE source = 'custom' AND id = :i", {'i': tool_id}).rowcount)


def validate(conn: Conn, text: str, signature: str | None = None) -> dict:
    """What the editor shows: the problems, the risk labels, and whether the signature given is one of the operator keys over this text."""
    text = normal_text(text or '')
    e, problems = load_entry(text)
    out = {'ok': not problems, 'problems': problems, 'sha256': sha256(text), 'text': text}
    if e and not problems:
        out['risks'] = risks(e)
        out['methods'] = [{'kind': m['kind'], 'label': METHOD_LABEL[m['kind']]} for m in e['methods']]
        if e['id'] in official(conn)['entries']:
            out['ok'] = False
            out['problems'] = [f'{e["id"]} is an official entry: give a custom entry a name of its own']
        out['sign'] = sign_command(e['id'])
    st, why, _ = _custom_trust(conn, text, (signature or '').strip() or None)
    out['signature'] = {'state': st, 'why': why}
    return out


# ── the catalog as offered ──────────────────────────────────────────
def _row(tid: str, text: str, digest: str, source: str, state: str, why: str, signed_by: str | None = None) -> dict:
    e, problems = load_entry(text) if text else (None, ['missing'])
    if problems and state != 'refused':
        state, why = 'refused', 'it does not pass the schema of this version: ' + '; '.join(problems[:3])
    out = {'id': tid, 'source': source, 'trust': state, 'trust_why': why, 'sha256': digest, 'signed_by': signed_by,
           'lab': 'lab-tested' if tid in LAB_PASSED else 'not lab-tested', 'text': text}
    if e and not problems:
        out.update({'name': e['name'], 'category': e['category'], 'summary': e['summary'], 'revision': e['revision'], 'app_version': e['app_version'],
                    'gui_level': e['gui']['level'], 'risks': risks(e), 'methods': [m['kind'] for m in e['methods']], 'entry': e,
                    'labels': [{'label': lb, 'means': LABELS[lb]} for lb in e['labels']], 'outside': e['outside'], 'license': e['license']})
    else:
        out.update({'name': tid, 'category': '', 'summary': '', 'revision': 0, 'app_version': '', 'gui_level': 'none', 'risks': [], 'methods': [], 'entry': None,
                    'labels': [], 'outside': '', 'license': ''})
    return out


def catalog(conn: Conn) -> list[dict]:
    off = official(conn)
    out = [_row(tid, x['text'], x['sha256'], 'official', x['state'], x['why'], 'release' if x['state'] == 'release-signed' else None)
           for tid, x in sorted(off['entries'].items())]
    seen = {x['id'] for x in out}
    keys = operator_signers(conn)
    for r in custom_rows(conn):
        if r['id'] in seen:
            continue
        st, why, principal = _custom_trust(conn, r['text'], r['signature'], keys)
        if sha256(r['text']) != r['sha256']:
            st, why = 'refused', 'the stored text is not the one that was saved'
        out.append(_row(r['id'], r['text'], r['sha256'], 'custom', st, why, principal))
    return out


def find(conn: Conn, tool_id: str) -> dict | None:
    return next((x for x in catalog(conn) if x['id'] == tool_id), None)


def public(row: dict, full: bool = False) -> dict:
    """An entry as the API gives it: without the parsed copy, and the text only when asked for."""
    out = {k: v for k, v in row.items() if k not in ('entry', 'text')}
    if full:
        out['text'] = row['text']
        e = row.get('entry')
        if e:
            out.update({'inputs': e['inputs'], 'exposure': e['exposure'], 'health': e['health'], 'backup': e['backup'], 'notes': e['notes'],
                        'homepage': e['homepage'], 'license': e['license'], 'gui': e['gui'], 'requires': e['requires'], 'steps': e['steps'],
                        'method_labels': {m['kind']: METHOD_LABEL[m['kind']] for m in e['methods']}, 'secrets': e['secrets'], 'mac': e['mac']})
    return out


TRUSTED = ('release-signed', 'packaged', 'operator-signed')


# ── overrides ───────────────────────────────────────────────────────
OVERRIDE_KEYS = ('ports', 'bind', 'exposure', 'volumes', 'method', 'image', 'env')
SYSTEM_PREFIXES = ('/etc', '/root', '/usr', '/boot', '/proc', '/sys', '/dev', '/run', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/var', '/tmp', '/snap')


def data_folder_ok(path: str) -> bool:
    """A folder a tool may keep its data in: a volume gets :Z (SELinux gives it to that container alone) and a rootless tool's account
    owns what it makes, so never a system folder or anything under one, never / and never a home folder itself."""
    p = '/' + path.strip('/')
    if p == '/' or any(p == s or p.startswith(s + '/') for s in SYSTEM_PREFIXES):
        return False
    return not (p == '/home' or (p.startswith('/home/') and p.count('/') == 2))


def load_override(text: str) -> tuple[dict, list[str]]:
    """An override: {ports: {container-port: host-port}, bind: address, exposure, volumes: {name: /host/path}, method, image}."""
    problems: list[str] = []
    if not (text or '').strip():
        return {}, []
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}, ['the override is not YAML']
    if not isinstance(raw, dict):
        return {}, ['an override is a mapping']
    out: dict = {}
    for k, v in raw.items():
        if k not in OVERRIDE_KEYS:
            problems.append(f'{k} cannot be overridden ({", ".join(OVERRIDE_KEYS)} can)')
        elif k == 'ports':
            if not isinstance(v, dict) or not all(str(a).isdigit() and isinstance(b, int) and 0 < b < 65536 for a, b in v.items()):
                problems.append('ports is {container-port: host-port}')
            else:
                out['ports'] = {int(a): int(b) for a, b in v.items()}
        elif k == 'bind':
            try:
                out['bind'] = str(ipaddress.ip_address(str(v)))
            except ValueError:
                problems.append('bind is one address of the host')
        elif k == 'exposure':
            if v not in EXPOSURES:
                problems.append(f'exposure is one of {", ".join(EXPOSURES)}')
            else:
                out['exposure'] = v
        elif k == 'volumes':
            if not isinstance(v, dict) or not all(isinstance(p, str) and CPATH.fullmatch(p) and '..' not in p.split('/') and data_folder_ok(p) for p in v.values()):
                problems.append('volumes is {name: /an/absolute/folder}, outside the system folders (/etc, /usr, /var, /root, /boot, /run and the like) '
                                'and not a home folder itself: the folder is relabelled for the container and given to its account')
            else:
                out['volumes'] = {str(a): b.rstrip('/') for a, b in v.items()}
        elif k == 'method':
            if v not in METHODS:
                problems.append(f'method is one of {", ".join(METHODS)}')
            else:
                out['method'] = v
        elif k == 'image':
            if not isinstance(v, str) or not IMAGE.fullmatch(v):
                problems.append('an image is pinned by digest: name:tag@sha256:...')
            else:
                out['image'] = v
        elif k == 'env':
            # a value of an environment variable the entry already sets (a server's own address, say); never a new one, never a secret
            if not isinstance(v, dict) or not all(ENV_KEY.fullmatch(str(a)) and not SECRETISH.search(str(a)) and isinstance(b, (str, int))
                                                  and not isinstance(b, bool) and ENV_VALUE.fullmatch(str(b)) for a, b in v.items()):
                problems.append('env is {NAME: value} for variables the entry sets, in letters, digits and . _ : / @ + = , - only, and never a secret')
            else:
                out['env'] = {str(a): str(b) for a, b in v.items()}
    return out, problems


def override_row(conn: Conn, host: str, tool_id: str) -> dict | None:
    r = conn.all('SELECT override_yaml, sha256, updated_at, updated_by FROM toolbox_overrides WHERE host = :h AND tool_id = :t', {'h': host, 't': tool_id})
    return {'text': r[0][0], 'sha256': r[0][1], 'updated_at': r[0][2], 'updated_by': r[0][3]} if r else None


def overrides(conn: Conn, host: str | None = None) -> list[dict]:
    rows = conn.all(f"SELECT host, tool_id, override_yaml, sha256, updated_at, updated_by FROM toolbox_overrides {'WHERE host = :h' if host else ''} ORDER BY host, tool_id", {'h': host})
    return [{'host': r[0], 'tool': r[1], 'text': r[2], 'sha256': r[3], 'updated_at': r[4], 'updated_by': r[5]} for r in rows]


def set_override(conn: Conn, host: str, tool_id: str, text: str, actor: str) -> dict | None:
    """Saves the override of one tool on one host, or removes it when text is empty. Kept apart from the entry: a catalog update leaves it."""
    if not (text or '').strip():
        conn.execute('DELETE FROM toolbox_overrides WHERE host = :h AND tool_id = :t', {'h': host, 't': tool_id})
        return None
    text = normal_text(text)
    _, problems = load_override(text)
    if problems:
        raise CatalogError('; '.join(problems))
    p = {'h': host, 't': tool_id, 'y': text, 's': sha256(text), 'n': int(time.time()), 'a': actor[:60]}
    with conn.tx():
        conn.execute('DELETE FROM toolbox_overrides WHERE host = :h AND tool_id = :t', p)
        conn.execute('INSERT INTO toolbox_overrides (host, tool_id, override_yaml, sha256, updated_at, updated_by) VALUES (:h, :t, :y, :s, :n, :a)', p)
    return override_row(conn, host, tool_id)


# ── the host, as the index knows it ─────────────────────────────────
def host_name(conn: Conn, host: str) -> str:
    r = conn.all('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h OR ip_address = :h ORDER BY host_id LIMIT 1', {'h': host})
    if not r:
        raise LookupError(f'{host} has not been scanned')
    return r[0][0]


def host_facts(conn: Conn, host: str) -> dict:
    """What choosing a method needs: the package manager, Podman and Docker, and whether deploys are refused on this system."""
    from . import inframeasure, preflight
    from .runtimes import docker
    facts = preflight.facts_from_scan(conn, host)
    pm_raw = (facts.get('pm') or '').lower()
    pm = next((p for p, words in (('apt', ('apt',)), ('dnf', ('dnf', 'yum')), ('zypper', ('zypper',)), ('pacman', ('pacman',))) if any(w in pm_raw for w in words)), None)
    tools = set((inframeasure.reading(conn, host) or {}).get('tools') or [])
    engines = {v.get('engine') for v in docker.listing(conn, host)}
    return {'pm': pm, 'podman': 'podman' in tools or 'podman' in engines, 'docker': 'docker' in engines, 'platform': facts.get('platform'),
            'scanned': facts.get('pm') is not None or bool(tools)}


def choose(e: dict, facts: dict, wanted: str | None = None) -> tuple[dict | None, str, bool]:
    """The method to use: (method, why, needs a runtime first). The one asked for, else the safest the host can take now, else the safest
    that needs only a container runtime installed first."""
    by = {m['kind']: m for m in e['methods']}
    if wanted:
        m = by.get(wanted)
        if not m:
            return None, f'{e["name"]} has no {wanted} method ({", ".join(by)})', False
        return m, f'{METHOD_LABEL[wanted]}, as asked', _needs_runtime(m, facts)
    for m in e['methods']:
        if not _usable(m, facts):
            continue
        return m, f'{METHOD_LABEL[m["kind"]]}: the safest method this host can take now', False
    for m in e['methods']:
        if m['kind'] in ('container', 'quadlet', 'compose'):
            return m, f'{METHOD_LABEL[m["kind"]]}: no method fits this host as it is, so Podman is installed first', True
    if facts.get('pm') is None and any(m['kind'] == 'package' for m in e['methods']):
        m = next(m for m in e['methods'] if m['kind'] == 'package')
        return m, 'distribution package: the last scan did not say which package manager this host has, so the script finds out', False
    return None, f'no method of {e["name"]} fits this host: ' + ', '.join(METHOD_LABEL[m['kind']] for m in e['methods']), False


def _usable(m: dict, facts: dict) -> bool:
    if m['kind'] in ('container', 'quadlet'):
        return facts.get('podman', False)
    if m['kind'] == 'compose':
        return facts.get('podman', False) or facts.get('docker', False)
    if m['kind'] == 'package':
        return bool(facts.get('pm')) and facts['pm'] in m['packages']
    return m['kind'] == 'binary'


def _needs_runtime(m: dict, facts: dict) -> bool:
    return m['kind'] in ('container', 'quadlet', 'compose') and not _usable(m, facts)


# ── what an install makes ───────────────────────────────────────────
def account_of(tool_id: str) -> str:
    return f'sf-{tool_id}'[:32]


def resolve(e: dict, m: dict, ovr: dict, exposure: str, bind: str) -> dict:
    """The values an install takes: ports with their address, host folders for volumes, the image. Overrides win over the entry."""
    exposure = ovr.get('exposure') or exposure or e['exposure']['default']
    bind = ovr.get('bind') or bind or ''
    addr = {'loopback': '127.0.0.1', 'management': bind, 'any': ''}[exposure]
    ports = []
    for p in m.get('ports') or []:
        host_port = (ovr.get('ports') or {}).get(p['container'], p['host'])
        ports.append({'bind': addr, 'host': host_port, 'container': p['container'], 'proto': p['proto']})
    names = set(m.get('volumes') or {}) | {n for sc in m.get('sidecars') or [] for n in sc.get('volumes') or {}}
    vols = {name: (ovr.get('volumes') or {}).get(name, f'{DATA_ROOT}/{e["id"]}/{name}') for name in sorted(names)}
    env = dict(m.get('env') or {})
    env.update({k: v for k, v in (ovr.get('env') or {}).items() if k in env})
    return {'exposure': exposure, 'bind': addr, 'ports': ports, 'volumes': vols, 'image': ovr.get('image') or m.get('image') or '', 'env': env,
            'env_ignored': sorted(k for k in (ovr.get('env') or {}) if k not in env)}


def image_verification_words(m: dict, image: str) -> list[str]:
    """Exact images and their cataloged keys, ready to pass to the host as pairs."""
    if not m.get('cosign_key'):
        return []
    if not _qualified_image(image):
        raise CatalogError('Cosign needs an explicit registry host in the image override')
    return [image, m['cosign_key'], *(v for sc in m.get('sidecars', []) for v in (sc['image'], sc['cosign_key']))]


def publish(p: dict) -> str:
    return f'{p["bind"] + ":" if p["bind"] else ""}{p["host"]}:{p["container"]}/{p["proto"]}'


def quadlet_text(e: dict, m: dict, r: dict, rootless: bool) -> str:
    """The Quadlet unit for a container method. Every value was checked by the schema, so none can end a line or carry a % to expand."""
    lines = [f'# Written by StorageForge for the Toolbox entry {e["id"]}, revision {e["revision"]}. The next install of the entry writes it again.',
             '[Unit]', f'Description={e["name"]} (StorageForge Toolbox)', 'After=network-online.target', '', '[Container]',
             f'ContainerName=sf-{e["id"]}', f'Image={r["image"]}', 'Label=storageforge.managed=true', f'Label=storageforge.tool={e["id"]}',
             f'Label=storageforge.revision={e["revision"]}', 'NoNewPrivileges=true']
    lines += [f'PublishPort={publish(p)}' for p in r['ports']]
    lines += [f'Volume={r["volumes"][name]}:{target}:{"Z,U" if m.get("volume_owner") else "Z"}' for name, target in sorted((m.get('volumes') or {}).items())]
    if e.get('secrets'):
        lines.append(f'Volume={DATA_ROOT}/{e["id"]}/secrets:/run/secrets/{e["id"]}:{"ro,Z,U" if m.get("volume_owner") else "ro,Z"}')
    lines += [f'Volume={DATA_ROOT}/{e["id"]}/files/{name}:{f["path"]}:{"ro,Z,U" if m.get("volume_owner") else "ro,Z"}' for name, f in sorted((m.get('files') or {}).items())]
    if m.get('engine_socket'):        # its own account's Podman socket, which the step switches on: %t is that account's runtime folder
        lines += ['Volume=%t/podman/podman.sock:/var/run/docker.sock', 'SecurityLabelDisable=true']
    lines += [f'Environment={k}={v}' for k, v in sorted(r.get('env', m.get('env') or {}).items())]
    if m.get('drop_caps'):
        lines.append('DropCapability=ALL')
    lines += [f'AddCapability={c}' for c in m.get('caps') or []]
    if m.get('network') == 'host':
        lines.append('Network=host')
    if m.get('read_only'):
        lines.append('ReadOnly=true')
    if m.get('user'):
        lines.append(f'User={m["user"]}')
    if m.get('args'):
        lines.append('Exec=' + ' '.join(m['args']))
    lines += ['', '[Service]', 'Restart=always', 'TimeoutStartSec=600', '', '[Install]', f'WantedBy={"default.target" if rootless else "multi-user.target"}']
    return '\n'.join(lines) + '\n'


def compose_text(e: dict, m: dict, r: dict) -> str:
    parts = [m, *(m.get('sidecars') or [])]
    used = [n for p in parts for n in (p.get('volumes') or {})]
    r = dict(r, shared={n for n in used if used.count(n) > 1} | ({'secrets'} if len(parts) > 1 else set()))
    services = {e['id']: _compose_service(e, m, r, r['image'], f'sf-{e["id"]}', r.get('env', m.get('env') or {}))}
    if r['ports']:
        services[e['id']]['ports'] = [publish(p) for p in r['ports']]
    for sc in m.get('sidecars') or []:       # reached by the tool by its name inside the stack; it publishes nothing
        services[sc['name']] = _compose_service(e, sc, r, sc['image'], f'sf-{e["id"]}-{sc["name"]}', sc.get('env') or {}, part=sc['name'])
    if m.get('sidecars'):
        services[e['id']]['depends_on'] = [sc['name'] for sc in m['sidecars']]
    return yaml.safe_dump({'services': services}, sort_keys=False)


def _compose_service(e: dict, m: dict, r: dict, image: str, name: str, env: dict, part: str = '') -> dict:
    svc = {'image': image, 'container_name': name, 'restart': 'unless-stopped',
           'labels': {'storageforge.managed': 'true', 'storageforge.tool': e['id'], 'storageforge.revision': str(e['revision']), **({'storageforge.part': part} if part else {})},
           'security_opt': ['no-new-privileges:true']}
    # :Z gives a folder to one container alone; a folder two services of the stack mount (the secrets, say) takes :z, shared by them
    shared = r.get('shared') or set()
    vols = [f'{r["volumes"][n]}:{t}:{"z" if n in shared else "Z"}' for n, t in sorted((m.get('volumes') or {}).items())]
    if e.get('secrets'):
        vols.append(f'{DATA_ROOT}/{e["id"]}/secrets:/run/secrets/{e["id"]}:{"ro,z" if "secrets" in shared else "ro,Z"}')
    vols += [f'{DATA_ROOT}/{e["id"]}/files/{fname}:{f["path"]}:ro,Z' for fname, f in sorted((m.get('files') or {}).items())]
    if vols:
        svc['volumes'] = vols
    if env:
        svc['environment'] = dict(sorted(env.items()))
    if m.get('args'):
        svc['command'] = list(m['args'])
    if m.get('caps'):
        svc['cap_add'] = list(m['caps'])
    if m.get('drop_caps'):
        svc['cap_drop'] = ['ALL']
    if m.get('network') == 'host':
        svc['network_mode'] = 'host'
    if m.get('read_only'):
        svc['read_only'] = True
    if m.get('user'):
        svc['user'] = m['user']
    return svc


def made(e: dict, m: dict, r: dict, facts: dict | None = None) -> dict:
    """What an install of this method makes on the host: what removing it takes away, and the data it leaves."""
    out = {'method': m['kind'], 'data': sorted(set(r['volumes'].values())) + ([f'{DATA_ROOT}/{e["id"]}/secrets'] if e.get('secrets') else []),
           'ports': [publish(p) for p in r['ports']], 'exposure': r['exposure']}
    if m['kind'] == 'container':
        out.update(account=account_of(e['id']), unit=f'{e["id"]}.service', quadlet=f'{TOOLS_HOME}/{e["id"]}/.config/containers/systemd/{e["id"]}.container')
    elif m['kind'] == 'quadlet':
        out.update(unit=f'{e["id"]}.service', quadlet=f'/etc/containers/systemd/{e["id"]}.container')
    elif m['kind'] == 'compose':
        out.update(stack=f'sf-{e["id"]}', dir=f'{DATA_ROOT}/{e["id"]}/compose', runtime='podman' if (facts or {}).get('podman') and not (facts or {}).get('docker') else 'docker')
    elif m['kind'] == 'package':
        out.update(packages=m['packages'], units=m['units'], socket=m['socket'])
    elif m['kind'] == 'binary':
        out.update(binary=f'/usr/local/bin/{m["name"]}')
    return out


# ── staging ─────────────────────────────────────────────────────────
def installs(conn: Conn, host: str | None = None) -> list[dict]:
    rows = conn.all(f"""SELECT id, host, tool_id, revision, sha256, method, params_json, status, plan_id, managed_by, unsigned_by, staged_at, staged_by, updated_at
                        FROM toolbox_installs {'WHERE host = :h' if host else ''} ORDER BY host, tool_id""", {'h': host})
    return [{'id': r[0], 'host': r[1], 'tool': r[2], 'revision': r[3], 'sha256': r[4], 'method': r[5], 'params': json.loads(r[6] or '{}'), 'status': r[7],
             'plan_id': r[8], 'managed_by': r[9], 'unsigned_by': r[10], 'staged_at': r[11], 'staged_by': r[12], 'updated_at': r[13]} for r in rows]


def install_of(conn: Conn, host: str, tool_id: str) -> dict | None:
    return next((i for i in installs(conn, host) if i['tool'] == tool_id), None)


def preview(conn: Conn, host: str, tool_id: str, method: str | None = None, inputs: dict | None = None, exposure: str | None = None,
            bind: str | None = None, allow_from: str | None = None, row: dict | None = None) -> dict:
    """The plan an install would be, and the report beside it: method and why, risk labels, what is kept, what to watch. Saves nothing.
    row: an entry not in the catalog yet (the editor's dry run)."""
    from . import changes, preflight
    host = host_name(conn, host)
    row = row or find(conn, tool_id)
    if not row:
        raise LookupError(f'no catalog entry {tool_id}')
    e = row['entry']
    report: list[dict] = []
    say = lambda level, text: report.append({'level': level, 'text': text})      # noqa: E731
    if not e or row['trust'] == 'refused':
        raise CatalogError(f'{tool_id} cannot be staged: {row["trust_why"]}')
    facts = host_facts(conn, host)
    if facts.get('platform') in preflight.APPLIANCES:
        raise CatalogError(f'{host}: {preflight.APPLIANCES[facts["platform"]]}')
    ovr_row = override_row(conn, host, e['id'])
    ovr, problems = load_override(ovr_row['text']) if ovr_row else ({}, [])
    for p in problems:
        say('warn', f'the override of {e["id"]} on {host} is left out: {p}')
    m, why, runtime_first = choose(e, facts, method or ovr.get('method'))
    if not m:
        raise CatalogError(why)
    exposure = exposure or None
    if exposure and exposure not in EXPOSURES:
        raise CatalogError(f'exposure is one of {", ".join(EXPOSURES)}')
    r = resolve(e, m, ovr, exposure or '', bind or '')
    if r['exposure'] == 'management' and not r['bind']:
        raise CatalogError('management exposure binds to one address of the host: give it')
    verification = image_verification_words(m, r['image'])
    for image in verification[::2]:
        say('note', f'Cosign verifies {image} with the catalog publisher key on apply, before installing the tool')
    say('note', f'method: {why}')
    say('ok' if row['trust'] in ('release-signed', 'operator-signed') else 'note' if row['trust'] == 'packaged' else 'warn',
        f'{e["name"]}, entry revision {e["revision"]}: {row["trust_why"]}')
    if row['lab'] != 'lab-tested':
        say('note', f'{e["name"]} is not lab-tested')
    for k in ('ports', 'volumes', 'image', 'exposure', 'bind', 'method', 'env'):
        if k in ovr:
            say('note' if k != 'image' else 'warn', f'overridden on {host}: {k} ({ovr_row["updated_by"]})')
    for rk in risks(e, m['kind'], r['exposure']):
        say('warn', f'risk: {rk["title"]}: {rk["means"]}. {rk["mitigation"]}')
    for lb in e['labels']:
        say('warn' if lb in ('outside-account', 'non-commercial', 'source-available') else 'note', f'{e["name"]} {LABELS[lb]}' + (f': {e["outside"]}' if lb.startswith('outside') and e['outside'] else ''))
    for k in r['env_ignored']:
        say('warn', f'the override sets env {k}, which {e["name"]} does not set: it is left out')
    if r['exposure'] == 'loopback' and r['ports']:
        say('note', f'listens on 127.0.0.1 only: reach it through SSH (ssh -L {r["ports"][0]["host"]}:127.0.0.1:{r["ports"][0]["host"]} {host}) or a reverse proxy')
    elif r['exposure'] == 'any' and not allow_from and (r['ports'] or m['kind'] == 'package'):
        say('warn', f'open to every network {host} is on: give the addresses allowed to reach it, or keep it on loopback')
    if allow_from and m['kind'] in ('quadlet',):
        say('crit', 'a container run by root Podman publishes past the host firewall: bind it to one address instead of fencing it')
    cleaned = {}
    for inp in e['inputs']:
        v = str((inputs or {}).get(inp['name']) or inp['default'] or '')
        if not v or not changes.CHECKS[inp['kind']].fullmatch(v):
            raise CatalogError(f'{inp["label"]}: {v!r} is not a valid {inp["kind"]}')
        cleaned[inp['name']] = v
    tasks = []
    if runtime_first:
        tasks.append({'host': host, 'type': 'runtime-install', 'params': {'runtime': 'podman', 'source': 'distro', 'rootless': False, 'user': ''},
                      'note': f'for {e["name"]}'})
        say('note', 'Podman is installed first, from the distribution: no method of this entry runs without a container runtime here')
    for s in e['secrets']:
        name = f'tool-{e["id"]}-{s["name"]}'
        from . import secretstore
        if not secretstore.meta(conn, name):
            say('crit', f'make the secret {name} ({s["kind"]}) under Keys, Secrets for plan steps, before this plan is applied')
        tasks.append({'host': host, 'type': 'secret-file', 'params': {'secret': name, 'path': f'{DATA_ROOT}/{e["id"]}/secrets/{s["name"]}',
                      'owner': account_of(e['id']) if m['kind'] == 'container' else (m.get('volume_owner') or 'root') if m['kind'] == 'compose' else 'root',
                      'mode': '0600', 'state': 'present'}, 'note': f'for {e["name"]}'})
    ovr_sha = ovr_row['sha256'] if ovr_row and not problems else ''
    tasks.append({'host': host, 'type': 'tool-install', 'params': {'tool': e['id'], 'method': m['kind'], 'sha': row['sha256'], 'override': ovr_sha,
                  'exposure': r['exposure'], 'bind': r['bind'] if r['exposure'] == 'management' else '', 'allow_from': allow_from or ''},
                  'note': f'{e["name"]} from the Toolbox catalog'})
    for st in e['steps']:
        params = {k: re.sub(r'\{([a-z0-9_]+)\}', lambda mm: cleaned[mm[1]], v) for k, v in st['params'].items()}
        tasks.append({'host': host, 'type': st['type'], 'params': params, 'note': f'part of {e["name"]}'})
    from . import tbstorage
    tasks += tbstorage.wire(conn, host, e, m, r, allow_from, say)       # a storage-facing app: placement, WORM, decoys and its fence
    if e['backup']['paths']:
        say('note', 'its data: ' + ', '.join(r['volumes'].get(p, p) for p in e['backup']['paths']) + f' ({e["backup"]["consistency"]}); removing the tool keeps it')
    for note in (e['mac'].get('notes'),):
        if note:
            say('note', f'MAC: {note}')
    if e['notes']:
        say('note', e['notes'])
    if row['trust'] == 'unsigned':
        say('warn', 'this entry is not signed: whoever accepts it vouches for every command it leads to on this host')
    return {'host': host, 'tool': e['id'], 'name': e['name'], 'method': m['kind'], 'method_label': METHOD_LABEL[m['kind']], 'why': why,
            'trust': row['trust'], 'sha256': row['sha256'], 'resolved': r, 'made': made(e, m, r, facts), 'tasks': tasks, 'report': report,
            'risks': risks(e, m['kind'], r['exposure']), 'runtime_first': runtime_first}


def _plan_name(conn: Conn, base: str) -> str:
    name, n = base[:80], 2
    while conn.scalar('SELECT 1 FROM change_plans WHERE lower(name) = lower(:n)', {'n': name}):
        name, n = f'{base[:74]} ({n})', n + 1
    return name


def stage(conn: Conn, host: str, tool_id: str, actor: str, *, method=None, inputs=None, exposure=None, bind=None, allow_from=None,
          accept_unsigned: bool = False) -> dict:
    """Saves the plan of an install and records the install as staged. Nothing runs: the plan is deployed like any other, report first."""
    from . import changes
    pv = preview(conn, host, tool_id, method, inputs, exposure, bind, allow_from)
    if pv['trust'] == 'unsigned' and not accept_unsigned:
        raise CatalogError(f'{tool_id} is not signed: accept it for {pv["host"]} to stage it, or sign it with an operator key')
    if any(x['level'] == 'crit' for x in pv['report'] if 'secret' not in x['text']):
        raise CatalogError('; '.join(x['text'] for x in pv['report'] if x['level'] == 'crit'))
    plan_id = changes.save_plan(conn, {'name': _plan_name(conn, f'Toolbox: install {pv["name"]} on {pv["host"]}'), 'tasks': pv['tasks']}, actor)
    return record_install(conn, pv, plan_id, actor)


def record_install(conn: Conn, pv: dict, plan_id: int, actor: str) -> dict:
    """The install of a preview recorded as staged in the plan plan_id (an install of its own, or one tool of a bundle), and its decoy
    folders added to the host's sentinel configuration when it is a storage-facing app (tbstorage.py)."""
    from . import tbstorage
    t = int(time.time())
    rev = find(conn, pv['tool'])['revision']
    p = {'h': pv['host'], 't': pv['tool'], 'r': rev, 's': pv['sha256'], 'm': pv['method'], 'j': json.dumps(pv['made']), 'p': plan_id,
         'u': actor[:60] if pv['trust'] == 'unsigned' else None, 'n': t, 'a': actor[:60]}
    with conn.tx():
        conn.execute('DELETE FROM toolbox_installs WHERE host = :h AND tool_id = :t', p)
        conn.execute("""INSERT INTO toolbox_installs (host, tool_id, revision, sha256, method, params_json, status, plan_id, managed_by, unsigned_by, staged_at, staged_by, updated_at)
                        VALUES (:h, :t, :r, :s, :m, :j, 'staged', :p, 'storageforge', :u, :n, :a, :n)""", p)
    return pv | {'plan_id': plan_id, 'decoy_folders_added': tbstorage.after_stage(conn, pv, actor)}


def stage_remove(conn: Conn, host: str, tool_id: str, actor: str, with_data: bool = False) -> dict:
    """The plan of a removal: the program goes and its data stays. with_data adds a destructive step that moves the data to the host's trash."""
    from . import changes
    host = host_name(conn, host)
    inst = install_of(conn, host, tool_id)
    if not inst or inst['managed_by'] != 'storageforge':
        raise LookupError(f'{tool_id} was not installed on {host} by StorageForge: there is nothing of it here to remove')
    tasks = [{'host': host, 'type': 'tool-remove', 'params': {'tool': tool_id, 'method': inst['method']}, 'note': 'its data stays'}]
    if with_data and inst['params'].get('data'):
        tasks.append({'host': host, 'type': 'tool-data-remove', 'params': {'tool': tool_id, 'confirm': tool_id}, 'note': 'moved to the host trash'})
    name = (find(conn, tool_id) or {}).get('name') or tool_id
    plan_id = changes.save_plan(conn, {'name': _plan_name(conn, f'Toolbox: remove {name} from {host}'), 'tasks': tasks}, actor)
    conn.execute("UPDATE toolbox_installs SET status = 'remove-staged', plan_id = :p, updated_at = :n WHERE id = :i",
                 {'p': plan_id, 'n': int(time.time()), 'i': inst['id']})
    return {'host': host, 'tool': tool_id, 'plan_id': plan_id, 'tasks': tasks, 'kept': inst['params'].get('data') or []}


# ── at script time: the words a tool step runs with ─────────────────
def install_words(conn: Conn, t: dict) -> list[str]:
    """verdict, why, and the method's values, taken from the catalog as it is now. A refusal reaches the host as a conflict and does nothing."""
    p = t['params']
    try:
        host = host_name(conn, t['host'])
    except LookupError:
        return ['refused', f'{t["host"]} has not been scanned']
    row = find(conn, p['tool'])
    if not row or not row['entry']:
        return ['refused', f'there is no catalog entry {p["tool"]} it can be installed from']
    if row['trust'] == 'refused':
        return ['refused', f'{p["tool"]}: {row["trust_why"]}']
    if row['sha256'] != p['sha']:
        return ['refused', f'the catalog entry {p["tool"]} changed after this step was staged: stage it again from the Toolbox']
    if row['trust'] == 'unsigned':
        inst = install_of(conn, host, p['tool'])
        if not inst or inst['sha256'] != p['sha'] or not inst['unsigned_by']:
            return ['refused', f'{p["tool"]} is not signed, and nobody accepted it for {host}']
    e = row['entry']
    ovr_row = override_row(conn, host, e['id'])
    if (ovr_row['sha256'] if ovr_row else '') != (p.get('override') or ''):
        return ['refused', f'the override of {p["tool"]} on {host} changed after this step was staged: stage it again']
    ovr, problems = load_override(ovr_row['text']) if ovr_row else ({}, [])
    if problems:
        ovr = {}
    m = next((x for x in e['methods'] if x['kind'] == p['method']), None)
    if not m:
        return ['refused', f'{p["tool"]} has no {p["method"]} method']
    r = resolve(e, m, ovr, p.get('exposure') or '', p.get('bind') or '')
    if r['exposure'] == 'management' and not r['bind']:
        return ['refused', 'management exposure needs the address to bind to']
    why = f'{e["name"]}, entry revision {e["revision"]}, {row["trust_why"]}'
    try:
        verification = image_verification_words(m, r['image'])
    except CatalogError as exc:
        return ['refused', str(exc)]
    if m['kind'] in ('container', 'quadlet'):
        rootless = m['kind'] == 'container'
        dirs = ','.join(sorted(set(r['volumes'].values())) + ([f'{DATA_ROOT}/{e["id"]}/secrets'] if e['secrets'] else []))
        ports = ','.join(f'{x["host"]}/{x["proto"]}' for x in r['ports'])
        return ['ok', why, quadlet_text(e, m, r, rootless), account_of(e['id']) if rootless else '', dirs, ports, r['image'],
                '1' if m.get('engine_socket') else '', *file_words(e, m), *verification]
    if m['kind'] == 'compose':
        from . import steps_workloads
        facts = host_facts(conn, host)
        runtime = 'podman' if facts.get('podman') and not facts.get('docker') else 'docker'
        text = compose_text(e, m, r)
        model = steps_workloads.compose_model(text)
        if model['error']:
            return ['refused', f'the compose file made for {e["id"]} is not one: {model["error"]}']
        override = steps_workloads.override(f'sf-{e["id"]}', model, {'storageforge.tool': e['id']})
        dirs = ','.join(sorted(set(r['volumes'].values())))
        ports = steps_workloads.fenced_ports([x for s in model['services'].values() for x in s['ports']])
        return ['ok', why, runtime, f'sf-{e["id"]}', text, f'{DATA_ROOT}/{e["id"]}/compose', override, ports, dirs,
                m.get('volume_owner') or '', *file_words(e, m), *verification]
    if m['kind'] == 'package':
        sock = m['socket'] or {}
        listen = '' if not sock else (f'{r["bind"]}:{sock["port"]}' if r['bind'] else str(sock['port']))
        return ['ok', why, *(','.join(m['packages'].get(pm, [])) for pm in PMS), ','.join(m['units']), sock.get('unit', ''), listen, str(sock.get('port', ''))]
    if m['kind'] == 'binary':
        f = m['files']
        files = [f.get(arch, {}) for arch in ('x86_64', 'aarch64')]
        signatures = []
        for file in files:
            verifier = next((name for name in ('minisign', 'cosign') if name in file), '')
            signature = file.get(verifier, {})
            signatures.extend((verifier, signature.get('url', ''), signature.get('public_key', '')))
        return ['ok', why, m['name'], *(file.get(key, '') for file in files for key in ('url', 'sha256')),
                *(file.get('archive', {}).get(key, '') for file in files for key in ('member', 'sha256')),
                *signatures]
    return ['refused', f'{m["kind"]} cannot be installed by this version']


def file_words(e: dict, m: dict) -> list[str]:
    """The folder of the small files an entry gives its container, and the files as name=base64 words joined by commas: the text was
    checked by the schema and reaches the host as data, never as a command."""
    import base64
    files = m.get('files') or {}
    if not files:
        return ['', '']
    return [f'{DATA_ROOT}/{e["id"]}/files', ','.join(f'{n}={base64.b64encode(f["text"].encode()).decode()}' for n, f in sorted(files.items()))]


def remove_words(conn: Conn, t: dict, data: bool = False) -> list[str]:
    """What the install made, from its record: removal needs no trusted entry, since it only stops and takes away what was put there."""
    p = t['params']
    try:
        host = host_name(conn, t['host'])
    except LookupError:
        return ['refused', f'{t["host"]} has not been scanned']
    inst = install_of(conn, host, p['tool'])
    if not inst or inst['managed_by'] != 'storageforge':
        return ['refused', f'StorageForge has no record of installing {p["tool"]} on {host}']
    mk = inst['params']
    if data:
        return ['ok', f'{p["tool"]} as staged {inst["staged_by"] and "by " + inst["staged_by"]}', ','.join(mk.get('data') or [])]
    if inst['method'] != p['method']:
        return ['refused', f'{p["tool"]} was installed as {inst["method"]}, not {p["method"]}']
    keep = ','.join(mk.get('data') or [])
    if inst['method'] in ('container', 'quadlet'):
        return ['ok', f'{p["tool"]}, installed as {METHOD_LABEL[inst["method"]]}', mk.get('account') or '', mk.get('unit') or '', mk.get('quadlet') or '', keep]
    if inst['method'] == 'compose':
        return ['ok', f'{p["tool"]}, installed as a compose stack', mk.get('runtime') or 'docker', mk.get('stack') or '', mk.get('dir') or '', keep]
    if inst['method'] == 'package':
        pk = mk.get('packages') or {}
        return ['ok', f'{p["tool"]}, installed from packages', *(','.join(pk.get(pm, [])) for pm in PMS), ','.join(mk.get('units') or []),
                (mk.get('socket') or {}).get('unit', ''), keep]
    if inst['method'] == 'binary':
        return ['ok', f'{p["tool"]}, installed as a binary', mk.get('binary') or '', keep]
    return ['refused', f'{inst["method"]} cannot be removed by this version']


# ── updates ─────────────────────────────────────────────────────────
def updates(conn: Conn) -> list[dict]:
    """Each install whose entry has a newer revision in the catalog, or whose entry is no longer trusted. Nothing is applied: an update
    is staged as an install again, and its report shows what changes."""
    out = []
    cat = {x['id']: x for x in catalog(conn)}
    for i in installs(conn):
        if i['status'] in ('removed',):
            continue
        row = cat.get(i['tool'])
        if not row or not row['entry']:
            out.append({'host': i['host'], 'tool': i['tool'], 'state': 'gone', 'why': 'its entry is no longer in the catalog'})
        elif row['trust'] == 'refused':
            out.append({'host': i['host'], 'tool': i['tool'], 'state': 'refused', 'why': row['trust_why']})
        elif row['sha256'] != i['sha256']:
            out.append({'host': i['host'], 'tool': i['tool'], 'state': 'update', 'from_revision': i['revision'], 'to_revision': row['revision'],
                        'app_version': row['app_version'], 'why': f'revision {row["revision"]} of the entry is in the catalog; {i["revision"]} was staged'})
    return out


def write_manifest(serial: int, folder: Path | None = None) -> Path:
    """catalog.json for the YAML files in folder, to be signed with the release key: ssh-keygen -Y sign -n storageforge-catalog catalog.json."""
    folder = Path(folder or CATALOG_DIR)
    texts = {f.stem: f.read_text() for f in sorted(folder.glob('*.yaml'))}
    for tid, text in texts.items():
        e, problems = load_entry(text)
        if problems or e['id'] != tid:
            raise CatalogError(f'{tid}: ' + ('; '.join(problems[:3]) if problems else 'the file name and the id differ'))
    out = folder / 'catalog.json'
    out.write_text(manifest_of(texts, serial))
    return out


if __name__ == '__main__':          # python -m storageforge_index.toolbox manifest SERIAL: catalog/catalog.json, for the release key to sign
    import sys
    if len(sys.argv) != 3 or sys.argv[1] != 'manifest' or not sys.argv[2].isdigit():
        sys.exit('usage: python -m storageforge_index.toolbox manifest SERIAL')
    print(write_manifest(int(sys.argv[2])))
