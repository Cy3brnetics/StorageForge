"""Deploys from the web UI: StorageForge signs a script, a restricted runner on the host checks it and runs it as root.

    vault: storageforge-signing (ed25519) ──SSHSIG──► request = header (host, issued, nonce, args) + script + signature
    vault: storageforge-deploy  (ed25519) ──ssh──► storageforge-deploy@host
        authorized_keys: restrict,command="sudo -n /usr/local/sbin/storageforge-run"    (whatever ssh asks for)
        sudoers:         storageforge-run, storageforge-job --serve *                     (nothing else)
        storageforge-run: verify the signature (ssh-keygen -Y verify), this host (short name, and the machine id
                          from its last scan), issued < 10 min ago, nonce unused (claimed atomically),
                          then bash <script> <args> as root; output and exit code come back over ssh

The deploy key alone runs nothing: every request needs a fresh signature from the signing key, which never leaves
the vault. Setting a host up takes root once: a sudo password typed into the request (never stored), or the
setup script run by hand. See deployments-design.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import struct
import subprocess
import threading
import time
import traceback
import uuid
from contextlib import contextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .db import Database
from .moves import host_slug
from .remote import RemoteError, Transport, child_env
from .runner import connect_address, ephemeral_agent, known_hosts_path
from .vault import AuditLog, NoBinding, Vault, VaultError, actor_name

SIGNING_KEY = 'storageforge-signing'
DEPLOY_KEY = 'storageforge-deploy'
DEPLOY_USER = 'storageforge-deploy'
NAMESPACE = 'storageforge-deploy'
RUNNER = '/usr/local/sbin/storageforge-run'
JOBBIN = '/usr/local/sbin/storageforge-job'
MAX_OUTPUT = 256 * 1024
ARG_RE = re.compile(r'[A-Za-z0-9=_./:,@+-]{1,200}')
REFUSED = 97                                   # the runner's exit code for a request it would not run
UNFINISHED = re.compile(r'^  (?:\x1b\[[0-9;]*m)?missing\b', re.M)   # during an apply, a "missing" line is a step not done
FINISHED = ('ok', 'incomplete')                # the script ran to its end; 'incomplete' left steps for the operator
_host_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class DeployError(RuntimeError):
    pass


# ── signatures (OpenSSH SSHSIG, verified on hosts with ssh-keygen -Y verify) ──
def _s(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def sshsig(key: ed25519.Ed25519PrivateKey, message: bytes, namespace: str = NAMESPACE) -> str:
    """An armored SSH signature of message, as ssh-keygen -Y sign writes it (PROTOCOL.sshsig, sha512)."""
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signed = b'SSHSIG' + _s(namespace.encode()) + _s(b'') + _s(b'sha512') + _s(hashlib.sha512(message).digest())
    blob = (b'SSHSIG' + struct.pack('>I', 1) + _s(_s(b'ssh-ed25519') + _s(pub)) + _s(namespace.encode()) + _s(b'')
            + _s(b'sha512') + _s(_s(b'ssh-ed25519') + _s(key.sign(signed))))
    b64 = base64.b64encode(blob).decode()
    return ('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(b64[i:i + 70] for i in range(0, len(b64), 70))
            + '\n-----END SSH SIGNATURE-----\n')


def request(key: ed25519.Ed25519PrivateKey, host: str, script: str, args=(), now: float | None = None,
            machine: str | None = None, nonce: str | None = None) -> bytes:
    """The bytes storageforge-run reads from stdin: a signed header + script for one host, usable once. machine is
    the host's /etc/machine-id (from its scans): when given, no other machine runs it, even one with the same name."""
    for a in args:
        if not ARG_RE.fullmatch(a):
            raise ValueError(f'argument not allowed: {a!r}')
    if machine and not re.fullmatch(r'[0-9a-f]{32}', machine):
        raise ValueError('bad machine id')
    nonce = nonce or secrets.token_hex(16)
    if not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('bad nonce')
    header = (f'host: {host_slug(host)}\nissued: {int(now or time.time())}\nnonce: {nonce}\n'
              + (f'machine: {machine}\n' if machine else '') + f'args: {" ".join(args)}\n\n')
    payload = (header + script).encode()
    sig = sshsig(key, payload).encode()
    return f'STORAGEFORGE-RUN 1\n{len(payload)}\n{len(sig)}\n'.encode() + payload + sig


# ── what goes on the host ───────────────────────────────────────────
RUNNER_SCRIPT = r"""#!/bin/bash
# storageforge-run: runs a script as root only if StorageForge signed it for this host in the last 10 minutes.
# Installed by the StorageForge deploy setup. storageforge-deploy's SSH key can start nothing else (forced command).
set -uo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
ETC=/etc/storageforge STATE=/var/lib/storageforge/run LOG=/var/log/storageforge/run.log MID=/etc/machine-id
[[ -r $MID ]] || MID=/var/lib/dbus/machine-id
if ((EUID != 0)); then   # tests run it unprivileged; under sudo the environment is reset, so root never sees these
  ETC=${STORAGEFORGE_RUN_ETC:-$ETC} STATE=${STORAGEFORGE_RUN_STATE:-$STATE} LOG=${STORAGEFORGE_RUN_LOG:-$LOG}
  MID=${STORAGEFORGE_RUN_MACHINE_ID:-$MID}
fi
log() { mkdir -p "${LOG%/*}" 2>/dev/null; printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null || true; }
die() { echo "storageforge-run: $*" >&2; log "refused: $*"; exit 97; }
slug() { local n=${1%%.*}; n=$(tr 'A-Z' 'a-z' <<<"$n" | tr -cd 'a-z0-9_-'); echo "${n:-unknown}"; }

IFS= read -r magic || die "no request"
[[ $magic == 'STORAGEFORGE-RUN 1' ]] || die "not a StorageForge request"
IFS= read -r plen || die "no length"
IFS= read -r slen || die "no length"
[[ $plen =~ ^[0-9]{1,8}$ && $slen =~ ^[0-9]{1,5}$ ]] || die "bad lengths"
payload= sig=
IFS= read -r -d '' -N "$plen" payload
((${#payload} == plen)) || die "short request"
IFS= read -r -d '' -N "$slen" sig
((${#sig} == slen)) || die "short signature"
work=$(mktemp -d /run/sf-run.XXXXXX 2>/dev/null || mktemp -d /tmp/sf-run.XXXXXX) || die "no temporary directory"     # /run: job keys stay off the disk
trap 'rm -rf "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 143' TERM
printf '%s' "$payload" >"$work/payload"
printf '%s' "$sig" >"$work/sig"
ssh-keygen -Y verify -f "$ETC/allowed_signers" -I storageforge -n storageforge-deploy -s "$work/sig" \
  <"$work/payload" >/dev/null 2>&1 || die "the signature does not verify"
host= issued= nonce= args= machine=
while IFS= read -r line; do
  [[ -z $line ]] && break
  case $line in
    'host: '*) host=${line#host: } ;;
    'machine: '*) machine=${line#machine: } ;;
    'issued: '*) issued=${line#issued: } ;;
    'nonce: '*) nonce=${line#nonce: } ;;
    'args: '*) args=${line#args: } ;;
  esac
done <"$work/payload"
me=$(slug "$(uname -n)")
[[ $host == "$me" ]] || die "signed for $host, but this is $me"
if [[ -n $machine ]]; then   # the short name can repeat across machines; the machine id does not
  mid=$(cat "$MID" 2>/dev/null)
  [[ $machine =~ ^[0-9a-f]{32}$ && $machine == "$mid" ]] || die "signed for machine $machine, but this is ${mid:-a machine without a machine id}"
fi
now=$(date +%s)
[[ $issued =~ ^[0-9]{9,11}$ ]] || die "bad issue time"
((now - issued <= 600 && issued - now <= 300)) || die "the request is too old, or the clocks differ (issued $issued, now $now)"
[[ $nonce =~ ^[0-9a-f]{32}$ ]] || die "bad nonce"
mkdir -p "$STATE/seen" || die "cannot write $STATE"
find "$STATE/seen" -type f -mmin +1440 -delete 2>/dev/null
( set -o noclobber; : >"$STATE/seen/$nonce" ) 2>/dev/null || die "this request was already used"   # atomic: one run per nonce
[[ $args =~ ^[A-Za-z0-9=_./:,@+\ -]*$ ]] || die "bad arguments"
read -r -a argv <<<"$args"
sed '1,/^$/d' "$work/payload" >"$work/script"
log "run $nonce $(sha256sum <"$work/script" | cut -c1-16) args=[$args]"
cd /
umask 022     # the runner's own files stay private above; what a script makes (shared folders, config) must not
bash "$work/script" "${argv[@]}"
rc=$?
log "done $nonce rc=$rc"
mkdir -p "$STATE" 2>/dev/null || true
printf '{"nonce":"%s","rc":%d,"started":%d,"finished":%d}\n' "$nonce" "$rc" "$now" "$(date +%s)" >>"$STATE/runs.jsonl" 2>/dev/null || true
chmod 0644 "$STATE/runs.jsonl" 2>/dev/null || true
exit $rc
"""

# Prepended to every signed script: brings an older storageforge-run up to date (machine-id binding, atomic nonce
# claims) without running the setup again. Silent, so it cannot mix into data streamed on stdout (restores).
# It is line 1 of the script, so it carries the shebang: a storage task installs this very file ($0) as the
# ExecStart of its systemd unit, and without #! the kernel refuses to run it (203/EXEC).
# Not when an installed copy runs: a task's timer would put back whatever runner its copy holds, older or not, on every tick.
RUNNER_UPDATE = ('#!/bin/bash\n'
                 # nothing is installed unless the copy was written whole: an empty runner locks every deploy out of the host
                 'if ((EUID == 0)) && [[ $0 != /usr/local/lib/storageforge/* ]]; then _sf_new=$(mktemp) && cat >"$_sf_new" <<\'STORAGEFORGE_RUNNER_UPDATE\' &&\n'
                 + RUNNER_SCRIPT + 'STORAGEFORGE_RUNNER_UPDATE\n'
                 f'  [ -s "$_sf_new" ] && {{ cmp -s "$_sf_new" {RUNNER} || install -o root -g root -m 0755 "$_sf_new" {RUNNER}; }}\n'
                 'rm -f "$_sf_new"; unset _sf_new; fi >/dev/null 2>&1\n'
                 'umask 022\n')         # an older runner still in charge of this very run leaves 077

SETUP = r"""set -eu
U=%(user)s
HOME_DIR=/var/lib/storageforge/deploy
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen is missing: install openssh-client" >&2; exit 3; }
command -v visudo >/dev/null 2>&1 || { echo "sudo is missing: install sudo" >&2; exit 3; }
command -v bash >/dev/null 2>&1 || { echo "bash is missing" >&2; exit 3; }
for c in useradd usermod install mktemp; do
  command -v "$c" >/dev/null 2>&1 || { echo "$c is missing: deploys need a full userland (on Alpine: apk add shadow coreutils)" >&2; exit 3; }
done
command -v ssh >/dev/null 2>&1 || { echo "ssh is missing: install the OpenSSH client" >&2; exit 3; }
ver=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
set -- $ver
if [ "${1:-0}" -lt 8 ] || { [ "${1:-0}" -eq 8 ] && [ "${2:-0}" -lt 1 ]; }; then
  echo "OpenSSH ${1:-?}.${2:-?} is too old: signed deploys need ssh-keygen -Y (OpenSSH 8.1 or later)" >&2; exit 3
fi
install -d -o root -g root -m 0755 /etc/storageforge /etc/storageforge/jobs /etc/storageforge/serve /var/lib/storageforge /var/log/storageforge
if ! id "$U" >/dev/null 2>&1; then
  useradd --system --home-dir "$HOME_DIR" --create-home --shell /bin/sh --comment "StorageForge deploys" "$U"
  echo "created user $U"
fi
usermod -p '*' "$U"            # no password, but not locked: sshd without PAM refuses key logins to locked accounts
install -d -o "$U" -g root -m 0750 "$HOME_DIR"
install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"
printf 'storageforge namespaces="storageforge-deploy" %%s\n' %(signer)s >/etc/storageforge/allowed_signers
chmod 0644 /etc/storageforge/allowed_signers
tmp=$(mktemp)
cat >"$tmp" <<'STORAGEFORGE_RUNNER'
%(runner)sSTORAGEFORGE_RUNNER
install -o root -g root -m 0755 "$tmp" %(runner_path)s
rm -f "$tmp"
# the deploy key can only start the runner; job keys (added by deploys) can only reach their own job
keys=$HOME_DIR/.ssh/authorized_keys
{ printf 'restrict,command="sudo -n %(runner_path)s" %%s\n' %(deploy)s
  [ -f "$keys" ] && grep -F 'storageforge-job --serve' "$keys" || true; } >"$keys.new"
chown root:root "$keys.new"; chmod 0644 "$keys.new"; mv "$keys.new" "$keys"
sudo_tmp=$(mktemp)
cat >"$sudo_tmp" <<STORAGEFORGE_SUDO
Defaults:$U !requiretty
$U ALL=(root) NOPASSWD: %(runner_path)s, %(job_path)s --serve *
STORAGEFORGE_SUDO
visudo -cf "$sudo_tmp" >/dev/null || { rm -f "$sudo_tmp"; echo "visudo rejected the sudoers rule" >&2; exit 4; }
install -o root -g root -m 0440 "$sudo_tmp" /etc/sudoers.d/storageforge-deploy
rm -f "$sudo_tmp"
if command -v sshd >/dev/null 2>&1 && sshd -T 2>/dev/null | grep -qiE '^(allowusers|allowgroups) '; then
  echo "note: sshd_config has AllowUsers/AllowGroups: add $U there, or deploys cannot log in" >&2
fi
echo "deploy access is ready: $U may only run signed StorageForge scripts"
"""

REMOVE = r"""set -eu
U=%(user)s
rm -f /etc/sudoers.d/storageforge-deploy %(runner_path)s /etc/storageforge/allowed_signers
if id "$U" >/dev/null 2>&1; then
  # its last login outlives the deploy by a few seconds, and userdel refuses while a process of its is alive
  for _ in 1 2 3 4 5 6 7 8; do pgrep -u "$U" >/dev/null 2>&1 || break; sleep 1; done
  pkill -KILL -u "$U" 2>/dev/null || true; sleep 1
  userdel -r "$U" 2>/dev/null || userdel "$U"
fi
rm -rf /var/lib/storageforge/deploy
echo "deploy access removed (installed jobs keep running on their timers; remove them first to stop them)"
"""


def setup_script(signer_pub: str, deploy_pub: str) -> str:
    return SETUP % {'user': DEPLOY_USER, 'signer': shlex.quote(' '.join(signer_pub.split()[:2])),
                    'deploy': shlex.quote(' '.join(deploy_pub.split()[:2]) + ' storageforge:deploy'),
                    'runner': RUNNER_SCRIPT, 'runner_path': RUNNER, 'job_path': JOBBIN}


def remove_script() -> str:
    return REMOVE % {'user': DEPLOY_USER, 'runner_path': RUNNER}


# ── keys, access, bindings ──────────────────────────────────────────
def ensure_keys(vault: Vault) -> tuple[str, str]:
    """The signing and deploy keys, made on first use. Returns their public lines."""
    have = {k['name'] for k in vault.list_keys()}
    if SIGNING_KEY not in have:
        vault.generate_key(SIGNING_KEY, comment='storageforge:signing')
    if DEPLOY_KEY not in have:
        vault.generate_key(DEPLOY_KEY, comment='storageforge:deploy')
    return vault.public_key(SIGNING_KEY), vault.public_key(DEPLOY_KEY)


def _signer(vault: Vault) -> ed25519.Ed25519PrivateKey:
    kid = vault.conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': SIGNING_KEY})
    if kid is None:
        raise DeployError('no signing key yet: set up deploy access on a host first')
    buf = vault.decrypt_key(kid)
    try:
        return serialization.load_ssh_private_key(bytes(buf.view()), None)
    finally:
        buf.wipe()


def canonical(conn, host: str) -> str:
    # by name, then by the address it was scanned at; the IP a host reports about itself only as a last resort
    row = conn.all("""SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h OR ip_address = :h
                      ORDER BY CASE WHEN lower(hostname) = lower(:h) THEN 0 WHEN ssh_host = :h THEN 1 ELSE 2 END""",
                   {'h': host})
    return row[0][0] if row else host


def _machine(conn, name: str) -> str | None:
    """The machine id the host reported in its last scan; deploys are signed for that machine only."""
    return conn.scalar('SELECT machine_id FROM hosts WHERE hostname = :h', {'h': name}) or None


def set_access(conn, host: str, state: str, detail: str, actor: str):
    conn.execute('DELETE FROM deploy_access WHERE host = :h', {'h': host})
    conn.execute('INSERT INTO deploy_access (host, state, detail, updated_at, updated_by) VALUES (:h, :s, :d, :t, :a)',
                 {'h': host, 's': state, 'd': detail[-2000:], 't': int(time.time()), 'a': actor})


def access(conn) -> list[dict]:
    rows = conn.all("""SELECT h.hostname, a.state, a.detail, a.updated_at, a.updated_by FROM hosts h
                       LEFT JOIN deploy_access a ON a.host = h.hostname ORDER BY h.hostname""")
    return [{'host': h, 'state': s or 'none', 'detail': d, 'updated_at': t, 'updated_by': by} for h, s, d, t, by in rows]


def ready(conn, host: str) -> bool:
    return conn.scalar("SELECT count(*) FROM deploy_access WHERE host = :h AND state = 'ready'", {'h': canonical(conn, host)}) > 0


def setup_for_download(db, conn) -> str:
    with Vault(db, conn).unlock() as v:
        return setup_script(*ensure_keys(v))


def enroll(db, conn, host: str, password: str, admin_user: str | None = None, actor: str | None = None,
           remove: bool = False, admin_key: str | None = None) -> dict:
    """Set deploy access up on host (or remove it) with sudo once, bind the deploy key, and prove a signed run works."""
    from .access import sudo_run
    from .preflight import facts_from_scan, findings
    actor = actor or actor_name()
    name, addr = canonical(conn, host), connect_address(conn, host)
    if not remove:      # a host deploys can't run on: say so before any password goes anywhere
        crit = [i['text'] for i in findings(facts_from_scan(conn, name)) if i['level'] == 'crit']
        if crit:
            raise RemoteError(f'{name} cannot run deploys: ' + '; '.join(crit))
    with Vault(db, conn).unlock() as v:
        signer_pub, deploy_pub = ensure_keys(v)
        audit = AuditLog(db, conn, v.audit_key)
        try:
            r = sudo_run(db, conn, addr, lambda _u: remove_script() if remove else setup_script(signer_pub, deploy_pub),
                         password, admin_user, admin_key)
        except Exception as exc:
            audit.append(actor, 'deploy.remove' if remove else 'deploy.setup', 'failed', name, None, {'error': str(exc)[:500]})
            raise
        port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or r['port']   # where sudo_run got in
        mine = [b for b in v.bindings() if b['key'] == DEPLOY_KEY and b['pattern'] == addr]
        if remove:
            for b in mine:
                v.unbind(b['binding_id'])
            set_access(conn, name, 'removed', r['output'], actor)
            audit.append(actor, 'deploy.remove', 'ok', name, None, {})
            return {'host': name, 'state': 'removed', 'output': r['output']}
        if not mine:
            v.bind(DEPLOY_KEY, addr, DEPLOY_USER, port, actions='deploy', priority=50)
        audit.append(actor, 'deploy.setup', 'ok', name, None, {'via': r.get('via')})
    probe = run(db, name, 'echo "signed runs work on $(uname -n): $(id -un), $(ssh -V 2>&1)"', kind='setup', ref='probe',
                mode='apply', actor=actor, require_ready=False)
    state = 'ready' if probe['status'] == 'ok' else 'failed'
    set_access(conn, name, state, r['output'] + '\n' + probe['output'], actor)
    return {'host': name, 'state': state, 'output': (r['output'] + '\n' + probe['output']).strip()}


# ── runs ────────────────────────────────────────────────────────────
def run_status(rc: int | None, mode: str, text: str) -> str:
    if rc == REFUSED:
        return 'refused'
    if rc != 0:
        return 'failed'
    return 'incomplete' if mode == 'apply' and UNFINISHED.search(text) else 'ok'


def audit_outcome(status: str) -> str:
    """audit_log takes ok, denied, failed and info only."""
    return {'ok': 'ok', 'refused': 'denied', 'incomplete': 'info', 'cancelled': 'info'}.get(status, 'failed')


def ssh_failure(text: str) -> str:
    """Exit 255 means ssh itself failed: say which of the usual reasons this was."""
    if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in text or 'Host key verification failed' in text:
        return ('\nSSH refused: this host presents a different key than the one pinned for it. If it was reinstalled: '
                'storageforge-index hosts rekey <name>, then scan it\n')
    if 'Permission denied' in text:
        return '\nSSH refused the deploy key: run Set up again. If it still fails, check AllowUsers in the host\'s sshd_config\n'
    return '\nSSH failed: the host is unreachable, or storageforge-deploy cannot log in\n'


def _lock(host: str) -> threading.Lock:
    with _locks_guard:
        return _host_locks.setdefault(host, threading.Lock())


@contextmanager
def _host_turn(name: str, out: list, save, live=None):
    """One script per host at a time, across every deploy. A wait says so, or the run just looks hung."""
    lock = _lock(name)
    said = False
    while not lock.acquire(timeout=1):
        if live and live.cancelled:
            raise DeployError(f'not run: cancelled by {live.by}')
        if not said:
            said = True
            out.append(f'waiting for another deploy on {name} to end\n')
            save()
    try:
        yield
    finally:
        lock.release()


def run(db: Database, host: str, script: str, args=(), *, kind: str, ref: str | None = None, mode: str = 'report',
        actor: str | None = None, group_id: str | None = None, data=None, timeout: int = 1800,
        require_ready: bool = True, run_id_box: list | None = None, run_id: int | None = None, live=None,
        sign_as: str | None = None) -> dict:
    """Run one signed script as root on host and record it in deploy_runs. data: bytes or an iterable of byte chunks
    for the script's stdin (after the signed request). Blocks until the script ends. run_id: the queued row this run
    fills in (engine.py). live: the group it belongs to, which may ask to stop it. sign_as: the host's own name, when
    it has not been scanned yet and host is only an address."""
    actor = actor or actor_name()
    group_id = group_id or uuid.uuid4().hex
    conn = db.connect()
    started = int(time.time())
    sha = hashlib.sha256(script.encode()).hexdigest()[:16]
    nonce = secrets.token_hex(16)
    if run_id:
        conn.execute("UPDATE deploy_runs SET status = 'running', script_sha = :sha, started_at = :t, nonce = :n WHERE run_id = :r",
                     {'sha': sha, 't': started, 'r': run_id, 'n': nonce})
    else:
        run_id = conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, script_sha, actor, started_at, nonce)
                                VALUES (:g, :h, :k, :r, :m, 'running', :sha, :a, :t, :n) RETURNING run_id""",
                             {'g': group_id, 'h': host, 'k': kind, 'r': ref, 'm': mode, 'a': actor, 't': started, 'sha': sha, 'n': nonce})
    if run_id_box is not None:
        run_id_box.append(run_id)
    out: list[str] = []
    size = [0]

    def save(status: str | None = None, rc: int | None = None):
        text = ''.join(out)
        if len(text) > MAX_OUTPUT:
            text = text[:MAX_OUTPUT // 4] + '\n… (output cut) …\n' + text[-MAX_OUTPUT * 3 // 4:]
        conn.execute('UPDATE deploy_runs SET output = :o' + (', status = :s, exit_code = :c, finished_at = :f' if status else '')
                     + ' WHERE run_id = :id', {'o': text, 's': status, 'c': rc, 'f': int(time.time()), 'id': run_id})

    status, rc = 'failed', None
    try:
        name = canonical(conn, host)
        if require_ready and not ready(conn, name):
            raise DeployError(f'{name} is not set up for deploys yet (Deploy tab → Set up deploy access)')
        addr = connect_address(conn, name)
        with _host_turn(name, out, save, live), Vault(db, conn).unlock() as v:
            audit = AuditLog(db, conn, v.audit_key)
            try:
                b = v.resolve(addr, 'deploy')
            except NoBinding as exc:
                raise DeployError(f'{name}: {exc}') from None
            req = request(_signer(v), sign_as or name, RUNNER_UPDATE + script, args, machine=_machine(conn, name), nonce=nonce)
            if isinstance(data, (bytes, bytearray)):
                data = [bytes(data)]
            t = None
            try:
                with ephemeral_agent(v.decrypt_key(b.key_id), ttl=timeout + 60) as sock:
                    t = Transport(host=addr, user=b.user, port=b.port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                                  isolated=True)
                    p = subprocess.Popen(t.argv('storageforge-run'), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, env=child_env())
                    if live:
                        live.attach(run_id, p)

                    def feed():
                        try:
                            p.stdin.write(req)
                            for chunk in data or ():
                                p.stdin.write(chunk)
                        except (BrokenPipeError, OSError):
                            pass
                        finally:
                            try:
                                p.stdin.close()
                            except OSError:
                                pass
                    threading.Thread(target=feed, daemon=True).start()

                    def drain():
                        for line in iter(p.stdout.readline, b''):
                            s = line.decode('utf-8', 'replace')
                            size[0] += len(s)
                            if size[0] < MAX_OUTPUT * 4:
                                out.append(s)
                    reader = threading.Thread(target=drain, daemon=True)
                    reader.start()
                    deadline, last = time.time() + timeout, 0.0
                    while reader.is_alive():
                        reader.join(0.5)
                        if time.time() - last > 1:
                            save(); last = time.time()
                        if time.time() > deadline:
                            p.kill(); out.append(f'\nstopped after {timeout} s\n')
                            break
                    rc = p.wait(30)
            finally:
                if live:
                    live.detach(run_id)
                if t:
                    t.close()
            status = run_status(rc, mode, ''.join(out))
            if live and live.cancelled == 'force' and status == 'failed':
                status = 'cancelled'
                out.append(f'\nstopped: cancelled by {live.by}\n')
            elif rc == 255:
                out.append(ssh_failure(''.join(out[-3:])))
            audit.append(actor, f'deploy.{kind}', audit_outcome(status), name, b.fingerprint,
                         {'mode': mode, 'ref': ref, 'run': run_id, 'exit': rc, 'args': list(args)})
    except (DeployError, VaultError, ValueError) as exc:
        out.append(f'{exc}\n')
    except Exception as exc:                       # never leave a run "running"
        traceback.print_exc()
        out.append(f'internal error: {type(exc).__name__}: {exc}\n')
    finally:
        if live and live.cancelled and rc is None and status == 'failed':    # stopped while it waited for the host
            status = 'cancelled'
        save(status, rc)
        conn.close()
    return {'run_id': run_id, 'group_id': group_id, 'host': host, 'status': status, 'exit_code': rc, 'output': ''.join(out)}


@contextmanager
def raw(db: Database, host: str, script: str, *, kind: str, ref: str | None = None, actor: str | None = None,
        group_id: str | None = None):
    """A signed run whose stdout is handed over raw (a tar stream); its stderr and outcome go to deploy_runs."""
    actor = actor or actor_name()
    conn = db.connect()
    name = canonical(conn, host)
    if not ready(conn, name):
        conn.close()
        raise DeployError(f'{name} is not set up for deploys yet')
    nonce = secrets.token_hex(16)
    run_id = conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at, nonce)
                            VALUES (:g, :h, :k, :r, 'apply', 'running', :a, :t, :n) RETURNING run_id""",
                         {'g': group_id or uuid.uuid4().hex, 'h': name, 'k': kind, 'r': ref, 'a': actor, 't': int(time.time()), 'n': nonce})
    err: list[bytes] = []
    status, rc, t = 'failed', None, None
    try:
        addr = connect_address(conn, name)
        with _lock(name), Vault(db, conn).unlock() as v:     # one run per host at a time, like run()
            b = v.resolve(addr, 'deploy')
            req = request(_signer(v), name, RUNNER_UPDATE + script, machine=_machine(conn, name), nonce=nonce)
            with ephemeral_agent(v.decrypt_key(b.key_id)) as sock:
                t = Transport(host=addr, user=b.user, port=b.port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                              isolated=True)
                p = subprocess.Popen(t.argv('storageforge-run'), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=child_env())
                p.stdin.write(req)
                p.stdin.close()
                drain = threading.Thread(target=lambda: err.extend(iter(lambda: p.stderr.read(4096), b'')), daemon=True)
                drain.start()
                p.errors = err          # its stderr, complete once the block is left
                try:
                    yield p
                finally:
                    if p.poll() is None:
                        p.stdout.close()
                    rc = p.wait(60)
                    drain.join(5)
                status = run_status(rc, 'report', '')
            AuditLog(db, conn, v.audit_key).append(actor, f'deploy.{kind}', audit_outcome(status), name, b.fingerprint,
                                                   {'ref': ref, 'run': run_id, 'exit': rc})
    finally:
        if t:
            t.close()
        conn.execute("""UPDATE deploy_runs SET status = :s, exit_code = :c, output = :o, finished_at = :f
                        WHERE run_id = :id""", {'s': status, 'c': rc, 'o': b''.join(err).decode('utf-8', 'replace')[-MAX_OUTPUT:],
                                               'f': int(time.time()), 'id': run_id})
        conn.close()


def start_group(db: Database, items: list[dict], actor: str, stop_on_failure: bool = True, after=None, **group) -> str:
    """Run items as one deploy (engine.py); returns the group id to poll."""
    from . import engine
    return engine.start(db, items, actor, stop_on_failure=stop_on_failure, after=after, **group)


def _guard(fn):
    try:
        fn()
    except Exception:
        traceback.print_exc()


def start_task(db: Database, host: str, kind: str, ref: str | None, actor: str, fn) -> str:
    """fn(group_id) in a background thread: work that can take hours (a restore) must not hold one of the web
    server's few threads. Its runs are recorded under the group id returned here, which the UI polls like a deploy."""
    gid = uuid.uuid4().hex
    conn = db.connect()
    try:      # the task's own row, running until it ends: a poll never takes the group for finished too early
        rid = conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at)
                             VALUES (:g, :h, :k, :r, 'apply', 'running', :a, :t) RETURNING run_id""",
                          {'g': gid, 'h': host, 'k': kind, 'r': ref, 'a': actor, 't': int(time.time())})
    finally:
        conn.close()

    def work():
        try:
            fn(gid)
        except Exception as exc:     # failed before (or between) its runs: the task's row says why
            traceback.print_exc()
            c = db.connect()
            try:
                c.execute("""UPDATE deploy_runs SET status = 'failed', output = :o, finished_at = :t WHERE run_id = :r""",
                          {'o': str(exc)[-MAX_OUTPUT:], 't': int(time.time()), 'r': rid})
            finally:
                c.close()
            return
        c = db.connect()
        try:      # its runs tell how it went
            c.execute('DELETE FROM deploy_runs WHERE run_id = :r', {'r': rid})
        finally:
            c.close()
    threading.Thread(target=lambda: _guard(work), name=f'task-{gid[:8]}', daemon=True).start()
    return gid


def group(conn, gid: str) -> list[dict]:
    rows = conn.all("""SELECT run_id, host, kind, ref, mode, status, exit_code, output, actor, started_at, finished_at, phase,
                              nonce, host_state, host_exit, confirmed_at
                       FROM deploy_runs WHERE group_id = :g ORDER BY run_id""", {'g': gid})
    return [dict(zip(('run_id', 'host', 'kind', 'ref', 'mode', 'status', 'exit_code', 'output', 'actor', 'started_at',
                      'finished_at', 'phase', 'nonce', 'host_state', 'host_exit', 'confirmed_at'), r)) for r in rows]


def history(conn, host: str | None = None, limit: int = 50) -> list[dict]:
    rows = conn.all(f"""SELECT run_id, group_id, host, kind, ref, mode, status, exit_code, actor, started_at, finished_at,
                               nonce, host_state, host_exit, confirmed_at
                        FROM deploy_runs {'WHERE host = :h' if host else ''} ORDER BY run_id DESC LIMIT :l""",
                    {'h': host, 'l': limit})
    return [dict(zip(('run_id', 'group_id', 'host', 'kind', 'ref', 'mode', 'status', 'exit_code', 'actor', 'started_at',
                      'finished_at', 'nonce', 'host_state', 'host_exit', 'confirmed_at'), r)) for r in rows]


def output(conn, run_id: int) -> dict:
    rows = conn.all("""SELECT run_id, host, kind, ref, mode, status, exit_code, output, nonce, host_state, host_exit, confirmed_at
                       FROM deploy_runs WHERE run_id = :r""", {'r': run_id})
    if not rows:
        raise LookupError(f'no deploy run {run_id}')
    return dict(zip(('run_id', 'host', 'kind', 'ref', 'mode', 'status', 'exit_code', 'output', 'nonce', 'host_state',
                      'host_exit', 'confirmed_at'), rows[0]))


def mark_deployed(conn, host: str, kind: str, ref: str, deploy_hash: str, detail: dict, actor: str):
    conn.execute('DELETE FROM deployed WHERE host = :h AND kind = :k AND ref = :r', {'h': host, 'k': kind, 'r': ref})
    conn.execute("""INSERT INTO deployed (host, kind, ref, deploy_hash, detail_json, deployed_at, deployed_by)
                    VALUES (:h, :k, :r, :d, :j, :t, :a)""",
                 {'h': host, 'k': kind, 'r': ref, 'd': deploy_hash, 'j': json.dumps(detail), 't': int(time.time()), 'a': actor})


def finished_at(marks: list[dict], ref: str, digest: str) -> int | None:
    """When this version of a plan last finished on all its hosts (their list is in each mark's detail), if it has."""
    done = [d for d in marks if d['ref'] == ref and d['hash'] == digest]
    if not done or not set(done[0]['detail'].get('hosts') or ()) <= {d['host'] for d in done}:
        return None
    return max(d['at'] for d in done)


def deployed(conn, host: str | None = None, kind: str | None = None) -> list[dict]:
    where = ' AND '.join(x for x, on in (('host = :h', host), ('kind = :k', kind)) if on)
    rows = conn.all(f"""SELECT host, kind, ref, deploy_hash, detail_json, deployed_at, deployed_by FROM deployed
                        {'WHERE ' + where if where else ''} ORDER BY host, kind, ref""", {'h': host, 'k': kind})
    return [{'host': h, 'kind': k, 'ref': r, 'hash': d, 'detail': json.loads(j or '{}'), 'at': t, 'by': by}
            for h, k, r, d, j, t, by in rows]


def adopt(db, conn, host: str, actor: str | None = None) -> dict:
    """After the setup script was run by hand: bind the deploy key to the host and prove a signed run works."""
    from .scriptkit import host_name
    actor = actor or actor_name()
    host = host_name(host, 'the host')            # one host: never a glob, a CIDR or something ssh reads as an option
    name, addr = canonical(conn, host), connect_address(conn, host)
    port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or 22
    made = None
    with Vault(db, conn).unlock() as v:
        ensure_keys(v)
        if not [b for b in v.bindings() if b['key'] == DEPLOY_KEY and b['pattern'] == addr]:
            made = v.bind(DEPLOY_KEY, addr, DEPLOY_USER, port, actions='deploy', priority=50)
    probe = run(db, name, 'echo "signed runs work on $(uname -n): $(id -un), $(ssh -V 2>&1)"', kind='setup', ref='probe',
                mode='apply', actor=actor, require_ready=False)
    state = 'ready' if probe['status'] == 'ok' else 'failed'
    if state == 'failed' and made:      # not set up after all: no deploy key left pointing at it
        with Vault(db, conn).unlock() as v:
            v.unbind(made)
    set_access(conn, name, state, probe['output'], actor)
    return {'host': name, 'state': state, 'output': probe['output']}
