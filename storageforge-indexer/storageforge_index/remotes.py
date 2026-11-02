"""Remote nodes: hosts behind NAT that dial out to StorageForge, as Hawser's edge mode does, instead of being dialled.

A node holds one reverse SSH tunnel to the tunnel container (docker-compose.remote.yml), which offers the node's own
sshd on a loopback address only this server can reach. Each node has its own 127.77.x.y, because hosts are told apart
by address. Scans and deploys then use it like any other host, through the same keys, pinned host keys and signed
scripts: the tunnel carries bytes and adds no way to run anything.

A tunnel key can only listen on its one address. Stolen, it can take that address while the node is away, and the
pinned host key then refuses whoever answers. Until a node is adopted its key expires, like an invitation. The private
half goes out once, in the install script, and only the public half is kept.
"""
from __future__ import annotations

import os
import re
import shlex
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import access, deploy
from .alerts import get_setting, set_setting
from .db import Conn
from .scriptkit import host_name
from .vault import AuditLog, Vault

NET = '127.77.'
LISTEN_PORT = 10022
TUNNEL_USER = 'sftunnel'
SCAN_USER = 'sfscan'
SCAN_KEY = 'storageforge-remote-scan'
ENDPOINT_KEY = 'remote.endpoint'
INVITE_SECONDS = 24 * 3600
MAX_NODE_ID = 65535      # all of 127.77.x.y: ids are never reused, and one more would share node 1's address
NAME_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
ENDPOINT_RE = re.compile(r'(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]{2,45}\])(?::(?P<port>[0-9]{1,5}))?')


def is_tunnel(address: str | None) -> bool:
    return (address or '').startswith(NET)


def address(node_id: int) -> str:
    return f'{NET}{(node_id >> 8) & 255}.{node_id & 255}'


def _keys_dir() -> Path | None:
    p = os.environ.get('STORAGEFORGE_TUNNEL_KEYS')
    return Path(p) if p else None


def host_key_line() -> str:
    """The tunnel's public host key, which nodes pin before they ever connect."""
    folder = os.environ.get('STORAGEFORGE_TUNNEL_HOST')
    try:
        parts = Path(folder, 'ssh_host_ed25519_key.pub').read_text().split() if folder else []
    except OSError:
        parts = []
    if len(parts) < 2:
        raise ValueError('the tunnel is not running: start the stack with docker-compose.remote.yml as well')
    return f'{parts[0]} {parts[1]}'


def parse_endpoint(text) -> tuple[str, int]:
    m = ENDPOINT_RE.fullmatch(str(text or '').strip())
    port = int(m['port'] or 2222) if m else 0
    if not m or not 1 <= port <= 65535:
        raise ValueError('the tunnel endpoint must be the name or address nodes dial, such as forge.example.com:2222')
    return m['host'], port


def _rows(conn: Conn, where: str = 'revoked_at IS NULL', params: dict | None = None) -> list[dict]:
    rows = conn.all(f"""SELECT node_id, name, public_key, created_at, created_by, expires_at, adopted_at, revoked_at
                        FROM remote_nodes WHERE {where} ORDER BY node_id""", params or {})
    return [dict(zip(('id', 'name', 'public_key', 'created_at', 'created_by', 'expires_at', 'adopted_at', 'revoked_at'), r)) for r in rows]


def authorized_lines(conn: Conn, now: float | None = None) -> str:
    now = now or time.time()
    out = []
    for n in _rows(conn):
        if not n['adopted_at'] and n['expires_at'] <= now:
            continue
        # restrict turns everything off; port-forwarding turns one thing back on, for one address
        opts = f'restrict,port-forwarding,permitlisten="{address(n["id"])}:{LISTEN_PORT}",command="/bin/false"'
        if not n['adopted_at']:
            opts += ',expiry-time="' + time.strftime('%Y%m%d%H%MZ', time.gmtime(n['expires_at'])) + '"'
        out.append(f'{opts} {" ".join(n["public_key"].split()[:2])} storageforge:node:{n["name"]}\n')
    return ''.join(out)


def sync(conn: Conn, drop_sessions: bool = False) -> None:
    """Write what the tunnel reads. The database decides, so a restored backup or a lost volume comes right here."""
    folder = _keys_dir()
    if not folder:
        return
    lines, live = authorized_lines(conn), folder / 'authorized_keys'
    if not live.exists() or live.read_text() != lines:     # every look at the page lands here, and only a change writes
        tmp = folder / f'authorized_keys.{os.getpid()}.{threading.get_ident()}.new'
        tmp.write_text(lines)
        tmp.chmod(0o644)
        tmp.replace(live)
    if drop_sessions:
        tmp = folder / 'generation.new'
        tmp.write_text(f'{time.time_ns()}\n')
        tmp.chmod(0o644)
        tmp.replace(folder / 'generation')


def online(addr: str, timeout: float = 2.0) -> bool:
    """Is the node's sshd answering through its tunnel? Its banner says so; an open port alone could be a stale forward."""
    try:
        with socket.create_connection((addr, LISTEN_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(8).startswith(b'SSH-')
    except OSError:
        return False


def _host_of(conn: Conn, addr: str) -> str | None:
    return conn.scalar('SELECT hostname FROM hosts WHERE ssh_host = :a', {'a': addr})


def overview(conn: Conn) -> dict:
    sync(conn)
    nodes = []
    now = time.time()
    rows = _rows(conn)
    # together: a node that hung holds its probe for seconds, and this runs on a web worker
    with ThreadPoolExecutor(max_workers=16) as pool:
        ups = list(pool.map(online, [address(n['id']) for n in rows]))
    for n, up in zip(rows, ups):
        addr = address(n['id'])
        host = _host_of(conn, addr)
        expired = not n['adopted_at'] and n['expires_at'] <= now
        nodes.append({'id': n['id'], 'name': n['name'], 'address': addr, 'host': host, 'online': up, 'created_at': n['created_at'],
                      'expires_at': None if n['adopted_at'] else n['expires_at'], 'adopted_at': n['adopted_at'],
                      'state': 'expired' if expired else 'ready' if n['adopted_at'] and up else 'offline' if n['adopted_at']
                      else 'connected' if up else 'waiting'})
    return {'nodes': nodes, 'endpoint': get_setting(conn, ENDPOINT_KEY) or '', 'tunnel': bool(_keys_dir())}


INSTALL = r"""#!/usr/bin/env bash
# StorageForge remote node "@NAME@". Run it as root on that machine: no flags reports, --apply sets it up, --remove undoes it.
# THIS FILE HOLDS THE NODE'S PRIVATE TUNNEL KEY: delete it after running it. Unused, the key stops working on @EXPIRES@.
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
MODE=report
case ${1:-} in '') ;; --apply) MODE=apply ;; --remove) MODE=remove ;; *) echo "usage: $0 [--apply|--remove]" >&2; exit 2 ;; esac
HOST=@HOST@ PORT=@PORT@ LISTEN=@LISTEN@ DIR=/etc/storageforge/remote UNIT=/etc/systemd/system/storageforge-remote.service BIN=/usr/local/sbin/storageforge-remote
RUNAS=storageforge-remote SCAN=@SCAN@
PROBLEMS=0
ok() { echo "  ok       $*"; }
would() { echo "  missing  $*"; }
conflict() { echo "  conflict $*"; PROBLEMS=$((PROBLEMS + 1)); }
[[ $MODE == report || $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if [[ $MODE == remove ]]; then
  systemctl disable --now storageforge-remote.service 2>/dev/null
  rm -f "$UNIT" "$BIN"; rm -rf "$DIR"; systemctl daemon-reload
  id "$RUNAS" >/dev/null 2>&1 && userdel "$RUNAS"
  bash -s <<'@TAG@_A'
@REMOVE_ACCESS@
@TAG@_A
  bash -s <<'@TAG@_B'
@REMOVE_DEPLOY@
@TAG@_B
  id "$SCAN" >/dev/null 2>&1 && userdel -r "$SCAN" 2>/dev/null
  echo "removed: this machine no longer dials StorageForge"
  exit 0
fi

command -v systemctl >/dev/null && ok "systemd" || conflict "systemd runs the tunnel, and this machine has none"
command -v ssh >/dev/null && ok "ssh client: $(command -v ssh)" || conflict "the OpenSSH client is not installed"
command -v sshd >/dev/null && ok "sshd" || conflict "the OpenSSH server is not installed: StorageForge reaches this machine through it"
LOCAL=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }'); LOCAL=${LOCAL:-22}
timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$LOCAL" 2>/dev/null && ok "sshd answers on 127.0.0.1:$LOCAL" \
  || conflict "sshd does not answer on 127.0.0.1:$LOCAL: the tunnel ends there"
timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$PORT" 2>/dev/null && ok "reached the tunnel at $HOST:$PORT" \
  || conflict "cannot reach $HOST:$PORT: outbound TCP must get through, and the tunnel must be running"
if [[ $MODE == report ]]; then
  [[ -e $UNIT ]] && ok "the tunnel is set up" || would "would set up the tunnel, $RUNAS, $SCAN and deploy access"
  ((PROBLEMS)) && { echo "$PROBLEMS problem(s)"; exit 1; }
  echo "report only: run again with --apply"
  exit 0
fi
((PROBLEMS)) && { echo "$PROBLEMS problem(s): nothing changed"; exit 1; }

id "$RUNAS" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /sbin/nologin "$RUNAS" || exit 1
install -d -o root -g "$RUNAS" -m 0750 "$DIR" || exit 1
( umask 077; cat >"$DIR/key" <<'@TAG@_K'
@PRIVATE@
@TAG@_K
)
chown "$RUNAS" "$DIR/key"; chmod 0400 "$DIR/key"
cat >"$DIR/known_hosts" <<'@TAG@_H'
@KNOWN@
@TAG@_H
chmod 0644 "$DIR/known_hosts"
# A program of its own, not ssh in ExecStart: SELinux policy lets systemd start bin_t programs as a service, but not ssh_exec_t
# ones (Permission denied on Rocky 10). NoNewPrivileges is left out for the same reason: it blocks the step into ssh's domain.
cat >"$BIN" <<EOF
#!/bin/sh
exec $(command -v ssh) -F /dev/null -N -T -i $DIR/key -p $PORT -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ConnectTimeout=20 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$DIR/known_hosts -o GlobalKnownHostsFile=/dev/null -R $LISTEN:127.0.0.1:$LOCAL @LOGIN@@$HOST
EOF
chmod 0755 "$BIN"
command -v restorecon >/dev/null && restorecon "$BIN" 2>/dev/null
cat >"$UNIT" <<EOF
[Unit]
Description=StorageForge tunnel: offers this machine's SSH to StorageForge
After=network-online.target sshd.service ssh.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
User=$RUNAS
ExecStart=$BIN
Restart=always
RestartSec=15
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
id "$SCAN" >/dev/null 2>&1 || useradd --system --create-home --shell /bin/bash "$SCAN" || exit 1
home=$(getent passwd "$SCAN" | cut -d: -f6)
install -d -o "$SCAN" -m 0700 "$home/.ssh"
cat >"$home/.ssh/authorized_keys" <<'@TAG@_S'
@SCAN_KEY@
@TAG@_S
chown "$SCAN" "$home/.ssh/authorized_keys"; chmod 0600 "$home/.ssh/authorized_keys"
command -v restorecon >/dev/null && restorecon -R "$home/.ssh" "$DIR" 2>/dev/null
bash -s <<'@TAG@_A' || { echo "read-only scan access could not be set up" >&2; exit 1; }
@SETUP_ACCESS@
@TAG@_A
bash -s <<'@TAG@_B' || { echo "deploy access could not be set up" >&2; exit 1; }
@SETUP_DEPLOY@
@TAG@_B
systemctl daemon-reload && systemctl enable --now storageforge-remote.service || exit 1
sleep 3
systemctl is-active --quiet storageforge-remote.service && echo "the tunnel is up: press Adopt in StorageForge, then delete this file" \
  || { { echo "the tunnel did not stay up:"; journalctl -u storageforge-remote.service -n 10 --no-pager; } >&2; exit 1; }
"""


def install_script(name: str, node_id: int, endpoint: tuple[str, int], tunnel_host_key: str, private: str, scan_pub: str,
                   signer_pub: str, deploy_pub: str, expires_at: int) -> str:
    q = shlex.quote
    host, port = endpoint
    known = f'[{host.strip("[]")}]:{port} {tunnel_host_key}'
    values = {'@NAME@': name, '@HOST@': q(host.strip('[]')), '@PORT@': str(port), '@LISTEN@': f'{address(node_id)}:{LISTEN_PORT}',
              '@SCAN@': SCAN_USER, '@LOGIN@': TUNNEL_USER, '@EXPIRES@': time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(expires_at)),
              '@TAG@': 'SF_' + os.urandom(6).hex().upper(), '@PRIVATE@': private.strip(), '@KNOWN@': known,
              '@SCAN_KEY@': ' '.join(scan_pub.split()[:2]) + ' storageforge:scan',
              '@SETUP_ACCESS@': access.setup_script(SCAN_USER), '@REMOVE_ACCESS@': access.remove_script(SCAN_USER),
              '@SETUP_DEPLOY@': deploy.setup_script(signer_pub, deploy_pub), '@REMOVE_DEPLOY@': deploy.remove_script()}
    return re.sub('|'.join(map(re.escape, values)), lambda m: values[m[0]], INSTALL)


def add(db, conn: Conn, name: str, endpoint: str | None, actor: str) -> dict:
    """A new node and its install script. The script holds the only copy of the private key."""
    name = str(name or '').strip().lower()
    if not NAME_RE.fullmatch(name):
        raise ValueError('a node name is lowercase letters, digits and dashes')
    if _rows(conn, 'revoked_at IS NULL AND name = :n', {'n': name}):
        raise ValueError(f'there is already a remote node named {name}')
    if (conn.scalar('SELECT max(node_id) FROM remote_nodes') or 0) >= MAX_NODE_ID:
        raise ValueError('this install has used every remote node address')
    text = endpoint or get_setting(conn, ENDPOINT_KEY)
    where = parse_endpoint(text)
    tunnel_key = host_key_line()
    k = ed25519.Ed25519PrivateKey.generate()
    private = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    public = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    now = int(time.time())
    expires = now + INVITE_SECONDS
    with Vault(db, conn).unlock() as v:
        signer_pub, deploy_pub = deploy.ensure_keys(v)
        if not any(x['name'] == SCAN_KEY for x in v.list_keys()):
            v.generate_key(SCAN_KEY, comment='remote node scans')
        scan_pub = v.public_key(SCAN_KEY)
        node_id = conn.scalar("""INSERT INTO remote_nodes (name, public_key, created_at, created_by, expires_at)
                                 VALUES (:n, :k, :t, :a, :e) RETURNING node_id""",
                              {'n': name, 'k': public, 't': now, 'a': actor, 'e': expires})
        v.bind(SCAN_KEY, address(node_id), SCAN_USER, LISTEN_PORT, actions='scan', priority=50)
        AuditLog(db, conn, v.audit_key).append(actor, 'remote.add', 'ok', name, None, {'address': address(node_id)})
    set_setting(conn, ENDPOINT_KEY, text, actor)
    sync(conn)
    return {'id': node_id, 'name': name, 'address': address(node_id), 'expires_at': expires,
            'script': install_script(name, node_id, where, tunnel_key, private, scan_pub, signer_pub, deploy_pub, expires)}


def get(conn: Conn, node_id: int) -> dict:
    rows = _rows(conn, 'revoked_at IS NULL AND node_id = :i', {'i': node_id})
    if not rows:
        raise LookupError(f'no remote node {node_id}')
    return rows[0]


def find(conn: Conn, name: str) -> dict:
    rows = _rows(conn, 'revoked_at IS NULL AND name = :n', {'n': name})
    if not rows:
        raise LookupError(f'no remote node {name}')
    return rows[0]


def adopt(db, conn: Conn, node_id: int, actor: str, scan) -> dict:
    """Once the tunnel is up: scan it, then prove a signed run works. scan(address) may only queue the scan: adopt is
    called again until the host has reported itself. Its key stops expiring here."""
    n = get(conn, node_id)
    addr = address(node_id)
    if not online(addr):
        raise ValueError(f'{n["name"]} is not connected: run its install script there with --apply, and look at '
                         'journalctl -u storageforge-remote there')
    host = _host_of(conn, addr)
    if not n['adopted_at']:
        conn.execute('UPDATE remote_nodes SET adopted_at = :t WHERE node_id = :i', {'t': int(time.time()), 'i': node_id})
        sync(conn)
    if not host:
        scan(addr)
        host = _host_of(conn, addr)
        if not host:
            return {'id': node_id, 'state': 'scanning'}
    out = deploy.adopt(db, conn, host, actor=actor)
    return {'id': node_id, 'state': out['state'], 'host': host, 'output': out['output']}


def retired(conn: Conn, addr: str | None) -> str | None:
    """The host at this address is being retired: its node goes too. Retiring drops the host's bindings and audits this,
    and calls sync once the row is committed. Returns the node's name, if there was one."""
    for n in _rows(conn):
        if address(n['id']) == addr:
            conn.execute('UPDATE remote_nodes SET revoked_at = :t WHERE node_id = :i', {'t': int(time.time()), 'i': n['id']})
            return n['name']
    return None


def revoke(db, conn: Conn, node_id: int, actor: str) -> dict:
    """Cuts the tunnel now. The machine keeps its accounts until its script runs with --remove; nothing can reach them."""
    n = get(conn, node_id)
    addr = address(node_id)
    conn.execute('UPDATE remote_nodes SET revoked_at = :t WHERE node_id = :i', {'t': int(time.time()), 'i': node_id})
    with Vault(db, conn).unlock() as v:
        for b in v.bindings():
            if b['pattern'] == addr:
                v.unbind(b['binding_id'])
        AuditLog(db, conn, v.audit_key).append(actor, 'remote.revoke', 'ok', n['name'], None, {'address': addr})
    sync(conn, drop_sessions=True)
    return {'id': node_id, 'name': n['name'], 'host': _host_of(conn, addr)}
