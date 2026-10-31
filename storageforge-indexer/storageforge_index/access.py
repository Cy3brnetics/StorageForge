"""Read-only scan access: let the scan account list and checksum every file without being root.

The setup gives the scan user private copies of find and sha256sum that carry CAP_DAC_READ_SEARCH (the same approach
restic documents for backup users). That capability lets a process open any directory and read any file; it grants no
write, no ownership change and no other privilege, and programs those tools start do not inherit it. The copies live
in /usr/local/lib/storageforge, owned by root and executable only by the storageforge-scan group, so no other account
gains anything. Scans pick them up automatically (remote._tool) and fall back to the plain tools when they are absent.

Two ways to apply it, both "after the fact" from the web UI or CLI:
  * copy the script and run it as root yourself, or
  * let StorageForge run it once over SSH with sudo, using a password typed into the request and never stored:
    either the scan user's own sudo password (it connects with the vault key) or an admin account's password
    (password login, then sudo with the same password).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from .db import epoch
from .keyinstall import askpass_path, validate
from .remote import READONLY_DIR, RemoteError, Transport, child_env
from .runner import connect_address, ephemeral_agent, known_hosts_path, runtime_dir
from .vault import NoBinding, Vault

GROUP = 'storageforge-scan'
TIMEOUT = 90

SETUP = r"""set -eu
U=%(user)s
D=%(dir)s
G=%(group)s
command -v setcap >/dev/null 2>&1 || { echo "setcap is missing: install libcap2-bin (Debian/Ubuntu) or libcap (RHEL/Rocky/Fedora)" >&2; exit 3; }
id "$U" >/dev/null 2>&1 || { echo "there is no user $U on this host" >&2; exit 3; }
getent group "$G" >/dev/null 2>&1 || groupadd --system "$G" 2>/dev/null || groupadd "$G"
usermod -a -G "$G" "$U"
install -d -o root -g "$G" -m 0750 "$D"
for t in find sha256sum; do
  src=$(command -v "$t") || { echo "$t is not installed" >&2; exit 3; }
  install -o root -g "$G" -m 0750 "$(readlink -f "$src")" "$D/$t"
  setcap cap_dac_read_search+ep "$D/$t"
done
getcap "$D/find" "$D/sha256sum"
# prove it: the scan user must now be able to list a root-only directory
if command -v runuser >/dev/null 2>&1 && ! runuser -u "$U" -- "$D/find" /root -maxdepth 1 >/dev/null 2>&1; then
  echo "the capability does not work here: this is probably a container (Docker, LXC) whose capability bounding set" >&2
  echo "lacks CAP_DAC_READ_SEARCH; add it to the container, or scan from the host instead" >&2
  rm -rf "$D"
  exit 4
fi
echo "read-only scan access is ready for $U"
"""

REMOVE = r"""set -eu
rm -rf %(dir)s
gpasswd -d %(user)s %(group)s 2>/dev/null || true
groupdel %(group)s 2>/dev/null || true
echo "read-only scan access removed"
"""


def setup_script(user: str) -> str:
    validate('localhost', user, 22)
    return SETUP % {'user': shlex.quote(user), 'dir': READONLY_DIR, 'group': GROUP}


def remove_script(user: str) -> str:
    validate('localhost', user, 22)
    return REMOVE % {'user': shlex.quote(user), 'dir': READONLY_DIR, 'group': GROUP}


def status(conn, host: str | None = None, limit: int = 200) -> list[dict]:
    """Per host: how the last scan read the disks and which folders it could not open."""
    rows = conn.all(f"""SELECT h.hostname, h.inventory_json, s.scan_id, s.finished_at, s.read_errors
                       FROM hosts h LEFT JOIN scans s ON s.scan_id = (SELECT max(scan_id) FROM scans x
                                                                     WHERE x.host_id = h.host_id AND x.status <> 'running')
                       {'WHERE h.hostname = :h OR h.ip_address = :h' if host else ''} ORDER BY h.hostname""", {'h': host})
    out = []
    for name, inv, scan_id, finished, read_errors in rows:
        inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
        denied = conn.all('SELECT mount_point, path FROM scan_denied WHERE scan_id = :s ORDER BY path LIMIT :n',
                          {'s': scan_id, 'n': limit}) if scan_id else []
        total = conn.scalar('SELECT count(*) FROM scan_denied WHERE scan_id = :s', {'s': scan_id}) if scan_id else 0
        out.append({'host': name, 'access': inv.get('access') or None, 'scan_user': inv.get('scan_user') or None,
                    'scan_id': scan_id, 'finished_at': epoch(finished), 'read_errors': read_errors or 0,
                    'denied_total': total, 'denied': [{'mount': m, 'path': p} for m, p in denied]})
    return out


def _clean(out: str, password: str) -> str:
    out = out.replace(password, '********') if password else out
    return '\n'.join(l for l in out.splitlines() if l.strip() and not l.startswith('[sudo]'))[-2000:]


def _finish(p: subprocess.CompletedProcess, password: str) -> dict:
    out = _clean((p.stdout or '') + (p.stderr or ''), password)
    if p.returncode == 0:
        return {'ok': True, 'output': out}
    if re.search(r'incorrect password|Sorry, try again|no password was provided|a password is required', out, re.I):
        raise RemoteError('sudo did not accept that password')
    if re.search(r'not in the sudoers|not allowed to (run|execute)', out, re.I):
        raise RemoteError('that account may not use sudo; use an admin account, or run the script as root yourself')
    if re.search(r'Permission denied \(', out):
        raise RemoteError('SSH login was refused')
    raise RemoteError(f'setup failed (exit {p.returncode}): {out.splitlines()[-1] if out else "no output"}')


def grant(db, conn, host: str, password: str, admin_user: str | None = None, remove: bool = False) -> dict:
    """Set up (or remove) read-only scan access on host, with sudo."""
    def make(scan_user):
        if not scan_user:
            raise ValueError(f'no scan key is bound to {host}: bind one first (Keys tab, or storageforge-index vault bind)')
        return (remove_script if remove else setup_script)(scan_user)
    return sudo_run(db, conn, host, make, password, admin_user)


def sudo_run(db, conn, host: str, make_script, password: str, admin_user: str | None = None) -> dict:
    """Run a root script on host once, with sudo: make_script(scan_user) -> script, scan_user None when no scan key
    is bound to host (then only admin_user can log in). The password only travels on stdin and the askpass environment
    of one ssh process; it is never logged, stored or put on a command line."""
    if not password:
        raise ValueError('a sudo password is required')
    host = connect_address(conn, host)
    with Vault(db, conn).unlock() as v:
        try:
            b = v.resolve(host, 'scan')
        except NoBinding:      # fine with an admin account: deploy access can come before any scan
            if not admin_user:
                raise ValueError(f'no scan key is bound to {host}: give an admin account and its password') from None
            b = None
        port = b.port if b else conn.scalar('SELECT ssh_port FROM hosts WHERE ssh_host = :h OR hostname = :h',
                                            {'h': host}) or 22
        from .hostkeys import require_confirmed
        require_confirmed(conn, host, port)            # a password goes only to a host key a person confirmed
        script = make_script(b.user if b else None)
        # stdin carries the password to sudo -S. With NOPASSWD, or as root, sudo reads none of it: the script starts
        # on /dev/null, so nothing it runs can read the password that is left there.
        sudo = 'sudo -S -p "" sh -c ' + shlex.quote('exec </dev/null\n' + script)
        if b and (not admin_user or admin_user == b.user):
            # the scan user's own sudo rights, connecting with its vault key
            with ephemeral_agent(v.decrypt_key(b.key_id), ttl=120) as sock:
                t = Transport(host=host, user=b.user, port=b.port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                              isolated=True, strict=True)
                try:
                    p = subprocess.run(t.argv(sudo), input=password + '\n', capture_output=True, text=True,
                                       timeout=TIMEOUT, env=child_env())
                finally:
                    t.close()
            return {'host': host, 'port': port, 'user': b.user, 'via': b.user, **_finish(p, password)}
    # an admin account: password login (askpass answers ssh once), then sudo with the same password on stdin
    validate(host, admin_user, port)
    work = Path(tempfile.mkdtemp(prefix='grant-', dir=runtime_dir()))
    try:
        argv = ['ssh', '-F', '/dev/null', '-T', '-p', str(port), '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={known_hosts_path()}', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=10', f'{admin_user}@{host}', sudo]
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(work), 'SSH_ASKPASS': askpass_path(),
               'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': 'none', 'STORAGEFORGE_ASKPASS_SECRET': password}
        p = subprocess.run(argv, input=password + '\n', env=env, capture_output=True, text=True, timeout=TIMEOUT,
                           start_new_session=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {'host': host, 'port': port, 'user': b.user if b else None, 'via': admin_user, **_finish(p, password)}
