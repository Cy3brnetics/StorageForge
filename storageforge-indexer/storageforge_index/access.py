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

from . import health
from .db import epoch
from .keyinstall import askpass_path, validate
from .remote import READONLY_DIR, RemoteError, Transport, child_env
from .runner import connect_address, ephemeral_agent, known_hosts_path, runtime_dir
from .vault import NoBinding, Vault

GROUP = 'storageforge-scan'
TIMEOUT = 300       # the setup may install a package first, on a small VM with stale metadata

SETUP = r"""set -eu
U=%(user)s
D=%(dir)s
G=%(group)s
PATH=$PATH:/usr/sbin:/sbin
if [ -x /usr/bin/midclt ] && [ -r /etc/version ]; then    # read-only /usr, so nowhere to put a capability program
  echo "TrueNAS keeps its system read-only, so scan access can't be added here. Scans still work: they see what $U may read." >&2; exit 3
fi
id "$U" >/dev/null 2>&1 || { echo "there is no user $U on this host" >&2; exit 3; }
if ! command -v setcap >/dev/null 2>&1; then      # not every image has it: openSUSE's and Alpine's minimal ones don't
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libcap2-bin >&2 || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q libcap >&2 || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q libcap >&2 || true
  elif command -v zypper >/dev/null 2>&1; then zypper -nq install libcap-progs >&2 || true
  elif command -v pacman >/dev/null 2>&1; then pacman -S --needed --noconfirm libcap >&2 || true
  elif command -v apk >/dev/null 2>&1; then apk add -q libcap-setcap >&2 || true
  fi
  command -v setcap >/dev/null 2>&1 || { echo "setcap is missing and could not be installed: libcap2-bin (Debian, Ubuntu), libcap (RHEL, Fedora, Arch), libcap-progs (openSUSE) or libcap-setcap (Alpine)" >&2; exit 3; }
fi
if ! getent group "$G" >/dev/null 2>&1; then
  groupadd --system "$G" 2>/dev/null || groupadd "$G" 2>/dev/null || addgroup -S "$G"      # addgroup: BusyBox has no groupadd
fi
usermod -a -G "$G" "$U" 2>/dev/null || addgroup "$U" "$G"
# so scans can collect the journal (hostlogs.py). No such group, no journal to read.
if getent group systemd-journal >/dev/null 2>&1; then usermod -a -G systemd-journal "$U" 2>/dev/null || addgroup "$U" systemd-journal 2>/dev/null || true; fi
install -d -o root -g "$G" -m 0750 "$D"
for t in find sha256sum; do
  src=$(command -v "$t") || { echo "$t is not installed" >&2; exit 3; }
  install -o root -g "$G" -m 0750 "$(readlink -f "$src")" "$D/$t"
  setcap cap_dac_read_search+ep "$D/$t"
done
command -v getcap >/dev/null 2>&1 && getcap "$D/find" "$D/sha256sum"
# prove it: the scan user must now be able to list a root-only directory
if command -v runuser >/dev/null 2>&1 && ! runuser -u "$U" -- "$D/find" /root -maxdepth 1 >/dev/null 2>&1; then
  echo "the capability does not work here: this is probably a container (Docker, LXC) whose capability bounding set" >&2
  echo "lacks CAP_DAC_READ_SEARCH; add it to the container, or scan from the host instead" >&2
  rm -rf "$D"
  exit 4
fi
# the key this host signs its scan payloads with (scansign.py): readable by the scan group only. Its public half is printed so that
# StorageForge, which runs this over a connection that accepts only the host key a person confirmed, can pin it.
if command -v ssh-keygen >/dev/null 2>&1; then
  [ -f "$D/scan-sign" ] || ssh-keygen -q -t ed25519 -N '' -C "storageforge-scan@$(hostname 2>/dev/null || echo host)" -f "$D/scan-sign" </dev/null >/dev/null
  chown root:"$G" "$D/scan-sign" "$D/scan-sign.pub"
  chmod 0640 "$D/scan-sign"
  chmod 0644 "$D/scan-sign.pub"
  echo "SFSIGNKEY $(cut -d' ' -f1,2 "$D/scan-sign.pub")"
else
  echo "ssh-keygen is not installed here, so this host cannot sign its scans" >&2
fi
echo "read-only scan access is ready for $U"
"""

REMOVE = r"""set -eu
""" + health.UNINSTALL + r"""rm -rf %(dir)s
gpasswd -d %(user)s %(group)s 2>/dev/null || delgroup %(user)s %(group)s 2>/dev/null || true
gpasswd -d %(user)s systemd-journal 2>/dev/null || delgroup %(user)s systemd-journal 2>/dev/null || true
groupdel %(group)s 2>/dev/null || delgroup %(group)s 2>/dev/null || true
echo "read-only scan access removed"
"""


def setup_script(user: str) -> str:
    validate('localhost', user, 22)
    ready = 'echo "read-only scan access is ready for $U"\n'
    return SETUP.replace(ready, health.install_script(GROUP).replace('%', '%%') + ready) % {'user': shlex.quote(user), 'dir': READONLY_DIR, 'group': GROUP}


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


NO_PASSWORD_MARK = 'storageforge-sudo-took-no-password'


def _clean(out: str, password: str) -> str:
    out = out.replace(password, '********') if password else out
    return '\n'.join(l for l in out.splitlines() if l.strip() and not l.startswith('[sudo]'))[-2000:]


def _no_password_warning(host: str, login: str, how: str) -> str:
    if how == 'password':       # ssh checked it, sudo didn't
        return (f'sudo on {host} did not ask {login} for a password: only the SSH login checked the one you typed. '
                f'{login} can become root without a sudo password.')
    head = f'sudo on {host} did not ask {login} for a password, so the one you typed was not checked. '
    if how == 'scan':
        return (head + f'{login} can become root without a password, so its scan key has full root on {host}, '
                f'not read-only access. Remove the NOPASSWD rule for {login}, or scan with a low-privilege account.')
    return head + f'Anyone with the key {login} logs in with has full root on {host}.'


def _finish(p: subprocess.CompletedProcess, password: str, host: str, login: str, how: str) -> dict:
    lines = (p.stdout or '').splitlines()
    passwordless = NO_PASSWORD_MARK in lines
    out = _clean('\n'.join(l for l in lines if l != NO_PASSWORD_MARK) + '\n' + (p.stderr or ''), password)
    if p.returncode == 0:
        res = {'ok': True, 'output': out, 'passwordless': passwordless}
        return {**res, 'warning': _no_password_warning(host, login, how)} if passwordless else res
    if re.search(r'incorrect password|Sorry, try again|no password was provided|a password is required', out, re.I):
        raise RemoteError('sudo did not accept that password (openSUSE\'s default sudo asks for root\'s password, not the user\'s)')
    if re.search(r'not in the sudoers|not allowed to (run|execute)', out, re.I):
        raise RemoteError('that account may not use sudo; use an admin account, or run the script as root yourself')
    if re.search(r'Permission denied \(', out):
        raise RemoteError('SSH login was refused: wrong password, or this account may not log in over SSH')
    raise RemoteError(f'setup failed (exit {p.returncode}): {out.splitlines()[-1] if out else "no output"}')


def grant(db, conn, host: str, password: str, admin_user: str | None = None, remove: bool = False,
          admin_key: str | None = None) -> dict:
    """Set up (or remove) read-only scan access on host, with sudo."""
    def make(scan_user):
        if not scan_user:
            raise ValueError(f'no scan key is bound to {host}: bind one first (Keys tab, or storageforge-index vault bind)')
        return (remove_script if remove else setup_script)(scan_user)
    res = sudo_run(db, conn, host, make, password, admin_user, admin_key)
    from . import scansign
    if remove:
        scansign.forget(conn, res['host'], res['port'])
    elif res.get('ok'):
        m = re.search(r'^SFSIGNKEY (ssh-ed25519 [A-Za-z0-9+/=]+)$', res.get('output') or '', re.M)
        if m:                  # it came over a connection bound to the confirmed host key: the strongest pin there is
            scansign.pin(conn, res['host'], res['port'], m.group(1), 'scan access setup, host key confirmed')
            res['scan_signing_key'] = scansign.fingerprint(m.group(1))
    return res


def sudo_run(db, conn, host: str, make_script, password: str, admin_user: str | None = None,
             admin_key: str | None = None) -> dict:
    """Run a root script on host once, with sudo: make_script(scan_user) -> script, scan_user None when no scan key
    is bound to host (then only admin_user can log in). The password only travels on stdin and the askpass environment
    of one ssh process; it is never logged, stored or put on a command line. admin_key: a vault key admin_user logs in
    with, for hosts that take no SSH passwords: the password is then only sudo's."""
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
        # on /dev/null, so nothing it runs can read the password that is left there. The probe says when that happened:
        # -k ignores a cached sudo login, and it asks for sh because that is what the script runs as root.
        sudo = (f'sudo -n -k sh -c : </dev/null >/dev/null 2>&1 && echo {NO_PASSWORD_MARK}; '
                'sudo -S -p "" sh -c ' + shlex.quote('exec </dev/null\n' + script))
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
            return {'host': host, 'port': port, 'user': b.user, 'via': b.user, **_finish(p, password, host, b.user, 'scan')}
        if admin_key:         # an admin account with a key from the vault
            if not admin_user:
                raise ValueError('name the admin account the key logs in as')
            validate(host, admin_user, port)
            kid = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': admin_key})
            if kid is None:
                raise ValueError(f'the vault has no key named {admin_key}')
            with ephemeral_agent(v.decrypt_key(kid), ttl=TIMEOUT + 30) as sock:
                t = Transport(host=host, user=admin_user, port=port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                              isolated=True, strict=True)
                try:
                    p = subprocess.run(t.argv(sudo), input=password + '\n', capture_output=True, text=True,
                                       timeout=TIMEOUT, env=child_env())
                finally:
                    t.close()
            return {'host': host, 'port': port, 'user': b.user if b else None, 'via': f'{admin_user} (key {admin_key})',
                    **_finish(p, password, host, admin_user, 'key')}
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
    if p.returncode and 'Permission denied (' in (p.stderr or ''):      # the password or the server? Its answer says
        from .preflight import auth_methods, takes_password
        methods = auth_methods(host, port)
        if not takes_password(methods):
            raise RemoteError(f'{host} takes no SSH passwords (it offers: {", ".join(methods)}). Pick a vault key {admin_user} can log '
                              f'in with and give its sudo password, or run the setup script as root yourself')
    return {'host': host, 'port': port, 'user': b.user if b else None, 'via': admin_user, **_finish(p, password, host, admin_user, 'password')}
