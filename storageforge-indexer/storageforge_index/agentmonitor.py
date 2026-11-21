"""Monitoring-only hosts (roadmap section 11.5, "Hosts by mode"): a host the controller has no SSH scan key and no deploy access for,
where storageforge-agentctl is the only way in and the agent is the only way the controller hears of it.

    register(conn, name, address, port, arch, actor)   the host, and its agent switched on, in mode 'monitoring'
    setup(db, name)                     the setup script an admin runs by hand as root on the host, the same one a deploy sends,
                                        and the program it installs (by size and sha256): nothing reaches the host from here
    adopt(db, name, line, actor)        the line the setup printed (the host's machine id and SSH host key), pasted by an admin: the
                                        host key is pinned (a person compared it, as Keys → Confirm does), the machine id recorded,
                                        and the agent enrolled through storageforge-agentctl as on any host
    monitoring_only(conn, host)         whether a host is one
    refusal(conn, host, what)           the words for a feature a monitoring-only host does not get, or None

What a monitoring-only host gets: everything the agent reads, live (health, logs, disks, network, files, the scan plugin's inventory and
its mounts, the sentinel's events), wipe and stop, and a console that turns SSH on for one session through storageforge-agentctl
(agentconsole.py). What it does not get, and why: change plans, deploys, Moves, sends, clone, holds and quarantine all act over SSH as
root, which this controller does not have there. Adding SSH access later is an upgrade, not a reinstall.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time

from . import deploy, sfagent
from .db import Database

NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}')
ADDRESS_RE = re.compile(r'[A-Za-z0-9.:_\[\]-]{1,255}')
ADOPT_RE = re.compile(r'storageforge-agent-adopt ([0-9a-f]{32}) ssh-ed25519 ([A-Za-z0-9+/]{68})')
FEATURES = ('change plans', 'deploys', 'Moves', 'sends', 'clone', 'holds', 'quarantine')
WHY = ('{host} is monitoring only: StorageForge reaches it through storageforge-agentctl alone, which runs the agent and nothing else, '
       'so {what} cannot be done there. Set up SSH access to the host to have it')


class MonitoringError(RuntimeError):
    pass


def monitoring_only(conn, host: str) -> bool:
    return conn.scalar("SELECT count(*) FROM agents WHERE host = :h AND mode = 'monitoring' AND enabled = 1", {'h': deploy.canonical(conn, host)}) > 0


def refusal(conn, host: str, what: str) -> str | None:
    """The reason a feature is not offered on this host, or None when it is not a monitoring-only host."""
    name = deploy.canonical(conn, host)
    return WHY.format(host=name, what=what) if monitoring_only(conn, name) else None


def register(conn, name: str, address: str, port: int, arch: str, actor: str) -> dict:
    if not NAME_RE.fullmatch(name or '') or not ADDRESS_RE.fullmatch(address or '') or not 0 < int(port) < 65536:
        raise MonitoringError('a monitoring-only host is a name, an address and an SSH port')
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(arch, arch)
    if arch not in ('x86_64', 'aarch64'):
        raise MonitoringError('the agent is built for x86_64 and arm64')
    if conn.scalar('SELECT count(*) FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :a', {'h': name, 'a': address}):
        raise MonitoringError(f'{name} or {address} is a host StorageForge has already: switch the agent on for it instead')
    if conn.scalar('SELECT count(*) FROM network_devices WHERE name = :n', {'n': name}):
        raise MonitoringError(f'{name} is a network device: routers, firewalls, switches and appliances stay agentless')
    cast = ':inv' if conn.dialect == 'sqlite' else 'CAST(:inv AS jsonb)'
    import json
    conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port, inventory_json) VALUES (:h, :a, :u, :p, {cast})""",
                 {'h': name, 'a': address, 'u': sfagent.MANAGER, 'p': int(port), 'inv': json.dumps({'packages': f'arch\t{arch}', 'source': 'agent', 'label': 'reported by agent'})})
    sfagent.switch(conn, name, True, actor)
    sfagent._save(conn, name, actor, mode='monitoring', detail='set up the agent on the host by hand, then paste the line the setup printed')
    return sfagent.get(conn, name)


def setup(db: Database, name: str) -> dict:
    conn = db.connect()
    try:
        name = deploy.canonical(conn, name)
        if not monitoring_only(conn, name):
            raise MonitoringError(f'{name} is not a monitoring-only host: its agent is set up through its deploy access')
        program = sfagent.agentctl_program(sfagent.host_arch(conn, name))
        from .vault import Vault
        with Vault(db, conn).unlock() as v:
            signing_pub, login_pub = sfagent.ensure_keys(v)
        return {'host': name, 'script': sfagent.setup_script(signing_pub, login_pub, program), 'arch': sfagent.host_arch(conn, name),
                'program_sha256': hashlib.sha256(program).hexdigest(), 'program_size': len(program),
                'how': 'Copy storageforge-agentctl and this script to the host, then as root: bash storageforge-agent-setup.sh ./storageforge-agentctl. '
                       'It checks the program by size and sha256, makes the two accounts and the one sudoers line, and prints a line '
                       'beginning storageforge-agent-adopt: compare the host key in it with the host\'s own (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) '
                       'and paste it here.'}
    finally:
        conn.close()


def _pin(conn, address: str, port: int, key_b64: str, actor: str) -> str:
    """Pins the host key an admin pasted, as Keys → Confirm pins one a person compared. A key already pinned for that address that
    is another one is refused: that is what a machine in the middle would look like."""
    from .remote import known_host_keys, known_hosts_name
    from .runner import known_hosts_path
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(key_b64)).digest()).decode().rstrip('=')
    kh = known_hosts_path()
    pinned = known_host_keys(address, port, str(kh))
    if pinned and fp not in pinned:
        raise MonitoringError(f'StorageForge holds another host key for {address}: {", ".join(pinned)}. If the host was reinstalled, '
                              'forget the old key first (storageforge-index hosts rekey)')
    if not pinned:
        with kh.open('a') as f:
            f.write(f'{known_hosts_name(address, port)} ssh-ed25519 {key_b64}\n')
    conn.execute('DELETE FROM host_key_confirmations WHERE address = :a AND port = :p AND fingerprint = :f', {'a': address, 'p': port, 'f': fp})
    conn.execute("""INSERT INTO host_key_confirmations (address, port, fingerprint, confirmed_by, confirmed_at) VALUES (:a, :p, :f, :b, :t)""",
                 {'a': address, 'p': port, 'f': fp, 'b': actor, 't': int(time.time())})
    return fp


def adopt(db: Database, name: str, line: str, actor: str, install_podman: bool = False) -> dict:
    conn = db.connect()
    try:
        name = deploy.canonical(conn, name)
        row = sfagent.get(conn, name)
        if not row or row.get('mode') != 'monitoring' or not row['enabled']:
            raise MonitoringError(f'{name} is not a monitoring-only host')
        if row['state'] in ('running', 'stopped'):
            raise MonitoringError(f'{name} has an agent enrolled already: remove it before adopting the host again')
        m = ADOPT_RE.search(line or '')
        if not m:
            raise MonitoringError('that is not the line the setup printed: storageforge-agent-adopt, the machine id, then ssh-ed25519 and the host key')
        machine, key = m.group(1), m.group(2)
        address, port = conn.all('SELECT ssh_host, ssh_port FROM hosts WHERE hostname = :h', {'h': name})[0]
        fp = _pin(conn, address, int(port or 22), key, actor)
        import json
        conn.execute('UPDATE hosts SET machine_id = :m, host_keys = :k WHERE hostname = :h', {'m': machine, 'k': json.dumps([fp]), 'h': name})
        sfagent._save(conn, name, actor, host_key=f'ssh-ed25519 {key}', detail='')
        image, image_sig = sfagent.agent_image(), sfagent.image_signature()
        try:
            got = sfagent.enroll_set_up(db, conn, name, row, actor, image, image_sig, install_podman=install_podman)
        except Exception as exc:
            sfagent._save(conn, name, actor, state='failed', detail=str(exc))
            raise
        return got | {'host_key': fp, 'mode': 'monitoring'}
    finally:
        conn.close()
