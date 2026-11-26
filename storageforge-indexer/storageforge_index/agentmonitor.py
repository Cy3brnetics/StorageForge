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
from .sshwire import fingerprint_of_blob

NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}')
ADDRESS_RE = re.compile(r'[A-Za-z0-9.:_\[\]-]{1,255}')
ADOPT_RE = re.compile(r'storageforge-agent-adopt ([0-9a-f]{32}) ssh-ed25519 ([A-Za-z0-9+/]{68})')
FEATURES = ('change plans', 'deploys', 'Moves', 'sends', 'clone', 'holds', 'quarantine')
WHY = ('{host} is monitoring only: StorageForge reaches it through storageforge-agentctl alone, which runs the agent and nothing else, '
       'so {what} cannot be done there. Set up SSH access to the host to have it')


class MonitoringError(RuntimeError):
    pass


NO_WINDOWS = 'a native Windows agent is not shipped yet: a Windows host cannot be set up for monitoring only'


def monitoring_only(conn, host: str) -> bool:
    return conn.scalar("SELECT count(*) FROM agents WHERE host = :h AND mode = 'monitoring' AND enabled = 1", {'h': deploy.canonical(conn, host)}) > 0


def refusal(conn, host: str, what: str) -> str | None:
    """The reason a feature is not offered on this host, or None when it is not a monitoring-only host."""
    name = deploy.canonical(conn, host)
    return WHY.format(host=name, what=what) if monitoring_only(conn, name) else None


def host_os(conn, host: str) -> str:
    """Operating system family recorded for a monitoring-only host ('linux' or 'windows')."""
    import json
    inv = conn.scalar('SELECT inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': deploy.canonical(conn, host)})
    inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
    for line in str(inv.get('packages') or '').splitlines():
        if line.startswith('os\t'):
            val = line.split('\t', 1)[1].strip().lower()
            if val in ('linux', 'windows'):
                return val
    return 'linux'


def windows_setup_script(signing_pub: str, login_pub: str, program_sha256: str, program_size: int) -> str:
    """PowerShell setup script for a native Windows service monitoring-only agent managed over OpenSSH for Windows."""
    lines = [
        '# Run from an elevated Administrator PowerShell prompt on the Windows host:',
        '#   powershell -ExecutionPolicy Bypass -File .\\storageforge-agent-setup.ps1 .\\storageforge-agentctl.exe',
        'param([Parameter(Mandatory=$true)][string]$AgentCtlExe)',
        '$ErrorActionPreference = "Stop"',
        f'$ExpectedSize = {int(program_size)}',
        f'$ExpectedSha = "{program_sha256}"',
        '$Item = Get-Item -LiteralPath $AgentCtlExe',
        'if ($Item.Length -ne $ExpectedSize) { throw "storageforge-agentctl.exe size mismatch" }',
        '$Hash = (Get-FileHash -LiteralPath $AgentCtlExe -Algorithm SHA256).Hash.ToLowerInvariant()',
        'if ($Hash -ne $ExpectedSha) { throw "storageforge-agentctl.exe sha256 mismatch" }',
        r'$ProgDir = "C:\Program Files\StorageForge\Agent"',
        r'$DataDir = "C:\ProgramData\StorageForge\Agent"',
        r'New-Item -ItemType Directory -Force -Path $ProgDir, "$DataDir\etc", "$DataDir\manifest", "$DataDir\state", "$ProgDir\plugins" | Out-Null',
        r'Copy-Item -Force -LiteralPath $AgentCtlExe -Destination "$ProgDir\storageforge-agentctl.exe"',
        'icacls $DataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null',
        f'$SignerLine = "controller cert-authority,namespaces=`"storageforge-agentctl,storageforge-agent-manifest`" {signing_pub.strip()}"',
        r'Set-Content -Path "$DataDir\etc\controller_signers" -Value $SignerLine -Encoding Ascii',
        r'$AuthLine = "restrict,command=`"C:\\Program Files\\StorageForge\\Agent\\storageforge-agentctl.exe`" ' + login_pub.strip() + '"',
        r'Set-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $AuthLine -Encoding Ascii',
        'icacls "C:\\ProgramData\\ssh\\administrators_authorized_keys" /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null',
        r'$BinPath = "`"C:\Program Files\StorageForge\Agent\storageforge-agent.exe`" run --etc `"C:\ProgramData\StorageForge\Agent\etc`" --manifest `"C:\ProgramData\StorageForge\Agent\manifest`" --state `"C:\ProgramData\StorageForge\Agent\state`""',
        'if (Get-Service -Name StorageForgeAgent -ErrorAction SilentlyContinue) { Stop-Service -Name StorageForgeAgent -Force -ErrorAction SilentlyContinue }',
        'sc.exe create StorageForgeAgent binPath= $BinPath start= auto DisplayName= "StorageForge Monitoring Agent" | Out-Null',
        '$Mid = ((Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Cryptography").MachineGuid -replace "[^0-9a-fA-F]", "").ToLowerInvariant().PadRight(32, "0").Substring(0, 32)',
        '$HostKey = (Get-Content "C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub" -TotalCount 1).Trim().Split(" ")[0..1] -join " "',
        'Write-Output "storageforge-agent-adopt $Mid $HostKey"',
    ]
    return '\n'.join(lines) + '\n'


def register(conn, name: str, address: str, port: int, arch: str, actor: str, os_family: str = 'linux') -> dict:
    if not NAME_RE.fullmatch(name or '') or not ADDRESS_RE.fullmatch(address or '') or not 0 < int(port) < 65536:
        raise MonitoringError('a monitoring-only host is a name, an address and an SSH port')
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(arch, arch)
    if arch not in ('x86_64', 'aarch64'):
        raise MonitoringError('the agent is built for x86_64 and arm64')
    os_family = (os_family or 'linux').strip().lower()
    if os_family not in ('linux', 'windows'):
        raise MonitoringError('monitoring-only hosts support linux or windows')
    if os_family == 'windows':
        raise MonitoringError(NO_WINDOWS)
    with conn.tx():
        if conn.scalar('SELECT count(*) FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :a', {'h': name, 'a': address}):
            raise MonitoringError(f'{name} or {address} is a host StorageForge has already: switch the agent on for it instead')
        if conn.scalar('SELECT count(*) FROM network_devices WHERE name = :n', {'n': name}):
            raise MonitoringError(f'{name} is a network device: routers, firewalls, switches and appliances stay agentless')
        cast = ':inv' if conn.dialect == 'sqlite' else 'CAST(:inv AS jsonb)'
        import json
        conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port, inventory_json) VALUES (:h, :a, :u, :p, {cast})""",
                     {'h': name, 'a': address, 'u': sfagent.MANAGER, 'p': int(port), 'inv': json.dumps({'packages': f'arch\t{arch}\nos\t{os_family}', 'source': 'agent', 'label': 'reported by agent'})})
        sfagent.switch(conn, name, True, actor)
        sfagent._save(conn, name, actor, mode='monitoring', detail='set up the agent on the host by hand, then paste the line the setup printed')
        return sfagent.get(conn, name)


def _windows_agentctl(arch: str) -> bytes:
    """Finds storageforge-agentctl.exe for Windows when present, falling back to sfagent.agentctl_program."""
    import os
    from pathlib import Path
    folder = os.environ.get('STORAGEFORGE_AGENT_DIR', '').strip()
    if folder:
        exe = Path(folder) / arch / 'storageforge-agentctl.exe'
        if exe.is_file():
            data = exe.read_bytes()
            if data.startswith(b'MZ') and len(data) <= 32 * 1024 * 1024:
                return data
            raise sfagent.AgentError(f'{exe} is not a Windows executable')
    return sfagent.agentctl_program(arch)


def setup(db: Database, name: str) -> dict:
    conn = db.connect()
    try:
        name = deploy.canonical(conn, name)
        if not monitoring_only(conn, name):
            raise MonitoringError(f'{name} is not a monitoring-only host: its agent is set up through its deploy access')
        if host_os(conn, name) == 'windows':
            raise MonitoringError(NO_WINDOWS)
        arch = sfagent.host_arch(conn, name)
        os_family = host_os(conn, name)
        program = _windows_agentctl(arch) if os_family == 'windows' else sfagent.agentctl_program(arch)
        from .vault import Vault
        with Vault(db, conn).unlock() as v:
            signing_pub, login_pub = sfagent.ensure_keys(v)
        sha = hashlib.sha256(program).hexdigest()
        if os_family == 'windows':
            return {'host': name, 'platform': 'windows', 'service': 'StorageForgeAgent',
                    'script': windows_setup_script(signing_pub, login_pub, sha, len(program)),
                    'arch': arch, 'program_sha256': sha, 'program_size': len(program),
                    'how': 'Native Windows service (not a container), monitoring only, managed over OpenSSH for Windows. '
                           'Run the PowerShell script as Administrator, compare C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub, '
                           'and paste the storageforge-agent-adopt line here.'}
        return {'host': name, 'platform': 'linux', 'script': sfagent.setup_script(signing_pub, login_pub, program), 'arch': arch,
                'program_sha256': sha, 'program_size': len(program),
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
    fp = fingerprint_of_blob(base64.b64decode(key_b64))
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
        if host_os(conn, name) == 'windows':
            raise MonitoringError(NO_WINDOWS)
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
