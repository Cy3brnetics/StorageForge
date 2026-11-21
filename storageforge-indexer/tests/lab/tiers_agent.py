#!/usr/bin/env python3
"""Tier 24 of the KVM lab: the optional agent's base (roadmap section 11.1, and the rows of 11.6 that are about it) on real hosts.

NOT RUN. This file was written where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is not
lab-tested. What was run is tests/test_agent.py on one machine: the setup script in bash, the real storageforge-agentctl and agent
against a folder standing for a host, and the real image under the real Docker.

What a real host adds to that, and this tier is for: real accounts and a real sudoers file read by sudo, sshd's forced command, Podman
without root with a session that lingers, the distributions' own package managers, SELinux on the dnf hosts, and LXC on Proxmox VE.

**What the lab's build has to provide first, and does not yet** (lab.sh is not changed by this file):

    1. the agent's programs and image built with a release key made for the lab (agent/build.sh and the Dockerfile's `agent` stage
       with STORAGEFORGE_RELEASE_SIGNERS / AGENT_RELEASE_SIGNERS naming the lab key's signers file)
    2. that image in a registry every lab VM can pull from by digest (a registry on sf-ctl, and the VMs told it is plain HTTP)
    3. the lab's server given STORAGEFORGE_AGENT_IMAGE (the digest), STORAGEFORGE_AGENT_IMAGE_SIG (the lab key's signature of it) and
       STORAGEFORGE_AGENT_DIR (the programs)
    4. for the tunnel and receiver checks: the stack started with docker-compose.agent.yml as well, and STORAGEFORGE_AGENT_ENDPOINT
       naming sf-ctl's address and the receiver's port, so that agents have somewhere to dial
    5. for the plugin checks: the official plugins laid out and signed with the lab's release key (agent/plugins.sh lay, then sign),
       and STORAGEFORGE_AGENT_PLUGINS naming that folder on the lab's server

Until then /api/agents names no image and every check here shows as skip with that reason, not as a pass. Without 4, the tunnel and
receiver checks show as skip, with that reason.

    off             the agent is off for every host until it is switched on for one
    docker group    with the managing user in the docker group the setup is refused, with the reason, and nothing is installed
    install         switched on and installed: on a host with Docker, a host with Podman (it runs without root there), and a host with
                    no runtime, where the install stops, says Podman will be installed, and installs it only when told
    as sfagent      the agent's process is sfagent, with no capability, cannot gain any, and sfagent is in no group that gives root and
                    has no sudo
    one line        the managing user can run storageforge-agentctl through sudo with no arguments and nothing else: not docker, not
                    podman, not a shell, not storageforge-agentctl with an argument; and what it sends unsigned is refused
    no socket       no runtime's socket is in the container, its root is read-only, and it has no network but its tunnel's
    tunnel          the agent opens a session with the receiver; from inside its network namespace the receiver's port answers and
                    the host's own sshd, another host's sshd and the internet do not; the host's nft table is there and in its unit
    stolen key      the agent's key, copied off the host, opens a session while it is pinned and none after the agent is removed
    names another   a batch played with that key that names another host, its address and its machine id is stored under the
                    sender's host, and the claim is a security finding
    flood           batches past the agent's rate are refused and counted, the web UI answers meanwhile, and another host's agent
                    keeps every row
    replayed        batches deleted on the way show as a gap, and one played again with other bytes as a repeat, and is refused
    not built       a tripwire report naming another client, and a share freeze asked by one agent: neither action is built (the
                    Windows tripwire is 0.5.14), so these are skipped with that reason; the gate both go through, agentaction.py,
                    holds in the unit tests (test_agent_guard.Gate)
    checked         the check from outside, over SSH, finds nothing on an agent as it was made
    plugins         heartbeat, logs, health and network, each signed by the lab's release key and delivered through the tunnel: beats
                    arrive, a line written with logger arrives within seconds signed and matched by a log rule, health says sshd
                    listens on the host's SSH port, network reports the interfaces
    sshd down       sshd stopped for a minute and a half (a timer on the host starts it again): the agent goes on reporting and the
                    notification center says SSH is down
    written into    a file written into the running container's own layer: the check from outside wipes it, the container is
                    stopped and left stopped, its key is gone, a notification that cannot be ignored is open, and scans still work
    tampered        a file dropped into the plugin folder, a plugin program changed, and an old manifest put back, each as root on
                    the host: the agent wipes its key by itself within a minute, its last word reaches the controller, and the
                    controller revokes it; only an admin enrolls it again
    pve             on Proxmox VE the agent runs in an unprivileged LXC container made by pct, and Podman was never installed
    stop, remove    stopped it stays stopped; removed, the accounts, the sudoers line and the program are gone, and scans still work

The checks of the plugins and of wipe and stop (sections 11.3 and 11.4) were written with them, in 0.5.7, and have not run either.

Written in 0.5.8 and not run either (on the Docker host, after the checks above, and on one more host made monitoring only):

    disks           the disks plugin reports each disk (SMART where the disk answers it, the reason where it does not, as on virtio), and
                    its process gave up root for sfagent and holds SYS_RAWIO and nothing else, in every set the kernel shows
    files root      switching the files plugin on takes an admin, and the answer says it is root on the host in effect
    files           a file written by an ordinary account comes back with its process and account, and is in the file index
    hand edit       a line added by hand to /etc/exports is configuration drift that cannot be ignored
    off-hours       with no working hours set, an account reading many files is a notification
    from both       a file changed while the files plugin is held back is found by the next scan as a change the agent never reported;
                    a change the agent reports that did not happen (played with the agent's key) is contradicted by the next scan
    sentinel        an event the sentinel writes as root reaches the controller through the agent, marked as come through it
    monitoring      a host StorageForge forgets is registered monitoring only, set up by hand with the setup script and adopted with the
                    line it printed; its agent runs, its scan plugin's inventory and mounts arrive, and a deploy is refused with the reason
    console         on that host: refused until its admin lists an account; then a session opens as that account with a key made for it,
                    the key line is in its authorized_keys while the session runs and gone after, and sshd refuses the key once used
"""
import base64
import json
import shlex
import socket
import time

import demo
import roles

import tiers as t  # noqa: F401  (for the path set-up, as the other tier files do)
from tiers_platform import sudo

MANAGER, AGENT = 'storageforge-agentctl', 'sfagent'
CTL = '/usr/local/sbin/storageforge-agentctl'
ENDED = ('running', 'needs-podman', 'failed')


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def row(api, name):
    return next(a for a in api.get('/api/agents')['agents'] if a['host'] == name)


def install(api, name, **body):
    """Start an install and wait for it to end one way or another. Returns the agent's row."""
    api.post(f'/api/agents/{name}/install', body)
    return demo.wait(f'the agent on {name}', lambda: (lambda a: a if a['state'] in ENDED and a['state'] != 'on' else None)(row(api, name)), timeout=1200)


def has(node, program):
    return sudo(node.name, f'command -v {shlex.quote(program)} >/dev/null 2>&1 && echo yes; true', check=False).strip() == 'yes'


def agent_pid(node):
    out = sudo(node.name, 'pgrep -f "^/usr/bin/storageforge-agent run" | head -n 1; true', check=False).strip()
    want(out.isdigit(), 'no storageforge-agent process on the host')
    return out


def status_of(node, pid):
    text = sudo(node.name, f'cat /proc/{pid}/status')
    return dict(line.split(':\t', 1) for line in text.splitlines() if ':\t' in line)


def tier24(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    listed = api.get('/api/agents')
    if not listed.get('image'):
        r.add('agent', '-', None, 'the lab server is given no agent image: the lab build does not publish one yet (see the top of tiers_agent.py)')
        return
    vms = [n for n in roles.deployable() if not n.can('appliance')]
    with_docker = next((n for n in vms if has(n, 'docker')), None)
    with_podman = next((n for n in vms if has(n, 'podman') and not has(n, 'docker')), None)
    bare = next((n for n in vms if not any(has(n, p) for p in ('docker', 'podman', 'lxc-create', 'incus', 'pct'))), None)
    pve = next((n for n in roles.having('proxmox') if n.can('deploy')), None)

    def off():
        on = [a['host'] for a in listed['agents'] if a['enabled']]
        want(not on, f'the agent is on for {on} before anyone switched it on')
        status, out = api.raw('POST', f'/api/agents/{demo.known_as(api, vms[0].name)}/install', {})
        if status == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            status, out = api.raw('POST', f'/api/agents/{demo.known_as(api, vms[0].name)}/install', {})
        want(status == 409 and 'switched off' in out.get('error', ''), f'an install on a host with the agent off was not refused: {status} {out}')
        return 'off for every host, and an install is refused while it is'
    r.check('agent-off-by-default', '-', off)

    if with_docker:
        node, name = with_docker, demo.known_as(api, with_docker.name)

        def docker_group():
            api('PUT', f'/api/agents/{name}', {'enabled': True})
            sudo(node.name, f'id {MANAGER} >/dev/null 2>&1 || useradd --system --user-group --shell /bin/sh {MANAGER}; gpasswd -a {MANAGER} docker >/dev/null')
            try:
                got = install(api, name)
                want(got['state'] == 'failed', f'the setup went on with {MANAGER} in the docker group: {got["state"]}')
                want('is in the docker group, which is root on this host' in (got.get('detail') or ''), f'the reason was not given: {got.get("detail")}')
                want(not has(node, CTL), 'storageforge-agentctl was installed although the setup refused')
                want(sudo(node.name, 'ls /etc/sudoers.d/storageforge-agentctl 2>/dev/null; true', check=False).strip() == '', 'a sudoers line was written although the setup refused')
            finally:
                sudo(node.name, f'gpasswd -d {MANAGER} docker >/dev/null; userdel {MANAGER} 2>/dev/null; true', check=False)
            return 'refused before anything was installed, naming the group and how to leave it'
        r.check('agent-refused-in-docker-group', node.name, docker_group)

    def checks_on(node, expect):
        name = demo.known_as(api, node.name)

        def installed():
            api('PUT', f'/api/agents/{name}', {'enabled': True})
            got = install(api, name)
            if expect == 'podman-rootless' and node is bare:
                want(got['state'] == 'needs-podman', f'a host with no runtime was not stopped at the notice: {got["state"]}')
                want('Podman will be installed' in (got.get('detail') or ''), 'the user was not told Podman will be installed')
                want(not has(node, 'podman'), 'Podman was installed before anyone said so')
                got = install(api, name, install_podman=True)
            want(got['state'] == 'running', f'the agent is {got["state"]}: {got.get("detail")}')
            want(got['runtime'] == expect, f'the agent runs under {got["runtime"]}, expected {expect}')
            said = api.post(f'/api/agents/{name}/status')
            want(said['running'] and said['key_matches'], f'the host does not say it runs with the pinned key: {said}')
            return f'running under {got["runtime"]}, with the key {got["fingerprint"]} pinned'
        r.check('agent-install', node.name, installed)

        def as_sfagent():
            pid = agent_pid(node)
            s = status_of(node, pid)
            uid = sudo(node.name, f'id -u {AGENT}').strip()
            # under LXC and Podman the process is in a user namespace: its uid as the host sees it is what /proc shows here
            want(s['Uid'].split()[0] == uid, f'the agent runs as uid {s["Uid"].split()[0]}, and {AGENT} is {uid}')
            want(uid != '0', f'{AGENT} is root')
            want(int(s['CapEff'], 16) == 0 and int(s['CapPrm'], 16) == 0, f'the agent holds capabilities: {s["CapEff"]} {s["CapPrm"]}')
            want(s['NoNewPrivs'].strip() == '1', 'the agent can gain privileges')
            groups = sudo(node.name, f'id -nG {AGENT}').split()
            want(not set(groups) & {'docker', 'lxd', 'incus-admin', 'sudo', 'wheel', 'admin', 'root'}, f'{AGENT} is in {groups}')
            may = sudo(node.name, f'sudo -l -U {AGENT} 2>&1; true', check=False)
            want('not allowed to run sudo' in may, f'{AGENT} has sudo: {may[-200:]}')
            if expect == 'podman-rootless':
                owner = sudo(node.name, f'ps -o user= -p "$(pgrep -u {AGENT} -x conmon | head -n 1)"; true', check=False).strip()
                want(owner == AGENT, f'the container is not run by {AGENT} itself: conmon belongs to {owner or "nobody found"}')
            return f'uid {uid}, no capability, no new privileges, in {groups}, no sudo'
        r.check('agent-runs-as-sfagent', node.name, as_sfagent)

        def one_line():
            want(sudo(node.name, 'cat /etc/sudoers.d/storageforge-agentctl').strip() == f'{MANAGER} ALL=(root) NOPASSWD: {CTL} ""', 'the sudoers file is not the one line')
            as_manager = f'runuser -u {MANAGER} --'
            for attempt in ('sudo -n docker ps', 'sudo -n podman ps', 'sudo -n sh -c id', 'sudo -n id', f'sudo -n {CTL} status', f'sudo -n {CTL} --version', 'docker ps', 'cat /etc/shadow'):
                out = sudo(node.name, f'{as_manager} {attempt} >/dev/null 2>&1; echo $?', check=False).strip()
                want(out not in ('', '0'), f'{MANAGER} could run: {attempt}')
            # the one thing it may run, given something that is no signed request
            out = sudo(node.name, f'printf "STORAGEFORGE-AGENTCTL 1\\n2\\n2\\n{{}}{{}}" | {as_manager} sudo -n {CTL} >/dev/null 2>&1; echo $?', check=False).strip()
            want(out == '97', f'an unsigned request was not refused with 97: {out}')
            keys = sudo(node.name, f'cat "$(getent passwd {MANAGER} | cut -d: -f6)/.ssh/authorized_keys"')
            want(keys.startswith(f'restrict,command="sudo -n {CTL}" '), 'the login key is not held to the one command')
            return 'sudo runs storageforge-agentctl with no arguments and nothing else, and it refuses what is not signed'
        r.check('agent-one-sudoers-line', node.name, one_line)

        def no_socket():
            pid = agent_pid(node)
            mounts = sudo(node.name, f'cat /proc/{pid}/mountinfo')
            want(not any(word in mounts for word in ('docker.sock', 'podman.sock', 'containerd', 'unix.socket', '/run/pve', 'lxd')), 'a runtime socket is mounted in the container')
            for path in ('run/docker.sock', 'var/run/docker.sock', 'run/podman/podman.sock', 'var/lib/incus/unix.socket', 'bin/sh', 'usr/bin/ssh'):
                want(sudo(node.name, f'test -e /proc/{pid}/root/{path} && echo there; true', check=False).strip() == '', f'/{path} is in the container')
            if expect in ('docker', 'podman-rootless', 'podman'):
                root = [line for line in mounts.splitlines() if line.split()[4] == '/']
                want(root and 'ro' in root[0].split()[5].split(','), 'the root filesystem is not read-only')
            links = sudo(node.name, f'nsenter -t {pid} -n ip -o link | wc -l').strip()
            tunnel = bool(row(api, name).get('endpoint'))
            want(links == ('2' if tunnel else '1'), f'the container has {links} network interfaces, expected {"lo and its tunnel" if tunnel else "only lo"}')
            return 'no socket, no shell, no ssh, read-only root, no network but ' + ('lo and its tunnel\'s' if tunnel else 'lo')
        r.check('agent-no-socket-inside', node.name, no_socket)

        tunnel_checks(node, name)
        guard_checks(node, name, expect)

        def stop_remove():
            api.post(f'/api/agents/{name}/stop')
            want(sudo(node.name, 'pgrep -f "^/usr/bin/storageforge-agent run"; true', check=False).strip() == '', 'the agent still runs after stop')
            want(not api.post(f'/api/agents/{name}/status')['running'], 'the host says it runs after stop')
            api.post(f'/api/agents/{name}/start')
            agent_pid(node)
            got = api('DELETE', f'/api/agents/{name}')
            want(not got['problems'], f'removing left something behind: {got["problems"]}')
            for account in (MANAGER, AGENT):
                want(sudo(node.name, f'id {account} >/dev/null 2>&1 && echo there; true', check=False).strip() == '', f'{account} is still an account')
            left = sudo(node.name, f'ls {CTL} /etc/sudoers.d/storageforge-agentctl /etc/storageforge-agent /var/lib/storageforge-agent 2>/dev/null; true', check=False).strip()
            want(left == '', f'still on the host: {left}')
            api('PUT', f'/api/agents/{name}', {'enabled': False})
            demo.scan(api, [node.ip])          # SSH is the base, and is as it was
            return 'stopped it stayed stopped, started it ran, removed it left nothing; a scan works as before'
        r.check('agent-stop-and-remove', node.name, stop_remove)

    def tunnel_checks(node, name):
        """The tunnel and the receiver (roadmap 11.2 and the rows of 11.6 about them), on a host whose agent was just installed."""
        a = row(api, name)
        if not a.get('endpoint') or not a.get('receiver_key'):
            r.add('agent-tunnel', node.name, None, 'the lab server runs no agent receiver, or names no endpoint: start it with docker-compose.agent.yml and STORAGEFORGE_AGENT_ENDPOINT (see the top of tiers_agent.py)')
            return
        address, port = a['endpoint'].rsplit(':', 1)
        address = address.strip('[]')

        def session():
            peer = demo.wait(f'a session from the agent on {name}', lambda: (api.get(f'/api/agents/{name}/records').get('peer') or {}).get('heard') or None, timeout=300)
            want(peer, 'the agent never opened a session')
            got = api.get(f'/api/agents/{name}/records')
            want(got['peer']['fingerprint'] == a['fingerprint'], 'the session is counted under another key')
            return f'sessions: {got["peer"]["sessions"]}, last heard from {got["peer"]["last_address"]}'
        r.check('agent-tunnel-session', node.name, session)

        def reaches_only_the_receiver():
            pid = agent_pid(node)
            host_ip = node.ip
            other = next((v for v in roles.deployable() if v.name != node.name), None)

            def dial(ip, p):
                return sudo(node.name, f'nsenter -t {pid} -n timeout 5 bash -c {shlex.quote(f"exec 3<>/dev/tcp/{ip}/{p}")} >/dev/null 2>&1 && echo open; true', check=False).strip()
            want(dial(address, port) == 'open', f'the receiver at {address}:{port} does not answer from inside the agent\'s network')
            for ip, p, what in ((host_ip, 22, 'its own host\'s sshd'), (other.ip if other else None, 22, 'another host\'s sshd'), ('1.1.1.1', 443, 'the internet')):
                if ip:
                    want(dial(ip, p) != 'open', f'the agent can reach {what} at {ip}:{p}')
            table = sudo(node.name, 'nft list table inet storageforge_agent 2>&1; true', check=False)
            want(f'tcp dport {port} accept' in table and 'drop' in table, f'the egress rule is not loaded: {table[-300:]}')
            enabled = sudo(node.name, 'systemctl is-enabled storageforge-agent-egress.service 2>&1; true', check=False).strip()
            want(enabled == 'enabled', f'the egress rule is not loaded again at boot: {enabled}')
            return f'{address}:{port} answers; its own sshd, another host\'s and the internet do not'
        r.check('agent-tunnel-reaches-only-the-receiver', node.name, reaches_only_the_receiver)

        try:
            from storageforge_index import agenttunnel
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:
            r.add('agent-stolen-key', node.name, None, f'the lab driver cannot play an agent: {exc}')
            return
        seed = bytes.fromhex(sudo(node.name, 'cat /var/lib/storageforge-agent/state/agent_key').strip())
        key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        receiver = base64.b64decode(a['receiver_key'])

        def play(counter, records, claims=None):
            sock = socket.create_connection((address, int(port)), timeout=15)
            try:
                s, welcome = agenttunnel.initiate(sock, agenttunnel.x25519_of_seed(seed), receiver)
                s.send_json(sock, {'op': 'hello', 'version': 'lab', 'run': 1, 'claims': claims or {}, 'manifest': None, 'have': []})
                while json.loads(s.read(sock))['op'] != 'ready':
                    pass
                answers = []
                start = max(counter, json.loads(welcome)['last_counter'] + 1)
                for i, recs in enumerate(records):
                    body = json.dumps({'counter': start + i, 'run': 1, 'sent': int(time.time()), 'dropped': 0, 'records': recs}).encode()
                    s.send_json(sock, {'op': 'batch', 'body': body.decode(), 'signature': agenttunnel.sign_batch(key, body)})
                    answers.append(json.loads(s.read(sock))['op'])
                return answers
            finally:
                sock.close()

        others = [v for v in roles.deployable() if v.name != node.name]
        other_name = demo.known_as(api, others[0].name) if others else 'another-host'
        api.post(f'/api/agents/{name}/stop')            # the real agent steps aside: one session per key

        def names_another():
            other_machine = sudo(others[0].name, 'cat /etc/machine-id').strip() if others else 'f' * 32
            rec = [{'seq': 1, 'at': int(time.time()), 'plugin': 'probe', 'kind': 'reading', 'body': {'host': other_name, 'address': others[0].ip if others else '', 'machine_id': other_machine}}]
            want(play(1, [rec], claims={'machine': other_machine, 'hostname': other_name}) == ['ack'], 'the batch was not taken')
            mine = api.get(f'/api/agents/{name}/records')['records']
            want(mine and mine[0]['body'].get('host') == other_name and mine[0]['source'] == 'agent', 'the batch is not stored under the sender, as its claim')
            want(not api.get(f'/api/agents/{other_name}/records')['records'], f'something was stored under {other_name}')
            def finding():
                center = api.get(f'/api/notifications?host={name}')
                return any(x.get('key') == f'security-agent-claim:{name}' for g in center.get('groups', []) for x in g.get('items', [])) or None
            found = demo.wait('the claim as a finding in the notification center', finding, timeout=600)
            return f'stored under {name}, nothing under {other_name}, and a security finding: {bool(found)}'
        r.check('agent-batch-names-another-host', node.name, names_another)

        def flood():
            before = len(api.get(f'/api/agents/{other_name}/records')['records']) if others else 0
            began = time.time()
            answers = play(1, [[] for _ in range(200)])
            refused = answers.count('refused')
            want(refused >= 50, f'only {refused} of 200 batches in a burst were refused for the rate')
            t0 = time.time()
            api.get('/api/agents')
            want(time.time() - t0 < 5, 'the web UI took more than 5 seconds to answer during the flood')
            if others:
                want(len(api.get(f'/api/agents/{other_name}/records')['records']) == before, 'another host\'s rows changed')
            return f'{refused} of 200 refused in {time.time() - began:.0f} s; the web UI answered; nobody else\'s rows changed'
        r.check('agent-flood-costs-only-itself', node.name, flood)

        def replayed():
            last = json.loads(json.dumps(api.get(f'/api/agents/{name}/records')['peer'] or {})).get('last_counter') or 0
            # three batches never sent (deleted on the way), then one played again with other bytes
            want(play(last + 4, [[]]) == ['ack'], 'a batch after a gap was not taken')
            body = json.dumps({'counter': last + 4, 'run': 2, 'sent': int(time.time()), 'dropped': 0, 'records': []}).encode()
            sock = socket.create_connection((address, int(port)), timeout=15)
            try:
                s, _welcome = agenttunnel.initiate(sock, agenttunnel.x25519_of_seed(seed), receiver)
                s.send_json(sock, {'op': 'hello', 'version': 'lab', 'run': 2, 'claims': {}, 'manifest': None, 'have': []})
                while json.loads(s.read(sock))['op'] != 'ready':
                    pass
                s.send_json(sock, {'op': 'batch', 'body': body.decode(), 'signature': agenttunnel.sign_batch(key, body)})
                answer = json.loads(s.read(sock))
            finally:
                sock.close()
            want(answer['op'] == 'refused', f'a batch played again with other bytes was taken: {answer}')
            peer = api.get(f'/api/agents/{name}/records')['peer']
            want(peer['gaps'] >= 3 and peer['repeats'] >= 1, f'the gap and the repeat are not counted: {peer}')
            return f'{peer["gaps"]} missing, {peer["repeats"]} played again and refused'
        r.check('agent-batches-deleted-or-replayed', node.name, replayed)

        def stolen_after_removal():
            api('DELETE', f'/api/agents/{name}')
            time.sleep(8)                               # the receiver reads the pinned keys every few seconds
            try:
                play(10_000, [[]])
            except (OSError, ConnectionError, agenttunnel.TunnelError):
                pass
            else:
                raise AssertionError('a session opened with the key of an agent that was removed')
            got = install(api, name)                    # back as it was, for the checks that follow: a new agent, a new key
            want(got['state'] == 'running', f'the agent did not come back: {got.get("detail")}')
            want(row(api, name)['fingerprint'] != a['fingerprint'], 'the agent came back with the old key')
            return 'refused at the handshake once removed; enrolled again, the agent has a new key'
        r.check('agent-stolen-key-after-removal', node.name, stolen_after_removal)

        r.add('agent-tripwire-own-address', node.name, None, 'the tripwire is not built (section 11.4, Windows, 0.5.14); the gate it will go through, '
              'agentaction.on_self, acts on the reporter alone in the unit tests')
        r.add('agent-freeze-needs-second-witness', node.name, None, 'no share freeze is built; the gate it will go through, agentaction.wider, holds a request '
              'with no independent witness for a person in the unit tests')

    def reenroll(name):
        """An agent that was wiped, enrolled again by an admin (the lab signs in as one), for the checks that follow."""
        got = install(api, name)
        want(got['state'] == 'running', f'the agent was not enrolled again after the wipe: {got.get("detail")}')
        return got

    def wiped(name, timeout=180):
        return demo.wait(f'the agent on {name} wiped', lambda: row(api, name)['state'] == 'wiped' or None, timeout=timeout)

    def guard_checks(node, name, expect):
        """Wipe and stop (11.3), the plugins (11.4) and the rows of 11.6 about them, on a host whose agent runs."""
        if row(api, name)['state'] != 'running':
            r.add('agent-wipe-and-stop', node.name, None, 'the agent is not running here after the tunnel checks')
            return

        def checked_clean():
            got = api.post(f'/api/agents/{name}/check')
            want(got.get('checked') and got.get('clean'), f'the check from outside found something on an agent as it was made: {got}')
            return 'nothing found: image, mounts, capabilities, devices, files in the container, plugin and state folders'
        r.check('agent-checked-from-outside', node.name, checked_clean)

        a = row(api, name)
        done = {}
        if not a.get('endpoint'):
            r.add('agent-plugins', node.name, None, 'no receiver in the lab: plugins report through the tunnel')
        else:
            def plugins():
                got = api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat', 'logs', 'health', 'network']})
                want(got.get('state') == 'running', f'the plugins were not applied: {got}')
                demo.wait('a heartbeat', lambda: [x for x in api.get(f'/api/agents/{name}/records?plugin=heartbeat')['records']] or None, timeout=300)
                time.sleep(5)
                marker = f'sf-lab-push-{int(time.time())}'
                sudo(node.name, f'logger -p user.err -t sflab {marker}: Out of memory: Killed process 1 (lab)')
                found = demo.wait('the pushed line in host logs', lambda: [e for e in api.get(f'/api/hostlogs?host={name}&q={marker}')['entries']] or None, timeout=120)
                want(found[0].get('signed'), f'the line is not marked as pushed and signed: {found[0]}')
                status = api.get(f'/api/hostlogs/status?host={name}')['hosts'][0]
                want(status['via'] == 'agent' and status['delay_ms'] is not None, f'the host does not show its lines as pushed: {status}')
                health = demo.wait('a health reading', lambda: [x for x in api.get(f'/api/agents/{name}/records?plugin=health')['records'] if x['kind'] == 'health'] or None, timeout=180)
                want(22 in (health[0]['body'].get('ssh') or {}).get('listening', []), f'health does not see sshd listening: {health[0]["body"].get("ssh")}')
                traffic = demo.wait('a traffic reading', lambda: [x for x in api.get(f'/api/agents/{name}/records?plugin=network')['records'] if x['kind'] == 'traffic'] or None, timeout=180)
                want(traffic[0]['body']['interfaces'], 'no interface in the network reading')
                done['plugins'] = True
                return f'beats, health and traffic arrive; a line logged now came back in {status["delay_ms"]} ms, signed, gaps {status["gaps"]}'
            r.check('agent-plugins', node.name, plugins)
        plugins_ok = done.get('plugins', False)

        if plugins_ok:
            def sshd_down():
                unit = 'ssh' if 'ssh.service' in sudo(node.name, 'systemctl list-unit-files ssh.service 2>/dev/null; true', check=False) else 'sshd'
                # a timer on the host brings sshd back, since nothing else can reach it while it is down
                sudo(node.name, f'systemd-run --on-active=90 --unit=sflab-sshd-back systemctl start {unit}.socket {unit}.service >/dev/null 2>&1; '
                                f'(sleep 2; systemctl stop {unit}.socket {unit}.service) >/dev/null 2>&1 &')
                def said():
                    center = api.get(f'/api/notifications?host={name}')
                    return any(x.get('key') == f'agent-ssh-down:{name}' for g in center.get('groups', []) for x in g.get('items', [])) or None
                demo.wait('SSH down in the notification center', said, timeout=80)
                demo.wait('sshd back', lambda: sudo(node.name, 'true', check=False) == '' or None, timeout=180)
                return 'the agent said SSH was down while it was, and sshd came back on its timer'
            r.check('agent-says-sshd-is-down', node.name, sshd_down)

        if expect == 'docker':
            def written_into():
                upper = sudo(node.name, "docker inspect -f '{{.GraphDriver.Data.UpperDir}}' storageforge-agent").strip()
                want(upper.startswith('/'), f'the container has no layer of its own to write into: {upper}')
                sudo(node.name, f'mkdir -p {shlex.quote(upper)}/usr/bin && echo x > {shlex.quote(upper)}/usr/bin/sflab-dropped')
                got = api.post(f'/api/agents/{name}/check')
                want(not got.get('clean') and any('sflab-dropped' in f for f in got.get('findings', [])), f'the file was not found: {got}')
                want(row(api, name)['state'] == 'wiped', 'the agent was not wiped')
                state = sudo(node.name, "docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' storageforge-agent").strip()
                want(state == 'false no', f'the container is not stopped and left stopped: {state}')
                want(sudo(node.name, 'test -e /var/lib/storageforge-agent/state/agent_key && echo there; true', check=False).strip() == '', 'the agent\'s key is still on the host')
                center = api.get(f'/api/notifications?host={name}')
                items = [x for g in center.get('groups', []) for x in g.get('items', []) if x.get('key') == f'security-agent-wiped:{name}']
                want(items and not items[0].get('ignorable', True), f'no wiped notification that cannot be ignored: {items}')
                demo.scan(api, [node.ip])          # SSH is unaffected
                reenroll(name)
                return 'found from outside, wiped: stopped and left stopped, key gone, a notification that cannot be ignored; scans work'
            r.check('agent-file-written-into-container', node.name, written_into)

        def tampered(what, act):
            def check():
                if row(api, name)['state'] != 'running':
                    reenroll(name)
                act()
                wiped(name)
                left = sudo(node.name, 'cat /var/lib/storageforge-agent/state/wiped 2>/dev/null; true', check=False)
                actions = api.get(f'/api/agents/{name}/records').get('actions') or []
                want(left.strip(), 'the agent left no word of why on the host')
                reenroll(name)
                return f'the agent wiped itself ({left.strip()[:120]}); the controller acted on it alone: {[x["outcome"] for x in actions[:1]]}'
            r.check(f'agent-refuses-{what}', node.name, check)

        state = '/var/lib/storageforge-agent/state'
        tampered('a-stray-plugin-file', lambda: sudo(node.name, f'install -o sfagent -m 0600 /dev/null {state}/plugins/dropped.plugin'))
        if plugins_ok:
            tampered('a-changed-plugin', lambda: sudo(node.name, f'printf x >> {state}/plugins/heartbeat.plugin'))
        old = '/var/lib/storageforge-agent/manifest'
        sudo(node.name, f'cp {old}/manifest.json /root/sflab-old-manifest.json; cp {old}/manifest.json.sig /root/sflab-old-manifest.json.sig', check=False)
        api.post(f'/api/agents/{name}/plugins', {'plugins': []})
        tampered('an-old-manifest', lambda: sudo(node.name, f'cp /root/sflab-old-manifest.json {old}/manifest.json; cp /root/sflab-old-manifest.json.sig {old}/manifest.json.sig'))
        if plugins_ok and expect == 'docker':
            more_plugins(node, name)

    def records(name, plugin):
        return api.get(f'/api/agents/{name}/records?plugin={plugin}')

    def center_has(name, key):
        center = api.get(f'/api/notifications?host={name}')
        found = [x for g in center.get('groups', []) for x in g.get('items', []) if x.get('key') == key]
        return found[0] if found else None

    def more_plugins(node, name):
        """0.5.8: the disks, files and sentinel plugins on the Docker host (roadmap 11.4 and 9). Written, not run."""
        if row(api, name)['state'] != 'running':
            reenroll(name)

        def disks():
            got = api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat', 'disks']})
            want(got.get('state') == 'running', f'the disks plugin was not applied: {got}')
            listed = demo.wait('a disks reading', lambda: records(name, 'disks').get('disks') or None, timeout=300)
            want(all(d.get('health') or d.get('error') for d in listed), f'a disk with neither health nor a reason: {listed}')
            s = status_of(node, agent_pid(node))
            uid = sudo(node.name, f'id -u {AGENT}').strip()
            want(s['Uid'].split() == [uid] * 4, f'the agent is not sfagent in every uid: {s["Uid"]}')
            for field in ('CapPrm', 'CapBnd', 'CapAmb'):
                want(int(s[field], 16) == 1 << 17, f'{field} is {s[field]}, not SYS_RAWIO alone')
            want(int(s['CapEff'], 16) == 0, 'the agent itself holds an effective capability')
            return f'{len(listed)} disk(s); the agent is sfagent holding SYS_RAWIO alone: ' + ', '.join(f'{d["dev"]} {(d.get("health") or {}).get("smart") or d.get("error", "")[:40]}' for d in listed)
        r.check('agent-disks-plugin', node.name, disks)

        def files_root():
            got = api.get('/api/agents')
            files = next((p for p in got.get('plugins', []) if p['name'] == 'files'), None)
            want(files and files['root_in_effect'] and files['note'].startswith('ROOT ON THIS HOST IN EFFECT'), f'the files plugin is not listed as root in effect: {files}')
            got = api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat', 'files', 'sentinel']})
            want('ROOT ON THIS HOST IN EFFECT' in (got.get('warning') or ''), f'switching it on did not say it is root in effect: {got}')
            return 'listed as root in effect; switched on by an admin, and the answer says so again'
        r.check('agent-files-root-in-effect', node.name, files_root)

        def files():
            st = demo.wait('the files plugin watching', lambda: (records(name, 'files').get('files_state') or {}).get('watching') or None, timeout=300)
            want(st.get('filesystems'), f'no filesystem watched: {st}')
            marker = f'/var/tmp/sflab-files-{int(time.time())}'
            sudo(node.name, f'useradd -m sflabuser 2>/dev/null; su -s /bin/sh sflabuser -c "echo hello > {marker}"')
            ev = demo.wait('the change', lambda: [e for e in records(name, 'files')['files'] if e['path'] == marker] or None, timeout=120)
            want(ev[0]['user'] in ('sflabuser', None) and ev[0]['process'], f'no process or account: {ev[0]}')
            return f'{marker} by {ev[0]["process"]} as {ev[0]["user"] or ev[0]["uid"]}; index: {ev[0]["indexed"]}'
        r.check('agent-files-changes', node.name, files)

        def hand_edit():
            sudo(node.name, 'touch /etc/exports; echo "# sflab hand edit" >> /etc/exports')
            item = demo.wait('the hand edit in the notification center', lambda: center_has(name, f'agent-hand-edit:{name}:/etc/exports'), timeout=120)
            want(not item.get('ignorable', True), f'a hand edit can be ignored: {item}')
            sudo(node.name, "sed -i '/# sflab hand edit/d' /etc/exports")
            return 'drift, which cannot be ignored'
        r.check('agent-files-hand-edit', node.name, hand_edit)

        def offhours():
            demo_setting(api, {'work_days': [], 'offhours_reads_per_hour': 50})
            reads = shlex.quote('for i in $(seq 1 200); do cat /etc/hostname >/dev/null; done')
            sudo(node.name, f'su -s /bin/sh sflabuser -c {reads}')
            item = demo.wait('reads out of hours', lambda: next((x for g in api.get(f'/api/notifications?host={name}').get('groups', []) for x in g.get('items', []) if str(x.get('key', '')).startswith(f'agent-offhours:{name}:')), None), timeout=180)
            return item['title']
        r.check('agent-files-offhours', node.name, offhours)

        def from_both():
            api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat']})          # held back
            path = f'/srv/sflab-unreported-{int(time.time())}'
            sudo(node.name, f'mkdir -p /srv && echo x > {path}')
            api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat', 'files']})
            demo.scan(api, [node.ip])
            item = demo.wait('the disagreement', lambda: center_has(name, f'agent-files-disagree:{name}'), timeout=300)
            want('never reported' in item.get('detail', ''), f'not said as a change the agent never reported: {item}')
            return item['detail'][:200]
        r.check('agent-files-from-both', node.name, from_both)

        def sentinel():
            import uuid
            line = f'ev\t{uuid.uuid4()}\tsentinel_test\t{int(time.time())}\t{base64.b64encode(b"sflab").decode()}\t'
            sudo(node.name, 'logger -t storageforge-sentinel', stdin=line + '\n')        # as root, as the sentinel writes it
            got = demo.wait('the sentinel event through the agent', lambda: [e for e in api.get(f'/api/security/events?host={name}&all=1').get('events', []) if e.get('via') == 'agent'] or None, timeout=120)
            return f'{got[0]["kind"]} via {got[0]["via"]}'
        r.check('agent-sentinel-through-the-agent', node.name, sentinel)

    def demo_setting(api, value):
        """The files plugin's working hours: a setting, written as the web app writes it."""
        from tiers_platform import sql_write
        sql_write("DELETE FROM settings WHERE key = 'agent.files'")
        sql_write("INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES ('agent.files', '" + json.dumps(value) + "', 0, 'lab')")

    def monitoring_checks(node):
        """0.5.8: a monitoring-only host (roadmap 11.5) and its console. Written, not run."""
        name = demo.known_as(api, node.name)
        addr = node.ip
        arch = sudo(node.name, 'uname -m').strip()

        def adopted():
            status, out = api.raw('DELETE', f'/api/hosts/{name}')
            if status == 403 and out.get('reauth'):
                api.raw('POST', '/api/reauth', {'password': api.password})
                status, out = api.raw('DELETE', f'/api/hosts/{name}')
            want(status == 200, f'the host could not be forgotten first: {status} {out}')
            api.post('/api/agents/monitoring', {'host': name, 'address': addr, 'port': 22, 'arch': arch})
            bundle = api.get(f'/api/agents/{name}/setup')
            with api.web.open(demo.urllib.request.Request(demo.BASE + f'/api/agents/program/{arch}'), timeout=300) as resp:
                program = resp.read()
            sudo(node.name, 'base64 -d > /root/storageforge-agentctl', stdin=base64.b64encode(program).decode())
            sudo(node.name, 'cat > /root/storageforge-agent-setup.sh', stdin=bundle['script'])
            out = sudo(node.name, 'bash /root/storageforge-agent-setup.sh /root/storageforge-agentctl')
            line = next(l for l in out.splitlines() if l.startswith('storageforge-agent-adopt '))
            own = sudo(node.name, 'cut -d " " -f 2 /etc/ssh/ssh_host_ed25519_key.pub').strip()
            want(own in line, 'the line does not carry the host\'s own key')
            got = api.post(f'/api/agents/{name}/adopt', {'line': line})
            want(got.get('state') == 'running' and got.get('mode') == 'monitoring', f'not adopted: {got}')
            api.post(f'/api/agents/{name}/plugins', {'plugins': ['heartbeat', 'scan', 'health']})
            inv = demo.wait('the scan plugin\'s inventory', lambda: records(name, 'scan').get('inventory') or None, timeout=300)
            status, out = api.raw('POST', '/api/deploy/start', {'host': name, 'kind': 'nfs', 'mode': 'apply'})
            want(status >= 400 or 'monitoring only' in json.dumps(out), f'a deploy to a monitoring-only host was not refused: {status} {out}')
            return f'adopted; inventory sections {inv["sections"]}; a deploy is refused with the reason'
        r.check('agent-monitoring-only-host', node.name, adopted)

        def console():
            if row(api, name).get('mode') != 'monitoring':
                raise AssertionError('the host is not monitoring only after the check before')
            status, out = api.raw('POST', '/api/console/sessions', {'host': name, 'kind': 'ssh', 'user': 'sflabadmin'})
            if status == 403 and out.get('reauth'):
                api.raw('POST', '/api/reauth', {'password': api.password})
                status, out = api.raw('POST', '/api/console/sessions', {'host': name, 'kind': 'ssh', 'user': 'sflabadmin'})
            want(status == 409 and 'allows no console' in out.get('error', ''), f'a console opened without the host\'s own list: {status} {out}')
            sudo(node.name, 'useradd -m -s /bin/bash sflabadmin 2>/dev/null; echo sflabadmin > /etc/storageforge-agent/console_users')
            s = api.post('/api/console/sessions', {'host': name, 'kind': 'ssh', 'user': 'sflabadmin'})
            keys = sudo(node.name, 'cat ~sflabadmin/.ssh/authorized_keys')
            want('storageforge-console:' in keys and 'expiry-time=' in keys and 'restrict,pty' in keys, f'no session key line: {keys}')
            api('DELETE', f'/api/console/sessions/{s["id"]}')
            demo.wait('the key line gone', lambda: 'storageforge-console:' not in sudo(node.name, 'cat ~sflabadmin/.ssh/authorized_keys') or None, timeout=60)
            return 'refused until the host listed an account; then a session as it, and SSH off again after'
        r.check('agent-monitoring-console', node.name, console)

    for node, expect in ((with_docker, 'docker'), (with_podman, 'podman-rootless'), (bare, 'podman-rootless')):
        if node is None:
            r.add('agent-install', '-', None, f'no host for this in the build (wanted one that runs it under {expect})')
        else:
            checks_on(node, expect)

    spare = next((n for n in vms if n not in (with_docker, with_podman, bare) and (has(n, 'docker') or has(n, 'podman'))), None)
    if spare is None:
        r.add('agent-monitoring-only-host', '-', None, 'no further host with a runtime in this build to make monitoring only')
    else:
        monitoring_checks(spare)

    if pve is None:
        r.add('agent-lxc-on-pve', '-', None, 'no Proxmox VE host that takes deploys in this build')
        return
    name = demo.known_as(api, pve.name)

    def on_pve():
        api('PUT', f'/api/agents/{name}', {'enabled': True})
        got = install(api, name)
        want(got['state'] == 'running', f'the agent is {got["state"]} on Proxmox VE: {got.get("detail")}')
        want(got['runtime'] == 'pct', f'it runs under {got["runtime"]}, expected pct')
        want(not has(pve, 'podman'), 'Podman was installed on a Proxmox VE host')
        vmid = sudo(pve.name, 'cat /var/lib/storageforge-agent/ctl/vmid').strip()
        conf = sudo(pve.name, f'pct config {vmid}')
        want('unprivileged: 1' in conf, 'the container is not unprivileged')
        want('nesting=1' not in conf, 'nesting is on')
        s = status_of(pve, agent_pid(pve))
        want(s['Uid'].split()[0] == sudo(pve.name, f'id -u {AGENT}').strip(), 'the agent in the container is not sfagent on the host')
        api('DELETE', f'/api/agents/{name}')
        api('PUT', f'/api/agents/{name}', {'enabled': False})
        return f'container {vmid}: unprivileged, no nesting, the process is sfagent on the host, and no Podman'
    r.check('agent-lxc-on-pve', pve.name, on_pve)
