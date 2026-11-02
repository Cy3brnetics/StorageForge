#!/usr/bin/env python3
"""Fill a freshly reset lab through StorageForge's own API: scans, deploy access, shares, a backup job, a btrfs send
and one real alert sent to ntfy. Run it with lab.sh demo. Only what StorageForge leaves to an operator goes over the
lab's own SSH: login keys, the Samba account, and root's key for the send."""
import http.cookiejar
import json
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import roles

HERE = Path(__file__).resolve().parent
LAB = str(HERE / 'lab.sh')
STATE = Path(os.environ['SFLAB_STATE'])
CTL = os.environ.get('SFLAB_PREFIX', '10.77.0') + '.10'
BASE = f'https://{CTL}:8443'
NTFY = f'http://{CTL}:8090'
TOPIC = 'storageforge-lab'
COMPOSE = 'cd /opt/storageforge && sudo -n docker compose -f docker-compose.yml -f compose.lab.yml'
IPS = {n.name: n.ip for n in roles.build().values()}


def say(text):
    print(text, flush=True)


class DemoError(Exception):
    pass


def fail(text):
    raise DemoError(text)


def ssh(vm, command, stdin=None, check=True):
    p = subprocess.run([LAB, 'ssh', vm, command], input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=600)
    if check and p.returncode:
        fail(f'{vm}: {command}: exit {p.returncode}: {p.stderr[-400:]}')
    return p.stdout


def cli(*args):
    return ssh('sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index {shlex.join(args)}')


class Api:
    def __init__(self, password):
        self.password = password
        cert = cli_cert()
        with tempfile.NamedTemporaryFile('w', suffix='.pem') as f:
            f.write(cert)
            f.flush()
            context = ssl.create_default_context(cafile=f.name)
        self.web = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                               urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def raw(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(BASE + path, data=data, method=method, headers={'Content-Type': 'application/json'})
        try:
            with self.web.open(req, timeout=300) as r:
                return r.status, json.loads(r.read() or 'null')
        except urllib.error.HTTPError as e:
            text = e.read()
            try:
                return e.code, json.loads(text)
            except ValueError:
                return e.code, {'error': text.decode(errors='replace')[:400]}

    def text(self, path):
        """A generated script: the one kind of answer that isn't JSON."""
        with self.web.open(urllib.request.Request(BASE + path), timeout=300) as r:
            return r.read().decode()

    def __call__(self, method, path, body=None, expect=None):
        status, out = self.raw(method, path, body)
        if status == 403 and isinstance(out, dict) and out.get('reauth'):    # commands on hosts want a recent password
            self.raw('POST', '/api/reauth', {'password': self.password})
            status, out = self.raw(method, path, body)
        if expect is None and status >= 400 or expect is not None and status != expect:
            fail(f'{method} {path}: HTTP {status}: {json.dumps(out)[:1500]}')
        return out

    def get(self, path):
        return self('GET', path)

    def post(self, path, body=None):
        return self('POST', path, {} if body is None else body)


def cli_cert():
    return ssh('sf-ctl', f'{COMPOSE} exec -T storageforge cat /run/sf-secrets/tls_cert')


def wait(what, check, timeout=900):
    until = time.time() + timeout
    while time.time() < until:
        got = check()
        if got:
            return got
        time.sleep(3)
    fail(f'timed out waiting for {what}')


def scan(api, hosts):
    """Scans run as queued jobs; returns when each host's job has ended, and fails if any did not end well."""
    ids = {api.post('/api/scan', {'host': h})['job_id']: h for h in hosts}

    def done():
        jobs = {j['job_id']: j for j in api.get('/api/jobs')['jobs'] if j['job_id'] in ids}
        return jobs if len(jobs) == len(ids) and all(j['status'] not in ('queued', 'running') for j in jobs.values()) else None
    for jid, job in wait('scans', done).items():
        if job['status'] == 'partial':     # a mount the scan user can't read, such as Podman's overlay folder
            say(f'  {ids[jid]}: partial, {job["result"]["failed"]} mount unreadable')
        elif job['status'] != 'ok':
            fail(f'scan of {ids[jid]} ended {job["status"]}: {json.dumps(job["result"])[:800]}')


def deploy(api, kind, ref, title, may_fail=None, **options):
    """A deploy's two stages, as in the UI: the report, then apply from it. Returns the runs of the apply."""
    group = None
    for mode in ('report', 'apply'):
        body = {'kind': kind, 'ref': ref, 'mode': mode, 'title': f'{title} ({mode})'}
        if mode == 'apply':
            body |= {'report_group': group, **options}
        group = api.post('/api/deploy/start', body)['group']
        out = wait(f'{title}: {mode}', lambda g=group: finished(api, g))
        bad = [r for r in out['runs'] if r['status'] not in ('ok', 'incomplete')]
        if bad and bad[0]['host'] == may_fail and mode == 'apply':
            return None
        if bad:
            fail(f'{title}: {mode} on {bad[0]["host"]} ended {bad[0]["status"]}:\n{bad[0].get("output", "")[-1500:]}')
    return out['runs']


def finished(api, group):
    out = api.get(f'/api/deploy/groups/{group}')
    return out if out['group'].get('finished_at') else None


def sign_in():
    password = (STATE / 'ui-password').read_text().strip()
    api = Api(password)
    say('signing in')
    api.post('/api/login', {'username': 'demo', 'password': password})
    api('PUT', '/api/deploy/settings', {'report_url': BASE, 'alerts': {'ntfy': {'url': NTFY, 'topic': TOPIC}}})
    return api


def scan_everything(api):
    say('creating keys in the vault and installing them')
    api.post('/api/keys', {'name': 'lab-scan'})
    api.post('/api/keys', {'name': 'lab-admin'})
    keys = {k['name']: k['public_key'] for k in api.get('/api/keys')['keys']}
    for vm, ip in IPS.items():
        install_key(vm, 'scan', keys['lab-scan'])
        cli('vault', 'bind', '--key', 'lab-scan', '--host', ip, '--user', 'scan', '--actions', 'scan,checksum')
        if not roles.pool()[vm].can('controller'):
            install_key(vm, 'sfadmin', keys['lab-admin'])
    say('scanning every host')
    scan(api, list(IPS.values()))


def set_up_deploy_access(api):
    say('setting up deploy access with the sfadmin sudo password')
    admin_password = (STATE / 'admin-password').read_text().strip()
    hosts = [n.name for n in roles.deployable()]
    for vm in hosts:
        confirm_host_key(api, vm)
    for vm in hosts:
        out = api.post('/api/deploy/access', {'host': vm, 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': admin_password})
        if out['state'] != 'ready':
            fail(f'{vm}: deploy access is {out["state"]}:\n{out["output"][-1500:]}')
        say(f'  {vm}: ready')
    for node in roles.having('nosystemd'):
        status, out = api.raw('POST', '/api/deploy/access', {'host': node.name, 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': admin_password})
        if status < 400:
            fail(f'{node.name} has no systemd and should be refused deploy access: {out}')
        say(f'  {node.name}: refused, as it should be: {out.get("error", "")[:160]}')


def main():
    api = sign_in()
    scan_everything(api)
    set_up_deploy_access(api)
    share_nfs(api)
    share_smb(api)
    backup_job(api)
    btrfs_send(api)
    open_alert(api)

    ssh('sf-ctl', 'sudo -n touch /var/lib/sflab/demo')
    say('')
    say(f'StorageForge: {BASE}  (self-signed certificate)')
    say(f'Sign in as demo, password: {api.password}')
    say(f'Alerts: {NTFY}/{TOPIC}')


def confirm_host_key(api, vm):
    """The step a person does in the UI. StorageForge refuses a fingerprint that isn't the key its scan pinned."""
    actual = ssh(vm, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub').split()[1]
    api.post('/api/hostkey/confirm', {'host': IPS[vm], 'fingerprint': actual})


def install_key(vm, user, public):
    home = shlex.quote(f'~{user}')[1:-1]       # the shell has to expand it
    ssh(vm, f'sudo -n sh -c {shlex.quote(f"d={home}/.ssh; mkdir -p $d; echo {shlex.quote(public)} >>$d/authorized_keys; chown -R {user}: $d; chmod 700 $d; chmod 600 $d/authorized_keys")}')


def filled(node):
    return f'{node.fill}/lab-demo-fill.bin'


def nfs_pair():
    server = (roles.having('zfs') or roles.deployable())[0]
    return server, roles.other_than(server)


def share_nfs(api):
    server, client = nfs_pair()
    say(f'NFS: {server.name} {server.data} to {client.name}')
    api.post('/api/shares', {'host': server.name, 'export': {
        'protocol': 'NFSv4.2', 'name': 'media', 'path': server.data,
        'rules': [{'clients': client.ip, 'options': 'ro,sync,no_subtree_check'}],
        'mounts': [{'host': client.name, 'path': '/mnt/lab-nfs'}]}})
    deploy(api, 'shares', server.name, 'NFS share')
    ssh(client.name, 'ls /mnt/lab-nfs/lab-seed >/dev/null')
    say(f'  mounted, and {client.name} can read it')
    return server, client


def can_mount_smb(node):
    """Cloud kernels differ: some have no cifs module, or no nls_utf8 for the mount's iocharset=utf8."""
    p = subprocess.run([LAB, 'ssh', node.name, 'sudo -n modprobe -n cifs && sudo -n modprobe -n nls_utf8'], stdin=subprocess.DEVNULL, capture_output=True)
    return p.returncode == 0


def smb_client():
    # the deploy installs what a kernel lacks, so any host will do. One that has it already first, to test the share itself
    others = [n for n in roles.deployable() if n.name != roles.smb_server().name]
    return next((n for n in others if can_mount_smb(n)), next(iter(others), None))


def share_smb(api, server=None, name='labdata', mount='/mnt/lab-smb', client=None):
    server = server or roles.smb_server()
    client = client or smb_client()
    if client is None:
        say('SMB: skipped, because no host in this build has a kernel that can mount it')
        return server, None
    say(f'SMB: {server.name} {server.data} to {client.name}')
    # The script asks for the client's credentials on a terminal, and Samba accounts are the operator's: both by hand.
    samba = secrets.token_urlsafe(18)
    ssh(client.name, f'sudo -n sh -c "umask 077; mkdir -p /etc/samba/credentials; cat >/etc/samba/credentials/{server.name}-{name}"',
        stdin=f'username=scan\npassword={samba}\n')
    api.post('/api/shares', {'host': server.name, 'export': {
        'protocol': 'SMB3', 'name': name, 'path': server.data, 'clients': 'scan',
        'mounts': [{'host': client.name, 'path': mount}]}})
    # The account needs the Samba the deploy installs, and the same deploy mounts with it: so apply, add it, apply again.
    if deploy(api, 'shares', server.name, 'SMB share', may_fail=client.name) is not None:
        fail(f'{client.name} mounted the share before its Samba account existed')
    ssh(server.name, 'sudo -n smbpasswd -s -a scan', stdin=f'{samba}\n{samba}\n')
    deploy(api, 'shares', server.name, 'SMB share')
    ssh(client.name, f'ls {mount}/lab-seed >/dev/null')
    say(f'  mounted, and {client.name} can read it')
    return server, client


def backup_job(api):
    source = roles.smb_server()
    target = next(n for n in roles.deployable() if n.name != source.name and n.pm != 'dnf')     # rsnapshot is in every repository but EPEL's
    path = f'{target.room}/lab-rsnapshot'
    say(f'rsnapshot: {source.name} {source.data}/lab-seed to {target.name}')
    plan = api.post('/api/moves', {'name': 'Lab backup', 'steps': [{
        'method': 'rsnapshot', 'src': {'host': source.name, 'path': f'{source.data}/lab-seed'},
        'dst': {'host': target.name, 'path': path}, 'options': {'schedule': 'daily'}}]})
    deploy(api, 'jobs', plan['id'], 'rsnapshot job')
    job = f'p{plan["id"]}-{plan["steps"][0]["id"]}'
    api.post(f'/api/deploy/jobs/{job}/run')

    def ran():
        runs = api.get(f'/api/deploy/jobs/{job}')['runs']
        return runs[0] if runs else None
    run = wait('the rsnapshot job', ran)
    if run.get('rc') != 0:
        fail(f'rsnapshot job: {json.dumps(run)[:800]}')
    if not ssh(target.name, f'sudo -n find {path}/daily.0 -type f -name "*.cr2" -print -quit'):
        fail(f'the rsnapshot job finished, but its snapshot on {target.name} holds no seed photos')
    say(f'  installed, and its first snapshot is on {target.name}')
    return job, source, target


def root_login(frm, to):
    """StorageForge leaves this login to the operator on purpose (docs/target-hosts.md): root on the sender needs a key."""
    public = ssh(frm.name, 'sudo -n sh -c "mkdir -p /root/.ssh; test -f /root/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N \'\' -f /root/.ssh/id_ed25519; cat /root/.ssh/id_ed25519.pub"').strip()
    ssh(to.name, f'sudo -n sh -c {shlex.quote(f"mkdir -p /root/.ssh; echo {shlex.quote(public)} >>/root/.ssh/authorized_keys; chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys")}')
    ssh(to.name, "sudo -n sh -c \"mkdir -p /etc/ssh/sshd_config.d; printf 'PermitRootLogin prohibit-password\\n' >/etc/ssh/sshd_config.d/10-sflab-root.conf; systemctl reload sshd || systemctl reload ssh\"")
    ssh(frm.name, f'sudo -n ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@{to.ip} true')


def btrfs_send(api):
    frm, to = roles.sender(), roles.receiver()
    say(f'btrfs send: {frm.name} {frm.subvol} to {to.name}')
    root_login(frm, to)
    ssh(to.name, f'sudo -n mkdir -p {to.recv}')
    task = api.post('/api/tasks', {'name': 'Lab media replication', 'host': frm.name, 'schedule': '*-*-* 02:30:00', 'blocks': [
        {'type': 'btrfs_snapshot', 'params': {'subvol': frm.subvol, 'into': frm.snaps, 'prefix': 'daily'}},
        {'type': 'btrfs_send', 'params': {'into': frm.snaps, 'prefix': 'daily', 'dst_host': f'root@{to.ip}', 'dst': to.recv, 'keep': 7}},
    ]})
    deploy(api, 'tasks', task['id'], 'btrfs replication', run=True)
    if 'daily-' not in ssh(to.name, f'sudo -n ls {to.recv}'):
        fail(f'no snapshot arrived on {to.name}')
    say(f'  a snapshot arrived on {to.name}')
    return task['id'], frm, to


def open_alert(api):
    node = roles.fill_host()
    say(f'alert: filling {node.fill} on {node.name}')
    ssh(node.name, f'''sudo -n sh -c 'size=$(df -m --output=size {node.fill} | tail -1); dd if=/dev/urandom of={filled(node)} bs=1M count=$((size * 96 / 100)) status=none; sync' ''')
    scan(api, [node.ip])
    p = subprocess.run([LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index deploy alerts'],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    if p.returncode not in (0, 1):
        fail(f'deploy alerts: exit {p.returncode}: {p.stderr[-400:]}')
    opened = [a for a in api.get('/api/deploy')['alerts'] if node.fill in json.dumps(a)]
    if not opened:
        fail(f'no alert opened for {node.fill}:\n{p.stdout[-800:]}')
    with urllib.request.urlopen(f'{NTFY}/{TOPIC}/json?poll=1&since=all', timeout=30) as r:
        sent = r.read().decode()
    if node.fill not in sent:
        fail(f'the alert did not reach ntfy:\n{sent[-800:]}')
    say(f'  open in the Deploy tab and delivered to ntfy: {opened[0].get("title") or opened[0]}')
    return node


if __name__ == '__main__':
    try:
        main()
    except DemoError as exc:
        sys.exit(f'demo failed: {exc}')
