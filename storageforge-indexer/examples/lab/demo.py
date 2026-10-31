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

HERE = Path(__file__).resolve().parent
LAB = str(HERE / 'lab.sh')
STATE = Path(os.environ['SFLAB_STATE'])
BASE = 'https://10.77.0.10:8443'
NTFY = 'http://10.77.0.10:8090'
TOPIC = 'storageforge-lab'
COMPOSE = 'cd /opt/storageforge && sudo -n docker compose -f docker-compose.yml -f compose.lab.yml'
NODES = [line.split('|') for line in (HERE / 'nodes.conf').read_text().splitlines() if line.strip() and not line.startswith('#')]
IPS = {row[0]: row[6] for row in NODES}
DEPLOYABLE = ['sf-ubuntu', 'sf-fedora', 'sf-rocky', 'sf-suse', 'sf-arch']
FILLED = '/backup/lab-demo-fill.bin'


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
        if vm in DEPLOYABLE + ['sf-alpine']:
            install_key(vm, 'sfadmin', keys['lab-admin'])
    say('scanning every host')
    scan(api, list(IPS.values()))


def set_up_deploy_access(api):
    say('setting up deploy access with the sfadmin sudo password')
    admin_password = (STATE / 'admin-password').read_text().strip()
    for vm in DEPLOYABLE:
        confirm_host_key(api, vm)
    for vm in DEPLOYABLE:
        out = api.post('/api/deploy/access', {'host': vm, 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': admin_password})
        if out['state'] != 'ready':
            fail(f'{vm}: deploy access is {out["state"]}:\n{out["output"][-1500:]}')
        say(f'  {vm}: ready')
    status, out = api.raw('POST', '/api/deploy/access', {'host': 'sf-alpine', 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': admin_password})
    if status < 400:
        fail(f'sf-alpine has no systemd and should be refused deploy access: {out}')
    say(f'  sf-alpine: refused, as it should be: {out.get("error", "")[:160]}')


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


def share_nfs(api):
    say('NFS: sf-ubuntu /tank/media to sf-fedora')
    api.post('/api/shares', {'host': 'sf-ubuntu', 'export': {
        'protocol': 'NFSv4.2', 'name': 'media', 'path': '/tank/media',
        'rules': [{'clients': IPS['sf-fedora'], 'options': 'ro,sync,no_subtree_check'}],
        'mounts': [{'host': 'sf-fedora', 'path': '/mnt/ubuntu-media'}]}})
    deploy(api, 'shares', 'sf-ubuntu', 'NFS share')
    ssh('sf-fedora', 'ls /mnt/ubuntu-media/lab-seed >/dev/null')
    say('  mounted, and sf-fedora can read it')


def share_smb(api):
    say('SMB: sf-rocky /srv/data to sf-suse')
    # The script asks for the client's credentials on a terminal, and Samba accounts are the operator's: both by hand.
    samba = secrets.token_urlsafe(18)
    ssh('sf-suse', 'sudo -n sh -c "umask 077; mkdir -p /etc/samba/credentials; cat >/etc/samba/credentials/sf-rocky-labdata"',
        stdin=f'username=scan\npassword={samba}\n')
    api.post('/api/shares', {'host': 'sf-rocky', 'export': {
        'protocol': 'SMB3', 'name': 'labdata', 'path': '/srv/data', 'clients': 'scan',
        'mounts': [{'host': 'sf-suse', 'path': '/mnt/rocky-data'}]}})
    # The account needs the Samba the deploy installs, and the same deploy mounts with it: so apply, add it, apply again.
    if deploy(api, 'shares', 'sf-rocky', 'SMB share', may_fail='sf-suse') is not None:
        fail('sf-suse mounted the share before its Samba account existed')
    ssh('sf-rocky', 'sudo -n smbpasswd -s -a scan', stdin=f'{samba}\n{samba}\n')
    deploy(api, 'shares', 'sf-rocky', 'SMB share')
    ssh('sf-suse', 'ls /mnt/rocky-data/lab-seed >/dev/null')
    say('  mounted, and sf-suse can read it')


def backup_job(api):
    say('rsnapshot: sf-rocky /srv/data/lab-seed to sf-ubuntu')
    plan = api.post('/api/moves', {'name': 'Lab backup', 'steps': [{
        'method': 'rsnapshot', 'src': {'host': 'sf-rocky', 'path': '/srv/data/lab-seed'},
        'dst': {'host': 'sf-ubuntu', 'path': '/tank/backups/rocky'}, 'options': {'schedule': 'daily'}}]})
    deploy(api, 'jobs', plan['id'], 'rsnapshot job')
    job = f'p{plan["id"]}-{plan["steps"][0]["id"]}'
    api.post(f'/api/deploy/jobs/{job}/run')

    def ran():
        runs = api.get(f'/api/deploy/jobs/{job}')['runs']
        return runs[0] if runs else None
    run = wait('the rsnapshot job', ran)
    if run.get('rc') != 0:
        fail(f'rsnapshot job: {json.dumps(run)[:800]}')
    if not ssh('sf-ubuntu', 'sudo -n find /tank/backups/rocky/daily.0 -type f -name "*.cr2" -print -quit'):
        fail('the rsnapshot job finished, but its snapshot on sf-ubuntu holds no seed photos')
    say('  installed, and its first snapshot is on sf-ubuntu')
    return job


def btrfs_send(api):
    say('btrfs send: sf-fedora /data/media to sf-arch')
    # StorageForge leaves this login to the operator on purpose (docs/target-hosts.md): root on the sender needs a key.
    public = ssh('sf-fedora', 'sudo -n sh -c "test -f /root/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N \'\' -f /root/.ssh/id_ed25519; cat /root/.ssh/id_ed25519.pub"').strip()
    ssh('sf-arch', f'sudo -n sh -c {shlex.quote(f"mkdir -p /root/.ssh /srv/fedora-media; echo {shlex.quote(public)} >>/root/.ssh/authorized_keys; chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys")}')
    ssh('sf-arch', "sudo -n sh -c \"printf 'PermitRootLogin prohibit-password\\n' >/etc/ssh/sshd_config.d/10-sflab-root.conf; systemctl reload sshd\"")
    ssh('sf-fedora', f'sudo -n ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@{IPS["sf-arch"]} true')
    task = api.post('/api/tasks', {'name': 'Lab media replication', 'host': 'sf-fedora', 'schedule': '*-*-* 02:30:00', 'blocks': [
        {'type': 'btrfs_snapshot', 'params': {'subvol': '/data/media', 'into': '/data/snaps', 'prefix': 'daily'}},
        {'type': 'btrfs_send', 'params': {'into': '/data/snaps', 'prefix': 'daily', 'dst_host': f'root@{IPS["sf-arch"]}', 'dst': '/srv/fedora-media', 'keep': 7}},
    ]})
    deploy(api, 'tasks', task['id'], 'btrfs replication', run=True)
    if 'daily-' not in ssh('sf-arch', 'sudo -n ls /srv/fedora-media'):
        fail('no snapshot arrived on sf-arch')
    say('  a snapshot arrived on sf-arch')
    return task['id']


def open_alert(api):
    say('alert: filling the backup pool on sf-ubuntu')
    ssh('sf-ubuntu', f'''sudo -n sh -c 'size=$(df -m --output=size /backup | tail -1); dd if=/dev/urandom of={FILLED} bs=1M count=$((size * 96 / 100)) status=none; sync' ''')
    scan(api, [IPS['sf-ubuntu']])
    p = subprocess.run([LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index deploy alerts'],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    if p.returncode not in (0, 1):
        fail(f'deploy alerts: exit {p.returncode}: {p.stderr[-400:]}')
    opened = [a for a in api.get('/api/deploy')['alerts'] if '/backup' in json.dumps(a)]
    if not opened:
        fail(f'no alert opened for /backup:\n{p.stdout[-800:]}')
    with urllib.request.urlopen(f'{NTFY}/{TOPIC}/json?poll=1&since=all', timeout=30) as r:
        sent = r.read().decode()
    if '/backup' not in sent:
        fail(f'the alert did not reach ntfy:\n{sent[-800:]}')
    say(f'  open in the Deploy tab and delivered to ntfy: {opened[0].get("title") or opened[0]}')


if __name__ == '__main__':
    try:
        main()
    except DemoError as exc:
        sys.exit(f'demo failed: {exc}')
