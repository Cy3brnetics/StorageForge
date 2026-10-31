#!/usr/bin/env python3
"""Tiers 1, 3 and 4 of the KVM lab tests, and the report over all tiers. Tier 0 is test_tier0.py, tier 2 is gauntlet.py.
They change the VMs, so run them through examples/lab/lab.sh test --all, which resets the lab around each tier.

    tiers.py run <0|1|3|4>   tier 0 as a result file, or one tier against StorageForge on sf-ctl, through its API
    tiers.py report          the table per distro from every results file, into reports/

Results are checked on the VMs and against the seed manifests where a VM can answer, and against the running
StorageForge where the question is what it noticed. A check in KNOWN still fails, but is shown apart: it doesn't fail
the run, and it says so when it starts passing.
"""
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / 'examples' / 'lab'
sys.path[:0] = [str(LAB_DIR), str(ROOT)]
os.environ.setdefault('SFLAB_STATE', str(Path.home() / '.local' / 'state' / 'sflab'))

import demo  # noqa: E402
from demo import COMPOSE, IPS, STATE, cli, ssh  # noqa: E402
from storageforge_index.remote import DEFAULT_EXCLUDE_NAMES  # noqa: E402

RESULTS = STATE / 'results'
REPORTS = ROOT / 'reports'
VMS = list(IPS)
os.environ['LIBVIRT_DEFAULT_URI'] = 'qemu:///system'
# (check, vm): why it is expected to fail. Remove the line when the product is fixed.
KNOWN = {
    ('scan-status', 'sf-rocky'): "without scan access, Podman's overlay folder counts as a failed mount",
    ('child-subvolume', 'sf-suse'): 'finding GM-14: find -xdev stops at a child subvolume, so its files are never indexed',
    ('containers', 'sf-rocky'): "rootless podman ps succeeds with an empty list, so the sudo that would see root's containers is never tried",
    ('rescan-after-rekey-api', 'sf-suse'): 'rekey clears the scanned address, so the API turns the IP into the host name, which the key is not bound to',
    ('scan', 'sf-rocky'): "without scan access, Podman's overlay folder counts as a failed mount",
    ('job-run-copy', 'sf-rocky'): "rsync -X tries to remove security.selinux on the SELinux destination: all data arrives, but the job reports exit 23",
    ('job-run-git', 'sf-fedora'): "the job serves with git-upload-pack --strict, which refuses the working-copy path the Git panel sends",
    ('job-run-git', 'sf-suse'): "the job serves with git-upload-pack --strict, which refuses the working-copy path the Git panel sends",
    ('job-result-rsnapshot', 'sf-suse'): "rsnapshot's config has no --hard-links or xattrs, but verify compares with -HAX",
    ('job-verify-rsnapshot', 'sf-suse'): "rsnapshot's config has no --hard-links or xattrs, but verify compares with -HAX",
    ('job-result-rsnapshot', 'sf-fedora'): "rsnapshot's config has no --hard-links or xattrs, but verify compares with -HAX",
    ('job-verify-rsnapshot', 'sf-fedora'): "rsnapshot's config has no --hard-links or xattrs, but verify compares with -HAX",
    ('rsnapshot-on-el9', 'sf-rocky'): 'docs/deployments.md says EPEL has it; on Rocky 9 it does not',
    ('lvm-extend-unmounted', 'sf-rocky'): 'lvextend -r asks a question on an unmounted XFS volume, with no terminal to answer it',
    ('mergerfs-source', 'sf-arch'): 'the kernel reports the FUSE source as 1:2, and the branches are not read from anywhere else',
}
PACKAGE_MANAGERS = {'sf-ctl': 'apt-get', 'sf-ubuntu': 'apt-get', 'sf-fedora': 'dnf', 'sf-rocky': 'dnf', 'sf-suse': 'zypper', 'sf-arch': 'pacman', 'sf-alpine': 'none'}
TOPOLOGY = {'sf-ubuntu': ['tank', 'backup'], 'sf-rocky': ['vgdata'], 'sf-suse': ['md0'], 'sf-arch': ['secure', 'mergerfs']}


def conf(path):
    rows = (LAB_DIR / path).read_text().splitlines()
    return [r.split('|') for r in rows if r.strip() and not r.startswith('#')]


class Results:
    def __init__(self, tier):
        self.tier, self.rows = tier, []

    def add(self, check, vm, ok, note='', detail=''):
        status = 'skip' if ok is None else 'pass' if ok else 'FAIL'
        why = KNOWN.get((check, vm))
        if why:
            status, note = ('known' if status == 'FAIL' else 'fixed?'), f'{note} ({why})'
        self.rows.append({'tier': self.tier, 'check': check, 'host': vm, 'status': status, 'note': note, 'detail': str(detail)[-4000:]})
        print(f'  {status:6} {check:18} {vm:10} {note}'[:240], flush=True)
        if status == 'FAIL' and detail:
            for line in str(detail).strip().splitlines()[-10:]:
                print(f'         | {line}'[:240], flush=True)

    def check(self, check, vm, fn):
        """fn returns a note (passes), or raises to fail: a broken step costs one row, not the rest of the tier."""
        try:
            self.add(check, vm, True, fn() or '')
        except Exception as exc:
            self.add(check, vm, False, f'{type(exc).__name__}: {str(exc)[:170]}', traceback.format_exc())

    def save(self):
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / f'tier{self.tier}.json').write_text(json.dumps(self.rows, indent=1))
        return not [r for r in self.rows if r['status'] == 'FAIL']


def sql(query):
    out = ssh('sf-ctl', f'{COMPOSE} exec -T storageforge sqlite3 -json /app/data/index.db {shlex.quote(query)}')
    return json.loads(out) if out.strip() else []


def host_ids():
    return {r['hostname']: r['host_id'] for r in sql('SELECT hostname, host_id FROM hosts')}


def manifests():
    for vm, root, profile in conf('provision/seed-roots.conf'):
        yield vm, root, profile, json.loads((STATE / 'manifests' / f'{vm}{root.replace("/", "_")}.json').read_text())


def alerts_now():
    """Evaluate as the five-minute timer would, and return what is open. deploy alerts exits 1 while any are."""
    p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index deploy alerts'],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    if p.returncode not in (0, 1):
        raise AssertionError(f'deploy alerts: exit {p.returncode}: {p.stderr[-300:]}')
    return sql("SELECT kind, ref, title FROM alerts WHERE state = 'open'")


def wait_for(what, fn, timeout=300):
    until = time.time() + timeout
    while time.time() < until:
        got = fn()
        if got:
            return got
        time.sleep(3)
    raise AssertionError(f'timed out waiting for {what}')


def seed_hash(vm, path):
    return ssh(vm, f'sudo -n sha256sum {shlex.quote(path)}').split()[0]


def seed_file(vm, root, rel='shared/docs/handbook.txt'):
    m = json.loads((STATE / 'manifests' / f'{vm}{root.replace("/", "_")}.json').read_text())
    return next(e for e in m['entries'] if e['path'] == rel)


def job_run(api, job, verb, kind, since):
    api.post(f'/api/deploy/jobs/{job}/{verb}')

    def done():
        runs = [r for r in api.get(f'/api/deploy/jobs/{job}')['runs'] if r['kind'] == kind and r['start'] >= since - 5]
        return runs[0] if runs else None
    run = wait_for(f'{job} {verb}', done, 600)
    if run['rc'] != 0:
        raise AssertionError(f'{job} {verb}: rc {run["rc"]}: {run.get("message")}')
    return run


# ── tier 1: does a scan see what is there? ──────────────────────────
def tier1(r):
    api = demo.sign_in()
    jobs = {}

    def scan_all():
        demo.scan_everything(api)
    r.check('scan', '-', scan_all)
    for j in api.get('/api/jobs')['jobs']:
        jobs.setdefault(j['host'], j)
    ids = host_ids()
    for vm, ip in IPS.items():
        job = jobs.get(ip) or jobs.get(vm)
        r.add('scan-status', vm, bool(job) and job['status'] == 'ok', (job or {}).get('status', 'no job'), json.dumps((job or {}).get('result')))
    for vm in VMS:
        r.add('host-name', vm, vm in ids, 'indexed under its own name' if vm in ids else f'indexed as {sorted(ids)}')

    table = {}
    for m in sql("SELECT h.hostname host, m.mount_point mp, m.filesystem_type fs, m.fs_root root, m.scan_state state, m.source source FROM mounts m JOIN hosts h USING (host_id)"):
        table[m['host'], m['mp']] = m
    for vm in VMS:
        rows = [x for x in conf('provision/layout.conf') if x[0] == vm]
        bad = []
        for _, mount, fstype, fsroot in rows:
            got = table.get((vm, mount))
            if not got:
                bad.append(f'{mount} is missing')
            elif got['fs'] != fstype:
                bad.append(f'{mount} is {got["fs"]}, not {fstype}')
            elif fsroot and got['root'] != fsroot:
                bad.append(f'{mount} has root {got["root"]}, not {fsroot}')
        r.add('filesystems', vm, not bad if rows else None, '; '.join(bad) or f'{len(rows)} mounts match', '\n'.join(bad))

    index_vs_manifest(r, ids, 'manifest', denied_ok=True)

    for vm, root, profile, _ in manifests():
        if profile == 'full':
            denied = sql(f"SELECT path FROM scan_denied d JOIN scans s USING (scan_id) WHERE s.host_id = {ids.get(vm, -1)} AND d.path LIKE '{root}/lab-seed/restricted%'")
            r.add('reports-unreadable', vm, bool(denied), f'{root}/lab-seed/restricted is listed' if denied else 'the unreadable folder is not listed')

    inventory = {x['hostname']: json.loads(x['inventory_json'] or '{}') for x in sql('SELECT hostname, inventory_json FROM hosts')}
    for vm in VMS:
        words = [line.split(None, 1) for line in (inventory.get(vm, {}).get('packages') or '').splitlines() if ' ' in line]
        got = next((v for k, v in words if k == 'pm'), 'none')
        r.add('package-manager', vm, got == PACKAGE_MANAGERS[vm], got)
        init = next((v for k, v in words if k == 'init'), '')
        want = 'openrc' if vm == 'sf-alpine' else 'systemd'
        r.add('init-system', vm, init == want or (vm == 'sf-alpine' and init != 'systemd' and bool(init)), init or 'not reported')

    for vm, names in TOPOLOGY.items():
        text = json.dumps(api.get(f'/api/graph?host={vm}'))
        missing = [n for n in names if n not in text]
        r.add('topology', vm, not missing, f'missing {missing}' if missing else ', '.join(names))
    text = json.dumps(api.get('/api/graph?host=sf-suse'))
    r.add('nested-subvolumes', 'sf-suse', '@/home' in text and '@/.snapshots' in text, 'mounted subvolumes in the graph')
    p = sql(f"SELECT count(*) n FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = {ids.get('sf-suse', -1)} AND d.path LIKE '/srv/btrfs/var/lab-seed%'")
    r.add('child-subvolume', 'sf-suse', bool(p and p[0]['n']), f'{p[0]["n"] if p else 0} files found under the unmounted @/var (finding GM-14)')
    merged = table.get(('sf-arch', '/mnt/pool'), {})
    r.add('mergerfs-source', 'sf-arch', '/mnt/disk1' in str(merged.get('source')), f'source reported as {merged.get("source")!r}')

    def search():
        hits = api.get('/api/search?q=IMG_0001.cr2&limit=50')
        found = {h['host'] for h in hits['results']}
        want = {vm for vm, _, profile, _ in manifests() if profile == 'full'}
        if want - found:
            raise AssertionError(f'not found on {sorted(want - found)}')
        return f'found on {len(found)} hosts'
    r.check('search', '-', search)

    def access_then_rescan():
        for vm, ip in IPS.items():
            if vm == 'sf-alpine':
                continue
            script = cli('access', 'script', '--host', ip)
            ssh(vm, 'sudo -n sh -s', stdin=script)
        demo.scan(api, [ip for vm, ip in IPS.items() if vm != 'sf-alpine'])
    r.check('scan-access-setup', '-', access_then_rescan)
    latest = {}
    for j in api.get('/api/jobs')['jobs']:
        latest.setdefault(j['host'], j)
    for vm in VMS:
        if vm != 'sf-alpine':
            r.add('scan-with-access', vm, latest.get(vm, {}).get('status') == 'ok', latest.get(vm, {}).get('status', 'no job'))
    index_vs_manifest(r, ids, 'manifest-with-access', denied_ok=False, skip={'sf-alpine'})
    # The engine needs its own permission, which the operator gives: the docker group, or sudo for podman.
    ssh('sf-ubuntu', 'sudo -n usermod -aG docker scan')
    ssh('sf-rocky', "echo 'scan ALL=(root) NOPASSWD: /usr/bin/podman' | sudo -n tee /etc/sudoers.d/sflab-scan-podman >/dev/null")
    demo.scan(api, [IPS['sf-ubuntu'], IPS['sf-rocky']])
    for vm in ('sf-ubuntu', 'sf-rocky'):
        found = 'sflab-web' in json.dumps(api.get(f'/api/docker?host={vm}'))
        r.add('containers', vm, found, 'sflab-web found' if found else 'sflab-web not found')


def excluded(path):
    return any(fnmatch.fnmatch(part, name) for part in path.split('/') for name in DEFAULT_EXCLUDE_NAMES)


def index_vs_manifest(r, ids, check, denied_ok, skip=()):
    """Every seed entry the scan user can read is in the index with the right size, and nothing more is."""
    for vm, root, profile, m in manifests():
        if vm in skip or root == '/srv/btrfs/var':       # a child subvolume: it has its own check
            continue
        seed = f'{root}/lab-seed'
        rows = sql(f"""SELECT hex(CAST(d.path || '/' || f.filename AS BLOB)) x, f.file_size_bytes s
                       FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts mm ON mm.mount_id = f.mount_id
                       WHERE mm.host_id = {ids.get(vm, -1)} AND (d.path = '{seed}' OR d.path LIKE '{seed}/%')""")
        found = {bytes.fromhex(x['x']): x['s'] for x in rows}
        prefix = os.fsencode(seed + '/')
        missing, wrong, extra = [], [], set(found)
        extra = {k for k in extra if not excluded(k.decode(errors='replace'))}       # .git itself is listed, not walked
        for e in m['entries']:
            if excluded(e['path']):
                continue
            # the index keeps a name that isn't UTF-8 as text, with its bad bytes written out: \\xff
            key = prefix + os.fsencode(e['path']).decode('utf-8', 'backslashreplace').encode()
            extra.discard(key)
            if denied_ok and profile == 'full' and e['path'].startswith('restricted/'):
                continue
            if key not in found:
                missing.append(e['path'])
            elif e['type'] == 'f' and found[key] != e['size'] and not e.get('sparse'):
                wrong.append(f'{e["path"]}: {found[key]} bytes, wanted {e["size"]}')
        bad = [f'{len(missing)} missing, e.g. {missing[:3]!r}'] * bool(missing) + wrong[:3] + [f'{len(extra)} not in the manifest, e.g. {sorted(extra)[:2]!r}'] * bool(extra)
        r.add(check, vm, not bad, f'{root}: ' + ('; '.join(bad) or f'{len(found)} entries match'), '\n'.join(bad))


# ── tier 3: data going between hosts ────────────────────────────────
def tier3(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    handbook = 'lab-seed/shared/docs/handbook.txt'

    def nfs():
        demo.share_nfs(api)
        want = seed_file('sf-ubuntu', '/tank/media')['sha256']
        if seed_hash('sf-fedora', f'/mnt/ubuntu-media/{handbook}') != want:
            raise AssertionError('the file reads differently through the mount')
        return 'sf-ubuntu to sf-fedora, same bytes'
    r.check('nfs', 'sf-fedora', nfs)

    def smb():
        demo.share_smb(api)
        want = seed_file('sf-rocky', '/srv/data')['sha256']
        if seed_hash('sf-suse', f'/mnt/rocky-data/{handbook}') != want:
            raise AssertionError('the file reads differently through the mount')
        return 'sf-rocky to sf-suse, same bytes'
    r.check('smb', 'sf-suse', smb)

    job = {}

    def rsnapshot():
        job['id'] = demo.backup_job(api)
        return job['id']
    r.check('rsnapshot', 'sf-ubuntu', rsnapshot)

    def restore():
        rel = 'shared/docs/handbook.txt'
        want = seed_file('sf-rocky', '/srv/data')['sha256']
        ssh('sf-rocky', f'sudo -n rm /srv/data/{handbook}')
        out = api.post(f'/api/deploy/jobs/{job["id"]}/restore', {'snapshot': 'daily.0', 'path': rel})
        def done():       # a restore is a task: it has runs, but no group row
            runs = api.get(f'/api/deploy/groups/{out["group"]}')['runs']
            return runs and all(x['status'] not in ('queued', 'running') for x in runs)
        wait_for('the restore', done, 300)
        restored = f'{out["target"]}/handbook.txt'        # beside the original, in a folder of its own
        if seed_hash('sf-rocky', restored) != want:
            raise AssertionError('the restored file has other bytes')
        ssh('sf-rocky', f'sudo -n mv {restored} /srv/data/{handbook}')
        return f'{restored}, same bytes'
    if job:
        r.check('rsnapshot-restore', 'sf-rocky', restore)

    def move_steps(name, dst_host, dst):
        plan = api.post('/api/moves', {'name': name, 'steps': [{
            'method': 'move', 'src': {'host': 'sf-suse', 'path': '/mnt/raid/lab-seed'},
            'dst': {'host': dst_host, 'path': dst}, 'options': {'schedule': 'daily'}}]})
        demo.deploy(api, 'jobs', plan['id'], name)
        jid = f'p{plan["id"]}-{plan["steps"][0]["id"]}'
        now = int(ssh(dst_host, 'date +%s'))
        job_run(api, jid, 'run', 'run', now)
        job_run(api, jid, 'verify', 'verify', now)
        m = json.loads((STATE / 'manifests' / 'sf-suse_mnt_raid.json').read_text())
        bad = [e['path'] for e in m['entries'] if e['type'] == 'f' and seed_hash(dst_host, f'{dst}/{e["path"]}') != e['sha256']]
        if bad:
            raise AssertionError(f'other bytes at the destination: {bad[:3]}')
        return jid

    def move_across():
        jid = move_steps('Lab move across', 'sf-arch', '/mnt/disk1/from-suse')
        out = api.post(f'/api/deploy/jobs/{jid}/cutover')
        if out['status'] != 'failed' or 'by hand' not in out['output']:
            raise AssertionError(f'cutover across hosts should leave the source to the operator: {out["output"][-300:]}')
        if 'lab-seed' not in ssh('sf-suse', 'ls /mnt/raid').split():
            raise AssertionError('the read-only source host was changed')
        return 'copied and verified; cutover refused, source untouched'
    r.check('move-across-hosts', 'sf-arch', move_across)

    def move_here():
        jid = move_steps('Lab move here', 'sf-suse', '/srv/btrfs/moved')
        out = api.post(f'/api/deploy/jobs/{jid}/cutover')
        if out['status'] != 'ok':
            raise AssertionError(f'cutover: {out["output"][-400:]}')
        left = ssh('sf-suse', 'ls -l /mnt/raid')
        if 'lab-seed.migrated-' not in left or '-> /srv/btrfs/moved' not in left:
            raise AssertionError(f'expected a renamed source and a link to the destination: {left!r}')
        return 'copied, verified, source renamed, link left behind'
    r.check('move-cutover', 'sf-suse', move_here)

    task = {}

    def send():
        task['id'] = demo.btrfs_send(api)
        got = ssh('sf-arch', 'sudo -n ls /srv/fedora-media').split()
        want = seed_file('sf-fedora', '/data/media')['sha256']
        if seed_hash('sf-arch', f'/srv/fedora-media/{got[-1]}/{handbook}') != want:
            raise AssertionError('the file in the received snapshot has other bytes')
        return got[-1]
    r.check('btrfs-send', 'sf-arch', send)

    def send_again():
        time.sleep(61)                   # snapshot names go down to the minute
        before = set(ssh('sf-arch', 'sudo -n ls /srv/fedora-media').split())
        ssh('sf-fedora', 'sudo -n sh -c "echo second >/data/media/lab-seed-second.txt"')
        demo.deploy(api, 'tasks', task['id'], 'btrfs replication again', run=True)
        new = set(ssh('sf-arch', 'sudo -n ls /srv/fedora-media').split()) - before
        if not new:
            raise AssertionError('no new snapshot arrived')
        return f'{sorted(new)[0]} arrived'
    if task:
        r.check('btrfs-send-again', 'sf-arch', send_again)
    r.add('zfs-send-between-hosts', 'sf-ubuntu', None, 'only one VM has ZFS: tier 2 sends between its two pools')


# ── tier 4: what happens when things go wrong ───────────────────────
REPLAY = r'''
import json, subprocess, time
from storageforge_index import deploy, vault
from storageforge_index.db import Database
from storageforge_index.remote import Transport, child_env
from storageforge_index.runner import connect_address, ephemeral_agent, known_hosts_path
import os
db = Database(os.environ['STORAGEFORGE_DB']); c = db.connect()
name = 'sf-fedora'; addr = connect_address(c, name); machine = deploy._machine(c, name)
script = 'echo signed-script-ran\n'
out = {}
with vault.Vault(db, c).unlock() as v:
    key = deploy._signer(v); b = v.resolve(addr, 'deploy')
    with ephemeral_agent(v.decrypt_key(b.key_id), ttl=120) as sock:
        t = Transport(host=addr, user=b.user, port=b.port, agent_sock=sock, known_hosts=str(known_hosts_path()), isolated=True)
        def send(req):
            p = subprocess.run(t.argv('storageforge-run'), input=req, capture_output=True, env=child_env(), timeout=60)
            return {'rc': p.returncode, 'ran': b'signed-script-ran' in p.stdout, 'text': (p.stdout + p.stderr).decode(errors='replace')[-200:]}
        good = deploy.request(key, name, script, machine=machine)
        out['first'] = send(good)
        out['replay'] = send(good)
        out['other-host'] = send(deploy.request(key, 'sf-arch', script, machine=machine))
        out['other-machine'] = send(deploy.request(key, name, script, machine='0' * 32))
        out['expired'] = send(deploy.request(key, name, script, machine=machine, now=time.time() - 1200))
        out['tampered'] = send(deploy.request(key, name, script, machine=machine).replace(b'signed-script-ran', b'signed-script-rax'))
        t.close()
print('RESULT' + json.dumps(out))
'''


def tier4(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)

    def has_alert(kind, text):
        return [a for a in alerts_now() if a['kind'].startswith(kind) and text in json.dumps(a)]

    def degraded():
        disk = next(d.split()[0] for d in subprocess.run(['virsh', 'domblklist', 'sf-ubuntu'], capture_output=True, text=True).stdout.splitlines() if 'sf-ubuntu-data1' in d)
        subprocess.run(['virsh', '-q', 'detach-disk', 'sf-ubuntu', disk, '--live'], check=True, capture_output=True)
        ssh('sf-ubuntu', 'sudo -n sh -c "dd if=/dev/urandom of=/tank/photos/lab-io bs=1M count=20 status=none; sync; zpool scrub tank"')
        wait_for('tank to degrade', lambda: 'DEGRADED' in ssh('sf-ubuntu', 'sudo -n zpool list -H -o health tank'), 120)
        demo.scan(api, [IPS['sf-ubuntu']])
        got = has_alert('pool', 'tank')
        if not got:
            raise AssertionError(f'no pool alert: {alerts_now()}')
        return got[0]['title']
    r.check('pool-degraded', 'sf-ubuntu', degraded)

    def full():
        demo.open_alert(api)
        got = has_alert('disk-crit', '/backup')
        ssh('sf-ubuntu', f'sudo -n rm {demo.FILLED}')
        ssh('sf-ubuntu', 'sync; sleep 6')
        demo.scan(api, [IPS['sf-ubuntu']])
        if has_alert('disk-crit', '/backup'):
            raise AssertionError('the alert stayed open after the space came back')
        return f'{got[0]["title"]}, sent to ntfy, resolved after freeing the space'
    r.check('disk-full', 'sf-ubuntu', full)

    def offline():
        lines = subprocess.run(['virsh', 'domiflist', 'sf-alpine'], capture_output=True, text=True, check=True).stdout.splitlines()
        nic = next(x.split()[0] for x in lines if 'sflab' in x)
        subprocess.run(['virsh', '-q', 'domif-setlink', 'sf-alpine', nic, 'down'], check=True, capture_output=True)
        try:
            job = api.post('/api/scan', {'host': IPS['sf-alpine']})['job_id']
            ended = wait_for('the scan to fail', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 240)
            if ended['status'] != 'failed':
                raise AssertionError(f'the scan of an unreachable host ended {ended["status"]}')
            if not has_alert('scan-failed', 'sf-alpine'):
                raise AssertionError(f'no failed-scan alert: {alerts_now()}')
        finally:
            subprocess.run(['virsh', '-q', 'domif-setlink', 'sf-alpine', nic, 'up'], check=True, capture_output=True)
        wait_for('sf-alpine to come back', lambda: subprocess.run([demo.LAB, 'ssh', 'sf-alpine', 'true'], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0, 90)
        demo.scan(api, [IPS['sf-alpine']])
        if has_alert('scan-failed', 'sf-alpine'):
            raise AssertionError('the alert stayed open after a good scan')
        return 'scan failed, alert opened, and resolved after the next good scan'
    r.check('host-offline', 'sf-alpine', offline)

    def drift():
        demo.share_nfs(api)
        demo.scan(api, [IPS['sf-fedora']])
        clean = [d for d in api.get('/api/deploy')['drift'] if d['host'] == 'sf-fedora' and d['kind'] == 'changed']
        if clean:
            raise AssertionError(f'drift before anything changed: {clean}')
        ssh('sf-fedora', "sudo -n sed -i '/ubuntu-media/d' /etc/fstab")
        demo.scan(api, [IPS['sf-fedora']])
        seen = [d for d in api.get('/api/deploy')['drift'] if d['host'] == 'sf-fedora' and d['kind'] == 'changed']
        if not seen:
            raise AssertionError('removing the managed fstab line was not noticed')
        return seen[0]['text']
    r.check('drift', 'sf-fedora', drift)

    env = 'STORAGEFORGE_VAULT_SECRET_FILE=/run/sf-secrets/vault_secret'
    p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T -e {env} storageforge python -'], input=REPLAY,
                       capture_output=True, text=True, timeout=180)
    line = next((x for x in p.stdout.splitlines() if x.startswith('RESULT')), None)
    if not line:
        r.add('signed-requests', 'sf-fedora', False, 'the helper did not finish', p.stdout[-800:] + p.stderr[-1500:])
    else:
        got = json.loads(line[6:])
        r.add('signed-request', 'sf-fedora', got['first']['rc'] == 0 and got['first']['ran'], f'exit {got["first"]["rc"]}', got['first']['text'])
        for case, row in got.items():
            if case != 'first':
                r.add(f'refuses-{case}', 'sf-fedora', row['rc'] == 97 and not row['ran'], f'exit {row["rc"]}', row['text'])

    # Last: the lab's own SSH refuses this VM from here on, until the reset after this tier brings its key back.
    def reinstalled():
        ssh('sf-suse', "sudo -n sh -c 'rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; systemctl restart sshd'")
        job = api.post('/api/scan', {'host': IPS['sf-suse']})['job_id']
        ended = wait_for('the scan', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 120)
        if ended['status'] != 'failed':
            raise AssertionError(f'a changed host key was accepted: the scan ended {ended["status"]}')
        cli('hosts', 'rekey', 'sf-suse')
        job = api.post('/api/scan', {'host': IPS['sf-suse']})['job_id']
        ended = wait_for('the scan', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 120)
        r.add('rescan-after-rekey-api', 'sf-suse', ended['status'] == 'ok', ended['status'], json.dumps(ended['result']))
        cli('scan', '--host', IPS['sf-suse'])       # what rekey tells the operator to run
        return 'refused until rekey, then scanned through the CLI'
    r.check('changed-host-key', 'sf-suse', reinstalled)


def tier0(r):
    p = subprocess.run([sys.executable, '-m', 'unittest', 'test_tier0', '-v'], cwd=Path(__file__).parent, capture_output=True, text=True, timeout=600)
    failed = set(re.findall(r'^(?:FAIL|ERROR): (\w+)', p.stderr, re.M))
    for name, end in re.findall(r'^(test_\w+) \(.*?\)(?: \.\.\. (ok|skipped.*|FAIL|ERROR))?$', p.stderr, re.M):
        ok = None if end.startswith('skipped') else name not in failed
        r.add(name.removeprefix('test_'), '-', ok, '', p.stderr[-2000:] if not ok and ok is not None else '')


# ── report ──────────────────────────────────────────────────────────
TIERS = {0: 'Smoke', 1: 'Scan', 2: 'Deploy', 3: 'Cross-host', 4: 'Failure'}
CELL = {'pass': 'pass', 'FAIL': '**FAIL**', 'skip': 'skip', 'known': 'known', 'fixed?': 'fixed?'}


def report():
    rows = []
    for tier in TIERS:
        path = RESULTS / f'tier{tier}.json'
        if path.exists():
            rows += json.loads(path.read_text())
    if (STATE / 'gauntlet.json').exists():
        for x in json.loads((STATE / 'gauntlet.json').read_text()):
            why = KNOWN.get((x['stage'], x['host']))
            if why and x['status'] == 'FAIL':
                x = {**x, 'status': 'known', 'note': f'{x["note"]} ({why})'}
            rows.append({**x, 'tier': 2, 'check': x['stage']})
    REPORTS.mkdir(exist_ok=True)
    stamp = time.strftime('%Y-%m-%d-%H%M')
    commit = subprocess.run(['git', '-C', str(ROOT), 'log', '-1', '--format=%h'], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(ROOT), 'status', '--short'], capture_output=True, text=True).stdout.strip()
    count = {s: sum(x['status'] == s for x in rows) for s in CELL}
    lines = [f'# KVM lab results {stamp}', '', f'Commit `{commit}`{" with uncommitted changes" if dirty else ""}. '
             f'{count["pass"]} passed, {count["FAIL"]} failed, {count["known"]} known failures, {count["skip"]} skipped.', '']
    for tier, name in TIERS.items():
        here = [x for x in rows if x['tier'] == tier]
        if not here:
            lines += [f'## Tier {tier}: {name}', '', 'Not run.', '']
            continue
        lines += [f'## Tier {tier}: {name}', '', '| Check | ' + ' | '.join(f'`{v}`' for v in VMS) + ' | Other |', '| :--- |' + ' :--- |' * (len(VMS) + 1)]
        for check in dict.fromkeys(x['check'] for x in here):
            cells = []
            for host in [*VMS, None]:
                got = [x['status'] for x in here if x['check'] == check and (x['host'] == host if host else x['host'] not in VMS)]
                order = ('FAIL', 'known', 'fixed?', 'pass', 'skip')
                cells.append(CELL[next(s for s in order if s in got)] if got else '')
            lines.append(f'| {check} | ' + ' | '.join(cells) + ' |')
        lines.append('')
    problems = [x for x in rows if x['status'] in ('FAIL', 'known', 'fixed?')]
    if problems:
        lines += ['## Failures', '']
        lines += [f'- **{x["status"]}, tier {x["tier"]}, {x["check"]} on {x["host"]}:** {x["note"]}' for x in problems]
        lines.append('')
    out = REPORTS / f'lab-{stamp}.md'
    out.write_text('\n'.join(lines))
    print(f'report: {out}')
    return not count['FAIL']


def main():
    if sys.argv[1:2] == ['report']:
        return 0 if report() else 1
    tier = int(sys.argv[2])
    r = Results(tier)
    try:
        {0: tier0, 1: tier1, 3: tier3, 4: tier4}[tier](r)
    except Exception as exc:
        r.add('tier-setup', '-', False, f'{type(exc).__name__}: {str(exc)[:170]}', traceback.format_exc())
    return 0 if r.save() else 1


if __name__ == '__main__':
    sys.exit(main())
