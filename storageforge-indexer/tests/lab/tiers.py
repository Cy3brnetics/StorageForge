#!/usr/bin/env python3
"""Tiers 1, 3, 4, 5, 6 and 7 of the KVM lab tests, and the report over all tiers. Tier 0 is test_tier0.py, tier 2 is gauntlet.py, tiers 9 to 11 are tiers_platform.py, tier 13 is tiers_features.py, tier 16 is tiers_sends.py.
They change the VMs, so run them through examples/lab/lab.sh test --all, which resets the lab around each tier.

    tiers.py run <0|1|3|4|5|6|7|9|10|11|13|16>   tier 0 as a result file, or one tier against StorageForge on sf-ctl, through its API
    tiers.py report          the table per distro from every results file, into reports/

Results are checked on the VMs and against the seed manifests where a VM can answer, and against the running
StorageForge where the question is what it noticed. A build runs 7 of the 14 configs, so tests choose hosts by what they
can do (roles.py), and a check with no suitable host in this build shows as skip. A check in KNOWN still fails, but is shown apart: it doesn't fail
the run, and it says so when it starts passing.
"""
import fnmatch
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / 'examples' / 'lab'
sys.path[:0] = [str(LAB_DIR), str(ROOT)]
os.environ.setdefault('SFLAB_STATE', str(Path.home() / '.local' / 'state' / 'sflab'))

import demo  # noqa: E402
import roles  # noqa: E402
from demo import COMPOSE, IPS, STATE, cli, ssh  # noqa: E402
from storageforge_index.remote import DEFAULT_EXCLUDE_NAMES  # noqa: E402

RESULTS = STATE / 'results'
REPORTS = ROOT / 'reports'
VMS = list(IPS)
BUILD = roles.build()
os.environ['LIBVIRT_DEFAULT_URI'] = 'qemu:///system'
# (check, vm): why it is expected to fail. Remove the line when the product is fixed.
KNOWN = {}


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
    code = ("import json, sqlite3, sys; c = sqlite3.connect('/app/data/index.db'); c.row_factory = sqlite3.Row; "
            "print(json.dumps([dict(r) for r in c.execute(sys.argv[1])]))")
    return json.loads(ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(code)} {shlex.quote(query)}'))


def host_ids():
    return {r['hostname']: r['host_id'] for r in sql('SELECT hostname, host_id FROM hosts')}


def manifests():
    for vm, root, profile in (r for r in conf('provision/seed-roots.conf') if r[0] in BUILD):
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
        r.add('package-manager', vm, got == BUILD[vm].pm, got)
        init = next((v for k, v in words if k == 'init'), '')
        if BUILD[vm].can('nosystemd'):
            r.add('init-system', vm, bool(init) and init != 'systemd', init or 'not reported')
        else:
            r.add('init-system', vm, init == 'systemd', init or 'not reported')

    for node in BUILD.values():
        if node.topology:
            text = json.dumps(api.get(f'/api/graph?host={node.name}'))
            missing = [n for n in node.topology if n not in text]
            r.add('topology', node.name, not missing, f'missing {missing}' if missing else ', '.join(node.topology))
    if 'sf-suse' in BUILD:
        text = json.dumps(api.get('/api/graph?host=sf-suse'))
        r.add('nested-subvolumes', 'sf-suse', '@/home' in text and '@/.snapshots' in text, 'mounted subvolumes in the graph')
    for node in BUILD.values():
        child = node.tag('btrfs-child')
        if child:
            p = sql(f"SELECT count(*) n FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = {ids.get(node.name, -1)} AND d.path LIKE '{child}%'")
            r.add('child-subvolume', node.name, bool(p and p[0]['n']), f'{p[0]["n"] if p else 0} files found under the unmounted {child} (finding GM-14)')
    if 'sf-arch' in BUILD:
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
            if BUILD[vm].can('nosystemd'):
                continue
            script = cli('access', 'script', '--host', ip)
            ssh(vm, 'sudo -n sh -s', stdin=script)
        demo.scan(api, [ip for vm, ip in IPS.items() if not BUILD[vm].can('nosystemd')])
    r.check('scan-access-setup', '-', access_then_rescan)
    latest = {}
    for j in api.get('/api/jobs')['jobs']:
        latest.setdefault(j['host'], j)
    for vm in VMS:
        if not BUILD[vm].can('nosystemd'):
            r.add('scan-with-access', vm, latest.get(vm, {}).get('status') == 'ok', latest.get(vm, {}).get('status', 'no job'))
    index_vs_manifest(r, ids, 'manifest-with-access', denied_ok=False, skip={n.name for n in roles.having('nosystemd')})
    # The engine needs its own permission, which the operator gives: the docker group, or sudo for podman.
    for node in roles.having('docker'):
        ssh(node.name, 'sudo -n usermod -aG docker scan')
    for node in roles.having('podman'):
        ssh(node.name, "echo 'scan ALL=(root) NOPASSWD: /usr/bin/podman' | sudo -n tee /etc/sudoers.d/sflab-scan-podman >/dev/null")
    engines = roles.having('docker') + roles.having('podman')
    if engines:
        demo.scan(api, [n.ip for n in engines])
    for node in engines:
        found = 'sflab-web' in json.dumps(api.get(f'/api/docker?host={node.name}'))
        r.add('containers', node.name, found, 'sflab-web found' if found else 'sflab-web not found')


def excluded(path):
    return any(fnmatch.fnmatch(part, name) for part in path.split('/') for name in DEFAULT_EXCLUDE_NAMES)


def index_vs_manifest(r, ids, check, denied_ok, skip=()):
    """Every seed entry the scan user can read is in the index with the right size, and nothing more is."""
    for vm, root, profile, m in manifests():
        if vm in skip or root == BUILD[vm].tag('btrfs-child'):       # a child subvolume: it has its own check
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
        server, client = demo.share_nfs(api)
        want = seed_file(server.name, server.data)['sha256']
        if seed_hash(client.name, f'/mnt/lab-nfs/{handbook}') != want:
            raise AssertionError('the file reads differently through the mount')
        return f'{server.name} to {client.name}, same bytes'
    r.check('nfs', demo.nfs_pair()[1].name, nfs)

    def smb():
        server, client = demo.share_smb(api)
        if client is None:
            raise AssertionError('no host in this build can mount SMB')
        want = seed_file(server.name, server.data)['sha256']
        if seed_hash(client.name, f'/mnt/lab-smb/{handbook}') != want:
            raise AssertionError('the file reads differently through the mount')
        return f'{server.name} to {client.name}, same bytes'
    def client_module(node):
        if demo.can_mount_smb(node):
            return 'cifs and nls_utf8 are there'
        demo.share_smb(api, roles.smb_server(), f'labmod{node.name[3:]}', '/mnt/lab-smb-module', client=node)
        if not demo.can_mount_smb(node):
            raise AssertionError('the share mounted, but the kernel still lacks cifs or nls_utf8')
        return 'the deploy installed cifs and nls_utf8, and the share mounted'
    for node in (n for n in roles.deployable() if n.name != roles.smb_server().name):
        r.check('smb-client-module', node.name, lambda node=node: client_module(node))
    client = demo.smb_client()
    if client:
        r.check('smb', client.name, smb)
        for node in (n for n in roles.having('btrfs-nested') if n.can('selinux') and n.name != client.name):
            def nested(node=node):
                demo.share_smb(api, node, 'labnested', '/mnt/lab-nested')
                return f'{node.data} on {node.name} mounted on {client.name}'
            r.check('smb-unlabeled-parent', node.name, nested)
    else:
        r.add('smb', '-', None, 'no host in this build can mount SMB')

    job = {}

    def rsnapshot():
        job['id'], job['source'], target = demo.backup_job(api)
        return f'{job["id"]} on {target.name}'
    r.check('rsnapshot', roles.smb_server().name, rsnapshot)

    def restore():
        rel = 'shared/docs/handbook.txt'
        source = job['source']
        want = seed_file(source.name, source.data)['sha256']
        ssh(source.name, f'sudo -n rm {source.data}/{handbook}')
        out = api.post(f'/api/deploy/jobs/{job["id"]}/restore', {'snapshot': 'daily.0', 'path': rel})
        def done():       # a restore is a task: it has runs, but no group row
            runs = api.get(f'/api/deploy/groups/{out["group"]}')['runs']
            return runs and all(x['status'] not in ('queued', 'running') for x in runs)
        wait_for('the restore', done, 300)
        restored = f'{out["target"]}/handbook.txt'        # beside the original, in a folder of its own
        if seed_hash(source.name, restored) != want:
            raise AssertionError('the restored file has other bytes')
        ssh(source.name, f'sudo -n mv {restored} {source.data}/{handbook}')
        return f'{restored}, same bytes'
    if job:
        r.check('rsnapshot-restore', job['source'].name, restore)

    mover = roles.deployable()[0]
    elsewhere = roles.other_than(mover)

    def move_steps(name, folder, dst_host, dst):
        plan = api.post('/api/moves', {'name': name, 'steps': [{
            'method': 'move', 'src': {'host': mover.name, 'path': f'{mover.data}/lab-seed/{folder}'},
            'dst': {'host': dst_host, 'path': dst}, 'options': {'schedule': 'daily'}}]})
        demo.deploy(api, 'jobs', plan['id'], name)
        jid = f'p{plan["id"]}-{plan["steps"][0]["id"]}'
        now = int(ssh(dst_host, 'date +%s'))
        job_run(api, jid, 'run', 'run', now)
        job_run(api, jid, 'verify', 'verify', now)
        m = json.loads((STATE / 'manifests' / f'{mover.name}{mover.data.replace("/", "_")}.json').read_text())
        bad = [e['path'] for e in m['entries'] if e['type'] == 'f' and e['path'].startswith(f'{folder}/')
               and seed_hash(dst_host, f'{dst}/{e["path"].removeprefix(folder + "/")}') != e['sha256']]
        if bad:
            raise AssertionError(f'other bytes at the destination: {bad[:3]}')
        return jid

    def move_across():
        jid = move_steps('Lab move across', 'shared', elsewhere.name, f'{elsewhere.room}/from-{mover.name}')
        out = api.post(f'/api/deploy/jobs/{jid}/cutover')
        if out['status'] != 'failed' or 'by hand' not in out['output']:
            raise AssertionError(f'cutover across hosts should leave the source to the operator: {out["output"][-300:]}')
        if 'shared' not in ssh(mover.name, f'ls {mover.data}/lab-seed').split():
            raise AssertionError('the read-only source host was changed')
        return 'copied and verified; cutover refused, source untouched'
    r.check('move-across-hosts', elsewhere.name, move_across)

    def move_here():
        dst = f'{mover.room}/moved-here'
        jid = move_steps('Lab move here', 'dupes', mover.name, dst)
        out = api.post(f'/api/deploy/jobs/{jid}/cutover')
        if out['status'] != 'ok':
            raise AssertionError(f'cutover: {out["output"][-400:]}')
        left = ssh(mover.name, f'ls -l {mover.data}/lab-seed')
        if 'dupes.migrated-' not in left or f'-> {dst}' not in left:
            raise AssertionError(f'expected a renamed source and a link to the destination: {left!r}')
        return 'copied, verified, source renamed, link left behind'
    r.check('move-cutover', mover.name, move_here)

    task = {}

    def send():
        task['id'], task['from'], task['to'] = demo.btrfs_send(api)
        to = task['to']
        got = ssh(to.name, f'sudo -n ls {to.recv}').split()
        want = seed_file(task['from'].name, task['from'].data)['sha256']
        if seed_hash(to.name, f'{to.recv}/{got[-1]}/{handbook}') != want:
            raise AssertionError('the file in the received snapshot has other bytes')
        return got[-1]
    r.check('btrfs-send', roles.receiver().name, send)

    # a schedule on a real host: its timer fires within a minute, it reports, a pause reaches the host, and it can leave
    def schedule_for(vm):
        marker = f'/tmp/sf-lab-schedule-{vm}'
        made = api.post('/api/scheduler/schedules', {'name': f'lab-{vm}', 'host': vm, 'cron_expr': '* * * * *', 'task_type': 'command',
                                                     'task_ref': f'touch {marker}; echo lab-run'})['schedule']
        sid = made['schedule_id']
        demo.deploy(api, 'schedules', sid, f'schedule on {vm}')
        wait_for('the timer to fire', lambda: ssh(vm, f'test -e {marker} && echo yes', check=False).strip() == 'yes', timeout=150)
        wait_for('its report', lambda: api.get(f'/api/scheduler/schedules/{sid}/runs')['runs'], timeout=90)
        api.post(f'/api/scheduler/schedules/{sid}/pause', {'paused': True})
        wait_for('the pause to reach the host', lambda: ssh(vm, f'systemctl is-active sf-sched-{sid}.timer', check=False).strip() != 'active', timeout=120)
        demo.deploy(api, 'schedules', sid, 'uninstall', remove=True)
        api('DELETE', f'/api/scheduler/schedules/{sid}')
    for vm in [n.name for n in roles.deployable()[:2]]:
        r.check('schedule-timer', vm, lambda vm=vm: schedule_for(vm))

    keeper = roles.deployable()[-1].name

    def backup_copy():
        api('PUT', '/api/backups/target', {'host': keeper, 'path': '/srv/sf-backups'})
        made = api.post('/api/backups', {'kind': 'essentials'})
        if made.get('copy_error'):
            raise AssertionError(made['copy_error'])
        api('PUT', '/api/backups/target', {'host': '', 'path': ''})
        name = ssh(keeper, 'sudo -n ls /srv/sf-backups').split()[-1]
        if not name.endswith('.db.enc'):
            raise AssertionError(f'expected an encrypted copy, found {name}')
        copy = ssh(keeper, f'sudo -n base64 -w0 /srv/sf-backups/{name}')
        # back on the controller: it opens with the vault secret, and is a database holding the accounts
        check = ('import base64,sqlite3,sys,tempfile,pathlib;from storageforge_index import backup;from storageforge_index.vault import secret_from_env;'
                 'd=pathlib.Path(tempfile.mkdtemp());(d/"c").write_bytes(base64.b64decode(sys.stdin.read()));'
                 'backup.decrypt_file(str(d/"c"),str(d/"p"),secret_from_env());'
                 'print(sqlite3.connect(d/"p").execute("select count(*) from users").fetchone()[0])')
        out = ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(check)}', stdin=copy)
        if int(out.strip().splitlines()[-1]) < 1:
            raise AssertionError(f'the restored copy holds no accounts: {out[-200:]}')
    r.check('backup-copy-restores', keeper, backup_copy)

    def by_cron():
        # no systemd: deploy access refuses this host, so the script is run by hand, and cron wakes the runner
        vm, marker = roles.having('nosystemd')[0].name, '/tmp/sf-lab-schedule-cron'
        made = api.post('/api/scheduler/schedules', {'name': 'lab-cron', 'host': vm, 'cron_expr': '* * * * *', 'task_type': 'command', 'task_ref': f'touch {marker}'})['schedule']
        sid = made['schedule_id']
        script = api.text(f'/api/scheduler/schedules/{sid}/install-script')
        ssh(vm, 'sudo -n sh -c "command -v bash >/dev/null && command -v flock >/dev/null && command -v timeout >/dev/null || apk add -q bash util-linux coreutils; rc-service crond start >/dev/null 2>&1 || true"')
        before = ssh(vm, f'sudo -n bash -s -- --report', stdin=script)
        if 'needs to be installed' not in before or ssh(vm, f'test -e /usr/local/lib/storageforge/scheduler/run-{sid}.sh && echo there', check=False).strip():
            raise AssertionError(f'the report changed something: {before[-300:]}')
        ssh(vm, 'sudo -n bash -s -- --install', stdin=script)
        wait_for('cron to wake the runner', lambda: ssh(vm, f'test -e {marker} && echo yes', check=False).strip() == 'yes', timeout=150)
        ssh(vm, 'sudo -n bash -s -- --uninstall', stdin=script)
        api('DELETE', f'/api/scheduler/schedules/{sid}')
        return 'report changed nothing, cron ran it, and it left'
    r.check('schedule-cron', roles.having('nosystemd')[0].name, by_cron)

    def move_by_hand():
        # a move script run by hand on the host, and the rescan that shows the step as copied
        plan = api.post('/api/moves', {'name': 'Lab by hand', 'steps': [{'method': 'copy', 'src': {'host': mover.name, 'path': f'{mover.data}/lab-seed/unique'},
                                                                          'dst': {'host': mover.name, 'path': f'{mover.room}/by-hand'}}]})
        script = api.text(f'/api/moves/{plan["id"]}/script')
        ssh(mover.name, 'sudo -n bash -s -- --run', stdin=script)
        demo.scan(api, [mover.ip])
        state = api.get(f'/api/moves/{plan["id"]}')['progress'][0]
        if not state.get('copied'):
            raise AssertionError(f'the step does not show as copied: {state}')
        return f'copied {state["copied"]}'
    r.check('move-progress', mover.name, move_by_hand)

    def send_again():
        frm, to = task['from'], task['to']
        time.sleep(61)                   # snapshot names go down to the minute
        before = set(ssh(to.name, f'sudo -n ls {to.recv}').split())
        ssh(frm.name, f'sudo -n sh -c "echo second >{frm.subvol}/lab-seed-second.txt"')
        demo.deploy(api, 'tasks', task['id'], 'btrfs replication again', run=True)
        new = set(ssh(to.name, f'sudo -n ls {to.recv}').split()) - before
        if not new:
            raise AssertionError('no new snapshot arrived')
        newest = sorted(new)[0]
        if ssh(to.name, f'sudo -n cat {to.recv}/{newest}/lab-seed-second.txt').strip() != 'second':
            raise AssertionError('the change is not in the second snapshot')
        return f'{newest} arrived with the change'
    if task:
        r.check('btrfs-send-again', task['to'].name, send_again)

    pools = roles.having('zfs')
    if len(pools) < 2:
        r.add('zfs-send-between-hosts', pools[0].name, None, 'only one ZFS host in this build: tier 2 sends within it')
    else:
        def zfs_send():
            frm, to = pools[:2]
            data = f'{frm.tag("zfs-pool")}/media'
            into = f'{to.tag("zfs-pool")}/from-{frm.name}'
            made = api.post('/api/tasks', {'name': 'Lab ZFS replication', 'host': frm.name, 'schedule': '*-*-* 02:30:00', 'blocks': [
                {'type': 'zfs_snapshot', 'params': {'dataset': data, 'prefix': 'daily'}},
                {'type': 'zfs_send', 'params': {'dataset': data, 'prefix': 'daily', 'dst_host': to.name, 'dst': into, 'keep': 7}}]})
            demo.deploy(api, 'tasks', made['id'], 'ZFS replication', run=True)
            if 'daily-' not in ssh(to.name, f'sudo -n zfs list -H -t snapshot -o name {into}'):
                raise AssertionError('no snapshot arrived')
            return f'{data} to {to.name}:{into}'
        r.check('zfs-send-between-hosts', pools[1].name, zfs_send)


# ── tier 4: what happens when things go wrong ───────────────────────
REPLAY = r'''
import json, subprocess, time
from storageforge_index import deploy, vault
from storageforge_index.db import Database
from storageforge_index.remote import Transport, child_env
from storageforge_index.runner import connect_address, ephemeral_agent, known_hosts_path
import os
db = Database(os.environ['STORAGEFORGE_DB']); c = db.connect()
name = '@HOST@'; addr = connect_address(c, name); machine = deploy._machine(c, name)
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
        out['other-host'] = send(deploy.request(key, '@OTHER@', script, machine=machine))
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

    def pull_disk(vm, number=1):
        lines = subprocess.run(['virsh', 'domblklist', vm], capture_output=True, text=True).stdout.splitlines()
        disk = next(d.split()[0] for d in lines if f'{vm}-data{number}' in d)
        subprocess.run(['virsh', '-q', 'detach-disk', vm, disk, '--live'], check=True, capture_output=True)

    def degraded():
        node = roles.having('zfs')[0]
        pool = node.tag('zfs-pool')
        pull_disk(node.name)
        ssh(node.name, f'sudo -n sh -c "dd if=/dev/urandom of={node.room}/lab-io bs=1M count=20 status=none; sync; zpool scrub {pool}"')
        wait_for(f'{pool} to degrade', lambda: 'DEGRADED' in ssh(node.name, f'sudo -n zpool list -H -o health {pool}'), 120)
        demo.scan(api, [node.ip])
        got = has_alert('pool', pool)
        if not got:
            raise AssertionError(f'no pool alert: {alerts_now()}')
        return got[0]['title']
    r.check('pool-degraded', roles.having('zfs')[0].name, degraded)

    def full():
        node = demo.open_alert(api)
        got = has_alert('disk-crit', node.fill)
        ssh(node.name, f'sudo -n rm {demo.filled(node)}')
        ssh(node.name, 'sync; sleep 6')
        demo.scan(api, [node.ip])
        if has_alert('disk-crit', node.fill):
            raise AssertionError('the alert stayed open after the space came back')
        return f'{got[0]["title"]}, sent to ntfy, resolved after freeing the space'
    r.check('disk-full', roles.fill_host().name, full)

    away = roles.having('nosystemd')[0]

    def offline():
        lines = subprocess.run(['virsh', 'domiflist', away.name], capture_output=True, text=True, check=True).stdout.splitlines()
        nic = next(x.split()[0] for x in lines if 'sflab' in x)
        subprocess.run(['virsh', '-q', 'domif-setlink', away.name, nic, 'down'], check=True, capture_output=True)
        try:
            job = api.post('/api/scan', {'host': away.ip})['job_id']
            ended = wait_for('the scan to fail', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 240)
            if ended['status'] != 'failed':
                raise AssertionError(f'the scan of an unreachable host ended {ended["status"]}')
            if not has_alert('scan-failed', away.name):
                raise AssertionError(f'no failed-scan alert: {alerts_now()}')
        finally:
            subprocess.run(['virsh', '-q', 'domif-setlink', away.name, nic, 'up'], check=True, capture_output=True)
        wait_for(f'{away.name} to come back', lambda: subprocess.run([demo.LAB, 'ssh', away.name, 'true'], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0, 90)
        demo.scan(api, [away.ip])
        if has_alert('scan-failed', away.name):
            raise AssertionError('the alert stayed open after a good scan')
        return 'scan failed, alert opened, and resolved after the next good scan'
    r.check('host-offline', away.name, offline)

    client = demo.nfs_pair()[1]

    def drift():
        demo.share_nfs(api)
        demo.scan(api, [client.ip])
        clean = [d for d in api.get('/api/deploy')['drift'] if d['host'] == client.name and d['kind'] == 'changed']
        if clean:
            raise AssertionError(f'drift before anything changed: {clean}')
        ssh(client.name, "sudo -n sed -i '/lab-nfs/d' /etc/fstab")
        demo.scan(api, [client.ip])
        seen = [d for d in api.get('/api/deploy')['drift'] if d['host'] == client.name and d['kind'] == 'changed']
        if not seen:
            raise AssertionError('removing the managed fstab line was not noticed')
        return seen[0]['text']
    r.check('drift', client.name, drift)

    signer = roles.deployable()[0]
    env = 'STORAGEFORGE_VAULT_SECRET_FILE=/run/sf-secrets/vault_secret'
    helper = REPLAY.replace('@HOST@', signer.name).replace('@OTHER@', roles.other_than(signer).name)
    p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T -e {env} storageforge python -'], input=helper,
                       capture_output=True, text=True, timeout=180)
    line = next((x for x in p.stdout.splitlines() if x.startswith('RESULT')), None)
    if not line:
        r.add('signed-requests', signer.name, False, 'the helper did not finish', p.stdout[-800:] + p.stderr[-1500:])
    else:
        got = json.loads(line[6:])
        r.add('signed-request', signer.name, got['first']['rc'] == 0 and got['first']['ran'], f'exit {got["first"]["rc"]}', got['first']['text'])
        for case, row in got.items():
            if case != 'first':
                r.add(f'refuses-{case}', signer.name, row['rc'] == 97 and not row['ran'], f'exit {row["rc"]}', row['text'])

    # Last: the lab's own SSH refuses this VM from here on, until the reset after this tier brings its key back.
    moved = roles.deployable()[-1]

    def reinstalled():
        ssh(moved.name, "sudo -n sh -c 'rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; systemctl restart sshd || systemctl restart ssh'")
        job = api.post('/api/scan', {'host': moved.ip})['job_id']
        ended = wait_for('the scan', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 120)
        if ended['status'] != 'failed':
            raise AssertionError(f'a changed host key was accepted: the scan ended {ended["status"]}')
        cli('hosts', 'rekey', moved.name)
        job = api.post('/api/scan', {'host': moved.ip})['job_id']
        ended = wait_for('the scan', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), 120)
        r.add('rescan-after-rekey-api', moved.name, ended['status'] == 'ok', ended['status'], json.dumps(ended['result']))
        cli('scan', '--host', moved.ip)       # what rekey tells the operator to run
        return 'refused until rekey, then scanned through the CLI'
    r.check('changed-host-key', moved.name, reinstalled)


# ── tier 5: btrfs in depth ──────────────────────────────────────────
def btrfs_plan(api, name, node, tasks, destructive=False):
    plan = api.post('/api/changes', {'name': name, 'tasks': [{'type': t, 'host': node.name, 'params': p} for t, p in tasks]})
    return demo.deploy(api, 'changes', plan['id'], name, **({'destructive': True} if destructive else {}))


def fs_mount(node, path):
    """The mount a subvolume path is on: btrfs filesystem show and remount need that, not the path."""
    return ssh(node.name, f'findmnt -nT {path} -o TARGET').strip()


def tier5(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    hosts = roles.having('btrfs')
    ids = host_ids()
    for vm, ip in IPS.items():            # scan access: device errors and health need its collector
        if BUILD[vm].can('btrfs'):
            ssh(vm, 'sudo -n sh -s', stdin=cli('access', 'script', '--host', ip))
    demo.scan(api, [n.ip for n in hosts])

    for node in hosts:
        text = json.dumps(api.get(f'/api/graph?host={node.name}')).lower()
        profile = node.tag('btrfs-profile')
        if profile:
            r.add('btrfs-profile', node.name, profile in text, f'{profile} {"in" if profile in text else "not in"} the graph')
        child = node.tag('btrfs-child')
        if child:
            rows = sql(f"SELECT count(*) n FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = {ids.get(node.name, -1)} AND d.path LIKE '{child}%'")
            r.add('btrfs-child-indexed', node.name, bool(rows and rows[0]['n']), f'{rows[0]["n"] if rows else 0} entries under {child}')
        if node.can('btrfs-reflink'):
            rows = sql(f"SELECT f.file_size_bytes s FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = {ids.get(node.name, -1)} AND f.filename LIKE 'reflink-%'")
            r.add('btrfs-reflink-sizes', node.name, sorted(x['s'] for x in rows) == [64 << 20] * 2, f'{len(rows)} reflinked files indexed at their full size')
        if node.can('btrfs-quota'):
            job = next((j for j in api.get('/api/jobs')['jobs'] if j['host'] == node.name), {})
            r.add('btrfs-quota-scan', node.name, job.get('status') == 'ok', f'scan with quotas on: {job.get("status")}')

    def subvolumes(node):
        snap = f'{node.snaps}/ch-snap'
        btrfs_plan(api, f'btrfs basics {node.name}', node, [
            ('subvolume', {'path': f'{node.subvol}/ch-sub'}),
            ('snapshot', {'source': node.subvol, 'dest': snap}),
            ('to-subvolume', {'path': f'{node.data}/lab-seed/shared/docs'}),
            ('scrub', {'target': node.subvol})])
        made = ssh(node.name, f'sudo -n btrfs subvolume show {node.subvol}/ch-sub >/dev/null && sudo -n btrfs subvolume show {snap} >/dev/null && sudo -n btrfs subvolume show {node.data}/lab-seed/shared/docs >/dev/null && echo yes').strip()
        if made != 'yes':
            raise AssertionError('a subvolume the plan reported is not there')
        want = seed_file(node.name, node.data)['sha256']
        if seed_hash(node.name, f'{node.data}/lab-seed/shared/docs/handbook.txt') != want:
            raise AssertionError('turning the folder into a subvolume changed a file')
        return 'subvolume, snapshot, folder to subvolume and scrub, files unchanged'
    def nocow(node):
        path = f'{node.subvol}/lab-nocow'
        btrfs_plan(api, f'btrfs nocow {node.name}', node, [('subvolume', {'path': path, 'nocow': True})])
        flags = ssh(node.name, f'sudo -n lsattr -d {path}').split()[0]
        if 'C' not in flags:
            raise AssertionError(f'attributes are {flags}')
        return f'{path} has no copy-on-write'
    for node in (n for n in hosts if n.subvol):
        r.check('btrfs-nocow', node.name, lambda node=node: nocow(node))
    for node in (n for n in hosts if n.subvol):
        r.check('btrfs-plan-tasks', node.name, lambda node=node: subvolumes(node))

    frm, to = roles.sender(), roles.receiver()
    state = {}

    def full_send():
        state['task'], _, _ = demo.btrfs_send(api)
        names = ssh(to.name, f'sudo -n ls {to.recv}').split()
        show = ssh(to.name, f'sudo -n btrfs subvolume show {to.recv}/{names[-1]}')
        if not re_uuid(show):
            raise AssertionError(f'the received snapshot has no received UUID: {show[:300]}')
        state['name'] = names[-1]
        return f'{names[-1]} is a received, read-only subvolume'
    r.check('btrfs-send-full', to.name, full_send)

    def incremental():
        before = set(ssh(to.name, f'sudo -n ls {to.recv}').split())
        time.sleep(61)
        big = 'lab-incremental.bin'
        ssh(frm.name, f'sudo -n sh -c "head -c 32M /dev/urandom >{frm.subvol}/{big}"')
        want = seed_hash(frm.name, f'{frm.subvol}/{big}')
        used = lambda: int(ssh(to.name, f'sudo -n btrfs filesystem du -s --raw {to.recv} | tail -1').split()[0])
        size_before = used()
        runs = demo.deploy(api, 'tasks', state['task'], 'btrfs incremental', run=True)
        new = sorted(set(ssh(to.name, f'sudo -n ls {to.recv}').split()) - before)
        if not new:
            raise AssertionError('no new snapshot arrived')
        if seed_hash(to.name, f'{to.recv}/{new[-1]}/{big}') != want:
            raise AssertionError('the new file has other bytes on the receiver')
        output = ' '.join(x.get('output') or '' for x in runs)
        grew = used() - size_before
        return f'{new[-1]} arrived; receiver grew {grew >> 20} MiB for a 32 MiB change; parent mentioned: {"-p " in output or "parent" in output}'
    if 'task' in state:
        r.check('btrfs-send-incremental', to.name, incremental)

    def interrupted():
        # what a broken receive leaves: a writable subvolume with the right name and no received UUID
        name = next(n for n in sorted(ssh(frm.name, f'sudo -n ls {frm.snaps}').split(), reverse=True) if n.startswith('daily-'))
        ssh(to.name, f'sudo -n sh -c "btrfs property set -f {to.recv}/{name} ro false; btrfs subvolume delete {to.recv}/{name} >/dev/null; btrfs subvolume create {to.recv}/{name} >/dev/null"')
        made = api.post('/api/tasks', {'name': 'Lab send only', 'host': frm.name, 'blocks': [
            {'type': 'btrfs_send', 'params': {'into': frm.snaps, 'prefix': 'daily', 'dst_host': to.name, 'dst': to.recv, 'keep': 0}}]})
        demo.deploy(api, 'tasks', made['id'], 'btrfs send after a broken receive', run=True)
        show = ssh(to.name, f'sudo -n btrfs subvolume show {to.recv}/{name}')
        if not re_uuid(show):
            raise AssertionError('the broken copy was left in place')
        return f'{name} was removed and sent again'
    if 'task' in state:
        r.check('btrfs-receive-interrupted', to.name, interrupted)

    def add_device(node):
        number = node.tag('btrfs-spare')
        device = ssh(node.name, f'for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = sflab-data{number} ] && echo /dev/${{d##*/}}; done').strip()
        mount = fs_mount(node, node.subvol)
        before = ssh(node.name, f'sudo -n btrfs filesystem show {mount}').count('devid')
        btrfs_plan(api, f'btrfs add device {node.name}', node, [('btrfs-add', {'target': mount, 'device': device, 'confirm': device})], destructive=True)
        after = ssh(node.name, f'sudo -n btrfs filesystem show {mount}').count('devid')
        if after != before + 1:
            raise AssertionError(f'{before} devices before, {after} after')
        return f'{device} joined the filesystem'
    for node in (n for n in hosts if n.tag('btrfs-spare') and n.subvol):
        r.check('btrfs-add-device', node.name, lambda node=node: add_device(node))

    def convert(node):
        mount = fs_mount(node, node.subvol)
        try:
            btrfs_plan(api, f'btrfs convert {node.name}', node, [('btrfs-balance', {'target': mount, 'data': 'raid1', 'metadata': 'raid1'})])
        except demo.DemoError as exc:         # too little room is a right answer, if the filesystem is still writable after it
            if 'not converted' not in str(exc):
                raise
            ssh(node.name, f'sudo -n touch {mount}/lab-still-writable && sudo -n rm {mount}/lab-still-writable')
            return 'refused for lack of unallocated space, and the filesystem stays writable'
        wait_for('the balance to end', lambda: 'No balance found' in ssh(node.name, f'sudo -n btrfs balance status {mount}', check=False), 300)
        out = ssh(node.name, f'sudo -n btrfs filesystem df {mount}').lower()
        data = [x for x in out.splitlines() if x.startswith(('data', 'metadata'))]
        if not all(', raid1:' in x for x in data):
            ended = ssh(node.name, "sudo -n journalctl -k -n 300 --no-pager -o cat | grep -E 'balance: ended|ENOSPC' | tail -2", check=False)
            raise AssertionError(f'{" / ".join(data)}; {ended.strip()[:160]}')
        demo.scan(api, [node.ip])
        text = json.dumps(api.get(f'/api/graph?host={node.name}')).lower()
        return f'converted to raid1, and the scan {"shows" if "raid1" in text else "does not show"} it'
    converted = [n for n in hosts if n.tag('btrfs-profile') in ('raid10', 'raid1c3')]
    for node in converted:
        r.check('btrfs-balance-convert', node.name, lambda node=node: convert(node))

    def has_alert(kind, text):
        return [a for a in alerts_now() if a['kind'].startswith(kind) and text in json.dumps(a)]

    # A full filesystem, then a read-only one, then a pulled disk: each host only once, last things last.
    healthy = [n for n in hosts if ' rw' in f' {ssh(n.name, "findmnt -n -o OPTIONS --target " + (n.subvol or n.recv)).replace(",", " ")}']
    filler = next((n for n in healthy if n.can('btrfs-raid')), None) or healthy[0]

    def full():
        path = f'{filler.fill}/lab-fill.bin'
        # df's available space moves as btrfs frees deleted subvolumes and allocates chunks, so one pass can stop short
        ssh(filler.name, f'''sudo -n sh -c 'for i in 1 2 3 4; do avail=$(df -m --output=avail {filler.fill} | tail -1); [ "$avail" -gt 96 ] || break; dd if=/dev/urandom of={path}.$i bs=1M count=$((avail - 64)) status=none; sync; btrfs filesystem sync {filler.fill} 2>/dev/null; done; true' ''')
        demo.scan(api, [filler.ip])
        got = has_alert('disk', filler.name)
        usage = ssh(filler.name, f'df -m {filler.fill} | tail -1').split()
        ssh(filler.name, f'sudo -n sh -c "rm -f {path}.*; sync"')
        if not got:
            raise AssertionError(f'no disk alert with {filler.fill} at {usage[4]} ({usage[2]} of {usage[1]} MB): {[a["title"] for a in alerts_now()]}')
        return got[0]['title']
    r.check('btrfs-disk-full', filler.name, full)

    def read_only():
        node = next(n for n in healthy if n.subvol)
        mount = fs_mount(node, node.subvol)
        # a task must report a filesystem it can't write to, not call it done
        ssh(node.name, f'sudo -n mount -o remount,ro {mount}')
        try:
            made = api.post('/api/tasks', {'name': 'Lab read-only', 'host': node.name, 'blocks': [
                {'type': 'btrfs_snapshot', 'params': {'subvol': node.subvol, 'into': node.subvol, 'prefix': 'ro'}}]})
            group = api.post('/api/deploy/start', {'kind': 'tasks', 'ref': made['id'], 'mode': 'apply', 'run': True, 'title': 'read-only'})['group']
            out = wait_for('the run', lambda: demo.finished(api, group), 120)
            if all(x['status'] == 'ok' for x in out['runs']):
                raise AssertionError('the run reported ok on a read-only filesystem')
            return out['runs'][0]['status']
        finally:
            ssh(node.name, f'sudo -n mount -o remount,rw {mount}')
    r.check('btrfs-read-only', next(n.name for n in healthy if n.subvol), read_only)

    def pulled(node):
        # not disk 1: systemd ties the mount to the device it was mounted from, and unmounts the pool when that goes
        mount = fs_mount(node, node.subvol or node.recv)
        lines = subprocess.run(['virsh', 'domblklist', node.name], capture_output=True, text=True).stdout.splitlines()
        disk = next(d.split()[0] for d in lines if f'{node.name}-data2' in d)
        subprocess.run(['virsh', '-q', 'detach-disk', node.name, disk, '--live'], check=True, capture_output=True)
        ssh(node.name, f'sudo -n sh -c "dd if=/dev/urandom of={mount}/lab-degraded bs=1M count=32 status=none; sync; /usr/local/lib/storageforge/health >/dev/null 2>&1 || true"', check=False)
        demo.scan(api, [node.ip])
        missing = 'missing' in ssh(node.name, f'sudo -n btrfs filesystem show {mount}').lower()
        titles = [a['title'] for a in alerts_now() if node.name in json.dumps(a)]
        wanted = [t for t in titles if 'missing' in t.lower() or 'error' in t.lower() or 'degraded' in t.lower()]
        if not wanted:
            raise AssertionError(f'no missing-device or error alert (btrfs says missing: {missing}): {titles}')
        return wanted[0]
    raid = [n for n in healthy if n.can('btrfs-raid') and n.name != filler.name] or [n for n in healthy if n.can('btrfs-raid')]
    if raid:
        r.check('btrfs-disk-pulled', raid[0].name, lambda: pulled(raid[0]))
    else:
        r.add('btrfs-disk-pulled', '-', None, 'no btrfs raid host in this build')


def re_uuid(show):
    m = re.search(r'Received UUID:\s*(\S+)', show)
    return bool(m) and m.group(1) != '-'


def tier6(r):
    """The sync engine on real hosts: real ssh and the chrooted daemon, root btrfs and zfs. The overlays themselves are not
    here: a second address on the source stands in for a mesh address, which is all the job can see of one."""
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    root = lambda vm, command: ssh(vm, f'sudo -n bash -c {shlex.quote(command)}')   # noqa: E731
    deployable = roles.deployable()
    source, runner = deployable[0], roles.other_than(deployable[0])
    base = f'{source.room}/sync6'

    def job(name, method, src_node, src, dst_node, dst, **options):
        plan = api.post('/api/moves', {'name': name, 'steps': [{'method': method, 'src': {'host': src_node.name, 'path': src},
                                       'dst': {'host': dst_node.name, 'path': dst}, 'options': {'schedule': 'daily', **options}}]})
        demo.deploy(api, 'jobs', plan['id'], name)
        return f'p{plan["id"]}-{plan["steps"][0]["id"]}'

    def run(jid, node, verb='run', kind='run'):
        return job_run(api, jid, verb, kind, int(ssh(node.name, 'date +%s')))

    def run_fails(jid, node):
        since = int(ssh(node.name, 'date +%s'))
        api.post(f'/api/deploy/jobs/{jid}/run')

        def done():
            got = [x for x in api.get(f'/api/deploy/jobs/{jid}')['runs'] if x['kind'] == 'run' and x['start'] >= since - 5]
            return got[0] if got else None
        return wait_for(f'{jid} run', done, 300)

    def state(jid, node):
        return json.loads(root(node.name, f'cat /var/lib/storageforge/jobs/{jid}/state.json'))

    def digest(node, path):
        return root(node.name, f'sha256sum {shlex.quote(path)}').split()[0]

    def nic(node):
        return ssh(node.name, 'ip -4 route show default').split(' dev ')[1].split()[0]

    def dedup_across():
        src, dst = f'{base}/dedup-src', f'{runner.room}/sync6-dedup'
        root(source.name, f'mkdir -p {src}/sub; head -c 8000000 /dev/urandom >{src}/sub/new-name.bin')
        same = root(source.name, f'base64 {src}/sub/new-name.bin')
        root(runner.name, f'mkdir -p {dst}')
        ssh(runner.name, f'sudo -n bash -c "base64 -d >{dst}/old-name.bin"', stdin=same)
        jid = job('Lab sync dedup', 'mirror', source, src, runner, dst, dedup=True)
        got = run(jid, runner)
        if 'dedup kept 8000000' not in (got['message'] or ''):
            raise AssertionError(f'the file went over the network: {got["message"]}')
        if digest(runner, f'{dst}/sub/new-name.bin') != digest(source, f'{src}/sub/new-name.bin'):
            raise AssertionError('other bytes at the destination')
        run(jid, runner, 'verify', 'verify')
        return got['message']
    r.check('sync-dedup', runner.name, dedup_across)

    def reflink():
        node = next((n for n in roles.having('btrfs') if n.recv), None)
        if not node:
            return 'no btrfs host'
        area = f'{node.recv}/sync6-reflink'
        root(node.name, f'mkdir -p {area}/a; head -c 5000000 /dev/urandom >{area}/a/f')
        got = run(job('Lab sync reflink', 'copy', node, f'{area}/a', node, f'{area}/b', dedup=True), node)
        if 'dedup kept 5000000' not in (got['message'] or ''):
            raise AssertionError(got['message'])
        shared = root(node.name, f'btrfs filesystem du -s --raw {area}').splitlines()[1].split()[2]
        if int(shared) < 5000000:
            raise AssertionError(f'{shared} bytes shared: it was copied, not cloned')
        return f'{shared} bytes shared'
    r.check('sync-reflink', 'btrfs', reflink)

    def routes_and_failover():
        """Two addresses on the source; the first goes away while a limited transfer runs."""
        dev = nic(source)
        spare = source.ip.rsplit('.', 1)[0] + '.211'
        root(source.name, f'ip addr add {spare}/24 dev {dev}')
        src, dst = f'{base}/route-src', f'{runner.room}/sync6-route'
        root(source.name, f'mkdir -p {src}; head -c 100000000 /dev/urandom >{src}/big.bin')
        try:
            jid = job('Lab sync routes', 'mirror', source, src, runner, dst, bwlimit=2000, routes=[
                {'via': 'mesh', 'address': spare}, {'via': 'mesh', 'address': source.ip, 'iface': nic(runner)}])
            if 'storageforge-source' not in root(runner.name, f'cat /etc/storageforge/jobs/{jid}.hostkey'):
                raise AssertionError('no pinned key reached the runner')
            since = int(ssh(runner.name, 'date +%s'))
            api.post(f'/api/deploy/jobs/{jid}/run')
            wait_for('the transfer to start', lambda: root(runner.name, f'grep -q transferring /var/lib/storageforge/jobs/{jid}/state.json && echo y; true').strip(), 120)
            time.sleep(10)
            first = state(jid, runner)
            if first['node'] != spare:
                raise AssertionError(f'did not start on the first route: {first}')
            locked = ssh(runner.name, f'sudo -n env LOCK_WAIT=0 /usr/local/sbin/storageforge-job with-lock {dst} -- true; echo rc=$?', check=False)
            if 'rc=75' not in locked:
                raise AssertionError(f'a rotation could have run during a sync stream: {locked[-200:]}')
            root(source.name, f'ip addr del {spare}/24 dev {dev}')

            def done():
                got = [x for x in api.get(f'/api/deploy/jobs/{jid}')['runs'] if x['kind'] == 'run' and x['start'] >= since - 5]
                return got[0] if got else None
            got = wait_for('the run to finish', done, 500)
            if got['rc'] != 0:
                raise AssertionError(f'rc {got["rc"]}: {got["message"]}')
            end = state(jid, runner)
            if end['node'] != source.ip:
                raise AssertionError(f'finished on {end["node"]}')
            if digest(runner, f'{dst}/big.bin') != digest(source, f'{src}/big.bin'):
                raise AssertionError('other bytes after the failover')
            live = next(j for j in api.get('/api/deploy')['jobs'] if j['id'] == jid).get('live') or {}
            return f'moved to {end["node"]} mid-run, same bytes, API shows {live.get("state")}'
        finally:
            root(source.name, f'ip addr del {spare}/24 dev {dev} 2>/dev/null; true')
    r.check('sync-failover', runner.name, routes_and_failover)

    def room_check(node, area):
        def check():
            root(node.name, f'mkdir -p {area}/src; echo x >{area}/src/f')
            no = job(f'Lab sync no room {node.name}', 'copy', node, f'{area}/src', node, f'{area}/no', preflight=True, reserve_gb=100000)
            got = run_fails(no, node)
            if got['rc'] != 6:
                raise AssertionError(f'rc {got["rc"]}: {got["message"]}')
            if root(node.name, f'ls {area}/no 2>/dev/null; true').strip():
                raise AssertionError('it copied anyway')
            run(job(f'Lab sync room {node.name}', 'copy', node, f'{area}/src', node, f'{area}/yes', preflight=True, reserve_gb=0), node)
            return got['message'][:120]
        return check
    for node in [next(iter(roles.having('btrfs')), None), next(iter(roles.having('zfs')), None), next((n for n in deployable if not n.can('btrfs') and not n.can('zfs')), None)]:
        if node:
            r.check('sync-room', node.name, room_check(node, f'{node.room}/sync6-room'))

    def btrfs_stream():
        frm, to = roles.sender(), roles.receiver()
        dst = f'{to.recv}/sync6-stream'
        root(frm.name, f'echo one >{frm.subvol}/sync6-marker')
        jid = job('Lab sync btrfs', 'mirror', frm, frm.subvol, to, dst, transport='btrfs', preflight=True, reserve_gb=0)
        first = run(jid, to)
        if root(to.name, f'cat {dst}/latest/sync6-marker').strip() != 'one':
            raise AssertionError('the first stream did not arrive')
        root(frm.name, f'echo two >{frm.subvol}/sync6-marker')
        time.sleep(7)                      # job_run takes any run since 5 seconds ago
        second = run(jid, to)
        if 'incremental' not in second['message']:
            raise AssertionError(f'not incremental: {second["message"]}')
        if root(to.name, f'cat {dst}/latest/sync6-marker').strip() != 'two':
            raise AssertionError('the second stream did not arrive')
        if second['bytes'] >= max(first['bytes'], 1):
            raise AssertionError(f'incremental sent {second["bytes"]}, the full one {first["bytes"]}')
        if len(root(to.name, f'ls {dst}/.storageforge-stream').split()) != 1:
            raise AssertionError('older copies were left on the receiver')
        kept = root(frm.name, f'ls {frm.subvol}/.storageforge-snap/stream-{jid}').split()
        if len(kept) != 1:
            raise AssertionError(f'source snapshots left: {kept}')
        if 'true' not in root(to.name, f'btrfs property get -ts {dst}/latest/ ro'):
            raise AssertionError('the copy is writable')
        run(jid, to, 'verify', 'verify')
        return f'full {first["bytes"]} bytes, incremental {second["bytes"]}'
    if len(roles.having('btrfs')) > 1:
        r.check('sync-btrfs-stream', roles.receiver().name, btrfs_stream)

    def inner_refused():
        frm, to = roles.sender(), roles.receiver()
        root(frm.name, f'mkdir -p {frm.subvol}/sync6-inner')
        got = run_fails(job('Lab sync inner', 'mirror', frm, f'{frm.subvol}/sync6-inner', to, f'{to.recv}/sync6-inner', transport='btrfs'), to)
        if got['rc'] == 0:
            raise AssertionError('a folder inside a subvolume was sent as the whole subvolume')
        return got['message'][:100]
    if len(roles.having('btrfs')) > 1:
        r.check('sync-btrfs-inner', roles.sender().name, inner_refused)

    pools = roles.having('zfs')

    def zfs_stream():
        frm, to = pools[0], pools[1]
        a, b = frm.tag('zfs-pool'), to.tag('zfs-pool')
        src, dst = f'/{a}/sf6', f'/{b}/sf6'
        root(frm.name, f'zfs create -o mountpoint={src} {a}/sf6; echo one >{src}/marker')
        root(to.name, f'zfs create -o mountpoint={dst} {b}/sf6')
        jid = job('Lab sync zfs', 'mirror', frm, src, to, dst, transport='zfs', preflight=True, reserve_gb=0)
        first = run(jid, to)
        root(frm.name, f'echo two >{src}/marker')
        time.sleep(7)                      # job_run takes any run since 5 seconds ago
        second = run(jid, to)
        if 'incremental' not in second['message']:
            raise AssertionError(f'not incremental: {second["message"]}')
        target = f'{b}/sf6/sf-{jid}'
        here = root(to.name, f'zfs list -H -t snapshot -d 1 -o name {target}').split()
        there = root(frm.name, f'zfs list -H -t snapshot -d 1 -o name {a}/sf6').split()
        if len(here) != 1 or len(there) != 1 or here[0].split('@')[1] != there[0].split('@')[1]:
            raise AssertionError(f'snapshots: {here} and {there}')
        guid = lambda vm, snap: root(vm, f'zfs get -Hp -o value guid {snap}').strip()   # noqa: E731
        if guid(to.name, here[0]) != guid(frm.name, there[0]):
            raise AssertionError('the guids differ')
        if root(to.name, f'zfs get -H -o value mounted {target}').strip() != 'no':
            raise AssertionError('the copy was mounted over a folder')
        run(jid, to, 'verify', 'verify')
        root(to.name, f'zfs set mountpoint=/mnt/sf6check {target}; zfs mount {target}')
        text = root(to.name, 'cat /mnt/sf6check/marker').strip()
        if text != 'two':
            raise AssertionError(f'the copy reads {text}')
        return f'full {first["bytes"]} bytes, incremental {second["bytes"]}, guids match'
    if len(pools) > 1:
        r.check('sync-zfs-stream', pools[1].name, zfs_stream)
    else:
        r.add('sync-zfs-stream', pools[0].name if pools else '-', None, 'needs two ZFS hosts in this build')

    def duperemove():
        node = next(n for n in roles.having('btrfs') if n.recv and n.pm != 'none')
        area = f'{node.recv}/sync6-dupes'
        root(node.name, f'mkdir -p {area}/src; head -c 4000000 /dev/urandom >{area}/src/a; cp --reflink=never {area}/src/a {area}/src/b')
        jid = job('Lab sync duperemove', 'copy', node, f'{area}/src', node, f'{area}/dst', extent_dedup='weekly')
        run(jid, node)
        before = root(node.name, f'btrfs filesystem du -s --raw {area}/dst').splitlines()[1].split()
        got = run(jid, node, 'dedupe', 'dedupe')
        after = root(node.name, f'btrfs filesystem du -s --raw {area}/dst').splitlines()[1].split()
        if int(after[1]) + int(after[2]) > 4500000:
            raise AssertionError(f'still taking {after}, was {before}: {got["message"]}')
        if not 3000000 <= int(got['bytes'] or 0) <= 4500000:
            raise AssertionError(f'reported {got["bytes"]} bytes freed, from {before} to {after}')
        return f'{before[1:3]} to {after[1:3]}: {got["message"]}'
    if roles.having('btrfs'):
        r.check('sync-duperemove', roles.having('btrfs')[0].name, duperemove)


def tier7(r):
    """Hosts the server cannot dial: each VM drops SSH from sf-ctl, so all that works here came through its own tunnel."""
    remote_compose = f'{COMPOSE} -f docker-compose.remote.yml'
    ssh('sf-ctl', f'{remote_compose} up -d --no-build --wait --quiet-pull')
    ctl = BUILD['sf-ctl']
    api = demo.sign_in()
    root = lambda vm, command, check=True: ssh(vm, f'sudo -n bash -c {shlex.quote(command)}', check=check)   # noqa: E731
    in_app = lambda code: ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(code)}')      # noqa: E731
    nodes = [roles.deployable()[0], roles.deployable()[-1]]

    def container():
        info = ssh('sf-ctl', "sudo -n docker inspect --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' storageforge-tunnel-1").strip()
        if info != '10002:10002 true [ALL]':
            raise AssertionError(info)
        ports = ssh('sf-ctl', "sudo -n docker ps --format '{{.Names}} {{.Ports}}'")
        if '2222->2222' not in ports:
            raise AssertionError(ports)
        return info
    r.check('tunnel-container', 'sf-ctl', container)

    def block(node):
        rule = (f'nft add table inet sfblock; nft add chain inet sfblock gate "{{ type filter hook input priority -10; }}"; '
                f'nft add rule inet sfblock gate ip saddr {ctl.ip} tcp dport 22 drop')
        root(node.name, 'command -v nft >/dev/null || command -v iptables >/dev/null || dnf -y -q install nftables')
        root(node.name, f'if command -v nft >/dev/null; then {rule}; else iptables -I INPUT -s {ctl.ip} -p tcp --dport 22 -j DROP; fi')
        if ssh('sf-ctl', f"timeout 4 bash -c 'exec 3<>/dev/tcp/{node.ip}/22' && echo open || echo closed").strip() != 'closed':
            raise AssertionError('the server can still dial it')

    for node in nodes:
        made = {}

        def install(node=node, made=made):
            block(node)
            made.update(api.post('/api/remote/nodes', {'name': node.name.removeprefix('sf-'), 'endpoint': f'{ctl.ip}:2222'}))
            ssh(node.name, 'cat >/tmp/sf-remote.sh', stdin=made['script'])
            report = root(node.name, 'bash /tmp/sf-remote.sh')
            if 'report only' not in report or root(node.name, 'systemctl is-enabled storageforge-remote 2>/dev/null; true').strip() == 'enabled':
                raise AssertionError(f'the report changed something, or found a problem: {report[-300:]}')
            root(node.name, 'bash /tmp/sf-remote.sh --apply')
            wait_for('the tunnel', lambda: next((n for n in api.get('/api/remote/nodes')['nodes'] if n['id'] == made['id'] and n['online']), None), 120)
            return f'{made["address"]}, dialled out past its firewall'
        r.check('remote-install', node.name, install)
        if not made:
            continue

        def adopt(node=node, made=made):
            def step():
                out = api.post(f'/api/remote/nodes/{made["id"]}/adopt')
                return out if out['state'] != 'scanning' else None
            out = wait_for('the scan and signed run', step, 400)
            if out['state'] != 'ready':
                raise AssertionError(out)
            shown = [h for h in api.get('/api/hosts')['indexed'] if h['hostname'].split('.')[0] == node.name]
            if not shown or not any(a['host'] == out['host'] and a['state'] == 'ready' for a in api.get('/api/deploy')['access']):
                raise AssertionError(f'not indexed or not deployable: {shown}')
            return f'scanned through the tunnel, signed run works: {out["host"]}'
        r.check('remote-adopt', node.name, adopt)

        def job(node=node):
            area = f'{node.room}/remote7'
            root(node.name, f'mkdir -p {area}/a; head -c 200000 /dev/urandom >{area}/a/f')
            plan = api.post('/api/moves', {'name': f'Lab remote {node.name}', 'steps': [{'method': 'copy', 'src': {'host': node.name, 'path': f'{area}/a'},
                                           'dst': {'host': node.name, 'path': f'{area}/b'}, 'options': {'schedule': 'daily'}}]})
            demo.deploy(api, 'jobs', plan['id'], f'Lab remote {node.name}')
            job_run(api, f'p{plan["id"]}-{plan["steps"][0]["id"]}', 'run', 'run', int(ssh(node.name, 'date +%s')))
            if seed_hash(node.name, f'{area}/b/f') != seed_hash(node.name, f'{area}/a/f'):
                raise AssertionError('other bytes')
            return 'deployed and ran a job through the tunnel'
        r.check('remote-deploy', node.name, job)

        def stolen(node=node, made=made):
            base = f"ssh -F /dev/null -i /etc/storageforge/remote/key -p 2222 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/storageforge/remote/known_hosts -o ConnectTimeout=10"
            login = f'sftunnel@{ctl.ip}'
            bad = {'command': f'{base} {login} id; echo rc=$?',
                   'other address': f'timeout 10 {base} -N -o ExitOnForwardFailure=yes -R 127.77.200.200:10022:127.0.0.1:22 {login}; echo rc=$?',
                   'the app port': f'timeout 10 {base} -N -o ExitOnForwardFailure=yes -R 127.0.0.1:8081:127.0.0.1:22 {login}; echo rc=$?',
                   'every interface': f'timeout 10 {base} -N -o ExitOnForwardFailure=yes -R 0.0.0.0:10022:127.0.0.1:22 {login}; echo rc=$?'}
            for what, command in bad.items():
                out = root(node.name, command + ' 2>&1', check=False)
                if 'uid=' in out or 'rc=124' in out or 'rc=0' in out:
                    raise AssertionError(f'{what} worked: {out[-200:]}')
            out = root(node.name, f'timeout 12 {base} -N -L 127.0.0.1:18080:127.0.0.1:8080 {login} & sleep 4; curl -s -m 3 http://127.0.0.1:18080/healthz; echo end; kill %1 2>/dev/null; true', check=False)
            if 'ok' in out.split('end')[0].lower():
                raise AssertionError(f'reached the app through the tunnel: {out[-200:]}')
            return 'no command, no other address, no way back into the server'
        r.check('remote-stolen-key', node.name, stolen)

        def reconnects(node=node, made=made):
            root(node.name, 'systemctl kill -s KILL storageforge-remote')
            time.sleep(2)
            wait_for('the tunnel back', lambda: next((n for n in api.get('/api/remote/nodes')['nodes'] if n['id'] == made['id'] and n['online']), None), 150)
            return 'came back by itself'
        r.check('remote-reconnect', node.name, reconnects)

        def revoke(node=node, made=made):
            api('DELETE', f'/api/remote/nodes/{made["id"]}')
            probe = ("import socket\ntry:\n  s = socket.create_connection((%r, 10022), 2); print(s.recv(4))\nexcept OSError as e: print('closed')" % made['address'])

            def gone():
                return 'closed' in in_app(probe) or None
            wait_for('the tunnel to drop', gone, 60)
            time.sleep(25)                  # the node retries every 15 seconds, and must not get back in
            if 'closed' not in in_app(probe):
                raise AssertionError('it came back after being revoked')
            root(node.name, 'bash /tmp/sf-remote.sh --remove; rm -f /tmp/sf-remote.sh')
            left = root(node.name, 'ls /etc/storageforge/remote /etc/systemd/system/storageforge-remote.service /usr/local/sbin/storageforge-remote 2>/dev/null; id sfscan 2>/dev/null; id storageforge-remote 2>/dev/null; true').strip()
            if left:
                raise AssertionError(f'left behind: {left}')
            return 'cut off at once, stayed out, and the script took itself off'
        r.check('remote-revoke', node.name, revoke)


def tier8(r):
    """Proxmox, TrueNAS and XCP-ng through the real scanner, as an ordinary user, and what that means for deploys."""
    from storageforge_index import preflight
    from storageforge_index.db import loads
    appliances = roles.having('appliance')
    if not appliances:
        r.add('appliances', '-', None, 'none in this build: use up --pick')
        return
    tmp = tempfile.mkdtemp(prefix='sflab-tier8-')
    db = f'{tmp}/index.db'
    key = str(STATE / 'id_ed25519')

    def cli_access():
        return subprocess.run([sys.executable, '-m', 'storageforge_index', '--db', db, 'access', 'script', '--user', 'scan'],
                              cwd=ROOT, capture_output=True, text=True, timeout=60, check=True).stdout

    def scan(node, partial=False):
        argv = [sys.executable, '-m', 'storageforge_index', '--db', db, 'scan', '--host', node.ip, '--user', 'scan', '--key', key,
                '--ssh-option', f'UserKnownHostsFile={tmp}/known_hosts', '--json']
        out = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=600)
        if out.returncode and not partial:
            raise AssertionError(out.stdout[-800:] + out.stderr[-800:])
        return out.stdout

    def inventory(node):
        rows = sqlite3.connect(db).execute('SELECT inventory_json FROM hosts WHERE ssh_host = ? OR hostname LIKE ?', (node.ip, f'{node.name}%')).fetchall()
        return loads(rows[0][0])

    def facts(node):
        conn = sqlite3.connect(db)
        wrapper = type('C', (), {'all': lambda self, q, p: conn.execute('SELECT inventory_json FROM hosts WHERE ssh_host = ? OR hostname LIKE ?', (node.ip, f'{node.name}%')).fetchall()})()
        return preflight.facts_from_scan(wrapper, node.name)

    for node in appliances:
        kind = next(a for a in ('proxmox', 'truenas', 'xen') if node.can(a))

        def scanned(node=node, kind=kind):
            if kind == 'xen':      # attached late in boot, and a scan before that would miss it without saying so
                wait_for('the storage repository', lambda: 'sr-mount' in ssh(node.name, 'findmnt -l -o TARGET'), timeout=300)
                got = scan(node, partial=True)
                assert '"status": "partial"' in got, f'/run/sr-mount is root-only, yet: {got[-200:]}'
                install = cli_access()
                ssh_in = subprocess.run(['ssh', '-i', key, '-o', 'BatchMode=yes', '-o', f'UserKnownHostsFile={tmp}/known_hosts', '-o', 'StrictHostKeyChecking=accept-new',
                                         f'lab@{node.ip}', 'sudo -n sh -s -- --apply'], input=install, capture_output=True, text=True, timeout=120)
                assert not ssh_in.returncode, ssh_in.stdout[-400:] + ssh_in.stderr[-400:]
            return scan(node).strip().splitlines()[-1][:120]
        r.check('scan', node.name, scanned)

        def platform(node=node, kind=kind):
            got = facts(node).get('platform', '')
            assert got.startswith('xcp-ng ' if kind == 'xen' else kind + ' '), f'platform is {got!r}'
            return got
        r.check('platform', node.name, platform)

        def verdict(node=node, kind=kind):
            items = preflight.findings(facts(node))
            blocked = [i['text'] for i in items if i['level'] == 'crit']
            if kind == 'proxmox':
                assert not blocked, blocked
                return 'deploys allowed'
            assert any('nothing can be deployed' in t for t in blocked), blocked
            return 'deploys refused, with the reason'
        r.check('deploy-verdict', node.name, verdict)

        if node.tag('zfs-pool'):
            def pool(node=node):
                status = inventory(node)['zpool_status']
                assert f'pool: {node.tag("zfs-pool")}' in status, f'zpool status as scan: {status[:200]!r}'
            r.check('zfs-pool-seen', node.name, pool)

        if node.data:
            def seeded(node=node):
                seen = sqlite3.connect(db).execute("SELECT count(*) FROM mounts WHERE mount_point = ? AND scan_state = 'indexed'", (node.data,)).fetchone()[0]
                assert seen, f'{node.data} is not among the scanned mounts'
            r.check('data-indexed', node.name, seeded)

        def mounts(node=node, kind=kind):
            have = [row[0] for row in sqlite3.connect(db).execute("SELECT mount_point FROM mounts WHERE scan_state = 'indexed'")]
            if kind == 'proxmox':
                assert '/etc/pve' not in have, 'the cluster filesystem was indexed'
            if kind == 'xen':
                assert any(t.startswith('/run/sr-mount/') for t in have), f'no storage repository among {have}'
        r.check('mounts', node.name, mounts)

        if kind == 'truenas':
            def read_only(node=node):      # why deploys are refused: if a release changes this, the refusal needs another look
                out = ssh(node.name, 'sudo -n touch /usr/sflab-test 2>&1 || true; sudo -n apt-get --version 2>&1 | head -1')
                assert 'Read-only' in out and 'disabled' in out, out
            r.check('appliance-locked', node.name, read_only)
    shutil.rmtree(tmp, ignore_errors=True)


def tier0(r):
    p = subprocess.run([sys.executable, '-m', 'unittest', 'test_tier0', '-v'], cwd=Path(__file__).parent, capture_output=True, text=True, timeout=600)
    failed = set(re.findall(r'^(?:FAIL|ERROR): (\w+)', p.stderr, re.M))
    for name, end in re.findall(r'^(test_\w+) \(.*?\)(?: \.\.\. (ok|skipped.*|FAIL|ERROR))?$', p.stderr, re.M):
        ok = None if end.startswith('skipped') else name not in failed
        r.add(name.removeprefix('test_'), '-', ok, '', p.stderr[-2000:] if not ok and ok is not None else '')
    # a skip is a check that didn't happen: with a lab up, all of them skipping is a broken tier, and must not look like a quiet one
    ran = len(re.findall(r' \.\.\. (?:ok|FAIL|ERROR)$', p.stderr, re.M))
    r.add('tier0-ran', '-', ran > 0, f'{ran} checks ran' if ran else 'every check skipped: is every VM of the build answering?')


# ── report ──────────────────────────────────────────────────────────
TIERS = {0: 'Smoke', 1: 'Scan', 2: 'Deploy', 3: 'Cross-host', 4: 'Failure', 5: 'Btrfs', 6: 'Sync engine', 7: 'Remote nodes', 8: 'Appliances', 9: 'Security', 10: 'Infrastructure', 11: 'Changes', 12: 'Network appliances', 13: 'Features', 16: 'Sends'}
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
    lines = [f'# KVM lab results {stamp}', '', f'Build `{roles.seed()}`: {", ".join(VMS)}. Rebuild it with `lab.sh up ' + (f'--pick {",".join(VMS)}' if roles.seed() == 'pick' else f'--seed {roles.seed()}') + '`.', '', f'Commit `{commit}`{" with uncommitted changes" if dirty else ""}. '
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
        if tier == 16:
            import tiers_sends
            tiers_sends.tier16(r)
        elif tier == 13:
            import tiers_features
            tiers_features.tier13(r)
        elif tier == 12:
            import tiers_network
            tiers_network.tier12(r)
        elif tier >= 9:
            import tiers_platform     # it imports this file for its helpers, so it comes in here and not at the top
            getattr(tiers_platform, f'tier{tier}')(r)
        else:
            {0: tier0, 1: tier1, 3: tier3, 4: tier4, 5: tier5, 6: tier6, 7: tier7, 8: tier8}[tier](r)
    except Exception as exc:
        r.add('tier-setup', '-', False, f'{type(exc).__name__}: {str(exc)[:170]}', traceback.format_exc())
    return 0 if r.save() else 1


if __name__ == '__main__':
    sys.exit(main())
