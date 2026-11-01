#!/usr/bin/env python3
"""Tier 2: every deploy path, for real, on every lab VM. It changes the VMs, so run it through examples/lab/lab.sh gauntlet,
which starts from the golden snapshot and goes back to it afterwards.

StorageForge runs here on the libvirt host, on a throwaway database, and drives the same functions the web API does:
scan, scan access, deploy access, shares, jobs, changes, storage tasks, drift, removal. Results are checked on the VMs
themselves and against the seed manifests, never against what StorageForge reports about its own work.

    gauntlet.py [--only stage,stage] [--keep] [--json file]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
LAB_DIR = ROOT / 'examples' / 'lab'
LAB = str(LAB_DIR / 'lab.sh')
STATE = Path(os.environ.get('SFLAB_STATE', Path.home() / '.local' / 'state' / 'sflab'))
ACTOR = 'gauntlet'
STAGES = ('scan', 'scan-access', 'deploy-access', 'doctor', 'shares', 'jobs', 'changes', 'tasks', 'drift', 'engine', 'remove')
# Deploys can't run on Alpine: it has no bash, systemd or known package manager. It must say so instead of breaking.

work = Path(tempfile.mkdtemp(prefix='sf-gauntlet-', dir=os.environ.get('XDG_RUNTIME_DIR')))
os.environ.update(STORAGEFORGE_DATA_DIR=str(work / 'data'), STORAGEFORGE_RUNTIME_DIR=str(work),
                  STORAGEFORGE_VAULT_SECRET='lab gauntlet secret, thrown away with its database',
                  PATH=f'{Path(sys.executable).parent}:{os.environ["PATH"]}')

from storageforge_index import access, alerts, changes, deploy, hostkeys, jobs, moves, shares, tasks, vault  # noqa: E402
from storageforge_index.db import Database  # noqa: E402
from storageforge_index.remote import known_host_keys  # noqa: E402
from storageforge_index.runner import known_hosts_path, scan_via_vault  # noqa: E402
from storageforge_index.scanner import ScanOptions  # noqa: E402

vault.KDF_DEFAULTS = {'time_cost': 1, 'memory_kib': 8192, 'lanes': 1}


def conf(path):
    rows = (LAB_DIR / path).read_text().splitlines()
    return [r.split('|') for r in rows if r.strip() and not r.startswith('#')]


sys.path.insert(0, str(LAB_DIR))
import roles  # noqa: E402

BUILD = roles.build()
NODES = {n.name: n.ip for n in BUILD.values()}
VMS = list(NODES)
HOSTS = roles.deployable()          # takes hosts in order, each passing data to the next
UNSUPPORTED = {n.name for n in roles.having('nosystemd')}


def after(i):
    return HOSTS[(i + 1) % len(HOSTS)]
PASSWORD = (STATE / 'admin-password').read_text().strip() if (STATE / 'admin-password').exists() else ''


def raw(vm, command, timeout=300, stdin=b''):
    return subprocess.run([LAB, 'ssh', vm, command], input=stdin, capture_output=True, timeout=timeout)


def sh(vm, command, timeout=300):
    p = raw(vm, command, timeout)
    if p.returncode:
        raise AssertionError(f'{vm}: {command[:120]}: exit {p.returncode}: {p.stderr.decode(errors="replace")[-300:]}')
    return p.stdout.decode(errors='surrogateescape')


def manifest(vm, root):
    return json.loads((STATE / 'manifests' / f'{vm}{root.replace("/", "_")}.json').read_text())


def same_as_manifest(vm, path, m, modes=True):
    """Every entry of a seed manifest is at path on vm, with the same bytes, type, target and (full copies) mode."""
    q = shlex.quote(path)
    listing = raw(vm, f"sudo -n find {q} -mindepth 1 -not -path '*/.storageforge-snap*' -printf '%P\\0%y\\0%s\\0%m\\0%l\\0%i\\0'")
    if listing.returncode:
        return f'cannot list {path}: {listing.stderr.decode(errors="replace")[-200:]}'
    parts = listing.stdout.split(b'\0')[:-1]
    found = {os.fsdecode(parts[i]): parts[i + 1:i + 6] for i in range(0, len(parts), 6)}
    bad, inode = [], {}
    for e in m['entries']:
        got = found.get(e['path'])
        if got is None:
            bad.append(f'missing {e["path"]!r}')
            continue
        kind, size, mode, link, ino = got
        inode[e['path']] = ino
        if kind.decode() != e['type']:
            bad.append(f'{e["path"]!r} is {kind.decode()}, wanted {e["type"]}')
        if e['type'] == 'l' and os.fsdecode(link) != e['target']:
            bad.append(f'{e["path"]!r} points at {link!r}')
        if e['type'] == 'f' and int(size) != e['size']:
            bad.append(f'{e["path"]!r} is {int(size)} bytes')
        if modes and e['type'] != 'l' and int(mode, 8) != e['mode']:
            bad.append(f'{e["path"]!r} has mode {mode.decode()}')
    for e in m['entries']:
        if e.get('hardlink') and e['path'] in inode and inode[e['path']] != inode.get(e['hardlink']):
            bad.append(f'{e["path"]!r} is no longer a hardlink')
    p = raw(vm, f'cd {q} && sudo -n find . -type f -size -512M -not -path "./.storageforge-snap*" -print0 | sudo -n xargs -0 sha256sum -z')
    sums = {}
    for row in p.stdout.split(b'\0')[:-1]:
        digest, name = row.split(b'  ', 1)
        sums[os.fsdecode(name).removeprefix('./')] = digest.decode()
    for e in m['entries']:
        if e['type'] == 'f' and not e.get('sparse') and e['path'] in found and sums.get(e['path']) != e['sha256']:
            bad.append(f'{e["path"]!r} has other bytes')
    return '; '.join(bad[:6]) + (f' … {len(bad)} in all' if len(bad) > 6 else '') if bad else None


class Results:
    def __init__(self):
        self.rows = []

    def add(self, stage, host, ok, note='', detail=''):
        status = {True: 'pass', False: 'FAIL', None: 'skip'}[ok]
        self.rows.append({'stage': stage, 'host': host, 'status': status, 'note': note, 'detail': detail[-4000:]})
        print(f'  {status:4} {stage:14} {host:10} {note}'[:220], flush=True)
        if detail and ok is False:
            for line in detail.strip().splitlines()[-12:]:
                print(f'       | {line}'[:220], flush=True)

    def check(self, stage, host, fn):
        try:
            got = fn()
        except Exception as exc:
            self.add(stage, host, False, f'{type(exc).__name__}: {str(exc)[:160]}', traceback.format_exc())
            return None
        return got

    def matrix(self):
        stages = list(dict.fromkeys(r['stage'] for r in self.rows))
        print('\n' + ' ' * 14 + ''.join(f'{v[:10]:11}' for v in VMS))
        for s in stages:
            cells = []
            for v in VMS:
                got = [r['status'] for r in self.rows if r['stage'] == s and r['host'] == v]
                cells.append('FAIL' if 'FAIL' in got else 'pass' if 'pass' in got else 'skip' if got else '·')
            print(f'{s:14}' + ''.join(f'{c:11}' for c in cells))
        fails = [r for r in self.rows if r['status'] == 'FAIL']
        print(f'\n{len(fails)} failed, {sum(r["status"] == "pass" for r in self.rows)} passed, '
              f'{sum(r["status"] == "skip" for r in self.rows)} skipped')
        return not fails


R = Results()
db = Database(str(work / 'idx.db'))
main_conn = db.connect()
db.migrate(main_conn)
NAME: dict[str, str] = {}
READY: set[str] = set()


def wait_group(gid, timeout=1800):
    conn = db.connect()
    try:
        end = time.time() + timeout
        while time.time() < end:
            runs = deploy.group(conn, gid)
            if runs and all(r['status'] not in ('running', 'queued') for r in runs):
                return runs
            time.sleep(1)
        raise TimeoutError(f'deploy group {gid} still running after {timeout} s')
    finally:
        conn.close()


def execute(items, mode):
    return wait_group(deploy.start_group(db, items, ACTOR, stop_on_failure=mode == 'apply'))


def report_runs(stage, runs, want=('ok',), hosts=None):
    """One result per run. want: the statuses that pass."""
    good = True
    for r in runs:
        if hosts is not None and r['host'] not in hosts:
            continue
        ok = r['status'] in want
        good &= ok
        R.add(stage, r['host'], ok, f'{r["kind"]} {r["mode"]}: {r["status"]}', r['output'] or '')
    return good


# ── scan ────────────────────────────────────────────────────────────
def stage_scan():
    vault.Vault(db, main_conn, vault.secret_from_env()).init()
    with vault.Vault(db, main_conn).unlock() as v:
        v.generate_key('lab-scan', comment='gauntlet')
        v.generate_key('lab-admin', comment='gauntlet')      # the VMs take no SSH passwords: sfadmin logs in with this, and sudo gets the password
        pub, admin_pub = v.public_key('lab-scan'), v.public_key('lab-admin')
        for vm, ip in NODES.items():
            v.bind('lab-scan', ip, 'scan', 22, actions='scan,checksum')

    def one(vm):
        home = sh(vm, "getent passwd scan | cut -d: -f6").strip()
        raw(vm, f'sudo -n sh -c {shlex.quote(f"mkdir -p {home}/.ssh && cat >>{home}/.ssh/authorized_keys && chown -R scan {home}/.ssh && chmod 700 {home}/.ssh && chmod 600 {home}/.ssh/authorized_keys; command -v restorecon >/dev/null && restorecon -R {home}/.ssh; true")}',
            stdin=(pub + '\n').encode())
        raw(vm, f'sudo -n sh -c {shlex.quote("cat >>$(getent passwd sfadmin | cut -d: -f6)/.ssh/authorized_keys")}', stdin=(admin_pub + '\n').encode())
        res = scan_via_vault(db, NODES[vm], ScanOptions(), actor=ACTOR)
        return vm, res

    with cf.ThreadPoolExecutor(7) as ex:
        for vm, fut in [(v, ex.submit(one, v)) for v in VMS]:
            try:
                _, res = fut.result()
                ok = bool(res) and res.get('status') == 'ok'
                R.add('scan', vm, ok, f'{(res or {}).get("entries")} entries, {(res or {}).get("failed")} failed mounts', json.dumps(res, default=str))
            except Exception as exc:
                R.add('scan', vm, False, f'{type(exc).__name__}: {str(exc)[:160]}', traceback.format_exc())
    for name, addr in main_conn.all('SELECT hostname, ssh_host FROM hosts'):
        for vm, ip in NODES.items():
            if addr == ip:
                NAME[vm] = name
    for vm, ip in NODES.items():
        if vm in NAME:
            pinned = known_host_keys(ip, 22, str(known_hosts_path()))
            hostkeys.confirm(main_conn, ip, 22, pinned[0], ACTOR)


# ── access ──────────────────────────────────────────────────────────
def stage_scan_access():
    for vm, ip in NODES.items():
        if vm not in NAME:
            continue

        def run(vm=vm, ip=ip):
            r = access.grant(db, main_conn, ip, PASSWORD, 'sfadmin', admin_key='lab-admin')
            have = raw(vm, 'sudo -n -u scan /usr/local/lib/storageforge/find /root -maxdepth 0')
            R.add('scan-access', vm, have.returncode == 0, r['output'].splitlines()[-1][:120] if r.get('output') else '', r.get('output', ''))
        R.check('scan-access', vm, run)


def stage_deploy_access():
    for vm in VMS:
        if vm not in NAME:
            continue
        name = NAME[vm]

        def run(vm=vm, name=name):
            r = deploy.enroll(db, main_conn, name, PASSWORD, 'sfadmin', ACTOR, admin_key='lab-admin')
            ok = r['state'] == 'ready'
            if ok:
                READY.add(vm)
            return ok, r
        try:
            ok, r = run()
            if vm in UNSUPPORTED:
                R.add('deploy-access', vm, not ok, 'refused, as it should be' if not ok else 'set up on a host deploys cannot run on', r['output'])
            else:
                R.add('deploy-access', vm, ok, r['state'], r['output'])
        except Exception as exc:
            if vm in UNSUPPORTED:
                good = any(w in str(exc) for w in ('bash', 'systemd'))
                R.add('deploy-access', vm, good, f'refused: {str(exc)[:150]}', traceback.format_exc() if not good else '')
            else:
                R.add('deploy-access', vm, False, f'{type(exc).__name__}: {str(exc)[:150]}', traceback.format_exc())
                hand_setup(vm, name)


def hand_setup(vm, name):
    """The documented other path: the setup script run as root, then adopt. Keeps later stages going."""
    def run():
        script = deploy.setup_for_download(db, main_conn)
        p = raw(vm, 'sudo -n sh -s', stdin=script.encode())
        if p.returncode:
            raise AssertionError(f'setup script: exit {p.returncode}: {p.stderr.decode(errors="replace")[-300:]}')
        r = deploy.adopt(db, main_conn, name, ACTOR)
        if r['state'] == 'ready':
            READY.add(vm)
        R.add('deploy-by-hand', vm, r['state'] == 'ready', r['state'], r['output'])
    R.check('deploy-by-hand', vm, run)


def stage_doctor():
    """The preflight: what each host can run, and that it says why it can't, from the scan alone for hosts not set up."""
    from storageforge_index import preflight
    for vm in VMS:
        if vm not in NAME:
            continue

        def run(vm=vm):
            c = preflight.host_report(db, main_conn, NAME[vm], ACTOR)
            blockers = [x['text'] for x in c['items'] if x['level'] == 'crit']
            if vm in UNSUPPORTED:
                R.add('doctor', vm, bool(blockers) and not c['deployable'], '; '.join(blockers)[:150], json.dumps(c))
            else:
                R.add('doctor', vm, c['deployable'] and not blockers, f'{c["facts"].get("init")}, selinux {c["facts"].get("selinux")}, {c["facts"].get("pm")}', json.dumps(c))
        R.check('doctor', vm, run)


# ── shares ──────────────────────────────────────────────────────────
NFS_RW = 'rw,sync,no_subtree_check,no_root_squash'
SHARES = [  # server, folder, the seed root inside it, [(client, mount point)]
    *[(n.name, n.data, n.data, [(after(i).name, f'/mnt/sf/{n.name}-data')]) for i, n in enumerate(HOSTS)],
    ('sf-ctl', '/srv/export', None, [(HOSTS[0].name, '/mnt/sf/ctl-export')]),
]


def stage_shares():
    conn = db.connect()
    servers = [s for s in SHARES if s[0] in READY]
    for srv, folder, _, clients in servers:
        R.check('shares', srv, lambda srv=srv, folder=folder, clients=clients: shares.save_export(
            db, conn, NAME[srv], {'protocol': 'NFSv4.2', 'path': folder, 'rules': [{'clients': '10.77.0.0/24', 'options': NFS_RW}],
                                  'mounts': [{'host': NAME[c], 'path': p} for c, p in clients if c in READY]}, None, ACTOR))
        chk = R.check('shares', srv, lambda srv=srv: shares.check(conn, NAME[srv]))
        for x in (chk or {}).get('items', []):
            if x['level'] == 'crit':
                R.add('share-check', srv, False, x['text'])
        items = R.check('shares', srv, lambda srv=srv: shares.deploy_items(db, conn, NAME[srv], 'report', ACTOR))
        if items:
            report_runs('share-report', execute(items, 'report'), want=('ok',))
        items = R.check('shares', srv, lambda srv=srv: shares.deploy_items(db, conn, NAME[srv], 'apply', ACTOR))
        if items:
            report_runs('share-apply', execute(items, 'apply'))
    for srv, folder, seed, clients in servers:
        for c, path in clients:
            if c not in READY:
                continue

            def verify(srv=srv, folder=folder, seed=seed, c=c, path=path):
                probe = f'share-test-{c}'
                sh(c, f'sudo -n sh -c {shlex.quote(f"echo from-{c} >{path}/{probe}")}')
                got = sh(srv, f'sudo -n cat {folder}/{probe}').strip()
                sh(c, f'sudo -n rm -f {path}/{probe}')
                if got != f'from-{c}':
                    raise AssertionError(f'wrote from-{c} on the client, server has {got!r}')
                note = 'write reached the server'
                if seed:
                    m = manifest(srv, seed)
                    f = next(e for e in m['entries'] if e['path'] == 'shared/docs/handbook.txt')
                    hash_ = sh(c, f'sudo -n sha256sum {path}/lab-seed/shared/docs/handbook.txt').split()[0]
                    if hash_ != f['sha256']:
                        raise AssertionError('seed file differs through the mount')
                    note += ', seed reads the same'
                mode = sh(srv, f'stat -c %a {folder}').strip()
                R.add('share-mount', c, True, f'{srv}:{folder} at {path}: {note} (folder mode {mode})')
            R.check('share-mount', c, verify)

    # a folder the deploy has to create must not come out private
    for srv, folder, _, _ in servers:
        if srv == 'sf-ctl':
            def mode(srv=srv, folder=folder):
                m = sh(srv, f'stat -c %a {folder}').strip()
                R.add('share-mode', srv, m == '755', f'{folder} was created with mode {m}')
            R.check('share-mode', srv, mode)

    # SMB: the server's label on SELinux, its service and a real cifs mount
    srv, client = roles.smb_server().name, next((n.name for n in roles.deployable() if n.name != roles.smb_server().name
                                                 and raw(n.name, 'sudo -n modprobe -n cifs && sudo -n modprobe -n nls_utf8').returncode == 0), '')
    smb_dir = BUILD[srv].room
    if srv in READY and client in READY:
        def smb():
            sh(client, f'sudo -n mkdir -p /etc/samba/credentials && printf "username=sfadmin\\npassword=labpw\\n" | sudo -n tee /etc/samba/credentials/{deploy.host_slug(NAME[srv])}-fsmb >/dev/null; sudo -n chmod 600 /etc/samba/credentials/{deploy.host_slug(NAME[srv])}-fsmb')
            shares.save_export(db, conn, NAME[srv], {'protocol': 'SMB3', 'name': 'fsmb', 'path': smb_dir, 'clients': '10.77.0.0/24 sfadmin',
                                                     'mounts': [{'host': NAME[client], 'path': '/mnt/sf/fedora-smb'}]}, None, ACTOR)
            server_only = [i for i in shares.deploy_items(db, conn, NAME[srv], 'apply', ACTOR) if i['host'] == NAME[srv]]
            report_runs('smb-server', execute(server_only, 'apply'), want=('ok', 'incomplete'))     # it reports the account it can't make
            sh(srv, f'sudo -n chown sfadmin {smb_dir}')
            label = sh(srv, f'ls -Zd {smb_dir}')
            if BUILD[srv].can('selinux'):
                R.add('smb-server', srv, 'samba_share_t' in label, label.strip())
            sh(srv, "printf 'labpw\\nlabpw\\n' | sudo -n smbpasswd -s -a sfadmin")
            report_runs('smb-client', execute(shares.deploy_items(db, conn, NAME[srv], 'apply', ACTOR), 'apply'))
            sh(client, 'sudo -n sh -c "echo smb >/mnt/sf/fedora-smb/smb-test"')
            got = sh(srv, f'sudo -n cat {smb_dir}/smb-test').strip()
            R.add('smb-mount', client, got == 'smb', f'{srv}:{smb_dir} through cifs')
        R.check('smb', client, smb)
    conn.close()


# ── jobs ────────────────────────────────────────────────────────────
def job_steps():
    """method, source vm, source path, destination vm, path, options, the seed root it holds (for checking)."""
    a, b, c, d = HOSTS[0], after(0), after(1), after(2)
    snap = lambda n: {'snapshot': True} if n.subvol else {}     # noqa: E731
    return [
        ('mirror', a.name, f'{a.data}/lab-seed', b.name, f'{b.room}/mirror-{a.name}', snap(a), (a.name, a.data)),
        ('copy', b.name, f'{b.data}/lab-seed', c.name, f'{c.room}/copy-{b.name}', {}, (b.name, b.data)),
        ('rsnapshot', c.name, f'{c.data}/lab-seed', d.name, f'{d.room}/rsnapshot-{c.name}', {}, (c.name, c.data)),
        ('rsnapshot', d.name, f'{d.data}/lab-seed', a.name, f'{a.room}/rsnapshot-{d.name}', {}, (d.name, d.data)),
        ('mirror', a.name, f'{a.data}/lab-seed', a.name, f'{a.room}/mirror-here', {}, (a.name, a.data)),
        ('git', a.name, f'{a.data}/lab-seed/repos/sample', b.name, f'{b.room}/sample.git', {}, None),
    ]


def stage_jobs():
    conn = db.connect()
    for step in job_steps():
        if step[0] == 'rsnapshot' and BUILD[step[3]].pm == 'dnf' and 'fedora' not in step[3]:
            sh(step[3], 'sudo -n dnf -q -y install epel-release')     # rsnapshot comes from EPEL, which deploys expect to be on
    steps, kept = [], {}
    for i, (method, s, sp, d, dp, opts, seed) in enumerate(job_steps(), 1):
        if s not in READY or d not in READY:
            R.add('jobs', d, None, f'step {i}: {s} or {d} has no deploy access')
            continue
        o = {'schedule': 'daily', 'verify': 'weekly' if method != 'git' else None, **opts}
        if method == 'rsnapshot':
            o['keep'] = {'daily': 3, 'weekly': 2, 'monthly': 0, 'hourly': 0}
        steps.append({'id': f's{i}', 'method': method, 'src': {'host': NAME[s], 'path': sp}, 'dst': {'host': NAME[d], 'path': dp}, 'options': o})
        kept[f's{i}'] = (method, s, sp, d, dp, seed)
    pid = moves.save_plan(conn, {'name': 'gauntlet jobs', 'steps': steps}, ACTOR)
    plan = moves.get_plan(conn, pid)
    for s in moves.check(conn, moves.normalize(plan))['steps']:
        for it in s.get('items', []):
            if it['level'] == 'crit':
                R.add('job-check', '-', False, it['text'])
    report_runs('job-report', execute(jobs.deploy_items(db, conn, plan, 'report', None, ACTOR), 'report'))
    runs = execute(jobs.deploy_items(db, conn, plan, 'apply', None, ACTOR), 'apply')
    report_runs('job-apply', runs, want=('ok',))

    def last_run(vm, jid, kind, since):
        end = time.time() + 900
        while time.time() < end:
            p = raw(vm, f'cat /var/lib/storageforge/jobs/{jid}/runs.jsonl 2>/dev/null')
            for line in reversed(p.stdout.decode(errors='replace').splitlines()):
                r = json.loads(line)
                if r['kind'] == kind and r['start'] >= since:
                    return r
            time.sleep(3)
        raise TimeoutError(f'{jid} reported no {kind}')

    for sid, (method, s, sp, d, dp, seed) in kept.items():
        jid = jobs.job_id(pid, sid)

        def one(sid=sid, jid=jid, method=method, s=s, d=d, dp=dp, seed=seed, sp=sp):
            start = int(sh(d, 'date +%s').strip())
            r = jobs.action(db, conn, jid, 'dryrun', ACTOR)
            R.add(f'job-dryrun-{method}', d, r['status'] == 'ok', f'{method} from {s}', r['output'])
            r = jobs.action(db, conn, jid, 'run', ACTOR)
            if r['status'] != 'ok':
                R.add(f'job-run-{method}', d, False, f'{method} from {s}: could not start', r['output'])
                return
            got = last_run(d, jid, 'run', start)
            journal = jobs.action(db, conn, jid, 'log', ACTOR)['output'] if got['rc'] else ''
            R.add(f'job-run-{method}', d, got['rc'] == 0, f'{method} from {s}: rc={got["rc"]} {got["message"][:120]}', journal)
            if got['rc']:
                return
            if method == 'git':
                head = sh(d, f'sudo -n git -c safe.directory="*" -C {dp} log -1 --format=%s main').strip()
                R.add(f'job-result-{method}', d, head == 'first', f'archive holds the commit {head!r}')
                return
            target = f'{dp}/daily.0/lab-seed' if method == 'rsnapshot' else dp
            bad = same_as_manifest(d, target, manifest(*seed))
            R.add(f'job-result-{method}', d, not bad, bad or f'{method} from {s}: every entry matches the seed')
            start = int(sh(d, 'date +%s').strip())
            jobs.action(db, conn, jid, 'verify', ACTOR)
            got = last_run(d, jid, 'verify', start)
            R.add(f'job-verify-{method}', d, got['rc'] == 0, f'{method} from {s}: {got["message"][:140]}')
        R.check('job-run', d, one)
    conn.close()


# ── changes ─────────────────────────────────────────────────────────
def change_tasks(n):
    if n.can('controller'):
        return [('dir', {'path': '/srv/ch/plain'}), ('dir', {'path': '/srv/ch/modes', 'mode': '2775'}), ('symlink', {'path': '/srv/ch/link', 'target': '/srv/ch/plain'})]
    tasks = [('dir', {'path': f'{n.room}/ch'})]
    if n.can('zfs'):
        pool = n.tag('zfs-pool')
        tasks += [('zfs-dataset', {'dataset': f'{pool}/ch', 'options': 'compression=zstd'}), ('zfs-snapshot', {'dataset': f'{pool}/media', 'name': 'gauntlet'}),
                  ('zfs-send', {'dataset': f'{pool}/media', 'name': 'gauntlet', 'dest': f'{pool}/sent'}), ('zfs-scrub', {'pool': pool})]
    if n.subvol:
        tasks += [('subvolume', {'path': f'{n.subvol}/ch-sub'}), ('snapshot', {'source': n.subvol, 'dest': f'{n.snaps}/ch-snap'}),
                  ('to-subvolume', {'path': f'{n.data}/lab-seed/shared/docs'}), ('scrub', {'target': n.tag('btrfs-mount') or n.subvol})]
    if n.can('lvm'):
        vg = n.tag('vg')
        tasks += [('lvm-lv', {'vg': vg, 'lv': 'chlv', 'size': '320M', 'fstype': 'xfs', 'label': 'chlv'}),
                  ('mount', {'source': f'/dev/{vg}/chlv', 'target': '/srv/chlv', 'fstype': 'xfs', 'options': 'defaults,nofail'}),
                  ('lvm-extend', {'vg': vg, 'lv': 'chlv', 'size': '380M'}),
                  ('lvm-snapshot', {'vg': vg, 'lv': n.tag('lv'), 'name': 'chsnap', 'size': '128M'})]
    if n.can('luks') and 'sf-arch' == n.name:
        tasks += [('rename', {'path': '/mnt/secure/lab-seed/unique', 'dest': '/mnt/secure/lab-seed/renamed'}), ('trash', {'path': '/mnt/secure/lab-seed/shared'}),
                  ('perms', {'path': f'{n.room}/ch', 'mode': '0750', 'owner': 'scan'})]
    return tasks


def stage_changes():
    conn = db.connect()
    for vm in READY:
        ts = change_tasks(BUILD[vm])

        def one(vm=vm, ts=ts):
            body = {'name': f'gauntlet {vm}', 'tasks': [{'type': t, 'host': NAME[vm], 'params': p} for t, p in ts]}
            pid = changes.save_plan(conn, body, ACTOR)
            plan = changes.get_plan(conn, pid)
            for x in changes.check(conn, plan)['tasks']:
                for it in x['items']:
                    if it['level'] == 'crit':
                        R.add('change-check', vm, False, f'task {x["task"]}: {it["text"]}')
            report_runs('change-report', execute(changes.deploy_items(db, conn, plan, 'report', ACTOR), 'report'))
            report_runs('change-apply', execute(changes.deploy_items(db, conn, plan, 'apply', ACTOR), 'apply'))
            again = execute(changes.deploy_items(db, conn, plan, 'apply', ACTOR), 'apply')
            wrote = [r for r in again if re.search(r'^  (\x1b\[[0-9;]*m)?->', r['output'] or '', re.M)]
            R.add('change-rerun', vm, again[0]['status'] == 'ok' and not wrote, f'second apply {again[0]["status"]}, {"changed things" if wrote else "nothing to do"}', again[0]['output'] or '')
        R.check('change-apply', vm, one)
    lvm = next((n for n in roles.having('lvm') if n.name in READY), None)
    if lvm:
        def unmounted():
            vg = lvm.tag('vg')
            body = {'name': 'gauntlet unmounted', 'tasks': [
                {'type': 'lvm-lv', 'host': NAME[lvm.name], 'params': {'vg': vg, 'lv': 'chlv2', 'size': '320M', 'fstype': 'xfs', 'label': 'chlv2'}},
                {'type': 'lvm-extend', 'host': NAME[lvm.name], 'params': {'vg': vg, 'lv': 'chlv2', 'size': '380M'}}]}
            plan = changes.get_plan(conn, changes.save_plan(conn, body, ACTOR))
            run = execute(changes.deploy_items(db, conn, plan, 'apply', ACTOR), 'apply')[0]
            R.add('lvm-extend-unmounted', lvm.name, run['status'] == 'ok', run['status'], run['output'] or '')
        R.check('lvm-extend-unmounted', lvm.name, unmounted)
    if 'sf-ctl' in READY:
        def modes():
            got = sh('sf-ctl', 'stat -c "%a %n" /srv/ch/plain /srv/ch/modes').split('\n')
            R.add('change-modes', 'sf-ctl', got[0].startswith('755') and got[1].startswith('2775'), ' · '.join(got).strip(' ·'))
        R.check('change-modes', 'sf-ctl', modes)
    conn.close()


# ── storage tasks ───────────────────────────────────────────────────
def task_blocks(vm):
    n = BUILD[vm]
    data = n.room
    blocks = [{'type': 'mkdir', 'params': {'path': f'{data}/task-copy'}},
              {'type': 'command', 'params': {'cmd': f'cp /etc/os-release {data}/task-copy/ && echo copied'}},
              {'type': 'log', 'params': {'message': 'gauntlet task ran'}}]
    if n.subvol:
        blocks += [{'type': 'btrfs_snapshot', 'params': {'subvol': n.subvol, 'into': n.snaps, 'prefix': 'auto'}},
                   {'type': 'btrfs_prune', 'params': {'into': n.snaps, 'prefix': 'auto', 'keep': 2}}]
    if n.can('zfs'):
        pool = n.tag('zfs-pool')
        blocks += [{'type': 'zfs_snapshot', 'params': {'dataset': f'{pool}/media', 'prefix': 'auto'}},
                   {'type': 'zfs_prune', 'params': {'dataset': f'{pool}/media', 'prefix': 'auto', 'keep': 2}},
                   {'type': 'zfs_send', 'params': {'dataset': f'{pool}/media', 'prefix': 'auto', 'dst': f'{pool}/taskcopy'}}]
    return blocks, data


def stage_tasks():
    conn = db.connect()
    for vm in VMS:
        if vm not in READY:
            continue

        def one(vm=vm):
            blocks, data = task_blocks(vm)
            tid = tasks.save_task(conn, {'name': f'gauntlet {vm}', 'host': NAME[vm], 'schedule': '*-*-* 03:15:00', 'blocks': blocks}, ACTOR)
            task = tasks.get_task(conn, tid)
            report_runs('task-report', execute(tasks.deploy_items(db, conn, task, 'report', ACTOR), 'report'))
            report_runs('task-install', execute(tasks.deploy_items(db, conn, task, 'apply', ACTOR), 'apply'))
            sl = tasks.slug(task['name'])
            on = sh(vm, f'systemctl is-enabled sf-task-{sl}.timer').strip()
            p = raw(vm, f'sudo -n systemctl start sf-task-{sl}.service', timeout=600)
            journal = sh(vm, f'sudo -n journalctl -u sf-task-{sl} -n 30 --no-pager -o cat')
            last = raw(vm, f'sudo -n cat /var/lib/storageforge/tasks/{sl}.last').stdout.decode()
            good = p.returncode == 0 and '"rc":0' in last
            R.add('task-systemd', vm, good and on == 'enabled', f'timer {on}, service exit {p.returncode}, {last.strip()[:70]}', journal + p.stderr.decode(errors='replace'))
            # The installed copy of a task must not touch the deploy runner when its timer fires.
            size = sh(vm, 'sudo -n wc -c </usr/local/sbin/storageforge-run').strip()
            R.add('task-keeps-runner', vm, size != '0', f'storageforge-run is {size} bytes after the service ran')
            if size == '0':     # later stages need a working runner: setting up again restores it
                deploy.enroll(db, conn, NAME[vm], PASSWORD, 'sfadmin', ACTOR, admin_key='lab-admin')
            have = raw(vm, f'test -f {data}/task-copy/os-release').returncode == 0
            R.add('task-result', vm, have, 'the service did its work' if have else 'the file is not there')
            report_runs('task-runnow', execute(tasks.deploy_items(db, conn, task, 'apply', ACTOR, run_now=True), 'apply'))
        R.check('task-install', vm, one)
    conn.close()


# ── drift, after a rescan of everything the stages changed ──────────
def stage_drift():
    def rescan(vm):
        scan_via_vault(db, NODES[vm], ScanOptions(), actor=ACTOR)
    with cf.ThreadPoolExecutor(6) as ex:
        list(ex.map(rescan, [v for v in VMS if v in READY]))
    conn = db.connect()
    got = [d for d in alerts.drift(conn) if d['kind'] == 'changed']
    by = {}
    for d in got:
        by.setdefault(d['host'], []).append(d['text'])
    for vm in READY:
        texts = by.get(NAME[vm], [])
        R.add('drift-clean', vm, not texts, 'no false drift' if not texts else f'{len(texts)}: {texts[0][:140]}', '\n'.join(texts))
    # now a real change: it must be noticed
    vm = next((v for v in VMS if v in READY and raw(v, 'test -e /etc/exports.d/storageforge.exports').returncode == 0), None)
    if vm:
        sh(vm, 'sudo -n sh -c "echo \'# by hand\' >>/etc/exports.d/storageforge.exports"')
        rescan(vm)
        seen = [d for d in alerts.drift(conn) if d['kind'] == 'changed' and d['host'] == NAME[vm]]
        R.add('drift-real', vm, any('exports' in d['text'] for d in seen), f'{len(seen)} drift item(s) after a hand edit')
    conn.close()


# ── the engine: what groups do across real hosts ────────────────────
def stage_engine():
    from storageforge_index import engine
    conn = db.connect()
    ready = [v for v in VMS if v in READY]
    if len(ready) < 2:
        R.add('engine', '-', None, 'needs two hosts')
        return
    # a report on many hosts runs side by side
    items = [{'host': NAME[v], 'kind': 'probe', 'ref': 'parallel', 'mode': 'report', 'script': 'sleep 6; echo done\n'} for v in ready]
    t = time.time()
    gid = engine.start(db, items, ACTOR, title='parallel report', kind='probe', ref='parallel', mode='report')
    runs = wait_group(gid)
    took = time.time() - t
    R.add('engine', '-', all(r['status'] == 'ok' for r in runs) and took < 6 * len(ready) / 2,
          f'{len(ready)} hosts, 6 s each, took {took:.0f} s')
    # cancel: a queued host never starts, a running one is stopped
    items = [{'host': NAME[v], 'kind': 'probe', 'ref': 'cancel', 'mode': 'apply', 'script': 'sleep 60; echo finished\n', 'phase': i} for i, v in enumerate(ready[:2])]
    gid = engine.start(db, items, ACTOR, title='cancel', kind='probe', ref='cancel', mode='apply')
    time.sleep(3)
    engine.cancel(db, gid, ACTOR, force=True)
    runs = wait_group(gid, 60)
    R.add('engine', '-', sorted(r['status'] for r in runs) == ['cancelled', 'cancelled'], 'cancel: ' + ', '.join(r['status'] for r in runs))
    # a failing host stops the later phases, and retry runs only what did not finish
    a, b = ready[0], ready[1]
    flag = '/run/sf-gauntlet-retry'
    raw(a, f'sudo -n rm -f {flag}')
    items = [{'host': NAME[a], 'kind': 'probe', 'ref': 'retry', 'mode': 'apply', 'phase': 0, 'script': f'test -e {flag}\n'},
             {'host': NAME[b], 'kind': 'probe', 'ref': 'retry', 'mode': 'apply', 'phase': 1, 'script': 'echo second\n'}]
    gid = engine.start(db, items, ACTOR, title='retry', kind='probe', ref='retry', mode='apply')
    runs = wait_group(gid, 120)
    R.add('engine', '-', sorted(r['status'] for r in runs) == ['failed', 'skipped'], 'stop on failure: ' + ', '.join(r['status'] for r in runs))
    # the same host never runs two scripts at once, whatever the groups
    items = [{'host': NAME[a], 'kind': 'probe', 'ref': 'lock', 'mode': 'report', 'script': 'date +%s; sleep 4; date +%s\n'}]
    g1, g2 = (engine.start(db, items, ACTOR, title='lock', kind='probe', ref='lock', mode='report') for _ in range(2))
    r1, r2 = wait_group(g1)[0], wait_group(g2)[0]
    s1, s2 = [[int(w) for w in r['output'].split() if w.isdigit()] for r in (r1, r2)]     # a queued run also says it waited
    R.add('engine', a, s1[1] <= s2[0] or s2[1] <= s1[0], 'two groups took turns on one host')
    conn.close()


# ── removal ─────────────────────────────────────────────────────────
def stage_remove():
    conn = db.connect()
    for pid, name in conn.all('SELECT plan_id, name FROM move_plans'):
        plan = {'id': pid, 'name': name, 'steps': []}
        report_runs('remove-jobs', execute(jobs.deploy_items(db, conn, plan, 'apply', None, ACTOR), 'apply'))
    for task_id, name in conn.all('SELECT task_id, name FROM storage_tasks'):
        report_runs('remove-tasks', execute(tasks.deploy_items(db, conn, tasks.get_task(conn, task_id), 'apply', ACTOR, remove=True), 'apply'))
    for srv, *_ in SHARES:
        if srv not in READY:
            continue

        def one(srv=srv):
            from storageforge_index import graph
            bp = graph.stored_blueprint(conn, NAME[srv]) or {}
            for i in reversed(range(len(bp.get('exports') or []))):
                shares.remove_export(db, conn, NAME[srv], i)
            report_runs('remove-shares', execute(shares.deploy_items(db, conn, NAME[srv], 'apply', ACTOR), 'apply'))
        R.check('remove-shares', srv, one)
    for vm in sorted(READY):
        def left(vm=vm):
            access.grant(db, conn, NODES[vm], PASSWORD, 'sfadmin', remove=True, admin_key='lab-admin')   # scan access has its own timer
            fstab = raw(vm, 'grep -c "storageforge share" /etc/fstab').stdout.decode().strip()
            units = raw(vm, 'ls /etc/systemd/system | grep -c "^sf-"').stdout.decode().strip()
            R.add('remove-clean', vm, fstab in ('0', '') and units in ('0', ''), f'{fstab or 0} fstab lines, {units or 0} units left')
            try:
                r = deploy.enroll(db, conn, NAME[vm], PASSWORD, 'sfadmin', ACTOR, remove=True, admin_key='lab-admin')
                R.add('remove-at-once', vm, True, 'removed straight after a deploy')
            except deploy.RemoteError as exc:       # the last login's session outlives it by a few seconds
                R.add('remove-at-once', vm, False, str(exc)[:150])
                time.sleep(20)
                r = deploy.enroll(db, conn, NAME[vm], PASSWORD, 'sfadmin', ACTOR, remove=True, admin_key='lab-admin')
            gone = raw(vm, 'id storageforge-deploy').returncode != 0 and raw(vm, 'test -e /usr/local/sbin/storageforge-run').returncode != 0
            R.add('remove-access', vm, gone and r['state'] == 'removed', r['output'][-120:])
        R.check('remove-access', vm, left)
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default=','.join(STAGES))
    ap.add_argument('--keep', action='store_true', help='keep the database and its folder afterwards')
    ap.add_argument('--json', default=str(STATE / 'gauntlet.json'))
    args = ap.parse_args()
    if not PASSWORD:
        raise SystemExit('no lab is running: use lab.sh up')
    want = args.only.split(',')
    prerequisite = {'scan'}          # later stages need the hosts in the index
    t0 = time.time()
    for stage in STAGES:
        if stage not in want and stage not in prerequisite:
            continue
        print(f'\n── {stage} ──', flush=True)
        try:
            globals()['stage_' + stage.replace('-', '_')]()
        except Exception as exc:
            R.add(stage, '-', False, f'{type(exc).__name__}: {str(exc)[:160]}', traceback.format_exc())
    good = R.matrix()
    print(f'{time.time() - t0:.0f} s; details in {args.json}')
    Path(args.json).write_text(json.dumps(R.rows, indent=1))
    main_conn.close()
    if args.keep:
        print('kept', work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if good else 1


if __name__ == '__main__':
    sys.exit(main())
