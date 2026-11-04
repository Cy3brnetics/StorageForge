#!/usr/bin/env python3
"""Tier 13 of the KVM lab: every feature in docs/features/README.md that no other tier reached, on real hosts, through the
API and the command line on sf-ctl. tests/feature_map.py says which tier verifies each feature, and test_feature_map.py keeps it honest.

An answer from StorageForge is compared with what a VM shows, never with StorageForge's own report of its work. What takes
the server down (restore, reset) runs last, and the tier leaves the lab for lab.sh to reset.

    SFLAB_ONLY=git,clamav tiers.py run 13       just these checks, for working on them
"""
import csv
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import demo
import roles
from demo import COMPOSE, ssh

import tiers as t
from tiers_platform import grant_engines, quiet, sql_write, sudo

ROOT = Path(__file__).resolve().parents[2]
ONLY = {x for x in os.environ.get('SFLAB_ONLY', '').split(',') if x}
EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'     # the industry's harmless test file, not malware


def cli_rc(*args, stdin=None):
    """(exit status, stdout, stderr) of the command line in the running container, for commands whose exit status is the point."""
    p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index {shlex.join(args)}'],
                       input=stdin, stdin=subprocess.DEVNULL if stdin is None else None, capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout, p.stderr


def in_container(command):
    return ssh('sf-ctl', f'{COMPOSE} exec -T storageforge sh -c {shlex.quote(command)}')


def want(condition, text):
    if not condition:
        demo.fail(text)


def apt_install(packages):
    """A fresh VM may be running its own unattended upgrade: wait for it instead of failing, as the product's scripts do."""
    get = f'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 -qq install -y {packages} >/dev/null'
    return f'{get} 2>&1 || {{ apt-get -o DPkg::Lock::Timeout=300 -qq update && {get}; }}'


def lines_of(text):
    """--format json on the command line prints one object a line."""
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def full_seed():
    """(node, root) for each deployable host holding the full seed: awkward names, duplicates and the sample repository."""
    found = {vm: root for vm, root, profile, _ in t.manifests() if profile == 'full'}
    return [(n, found[n.name]) for n in roles.deployable() if n.name in found]


def rescan(api, node):
    demo.scan(api, [node.ip])


def fresh_login(name, password):
    """Another person's session, in its own cookie jar."""
    other = demo.Api(password)
    other.raw('POST', '/api/login', {'username': name, 'password': password})
    return other


def status_of(api, method, path, body=None):
    return api.raw(method, path, body)[0]


def deploy_failed(runs):
    return [r for r in runs if r['status'] not in ('ok', 'incomplete')]


# ── discovery ───────────────────────────────────────────────────────
def scan_schedule(api, node):
    """A host's own interval really starts a scan, and its quiet hours really hold one back. The scheduler looks every 10 minutes
    and once on start, so a restart makes it look now."""
    def jobs_after(since):
        return [j for j in api.get('/api/jobs')['jobs'] if j['host'] in (node.name, node.ip) and (j['queued_at'] or 0) >= since]

    def restart():
        ssh('sf-ctl', f'{COMPOSE} restart storageforge >/dev/null 2>&1')
        t.wait_for('the server', lambda: api.raw('GET', '/api/me')[0] == 200, 120)

    def run():
        got = api('PUT', f'/api/hosts/{node.name}/schedule', {'interval': '90m', 'quiet_hours': '22-6'})
        want(got['interval'] == 5400 and got['quiet_hours'] == '22-6', f'did not keep what it was given: {got}')
        want(api.get(f'/api/hosts/{node.name}/schedule') == got, 'reads back differently')
        for bad in ({'quiet_hours': '25-6'}, {'quiet_hours': '6-6'}, {'interval': 'soon'}):
            status, out = api.raw('PUT', f'/api/hosts/{node.name}/schedule', bad)
            want(status == 400, f'{bad} was accepted: {status} {out}')
        hour = int(in_container('date +%H').strip())     # the server's hour: its quiet hours are by its clock
        api('PUT', f'/api/hosts/{node.name}/schedule', {'interval': '1m', 'quiet_hours': f'{hour}-{(hour + 2) % 24}'})
        time.sleep(65)                                   # older than its interval, so only the quiet hours can hold it
        since = time.time()
        restart()
        time.sleep(30)
        queued = jobs_after(since)
        want(not queued, f'scanned in its quiet hours: {queued}')
        api('PUT', f'/api/hosts/{node.name}/schedule', {'interval': '1m', 'quiet_hours': ''})
        since = time.time()
        restart()
        t.wait_for('a scheduled scan', lambda: jobs_after(since), 120)
        api('PUT', f'/api/hosts/{node.name}/schedule', {'interval': '6h', 'quiet_hours': ''})
        return 'an interval of 1m started a scan, and quiet hours held it back'
    return run


def file_changes(api, node, root):
    def run():
        seed = f'{root}/lab-seed'
        sudo(node.name, f'echo soon >{seed}/sf-t13-gone.txt')
        rescan(api, node)
        sudo(node.name, f"echo new >{seed}/sf-t13-new.txt; echo more >>{seed}/shared/docs/handbook.txt; rm -f {seed}/sf-t13-gone.txt")
        rescan(api, node)
        rows = json.loads(demo.cli('changes', '--host', node.name, '--format', 'json', '--limit', '5000'))['changes']
        got = {(r['change'], r['path']) for r in rows}
        for pair in (('added', f'{seed}/sf-t13-new.txt'), ('modified', f'{seed}/shared/docs/handbook.txt'), ('deleted', f'{seed}/sf-t13-gone.txt')):
            want(pair in got, f'{pair} is not in the {len(got)} changes')
        web = api.get(f'/api/file-changes?host={node.name}')
        want(web['scan']['added'] >= 1 and web['scan']['modified'] >= 1 and web['scan']['deleted'] >= 1, f'the web answer disagrees: {web["scan"]}')
        want(any(f['folder'].startswith(root[:root.index('/', 1)] if '/' in root[1:] else root) for f in web['folders']), f'no folder under {root}: {web["folders"][:5]}')
        return f'added, modified and deleted all seen, in {len(got)} changes'
    return run


def capacity_trend(api, node):
    def run():
        fill = node.fill
        df = lambda: int(ssh(node.name, f'df -B1 --output=used {shlex.quote(fill)} | tail -1').strip())   # noqa: E731
        mount = ssh(node.name, f'findmnt -n -o TARGET --target {shlex.quote(fill)}').strip()
        rescan(api, node)

        def point():
            rows = [m for m in api.get(f'/api/capacity?host={node.name}')['mounts'] if m['mount'] == mount]
            want(rows, f'{mount} has no capacity series')
            return rows[0]
        before, real = point(), df()
        want(abs(before['used'] - real) <= max(real * 0.05, 64 << 20), f'says {before["used"]} used, df says {real}')
        sudo(node.name, f'dd if=/dev/urandom of={shlex.quote(fill)}/sf-t13-fill bs=1M count=64 status=none; sync')
        rescan(api, node)
        after = point()
        sudo(node.name, f'rm -f {shlex.quote(fill)}/sf-t13-fill')
        want(after['used'] > before['used'] and len(after['points']) > len(before['points']), f'did not move: {before["used"]} to {after["used"]}')
        return f'{mount}: {len(after["points"])} readings, agrees with df'
    return run


def duplicates(api, node, root):
    """Checksum scans find identical files. Folder comparison needs no checksums. Both against files whose bytes the seed fixed."""
    def run():
        code, out, err = cli_rc('scan', '--host', node.ip, '--checksum', '--checksum-min-size', '1', '--json')
        want(code == 0, f'a checksum scan failed: {err[-300:]}')
        groups = lines_of(demo.cli('dupes', '--host', node.name, '--min-size', '1', '--limit', '100000', '--format', 'json'))
        text = json.dumps(groups)
        want('report-copy.pdf' in text and 'report.pdf' in text, f'report.pdf and its copy are not a group, of {len(groups)}')
        real = {sudo(node.name, f'sha256sum {root}/lab-seed/dupes/{p}').split()[0] for p in ('report.pdf', 'archive/report-copy.pdf')}
        want(len(real) == 1, 'the seed is not what this test thinks: the two files differ')
        web = api.get(f'/api/dupes?host={node.name}&min_size=1&limit=500')['groups']
        want(len(web) == min(len(groups), 500), f'the CLI has {len(groups)} groups, the web {len(web)}')     # the web answers at most 500
        folders = api.get(f'/api/folders/duplicates?host={node.name}&min_files=2&min_size=1')
        text = json.dumps(folders)
        want('album-2024-copy' in text, 'album-2024 and album-2024-copy are not found as twins')
        cli_folders = demo.cli('folders', '--host', node.name, '--min-files', '2', '--min-size', '1', '--format', 'json')
        want('album-2024-copy' in cli_folders, 'the CLI does not list the twin folders')
        return f'{len(groups)} file groups, twin albums found, hashes agree on the VM'
    return run


def cold_data(api, node, root):
    def run():
        folder = f'{root}/lab-seed/sf-t13-cold'
        sudo(node.name, f'mkdir -p {folder}; dd if=/dev/urandom of={folder}/a.bin bs=1M count=2 status=none; touch -d 2015-01-01 {folder}/a.bin {folder}; '
                        f'mkdir -p {root}/lab-seed/sf-t13-warm; dd if=/dev/urandom of={root}/lab-seed/sf-t13-warm/a.bin bs=1M count=2 status=none')
        rescan(api, node)
        got = json.dumps(api.get(f'/api/folders/cold?host={node.name}&years=2&min_size=1MiB'))
        want('sf-t13-cold' in got, 'a folder last touched in 2015 is not cold')
        want('sf-t13-warm' not in got, 'a folder written today is listed as cold')
        return 'the 2015 folder is cold, and today\'s is not'
    return run


def containers(api, node, engine):
    def run():
        real = set(sudo(node.name, f"{engine} ps -a --format '{{{{.Names}}}}'").split())
        want(real, 'the seed holds containers on this host')
        rescan(api, node)
        text = json.dumps(api.get(f'/api/docker?host={node.name}'))
        missing = [c for c in real if c not in text]
        want(not missing, f'{missing} are on the host and not in the answer')
        usage = status_of(api, 'GET', f'/api/docker/usage?host={node.name}')
        want(usage < 500, f'/api/docker/usage: HTTP {usage}')
        printed = demo.cli('docker', '--host', node.name)     # stacks and counts: names are the API's
        running = len(sudo(node.name, f"{engine} ps --format '{{{{.Names}}}}'").split())
        want(f'{running}/{len(real)} running' in printed, f'the host has {running}/{len(real)} running, the CLI says: {printed[:200]}')
        return f'{engine}: {len(real)} containers, the same in the API and CLI as on the host'
    return run


def git_inventory(api, node, root):
    def run():
        repo = f'{root}/lab-seed/repos/sample'
        rescan(api, node)
        repos = api.get(f'/api/git?host={node.name}&all=1')['repos']
        found = [x for x in repos if x['path'] == repo]
        want(found, f'{repo} is not among {[x["path"] for x in repos][:8]}')
        head = sudo(node.name, f'git -c safe.directory="*" -C {repo} rev-parse HEAD').strip()
        want(found[0]['head_commit'] == head, f'says HEAD {found[0]["head_commit"]}, git says {head}')
        want(found[0]['head_subject'] == 'first', f'subject {found[0]["head_subject"]!r}')
        want(node.name in demo.cli('git', '--host', node.name), 'the CLI has no row for this host')

        history = api.post('/api/git/history', {'host': node.name, 'path': repo})
        want(history.get('commits') and history['commits'][0]['hash'].startswith(head[:7]), f'history: {str(history)[:300]}')
        commit = api.post('/api/git/commit', {'host': node.name, 'path': repo, 'sha': head})
        want('README.md' in commit['output'], f'the commit does not show its file: {str(commit)[:300]}')
        status_clean = api.post('/api/git/status', {'host': node.name, 'path': repo})
        want(not status_clean.get('dirty'), f'a clean repository reads dirty: {status_clean}')

        sudo(node.name, f'echo edit >>{repo}/README.md')
        status = api.post('/api/git/status', {'host': node.name, 'path': repo})
        # a repository the scan account does not own is reported as foreign, and not read for changes
        want(status.get('foreign') or status.get('dirty') == 1, f'an edited file does not read dirty: {status}')
        sudo(node.name, f'git -c safe.directory="*" -C {repo} checkout -- README.md')
        code, out = api.raw('POST', '/api/git/status', {'host': node.name, 'path': '/etc'})
        want(code in (400, 404, 409), f'a path no scan found was accepted: {code} {out}')
        surveyed = api.post('/api/git/survey', {'host': node.name})
        want(surveyed.get('repos', 0) >= 1, f'survey: {surveyed}')
        return f'HEAD {head[:8]}, history, commit, status and survey agree with git on the VM'
    return run


def host_configs(api, node):
    def run():
        rescan(api, node)
        versions = api.get(f'/api/hostconfigs?host={node.name}')['versions']
        want(versions, 'no configuration was captured')
        marker = f'/mnt/sf-t13-{node.name}'
        sudo(node.name, f"mkdir -p {marker}; echo 'tmpfs {marker} tmpfs nofail,noauto 0 0' >>/etc/fstab")
        rescan(api, node)
        newer = api.get(f'/api/hostconfigs?host={node.name}')['versions']
        want(len(newer) > len(versions), 'a changed fstab made no new version')
        latest = api.get(f'/api/hostconfigs/{newer[0]["config_id"]}')
        want(latest['previous'] == versions[0]['config_id'] and marker in json.dumps(latest), f'the version does not hold {marker}')
        want(latest['changes'], 'the version says nothing changed')
        printed = demo.cli('config', 'diff', str(versions[0]['config_id']), str(newer[0]['config_id']))
        want(marker in printed, f'the diff does not show {marker}')
        listed = demo.cli('config', 'list', node.name)
        want(str(newer[0]['config_id']) in listed, 'config list does not show the new version')
        script = api.text(f'/api/hostconfigs/script?host={node.name}')
        want(marker in script, 'the reinstall script does not recreate the new mount')
        ssh(node.name, 'bash -n', stdin=script)
        cli_script = demo.cli('config', 'script', node.name)
        want(marker in cli_script, 'the CLI\'s script does not have it')
        req = urllib.request.Request(demo.BASE + f'/api/hostconfigs/bundle?host={node.name}')
        with api.web.open(req, timeout=120) as resp:
            names = tarfile.open(fileobj=io.BytesIO(resp.read()), mode='r:gz').getnames()
        want(any(n.endswith('.sh') for n in names), f'the bundle has no script: {names[:8]}')
        in_container('storageforge-index config export -o /tmp/sf-t13.tar.gz && python -m tarfile -l /tmp/sf-t13.tar.gz >/dev/null')
        return f'{len(newer)} versions, the diff shows the fstab edit, and bash accepts the reinstall script on the host'
    return run


def reinstall_runs(api, node):
    """The script's whole point: on the host itself, a mount removed since the scan comes back."""
    def run():
        marker = f'/mnt/sf-t13-re-{node.name}'
        sudo(node.name, f"mkdir -p {marker}; echo 'tmpfs {marker} tmpfs nofail,noauto 0 0' >>/etc/fstab")
        rescan(api, node)
        script = api.text(f'/api/hostconfigs/script?host={node.name}')
        sudo(node.name, f"sed -i '\\#{marker}#d' /etc/fstab; rmdir {marker}")
        ssh(node.name, 'sudo -n tee /root/sf-t13-reinstall.sh >/dev/null', stdin=script)
        out = sudo(node.name, 'bash /root/sf-t13-reinstall.sh --help 2>&1')
        want('--apply' in out, f'the script says nothing about how to run it: {out[-300:]}')
        out = sudo(node.name, 'bash /root/sf-t13-reinstall.sh 2>&1; true')
        want(marker not in sudo(node.name, 'cat /etc/fstab'), f'the report changed fstab: {out[-300:]}')
        out = sudo(node.name, 'bash /root/sf-t13-reinstall.sh --apply 2>&1; true')
        want(marker in sudo(node.name, 'cat /etc/fstab'), f'--apply did not bring the mount back: {out[-600:]}')
        return 'an fstab line deleted after the scan came back on --apply'
    return run


def views(api, vms, ids):
    """Canvas, markdown, file map and structure: each names what the VMs really have."""
    names = [n.name for n in vms]

    def canvas():
        with api.web.open(urllib.request.Request(demo.BASE + '/api/canvas'), timeout=300) as resp:
            doc = json.loads(resp.read())
            want('attachment' in resp.headers.get('Content-Disposition', ''), 'not offered as a download')
        want(doc.get('nodes') and doc.get('edges') is not None, f'not a canvas: {list(doc)}')
        text = json.dumps(doc)
        missing = [n for n in names if n not in text]
        want(not missing, f'{missing} are not on the canvas')
        known = {n['id'] for n in doc['nodes']}
        dangling = [e for e in doc['edges'] if e['fromNode'] not in known or e['toNode'] not in known]
        want(not dangling, f'{len(dangling)} edges point at nothing, which Obsidian refuses')
        want(demo.cli('canvas', '--host', names[0]).lstrip().startswith('{'), 'the CLI printed no canvas')
        return f'{len(doc["nodes"])} nodes, {len(doc["edges"])} edges, nothing dangling'

    def markdown():
        text = demo.cli('export-markdown')
        missing = [n for n in names if n not in text]
        want(not missing, f'{missing} are not in the report')
        for n in vms:
            mp = ssh(n.name, f'findmnt -n -o TARGET --target {shlex.quote(n.data)}').strip()
            want(mp in text, f'{n.name}: its mount {mp} is not in the report')
        return f'{len(text.splitlines())} lines naming every host and its data mount'

    def filemap():
        got = api.get('/api/filemap?min_size=1KiB&folders=1')
        text = json.dumps(got)
        want(got and any(n in text for n in names), f'the file map names no host: {text[:300]}')
        want(status_of(api, 'GET', f'/api/filemap?host={names[0]}&min_size=1KiB') == 200, 'one host\'s file map failed')
        before = api.get('/api/files/ignore')['ignore']
        api('PUT', '/api/files/ignore', {'host': '', 'paths': ['/sf-t13-ignored']})
        now = api.get('/api/files/ignore')['ignore']
        want('/sf-t13-ignored' in json.dumps(now), f'an ignored path was not kept: {now}')
        api('PUT', '/api/files/ignore', {'host': '', 'paths': before.get('*', [])})
        return 'lists hosts, and an ignored path is kept'

    def structure():
        for n in vms:
            graph = api.get(f'/api/graph?host={n.name}')
            want(graph.get('nodes'), f'{n.name} has no graph')
        stats = demo.cli('graph', 'stats')
        want(stats.strip(), 'graph stats printed nothing')
        demo.cli('graph', 'build', '--host', names[0])
        return f'a graph for each of {len(vms)} hosts, and it rebuilds'
    return {'canvas': canvas, 'markdown': markdown, 'file-map': filemap, 'structure-graph': structure}


def browse(api, node, root):
    def run():
        got = api.get(f'/api/browse?host={node.name}&path={root}/lab-seed')
        text = json.dumps(got)
        want('shared' in text and 'dupes' in text, f'the seed folders are not listed: {text[:300]}')
        fs = api.get(f'/api/fs/browse?host={node.name}&path={root}/lab-seed')
        want('shared' in json.dumps(fs), f'/api/fs/browse: {str(fs)[:300]}')
        return 'the seed folders are listed'
    return run


def planner(api, node):
    def run():
        hosts = {h['host'] for h in api.get('/api/planner/hosts')['hosts']}
        want(node.name in hosts, f'{node.name} is not offered: {hosts}')
        design = api.get(f'/api/planner/design?host={node.name}&source=scan')
        bp = design['blueprint']
        mp = ssh(node.name, f'findmnt -n -o TARGET --target {shlex.quote(node.data)}').strip()
        want(mp in json.dumps(bp), f'the design read from the scan does not hold {mp}')
        api.post('/api/planner/changes', bp)    # nothing changed: this is the answer that must not fail
        api('PUT', '/api/planner/design', bp)
        saved = api.get(f'/api/planner/design?host={node.name}&source=saved')
        want(saved['source'] == 'saved', f'not saved: {saved["source"]}')
        act = api.get(f'/api/planner/activity?host={node.name}')
        want(isinstance(act, dict), f'activity: {act}')
        api('PUT', '/api/planner/offsite', {'host': node.name, 'offsite': True})
        want(api.get(f'/api/planner/design?host={node.name}')['offsite'] is True, 'offsite did not stick')
        api('PUT', '/api/planner/offsite', {'host': node.name, 'offsite': False})
        return 'a design read from a scan names the real mount, saves and compares'
    return run


# ── keys and identity ───────────────────────────────────────────────
def host_identity(api, node):
    def run():
        code, out, err = cli_rc('hosts', 'keys', node.name)
        want(code == 0, f'known keys only, and exit {code}: {out[-300:]} {err[-200:]}')
        pair = 'ssh-keygen -q -t ed25519 -N "" -f /tmp/sf-t13-key -C sf-t13 <<<y >/dev/null 2>&1; cat /tmp/sf-t13-key.pub'
        pub = ssh(node.name, f"bash -c {shlex.quote(pair)}").strip()
        demo.install_key(node.name, 'scan', pub)
        rescan(api, node)
        fp = ssh(node.name, 'ssh-keygen -lf /tmp/sf-t13-key.pub').split()[1]
        code, out, _ = cli_rc('hosts', 'keys', node.name)
        want(code == 1 and fp in out, f'a key nobody knows, and exit {code}: {out[-300:]}')
        demo.cli('hosts', 'allow-key', fp, '--note', 'tier 13')
        code, out, _ = cli_rc('hosts', 'keys', node.name)
        want(code == 0, f'allowed, and exit {code}: {out[-300:]}')
        demo.cli('hosts', 'disallow-key', fp)
        code, _, _ = cli_rc('hosts', 'keys', node.name)
        want(code == 1, f'disallowed, and exit {code}')
        sudo(node.name, f"sed -i '/sf-t13/d' ~scan/.ssh/authorized_keys")
        return 'an unknown key on the host is reported, allowing and disallowing it works'
    return run


def vault_cli(api, node):
    def run():
        want('lab-scan' in demo.cli('vault', 'list'), 'vault list has no lab-scan')
        demo.cli('vault', 'status')
        want(demo.cli('vault', 'pubkey', '--name', 'lab-scan').startswith('ssh-'), 'vault pubkey printed no key')
        want(node.ip in demo.cli('vault', 'bindings'), 'vault bindings has no row for the host')
        want('lab-scan' in demo.cli('vault', 'resolve', '--host', node.ip), 'vault resolve chose another key')
        out = demo.cli('vault', 'generate', '--name', 'sf-t13')
        want('ssh-ed25519' in out, f'vault generate: {out[-200:]}')
        demo.cli('vault', 'bind', '--key', 'sf-t13', '--host', 'sf-t13-*', '--user', 'scan')
        bid = next(b['binding_id'] for b in api.get('/api/keys')['bindings'] if b['key'] == 'sf-t13')
        status, conflict = api.raw('DELETE', '/api/keys/sf-t13')
        if status == 403 and conflict.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            status, conflict = api.raw('DELETE', '/api/keys/sf-t13')
        want(status == 409, f'a key with a binding was deleted: {status} {conflict}')
        api('DELETE', f'/api/bindings/{bid}')
        api('DELETE', '/api/keys/sf-t13')
        want('sf-t13' not in demo.cli('vault', 'list'), 'the key is still there')
        return 'list, status, pubkey, bindings, resolve, generate and removal'
    return run


# ── accounts ────────────────────────────────────────────────────────
def accounts(api, node):
    def run():
        word = 'Lab-viewer-pw-' + hashlib.sha256(api.password.encode()).hexdigest()[:12]
        api.post('/api/users', {'username': 'lab-viewer', 'password': word, 'role': 'viewer'})
        viewer = fresh_login('lab-viewer', word)
        want(viewer.raw('GET', '/api/me')[1].get('username') == 'lab-viewer', 'cannot sign in')
        want(viewer.raw('GET', f'/api/search?q=a&host={node.name}')[0] == 200, 'a viewer cannot search')
        code, out = viewer.raw('POST', '/api/scan', {'host': node.ip})
        want(code == 403, f'a viewer started a scan: {code} {out}')
        code, out = viewer.raw('POST', '/api/users', {'username': 'x', 'password': word, 'role': 'admin'})
        want(code == 403, f'a viewer made an admin: {code} {out}')

        catalog = api.get('/api/roles')['catalog']
        scan_perm = 'scans.run'
        want(scan_perm in [p['name'] for g in catalog for p in g['permissions']], f'the catalogue has no {scan_perm}')
        api.post('/api/roles', {'name': 'lab-scanner', 'description': 'tier 13', 'permissions': [scan_perm]})
        api('PUT', '/api/users/lab-viewer', {'role': 'lab-scanner'})
        scanner = fresh_login('lab-viewer', word)
        code, out = scanner.raw('POST', '/api/scan', {'host': node.ip})
        want(code == 202, f'a custom role with {scan_perm} cannot scan: {code} {out}')
        code, out = scanner.raw('POST', '/api/users', {'username': 'x', 'password': word, 'role': 'admin'})
        want(code == 403, f'a custom role made an admin: {code} {out}')

        api('PUT', '/api/users/lab-viewer', {'disabled': True})
        locked = demo.Api(word)
        code, _ = locked.raw('POST', '/api/login', {'username': 'lab-viewer', 'password': word})
        want(code in (401, 403), f'a disabled account signed in: {code}')
        api('PUT', '/api/users/lab-viewer', {'disabled': False})

        token = api.post('/api/users/lab-viewer/reset-link')['token']
        anon = demo.Api(word)
        want(anon.raw('POST', '/api/enroll/check', {'token': token})[0] == 200, 'the reset link is not accepted')
        new = word + '-reset'
        code, out = anon.raw('POST', '/api/enroll', {'token': token, 'username': 'lab-viewer', 'password': new})
        want(code == 200, f'reset: {code} {out}')
        old = demo.Api(word)
        want(old.raw('POST', '/api/login', {'username': 'lab-viewer', 'password': word})[0] in (401, 403), 'the old password still signs in')
        want(fresh_login('lab-viewer', new).raw('GET', '/api/me')[0] == 200, 'the new password does not sign in')
        want(anon.raw('POST', '/api/enroll/check', {'token': token})[0] == 403, 'a used link still works')

        invite = api.post('/api/invites', {'role': 'viewer', 'hours': 1, 'note': 'tier 13'})
        code, out = anon.raw('POST', '/api/enroll', {'token': invite['token'], 'username': 'lab-invited', 'password': word})
        want(code == 200, f'invite: {code} {out}')
        want(fresh_login('lab-invited', word).raw('GET', '/api/me')[0] == 200, 'the invited account cannot sign in')
        revoked = api.post('/api/invites', {'role': 'viewer', 'hours': 1})
        api('DELETE', f'/api/invites/{revoked["id"]}')
        want(anon.raw('POST', '/api/enroll/check', {'token': revoked['token']})[0] == 403, 'a revoked invite still works')

        listed = demo.cli('user', 'list')
        want('lab-invited' in listed and 'lab-viewer' in listed, f'user list: {listed}')
        api('DELETE', '/api/users/lab-invited')
        api('DELETE', '/api/users/lab-viewer')
        api('DELETE', '/api/roles/lab-scanner')
        code, out = api.raw('DELETE', '/api/users/demo')
        if code == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            code, out = api.raw('DELETE', '/api/users/demo')
        want(code >= 400, 'the last admin was removed')
        return 'viewer, custom role, disable, reset link, invite and revoke, all through real sign-ins'
    return run


# ── audit, log, backups ─────────────────────────────────────────────
def activity_log(api, node):
    def run():
        marker = 'sf-t13-log-' + str(int(time.time()))
        task = api.post('/api/tasks', {'name': marker, 'host': node.name, 'schedule': '*-*-* 04:00:00', 'blocks': [{'type': 'log', 'params': {'message': marker}}]})
        demo.deploy(api, 'tasks', task['id'], marker)
        page = api.get(f'/api/log?host={node.name}&limit=500')
        want(page['entries'], 'the log is empty for a host just deployed to')
        want(any(marker in json.dumps(e) for e in page['entries']), f'the deploy of {marker} is not in the log')
        deployed = next(e for e in page['entries'] if e.get('source') == 'deploy')
        out = api.get(f'/api/log/output?id={deployed["id"]}')
        want(out['output'], f'no output for {deployed["id"]}')
        filtered = api.get(f'/api/log?host={node.name}&sources=deploy&limit=500')['entries']
        want(filtered and all(e['source'] == 'deploy' for e in filtered), 'the source filter let others through')
        none = api.get(f'/api/log?q={marker}-no-such&limit=10')['entries']
        want(not none, 'a search for nothing found entries')
        with api.web.open(urllib.request.Request(demo.BASE + f'/api/log/export?host={node.name}&format=csv'), timeout=120) as resp:
            rows = list(csv.reader(io.StringIO(resp.read().decode())))
        want(len(rows) > 1 and marker in json.dumps(rows), f'the CSV has {len(rows)} rows, none with {marker}')
        printed = demo.cli('log', '--host', node.name, '--grep', marker)
        want(marker in printed, 'the CLI does not find it')
        want(demo.cli('log', '--host', node.name, '--format', 'json', '--limit', '20').strip(), 'the CLI\'s JSON is empty')
        return f'{len(page["entries"])} entries, filters, output, CSV and CLI all find a real deploy'
    return run


def backups(api, node):
    def run():
        made = api.post('/api/backups', {})
        folder_there = shlex.quote(str(Path(made['path']).parent))
        count = lambda: int(in_container(f'ls {folder_there} | wc -l').strip())    # noqa: E731
        before = count()
        listed = api.get('/api/backups')['backups']
        want(any(b['path'] == made['path'] for b in listed), f'{made["path"]} is not listed')
        printed = demo.cli('backup', 'list')
        want(Path(made['path']).name in printed, 'the CLI does not list it')
        demo.cli('backup', 'create')
        want(count() == before + 1, f'the CLI made no new file: {before} then {count()}')

        folder = f'{node.room}/sf-t13-backups'
        api('PUT', '/api/backups/target', {'host': node.name, 'path': folder})
        code, out = api.raw('PUT', '/api/backups/target', {'host': node.name, 'path': '../etc'})
        want(code == 400, f'a relative path was accepted: {code} {out}')
        copied = api.post('/api/backups', {})
        want(not copied.get('copy_error'), f'the copy failed: {copied.get("copy_error")}')
        name = Path(copied['path']).name + '.enc'
        there = sudo(node.name, f'ls -l {shlex.quote(folder)}')
        want(name in there and '.part' not in there, f'{name} did not arrive whole: {there}')
        want(sudo(node.name, f'head -c 15 {shlex.quote(folder)}/{shlex.quote(name)}') != 'SQLite format 3', 'the copy is in the clear')
        api('PUT', '/api/backups/target', {'host': '', 'path': ''})
        return f'made, listed and copied to {node.name}, encrypted. Tier 3 restores from a copy'
    return run


def audit_chain():
    """Change one row, as someone with the database file could: verify must point at it."""
    def run():
        before = lines_of(demo.cli('audit', 'tail', '--limit', '5', '--format', 'json'))
        want(before, 'the audit log is empty')
        code, out, err = cli_rc('audit', 'verify')
        want(code == 0, f'an untouched log fails: {out[-300:]} {err[-300:]}')
        row = t.sql("SELECT audit_id, outcome FROM audit_log WHERE outcome = 'ok' ORDER BY audit_id DESC LIMIT 1 OFFSET 3")[0]
        change = f"UPDATE audit_log SET outcome = 'denied' WHERE audit_id = {row['audit_id']}"
        try:
            sql_write(change)
            demo.fail('the database took a change to the audit log')
        except demo.DemoError as exc:
            want('the database took' not in str(exc), str(exc))      # refused by its trigger: now as someone who can drop that
        triggers = t.sql("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'")
        want(triggers, 'the audit log has no triggers')
        for x in triggers:
            sql_write(f'DROP TRIGGER {x["name"]}')
        sql_write(change)
        code, out, err = cli_rc('audit', 'verify')
        sql_write(f"UPDATE audit_log SET outcome = '{row['outcome']}' WHERE audit_id = {row['audit_id']}")
        for x in triggers:
            sql_write(x['sql'])
        want(code != 0, f'a changed row passed: {out[-300:]}')
        want(str(row['audit_id']) in out + err, f'verify does not name row {row["audit_id"]}: {out[-300:]} {err[-300:]}')
        code, _, _ = cli_rc('audit', 'verify')
        want(code == 0, 'putting the row back does not verify')
        return f'refused by the database; with its triggers dropped, row {row["audit_id"]} changed, and verify failed and named it'
    return run


def retire_host(api, node):
    def run():
        probe = 'IMG_0001.cr2'
        want(any(h['host'] == node.name for h in api.get(f'/api/search?q={probe}&limit=500')['results']), 'the host has no search hits to lose')
        plan = api.post('/api/moves', {'name': 'tier 13 retire', 'steps': [{'method': 'mirror', 'src': {'host': node.name, 'path': f'{node.data}/lab-seed/shared'},
                                                                            'dst': {'host': node.name, 'path': f'{node.room}/sf-t13-mirror'}, 'options': {'schedule': 'daily'}}]})
        demo.deploy(api, 'jobs', plan['id'], 'tier 13 retire')
        code, out = api.raw('DELETE', f'/api/hosts/{node.name}')
        if code == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            code, out = api.raw('DELETE', f'/api/hosts/{node.name}')
        want(code == 409 and 'still in use' in out.get('error', ''), f'retired with a job deployed: {code} {out}')
        demo.deploy(api, 'jobs', plan['id'], 'tier 13 retire, removing', remove=True)
        api('DELETE', f'/api/moves/{plan["id"]}')
        for row in t.sql(f"SELECT kind, ref FROM deployed WHERE lower(host) = lower('{node.name}')"):
            demo.fail(f'still deployed after removal: {row}')
        gone = api('DELETE', f'/api/hosts/{node.name}')
        want(gone['host'] == node.name, f'retire: {gone}')
        hosts = {h['hostname'] for h in api.get('/api/hosts')['indexed']}
        want(node.name not in hosts, 'still in the host list')
        want(not any(h['host'] == node.name for h in api.get(f'/api/search?q={probe}&limit=500')['results']), 'still in search')
        want(not api.get(f'/api/graph?host={node.name}').get('nodes'), 'still in the graph')
        want(api.raw('GET', f'/api/hosts/{node.name}/schedule')[0] == 404, 'its schedule still answers')
        want(any(e.get('action') == 'hosts.retire' for e in api.get('/api/audit?limit=20')['entries']), 'the retirement is not audited')
        code, out, err = cli_rc('hosts', 'remove', node.name)
        want(code != 0, f'retired twice: {out}')
        # the name can come back with a new scan
        demo.install_key(node.name, 'scan', next(k['public_key'] for k in api.get('/api/keys')['keys'] if k['name'] == 'lab-scan'))
        demo.cli('vault', 'bind', '--key', 'lab-scan', '--host', node.ip, '--user', 'scan', '--actions', 'scan,checksum')
        rescan(api, node)
        want(node.name in {h['hostname'] for h in api.get('/api/hosts')['indexed']}, 'a rescan did not bring it back')
        return 'refused with a job there, gone from search, graph and hosts after, and back with a new scan'
    return run


# ── snapshot jobs ───────────────────────────────────────────────────
def snapjobs_rsnapshot(api, node):
    """A job StorageForge did not deploy: found by a scan, imported without changing the host, and its runs read back."""
    def run():
        root = f'{node.room}/sf-t13-rsnap'
        conf = (f'config_version\t1.2\nsnapshot_root\t{root}/\ncmd_rsync\t/usr/bin/rsync\nretain\tdaily\t3\nlockfile\t/run/sf-t13-rsnapshot.pid\n'
                f'backup\t{node.data}/lab-seed/shared/\tlocal/\n')
        if node.pm == 'dnf' and 'fedora' not in node.name:
            sudo(node.name, 'dnf -q -y install epel-release >/dev/null')     # rsnapshot comes from EPEL
        sudo(node.name, 'command -v rsnapshot >/dev/null || { apt-get -o DPkg::Lock::Timeout=300 -qq install -y rsnapshot || dnf -q -y install rsnapshot || zypper -q -n install rsnapshot; } >/dev/null 2>&1')
        ssh(node.name, 'sudo -n tee /etc/rsnapshot-sft13.conf >/dev/null', stdin=conf)
        sudo(node.name, f'mkdir -p {root}; rsnapshot -c /etc/rsnapshot-sft13.conf daily')
        before = sudo(node.name, f'sha256sum {node.data}/lab-seed/shared/docs/handbook.txt').split()[0]
        hash_there = sudo(node.name, f'sha256sum {root}/daily.0/local/{node.data}/lab-seed/shared/docs/handbook.txt').split()[0]     # rsync --relative keeps the whole path
        want(before == hash_there, 'the job itself did not work: this test is wrong')
        rescan(api, node)
        api.post('/api/deploy/snapjobs/probe', {'host': node.name})
        found = [j for j in api.get('/api/deploy/snapjobs')['found'] if j.get('host') == node.name and j.get('config') == '/etc/rsnapshot-sft13.conf']
        want(found, 'the job is not found')
        want(found[0]['root'].rstrip('/') == root, f'its root reads {found[0].get("root")}')
        ran_before = sudo(node.name, f'stat -c %Y /etc/rsnapshot-sft13.conf')
        job = api.post('/api/deploy/snapjobs/import', {'host': node.name, 'tool': 'rsnapshot', 'config': '/etc/rsnapshot-sft13.conf'})['job']
        want(sudo(node.name, 'stat -c %Y /etc/rsnapshot-sft13.conf') == ran_before, 'import changed the host\'s config')
        detail = api.get(f'/api/deploy/jobs/{job}')
        want(detail['job']['method'] == 'rsnapshot' if 'job' in detail else detail.get('method') == 'rsnapshot', f'the job reads {str(detail)[:300]}')
        adv = api.get(f'/api/deploy/snapjobs/advice?host={node.name}&path={node.data}')
        want(adv.get('fstype'), f'advice: {adv}')
        api.post(f'/api/deploy/jobs/{job}/forget')
        return f'found, imported as {job}, and the config untouched'
    return run


def snapjobs_snapper(api, node):
    def run():
        path = node.subvol
        name = 'sft13'
        out = api.post('/api/deploy/snapjobs/snapper', {'host': node.name, 'path': path, 'name': name})
        want(out['status'] == 'ok', f'snapper: {out["status"]}: {out.get("output", "")[-500:]}')
        have = sudo(node.name, 'snapper list-configs')
        want(name in have and path in have, f'snapper on the host says: {have}')
        job = out['job']
        sudo(node.name, f'snapper -c {name} create --description sf-t13')     # as its timer would: under SELinux this needs the label
        sudo(node.name, 'systemctl stop snapperd; systemctl start snapper-timeline.service')      # and from a new daemon, as the next timer run has
        taken = t.wait_for('a timeline snapshot', lambda: (lambda x: x if 'timeline' in x else None)(sudo(node.name, f'snapper -c {name} list')), 60)
        want('first snapshot' in taken and 'sf-t13' in taken, f'snapper did not take all three: {taken}')
        journal = sudo(node.name, 'journalctl -u snapper-timeline -n 5 --no-pager')
        want('failed' not in journal.splitlines()[-1], f'the timeline run failed: {journal[-300:]}')
        api.post('/api/deploy/snapjobs/probe', {'host': node.name})
        found = next(j for j in api.get('/api/deploy/snapjobs')['found'] if j.get('host') == node.name and j.get('config') == name)
        want(found['count'] >= 2, f'two snapshots on the host, and it reads: {found}')
        sudo(node.name, f'snapper -c {name} delete-config 2>/dev/null; true')
        return f'{job}: a real config on {path} takes snapshots, and they are read'
    return run


# ── ClamAV ──────────────────────────────────────────────────────────
def clamav(api, node):
    """Install, a real detection of the EICAR test file, then quarantine, restore and ignore, each checked on the host."""
    def run():
        folder = f'{node.room}/sf-t13-av'
        sudo(node.name, f'mkdir -p {folder}')
        status, out = api.raw('POST', '/api/deploy/start', {'kind': 'clamav', 'ref': node.name, 'mode': 'report'})
        if status == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            status, out = api.raw('POST', '/api/deploy/start', {'kind': 'clamav', 'ref': node.name, 'mode': 'report'})
        want(status < 300, f'the dry run: {status} {out}')
        said = demo.wait('its dry run', lambda: demo.finished(api, out['group']), 300)['runs'][0].get('output') or ''
        memory = int(sudo(node.name, "awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo").strip())
        want(memory >= 2048 or 'MiB of memory' in said and 'conflict' in said, f'{memory} MiB, and the script does not say so: {said[-300:]}')
        # ClamAV refuses under 2 GiB, and the lab's biggest VMs are "2 GB" with less to show for it. Enough to run it, so past the guard only
        sudo(node.name, "awk '/^MemTotal:/ {print \"MemTotal: 4194304 kB\"; next} {print}' /proc/meminfo >/run/sf-t13-meminfo; mount --bind /run/sf-t13-meminfo /proc/meminfo")
        ssh(node.name, f'sudo -n tee {folder}/eicar.com >/dev/null', stdin=EICAR)
        api.post(f'/api/clamav/hosts/{node.name}/config', {'schedule': 'weekly', 'paths': [folder]})
        demo.deploy(api, 'clamav', node.name, 'ClamAV')
        demo.deploy(api, 'clamav', node.name, 'ClamAV run', run=True)
        unit = sudo(node.name, 'systemctl list-timers --all --no-pager | grep -i clam || true')
        want(unit.strip(), 'no ClamAV timer on the host')

        def detected():
            api.post(f'/api/clamav/hosts/{node.name}/collect')
            return [d for d in api.get(f'/api/clamav?host={node.name}')['detections'] if 'eicar.com' in json.dumps(d)]
        found = t.wait_for('the EICAR file to be found', detected, 600)
        did = found[0]['id']
        path = f'{folder}/eicar.com'
        before = sudo(node.name, f'sha256sum {path}').split()[0]
        code, out, _ = cli_rc('clamav', 'list', '--host', node.name)
        want(code == 1 and 'eicar' in out.lower(), f'the CLI sees nothing open: {code} {out[-200:]}')

        api.post(f'/api/clamav/detections/{did}/quarantine', {})
        want(quiet(node.name, f'test -e {path}') != 0, 'quarantined, and the file is still there')
        api.post(f'/api/clamav/detections/{did}/restore', {})
        want(sudo(node.name, f'sha256sum {path}').split()[0] == before, 'restored with other bytes')
        api.post(f'/api/clamav/detections/{did}/ignore', {'ignore': True, 'reason': 'the EICAR test file'})
        want(api.get(f'/api/clamav?host={node.name}')['detections'][0]['ignore_reason'] == 'the EICAR test file', 'the reason was not kept')
        code, out, _ = cli_rc('clamav', 'list', '--host', node.name)
        want(code == 0, f'restored means someone decided it is safe, and it still counts as open: {code} {out[-200:]}')
        demo.deploy(api, 'clamav', node.name, 'ClamAV removal', remove=True)
        sudo(node.name, 'umount /proc/meminfo')
        return 'found, quarantined, restored with the same bytes, ignored, and removed'
    return run


# ── guests that only a measurement can see ──────────────────────────
def lxc_guests(api, node):
    """Plain LXC: progress.md had these parsed and unit-tested only. A real container, created without a network image."""
    def run():
        sudo(node.name, apt_install('lxc busybox-static'))
        sudo(node.name, 'lxc-info -n sft13 >/dev/null 2>&1 || lxc-create -q -n sft13 -t busybox')
        real = sudo(node.name, 'lxc-ls -1').split()
        want('sft13' in real, f'lxc-ls: {real}')
        api.post('/api/infra/measure', {'host': node.name})
        got = [w for w in api.get(f'/api/workloads?host={node.name}')['workloads'] if w['name'] == 'sft13']
        want(got and got[0]['runtime'] == 'lxc', f'the container is on the host and reads as {got}')
        want('sft13' in json.dumps(api.get(f'/api/map?host={node.name}')), 'the container is in the workload list and not on the map')
        sudo(node.name, 'lxc-destroy -q -n sft13')
        return 'a real LXC container is on the map'
    return run


def incus_guests(api, node):
    def run():
        sudo(node.name, apt_install('incus'))
        sudo(node.name, 'incus admin init --minimal >/dev/null 2>&1; incus create --empty sft13i 2>&1 >/dev/null || incus init --empty sft13i >/dev/null')
        want('sft13i' in sudo(node.name, 'incus list -c n -f csv'), 'the instance was not made')
        api.post('/api/infra/measure', {'host': node.name})
        got = [w for w in api.get(f'/api/workloads?host={node.name}')['workloads'] if w['name'] == 'sft13i']
        want(got and got[0]['runtime'] == 'incus', f'the instance is on the host and reads as {got}')
        want('sft13i' in json.dumps(api.get(f'/api/map?host={node.name}')), 'the instance is in the workload list and not on the map')
        sudo(node.name, 'incus delete -f sft13i')
        return 'a real Incus instance is on the map'
    return run


def map_views(api, node):
    """The map's detail panes and reports, on what a measurement really read. The firewall and reach tiers check the facts: these check the routes."""
    def run():
        api.post('/api/infra/measure', {'host': node.name})
        graph = api.get(f'/api/map?host={node.name}')
        want(graph['nodes'] and graph['edges'], 'nothing on the map')
        node_id = next(n['id'] for n in graph['nodes'] if n.get('host') == node.name or n['label'] == node.name)
        detail = api.get('/api/map/node/' + urllib.parse.quote(node_id, safe=':/'))
        want(detail['node']['id'] == node_id, f'node: {str(detail)[:200]}')
        want(api.raw('GET', '/api/map/node/no-such-thing')[0] == 404, 'a node that is not there was found')
        e = graph['edges'][0]
        q = urllib.parse.urlencode({'src': e['src'], 'dst': e['dst'], 'rel': e['rel']})
        want(api.get(f'/api/map/edge?{q}')['edge']['rel'] == e['rel'], 'the edge did not come back')
        want(api.raw('GET', '/api/map/edge?src=a&dst=b&rel=c')[0] == 404, 'an edge that is not there was found')
        exposure = api.get(f'/api/map/exposure?host={node.name}')['hosts'][0]
        ports = {i['port'] for i in exposure['items']}
        want(22 in ports, f'SSH answers on this host, and exposure lists {sorted(ports)}')
        want(api.raw('GET', '/api/map/exposure?scope=mars')[0] == 400, 'a scope that is not one was accepted')
        coverage = api.get(f'/api/map/coverage?host={node.name}')
        want(coverage['coverage'], f'coverage: {coverage}')
        return f'{len(graph["nodes"])} nodes: node, edge, exposure with SSH on 22, and coverage'
    return run


# ── the deploy page's actions ───────────────────────────────────────
def deploy_actions(api, node):
    def run():
        task = api.post('/api/tasks', {'name': 'sf-t13-actions', 'host': node.name, 'schedule': '*-*-* 05:00:00', 'blocks': [
            {'type': 'command', 'params': {'cmd': 'sleep 90; echo finished'}}]})
        check = api.post('/api/deploy/check', {'host': node.name})
        want(check['deployable'] and check['source'] == 'probe', f'a host set up for deploys reads: {str(check)[:300]}')
        started = api.post('/api/deploy/start', {'kind': 'tasks', 'ref': task['id'], 'mode': 'report'})
        group = started['group']
        demo.wait('the dry run', lambda: demo.finished(api, group), 300)
        # a stale dry run: the plan changed since someone read it
        api('PUT', f'/api/tasks/{task["id"]}', {'name': 'sf-t13-actions', 'host': node.name, 'schedule': '*-*-* 05:30:00', 'blocks': [
            {'type': 'command', 'params': {'cmd': 'sleep 90; echo changed'}}]})
        status, out = api.raw('POST', '/api/deploy/start', {'kind': 'tasks', 'ref': task['id'], 'mode': 'apply', 'report_group': group})
        if status == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            status, out = api.raw('POST', '/api/deploy/start', {'kind': 'tasks', 'ref': task['id'], 'mode': 'apply', 'report_group': group})
        want(status == 409 and out.get('stale'), f'applied a plan changed since its dry run: {status} {out}')
        listed = api.get('/api/deploy/groups')
        want(group in json.dumps(listed), 'the group is not listed')
        runs = api.get('/api/deploy/runs')
        want(runs, 'no runs listed')
        run_id = runs['runs'][0]['run_id']
        want('output' in api.get(f'/api/deploy/runs/{run_id}'), 'a run has no output field')

        api('PUT', f'/api/tasks/{task["id"]}', {'name': 'sf-t13-actions', 'host': node.name, 'schedule': '*-*-* 05:30:00', 'blocks': [
            {'type': 'command', 'params': {'cmd': 'sleep 90; echo changed'}}]})
        demo.deploy(api, 'tasks', task['id'], 'actions')
        started = api.post('/api/deploy/start', {'kind': 'tasks', 'ref': task['id'], 'mode': 'apply', 'run': True, 'title': 'to cancel'})
        time.sleep(5)
        api.post(f'/api/deploy/groups/{started["group"]}/cancel', {'force': True})
        done = demo.wait('the cancel', lambda: demo.finished(api, started['group']), 180)
        want(any(r['status'] == 'cancelled' for r in done['runs']), f'cancel: {[r["status"] for r in done["runs"]]}')
        status_ = status_of(api, 'POST', f'/api/deploy/groups/{started["group"]}/retry')
        want(status_ < 500, f'retry: HTTP {status_}')

        code = status_of(api, 'POST', '/api/deploy/settings/test', {})
        want(code < 500, f'the test message: HTTP {code}')
        with urllib.request.urlopen(f'{demo.NTFY}/{demo.TOPIC}/json?poll=1&since=5m', timeout=30) as resp:
            want(resp.read().strip(), 'the test message did not reach ntfy')
        demo.deploy(api, 'tasks', task['id'], 'actions, removing', remove=True)
        return 'a stale dry run is refused, a run is cancelled, retried, and the test alert reached ntfy'
    return run


def cli_tour(node):
    """Every read-only command against real data: they must exit well and name what is there."""
    def run():
        must_name = [(('hosts',), node.name), (('search', 'IMG_0001.cr2'), 'IMG_0001.cr2'), (('deploy', 'status'), node.name),
                     (('user', 'list'), 'demo'), (('site', 'show'), ''), (('plan', 'types'), 'dir'), (('access', 'status'), ''),
                     (('moves', 'list'), ''), (('tasks', 'list'), ''), (('schedule', 'list'), ''), (('remote', 'list'), ''),
                     (('plan', 'list'), ''), (('deploy', 'setup-script'), '#!'),
                     (('access', 'script', '--user', 'scan'), '#!'), (('clamav', 'status'), ''), (('migrate',), ''), (('prune', '--days', '90'), '')]
        bad = []
        for args, needle in must_name:
            code, out, err = cli_rc(*args)
            if code != 0 and args[0] != 'search':
                bad.append(f'{" ".join(args)}: exit {code}: {err[-160:]}')
            elif needle and needle not in out:
                bad.append(f'{" ".join(args)}: {needle!r} is not in the output')
        want(not bad, '; '.join(bad))
        ssh('sf-ctl', 'bash -n', stdin=demo.cli('deploy', 'setup-script'))
        code, out, _ = cli_rc('healthcheck')
        want(code == 0, f'healthcheck: {code} {out}')
        return f'{len(must_name)} commands answered with what is there'
    return run


def api_sweep(api):
    """Every route that takes nothing, read from the source: none may answer 5xx on a lab full of real data."""
    def run():
        routes = set()
        for path in (ROOT / 'storageforge_index').glob('*.py'):
            routes.update(re.findall(r"\.get\('(/api/[a-z0-9/_-]+)'\)", path.read_text()))
        bad, counted = [], 0
        api.raw('POST', '/api/reauth', {'password': api.password})

        def status(route):      # only the status: some of these are downloads
            try:
                with api.web.open(urllib.request.Request(demo.BASE + route), timeout=300) as resp:
                    resp.read()
                    return resp.status, ''
            except urllib.error.HTTPError as e:
                return e.code, e.read()[:160]
        for route in sorted(routes):
            code, body = status(route)
            counted += 1
            if code >= 500:
                bad.append(f'{route}: {code} {body}')
        want(counted > 60 and not bad, '; '.join(bad) or f'only {counted} routes')
        return f'{counted} routes answered without a server error'
    return run


def pages(api):
    """The UI itself, on real data: every page and tab loads with no script error. Needs playwright where the tier runs."""
    from playwright.sync_api import sync_playwright
    errors, seen = [], 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append(f'{page.url}: {e}'))
        page.on('response', lambda r: errors.append(f'{r.status} {r.url}') if r.status >= 500 else None)
        page.goto(demo.BASE + '/login')
        page.fill('input[type=text], input[name=username], #username', 'demo')
        page.fill('input[type=password]', api.password)
        page.keyboard.press('Enter')
        page.wait_for_url(lambda u: 'login' not in u, timeout=30000)
        for path in ('/', '/planner', '/manage', '/search'):
            page.goto(demo.BASE + path, wait_until='networkidle', timeout=60000)
            seen += 1
        page.goto(demo.BASE + '/', wait_until='networkidle', timeout=60000)
        tabs = page.locator('nav [data-tab], .tabs [data-tab], button[data-tab]')
        for i in range(tabs.count()):
            try:
                tabs.nth(i).click(timeout=5000)
                page.wait_for_load_state('networkidle', timeout=30000)
                seen += 1
            except Exception as exc:
                errors.append(f'tab {i}: {str(exc)[:160]}')
        browser.close()
    want(seen >= 3 and not errors, '; '.join(errors[:8]) or f'only {seen} views')
    return f'{seen} pages and tabs, no script errors or 5xx'


# ── what takes the server down: last ────────────────────────────────
def compose_run(command):
    return ssh('sf-ctl', f'{COMPOSE} run --rm --no-deps -T storageforge {command}')


def restart_server(api):
    ssh('sf-ctl', f'{COMPOSE} up -d --no-build --wait --quiet-pull >/dev/null 2>&1')
    api.raw('POST', '/api/login', {'username': 'demo', 'password': api.password})


def restore_backup(api):
    def run():
        made = api.post('/api/backups', {})
        word = 'Lab-after-backup-' + hashlib.sha256(api.password.encode()).hexdigest()[:12]
        api.post('/api/users', {'username': 'lab-after-backup', 'password': word, 'role': 'viewer'})
        want('lab-after-backup' in demo.cli('user', 'list'), 'the account was not made')
        ssh('sf-ctl', f'{COMPOSE} stop storageforge proxy >/dev/null 2>&1')
        out = compose_run(f'storageforge-index restore {shlex.quote(made["path"])} --yes')
        want('restored' in out, f'restore: {out[-300:]}')
        restart_server(api)
        names = demo.cli('user', 'list')
        want('demo' in names and 'lab-after-backup' not in names, f'after the restore: {names}')
        code, out, err = cli_rc('vault', 'status')
        want(code == 0, f'the vault does not open after a restore: {err[-200:]}')
        code, out, err = cli_rc('audit', 'verify')
        want(code == 0, f'the audit chain breaks after a restore: {out[-200:]} {err[-200:]}')
        return 'an account made after the backup is gone, and the vault and audit chain still verify'
    return run


def site_and_reset(api, vm):
    def run():
        before = demo.cli('site', 'show').strip()
        want(before, 'no site identity')
        demo.cli('site', 'rename', 'Lab Client')
        want('Lab Client' in demo.cli('site', 'show'), 'the rename did not stick')
        status = demo.cli('site', 'status')
        want(status.startswith('Lab Client'), f'site status: {status}')
        prints = demo.cli('site', 'fingerprints')
        want(prints.strip(), 'no fingerprints')

        ssh('sf-ctl', f'{COMPOSE} stop storageforge proxy >/dev/null 2>&1')
        ssh('sf-ctl', 'sudo -n install -d -o 10001 -g 10001 -m 0700 /opt/storageforge/archive')     # as docs/operations.md says, then the command it gives
        admin = f'{COMPOSE} run --rm -T admin reset --site-name "New Client"'
        p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', admin], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
        want(p.returncode == 2 and 'rerun with --yes' in p.stderr, f'reset ran without --yes: {p.returncode} {p.stderr[-300:]}')
        p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{admin} --yes --abandon-deployed'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
        out = p.stdout + p.stderr
        want(p.returncode == 0 and 'is ready' in out and 'enroll#' in out, f'reset: {p.returncode}: {out[-800:]}')
        want(ssh('sf-ctl', 'sudo -n ls /opt/storageforge/archive').strip(), 'the old site is not in the archive')
        ssh('sf-ctl', 'sudo -n rm -f /opt/storageforge/secrets/vault_secret')
        token = re.search(r'enroll#(\S+)', out)[1]
        restart_server(api)
        want('New Client' in demo.cli('site', 'show'), 'the new site has another name')
        code, listed, _ = cli_rc('hosts')
        want(code != 0 or vm not in listed, f'the old hosts are still indexed: {listed}')
        anon = demo.Api('Lab-new-admin-' + hashlib.sha256(token.encode()).hexdigest()[:12])
        want(anon.raw('POST', '/api/enroll/check', {'token': token})[0] == 200, 'the first admin\'s link is not accepted')
        code, out_ = anon.raw('POST', '/api/enroll', {'token': token, 'username': 'newadmin', 'password': anon.password})
        want(code == 200, f'enroll: {code} {out_}')
        admin = fresh_login('newadmin', anon.password)
        want(admin.raw('GET', '/api/hosts')[0] == 200, 'the new admin cannot sign in')
        return 'renamed, refused without --yes, reset into an empty site, and its first admin signed in'
    return run


def tier13(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    grant_engines()
    vms = roles.deployable()
    seeded = full_seed()
    node, root = seeded[0]
    other, other_root = seeded[1] if len(seeded) > 1 else seeded[0]
    ids = t.host_ids()
    apt = next((n for n in vms if n.pm == 'apt-get' and not n.can('controller') and not n.can('docker')), None)
    apt2 = next((n for n in vms if n.pm == 'apt-get' and not n.can('controller') and n is not apt), None)
    btrfs = next((n for n in vms if n.subvol), None)
    plain = next((n for n in vms if not n.can('controller') and n.name not in (node.name, other.name)), other)
    away = next((n for n in reversed(vms) if not n.can('controller') and n.name not in (node.name, other.name, plain.name)), plain)
    engines = [(n, 'docker') for n in roles.having('docker')] + [(n, 'podman') for n in roles.having('podman')]

    def check(name, vm, fn):
        if not ONLY or name in ONLY:
            r.check(name, vm, fn)

    for host, top in seeded[:2]:
        check('file-changes', host.name, file_changes(api, host, top))
        check('duplicates', host.name, duplicates(api, host, top))
        check('cold-data', host.name, cold_data(api, host, top))
        check('browse', host.name, browse(api, host, top))
    for n in vms[:3]:
        if not n.can('controller'):
            check('capacity-trend', n.name, capacity_trend(api, n))
    for host, engine in engines:
        check(f'containers-{engine}', host.name, containers(api, host, engine))
    check('git', node.name, git_inventory(api, node, root))
    check('host-configs', other.name, host_configs(api, other))
    check('reinstall-apply', plain.name, reinstall_runs(api, plain))
    for name, fn in views(api, [n for n in roles.build().values() if not n.can('controller')], ids).items():
        check(name, '-', fn)
    check('planner', node.name, planner(api, node))
    check('host-identity', other.name, host_identity(api, other))
    check('vault-cli', node.name, vault_cli(api, node))
    check('accounts', node.name, accounts(api, node))
    check('activity-log', node.name, activity_log(api, node))
    check('backups', other.name, backups(api, other))
    check('audit-chain', '-', audit_chain())
    check('snapjobs-rsnapshot', plain.name, snapjobs_rsnapshot(api, plain))
    if btrfs:
        check('snapjobs-snapper', btrfs.name, snapjobs_snapper(api, btrfs))
    else:
        r.add('snapjobs-snapper', '-', None, 'no btrfs host')
    biggest = max((n for n in vms if not n.can('controller')), key=lambda n: int(ssh(n.name, "awk '/^MemTotal:/ {print $2}' /proc/meminfo").strip()))
    check('clamav', biggest.name, clamav(api, biggest))
    if apt:
        check('lxc-guests', apt.name, lxc_guests(api, apt))
    else:
        r.add('lxc-guests', '-', None, 'no Debian-family host without Docker')
    if apt2:
        check('incus-guests', apt2.name, incus_guests(api, apt2))
    else:
        r.add('incus-guests', '-', None, 'no second Debian-family host')
    check('map-views', node.name, map_views(api, node))
    check('deploy-actions', away.name, deploy_actions(api, away))
    check('scan-schedule', away.name, scan_schedule(api, away))
    check('cli-tour', node.name, cli_tour(node))
    check('api-sweep', '-', api_sweep(api))
    try:
        import playwright  # noqa: F401
        check('ui-pages', '-', lambda: pages(api))
    except ImportError:
        r.add('ui-pages', '-', None, 'playwright is not installed where the tier runs')
    check('retire-host', away.name, retire_host(api, away))
    check('restore-backup', '-', restore_backup(api))
    check('site-and-reset', '-', site_and_reset(api, node.name))
