#!/usr/bin/env python3
"""Tier 25 of the KVM lab: the change engine's exit test (roadmap section 5) and the secret store's boundary.

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real VM:
it is not lab-tested. What was run is tests/test_runtime_install.py (the step against stand-in package managers, with the real gpg)
and tests/test_secretstore.py (the store, the delivery script and the rotation script against folders, the real key enclave). A
first run will most likely have to correct this file before it says anything about StorageForge. A check that cannot be made shows
as skip or as failed, never as passed. The bridge that cuts SSH and rolls itself back, the last part of section 5's exit test, is
tier 26.

    runtime-report      on a host with no container runtime, a plan with runtime-install, reported only: the report says present,
                        installable or blocked for the runtime, and the host is what it was (its packages, enabled units, package
                        sources, subordinate ids and lingering users, hashed before and after)
    runtime-install     the same plan applied from that report on a bare VM: Podman, rootless for the scan account. podman runs, the
                        account has subordinate ids, lingers, and runs a container rootless; a second apply says present
    runtime-docker      Docker from its own repository on an apt host without it: the key on the host is the pinned one, the
                        repository is signed-by that key alone, and docker info answers. No install script was fetched and run
    runtime-libvirt     KVM and libvirt on another bare host: the report says whether /dev/kvm is there, and after the apply virsh
                        answers on qemu:///system
    plan-changed-409    a plan changed after its dry run is refused with 409 when applied from that dry run, and nothing runs
    secret-made-once    a secret made through the web is in its answer and in no list, audit row or later answer
    secret-delivered    a plan with a secret-file step that names the secret, applied: /run/storageforge/secrets and the step's file
                        hold it (mode 600, root), and the value is in no deploy output, no log under /var/log/storageforge, the journal, a process list taken
                        during the run, or the controller database outside its ciphertext
    secret-rotated      a rotation through the web: the host holds the new value under /run, the plan run again puts it in the
                        step's file, and the old one is nowhere on the host
"""
import json
import secrets
import shlex
import time

import demo
import roles

from tiers_platform import quiet, sudo

STATE_HASH = ('{ (dpkg-query -W -f="\\${Package} \\${Version}\\n" 2>/dev/null || rpm -qa 2>/dev/null || pacman -Q 2>/dev/null) | sort; '
              'systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | sort; ls -la /etc/apt/sources.list.d /etc/yum.repos.d /etc/zypp/repos.d 2>/dev/null; '
              'cat /etc/subuid /etc/subgid 2>/dev/null; ls /var/lib/systemd/linger 2>/dev/null; ls /etc/apt/keyrings /etc/pki/rpm-gpg 2>/dev/null; } | sha256sum')
DOCKER_APT_FPR = '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
SECRET = 'lab-secret'
TARGET = '/root/sf-lab-secret'
DUMP = "import sqlite3; print(chr(10).join(sqlite3.connect('/app/data/index.db').iterdump()))"          # the controller database as text


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def report_only(api, plan_id, title):
    group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': plan_id, 'mode': 'report', 'title': title})['group']
    out = demo.wait(title, lambda: demo.finished(api, group))
    return group, out['runs']


def plan(api, name, host, kind, params):
    return api.post('/api/changes', {'name': name, 'tasks': [{'type': kind, 'host': host, 'params': params}]})['id']


def bare(node):
    return not (node.can('docker') or node.can('podman') or node.can('nosystemd')) and node.pm in ('apt-get', 'dnf', 'zypper', 'pacman')


def tier25(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    hosts = [n for n in roles.deployable() if bare(n)]
    if not hosts:
        r.add('runtime-install', '-', None, 'no host of this build is without Docker and Podman and takes deploys')
        return
    node = hosts[0]
    host = demo.known_as(api, node.name)
    state = {}

    def runtime_report():
        want(quiet(node.name, 'command -v podman') != 0, f'{node.name} already has Podman: it is not a bare VM')
        state['plan'] = plan(api, f'lab: podman on {node.name}', host, 'runtime-install', {'runtime': 'podman', 'rootless': True, 'user': 'scan'})
        before = sudo(node.name, STATE_HASH)
        state['report'], runs = report_only(api, state['plan'], f'podman on {node.name}')
        out = said(runs)
        want('installable: podman' in out or 'blocked:' in out, f'the report said neither installable nor blocked:\n{out[-1200:]}')
        want(sudo(node.name, STATE_HASH) == before, 'the report changed the host: packages, units, sources, subordinate ids or lingering differ')
        want(quiet(node.name, 'command -v podman') != 0, 'Podman is there after a report')
        line = next((x for x in out.splitlines() if 'installable:' in x or 'blocked:' in x), '')
        return f'{line.strip()[:160]}; the host is what it was'
    r.check('runtime-report', node.name, runtime_report)

    def runtime_install():
        want(state.get('report'), 'no report to apply from')
        group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': state['plan'], 'mode': 'apply', 'report_group': state['report'], 'title': f'podman on {node.name} (apply)'})['group']
        runs = demo.wait('apply', lambda: demo.finished(api, group))['runs']
        out = said(runs)
        want(all(x['status'] == 'ok' for x in runs), f'the apply ended {[x["status"] for x in runs]}:\n{out[-1500:]}')
        version = demo.ssh(node.name, 'podman --version', check=False).strip()
        want(version.startswith('podman version'), f'podman does not answer: {version!r}')
        want(quiet(node.name, 'grep -q "^scan:" /etc/subuid && grep -q "^scan:" /etc/subgid') == 0, 'the scan account has no subordinate ids')
        want(quiet(node.name, 'test -e /var/lib/systemd/linger/scan') == 0, 'the scan account does not linger')
        rootless = sudo(node.name, 'cd /tmp && runuser -u scan -- podman info --format "{{.Host.Security.Rootless}}"', check=False).strip()
        want(rootless == 'true', f'podman as scan is not rootless: {rootless!r}')
        again = demo.deploy(api, 'changes', state['plan'], f'podman on {node.name} again')
        want('present: podman version' in said(again), f'a second apply did not find it present:\n{said(again)[-800:]}')
        return f'{version}, rootless for scan; a second apply found it present'
    r.check('runtime-install', node.name, runtime_install)

    def changed_409():
        pid = plan(api, f'lab: 409 on {node.name}', host, 'runtime-install', {'runtime': 'lxc'})
        group, _ = report_only(api, pid, f'409 on {node.name}')
        api('PUT', f'/api/changes/{pid}', {'name': f'lab: 409 on {node.name}', 'tasks': [{'type': 'runtime-install', 'host': host, 'params': {'runtime': 'incus'}}]})
        before = sudo(node.name, STATE_HASH)
        out = api('POST', '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'report_group': group, 'title': '409 (apply)'}, expect=409)
        want('changed since this dry run' in out.get('error', ''), f'the refusal does not say why: {out}')
        time.sleep(5)
        want(sudo(node.name, STATE_HASH) == before, 'something ran on the host after the 409')
        api('DELETE', f'/api/changes/{pid}')
        return '409: the plan changed since this dry run, and the host is what it was'
    r.check('plan-changed-409', node.name, changed_409)

    apt = next((n for n in hosts if n.pm == 'apt-get' and n.name != node.name), None)

    def runtime_docker():
        name = demo.known_as(api, apt.name)
        pid = plan(api, f'lab: docker on {apt.name}', name, 'runtime-install', {'runtime': 'docker', 'source': 'vendor'})
        runs = demo.deploy(api, 'changes', pid, f'docker on {apt.name}')
        out = said(runs)
        want(f'Docker signing key {DOCKER_APT_FPR} installed' in out, f'the pinned key was not installed:\n{out[-1200:]}')
        fpr = sudo(apt.name, 'gpg --batch --show-keys --with-colons /etc/apt/keyrings/docker.asc | awk -F: "/^fpr:/ {print \\$10; exit}"').strip()
        want(fpr == DOCKER_APT_FPR, f'the key on the host is {fpr}')
        listed = sudo(apt.name, 'cat /etc/apt/sources.list.d/docker.list').strip()
        want('signed-by=/etc/apt/keyrings/docker.asc' in listed and 'https://download.docker.com/linux/' in listed, f'the repository line is {listed!r}')
        want(quiet(apt.name, 'docker info >/dev/null') == 0, 'docker info does not answer')
        return f'Docker from download.docker.com, key {fpr[-16:]}, docker info answers'
    if apt:
        r.check('runtime-docker', apt.name, runtime_docker)
    else:
        r.add('runtime-docker', '-', None, 'needs a second bare apt-get host')

    virt = next((n for n in hosts if n.name not in (node.name, apt.name if apt else '')), None)

    def runtime_libvirt():
        name = demo.known_as(api, virt.name)
        pid = plan(api, f'lab: libvirt on {virt.name}', name, 'runtime-install', {'runtime': 'libvirt'})
        _, runs = report_only(api, pid, f'libvirt on {virt.name}')
        kvm = '/dev/kvm is there' in said(runs)
        want(kvm or 'no hardware virtualization here' in said(runs) or 'no /dev/kvm yet' in said(runs), f'the report said nothing of virtualization:\n{said(runs)[-800:]}')
        demo.deploy(api, 'changes', pid, f'libvirt on {virt.name}')
        want(quiet(virt.name, 'virsh -c qemu:///system list --all >/dev/null') == 0, 'virsh does not answer on qemu:///system')
        return f'libvirt answers on qemu:///system; the report said {"/dev/kvm is there" if kvm else "VMs would run emulated"}'
    if virt:
        r.check('runtime-libvirt', virt.name, runtime_libvirt)
    else:
        r.add('runtime-libvirt', '-', None, 'needs a third bare host')

    # ── the secret store's boundary ──
    def made_once():
        api.raw('DELETE', f'/api/keys/secrets/{SECRET}')          # one a cut-short run left
        made = api.post('/api/keys/secrets', {'name': SECRET, 'kind': 'token', 'length': 40, 'hosts': [host]})
        state['value'] = made['value']
        want(len(made['value']) == 40, f'the value is {len(made["value"])} characters')
        listed = json.dumps(api.get('/api/keys/secrets'))
        want(made['value'] not in listed, 'the list holds the value')
        want(made['value'] not in json.dumps(api.get('/api/audit')), 'the audit log holds the value')
        return 'a token of 40 shown once; the list and the audit log do not hold it'
    r.check('secret-made-once', node.name, made_once)

    def delivered():
        value = state['value']
        pid = api.post('/api/changes', {'name': f'lab: secret to {node.name}', 'tasks': [
            {'type': 'secret-file', 'host': host, 'params': {'secret': SECRET, 'path': TARGET, 'mode': '0600'}}]})['id']
        ps = f'/tmp/sf-lab-ps-{secrets.token_hex(4)}'
        sudo(node.name, f'(for i in $(seq 1 120); do ps -eo args >>{ps}; sleep 0.5; done) >/dev/null 2>&1 &')          # a process list while it runs
        group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'title': 'secret (apply)'})['group']
        runs = demo.wait('secret apply', lambda: demo.finished(api, group))['runs']
        out = said(runs)
        want('secret(s) from StorageForge written to /run/storageforge/secrets' in out, f'the secret was not written:\n{out[-1200:]}')
        q = shlex.quote(value)
        for path in (f'/run/storageforge/secrets/{SECRET}', TARGET):
            held = sudo(node.name, f'cat {path} 2>/dev/null; stat -c "%a %U" {path} 2>/dev/null', check=False).split()
            want(held[:1] == [value] and held[1:3] == ['600', 'root'], f'{path} holds {"the value" if held[:1] == [value] else "something else"}, mode and owner {held[1:3]}')
        want(value not in out, 'the value is in the deploy output')
        for where, cmd in (('a log under /var/log/storageforge', 'grep -rqF -- ' + q + ' /var/log/storageforge'), ('the journal', 'journalctl -q --no-pager | grep -qF -- ' + q),
                           ('a process list taken during the run', f'sleep 2; grep -qF -- {q} {ps}')):
            want(quiet(node.name, cmd) != 0, f'the value is in {where}')
        db = demo.ssh('sf-ctl', f'{demo.COMPOSE} exec -T storageforge python -c {shlex.quote(DUMP)}', check=False)
        want(value not in db, 'the value is in the controller database outside its ciphertext')
        sudo(node.name, f'rm -f {ps}', check=False)
        state['plan_secret'] = pid
        return f'in /run/storageforge/secrets and {TARGET}, mode 600; in no output, log, journal, process list or database row'
    if state.get('value'):
        r.check('secret-delivered', node.name, delivered)
    else:
        r.add('secret-delivered', node.name, None, 'no secret was made')

    def rotated():
        old = state['value']
        plan_ = api.get(f'/api/keys/secrets/{SECRET}/rotate')
        want([h['host'] for h in plan_['hosts']] == [host], f'the rotation would go to {plan_["hosts"]}')
        got = api.post(f'/api/keys/secrets/{SECRET}/rotate', {})
        want(got['rotated'] and got.get('value') and got['value'] != old, f'not rotated: {got.get("why")}')
        held = sudo(node.name, f'cat /run/storageforge/secrets/{SECRET}').strip()
        want(held == got['value'], 'the host does not hold the new value')
        demo.deploy(api, 'changes', state['plan_secret'], 'the secret file again, after the rotation')
        want(sudo(node.name, f'cat {TARGET}').strip() == got['value'], f'{TARGET} does not hold the new value after the plan ran again')
        want(quiet(node.name, f'grep -rqF -- {shlex.quote(old)} /run/storageforge /var/log/storageforge {TARGET}') != 0, 'the old value is still on the host')
        api('DELETE', f'/api/keys/secrets/{SECRET}')
        sudo(node.name, f'rm -f {TARGET}', check=False)
        return f'the host holds the new value in /run and, after the plan ran again, in {TARGET}; the old one is gone from it'
    if state.get('plan_secret'):
        r.check('secret-rotated', node.name, rotated)
    else:
        r.add('secret-rotated', node.name, None, 'the secret was not delivered')
