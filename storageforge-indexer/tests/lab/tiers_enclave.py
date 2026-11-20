#!/usr/bin/env python3
"""Tier 19 of the KVM lab: the key enclave (roadmap section 14) on the lab's controller, in its micro VM under Firecracker.

Written for 0.5.5 and not run yet: nothing here has passed until a lab run says so.

It needs KVM inside sf-ctl. The lab starts every VM with the host's CPU passed through, so it is there when the lab's own host allows
nested virtualization; where it is not, the checks that need the enclave are skipped with that reason, and the last one, the label
on a host without KVM, is the one that runs.

What a socket file on a developer's machine cannot say, and this tier is for:

    labelled      before anything is turned on: today's vault, and the Keys page's line saying the extra layer is not there. A
                  container without /dev/kvm says the same, with the reason
    boots         the stack brought up with docker-compose.enclave.yml: the enclave is a micro VM (the only program in it, memory
                  locked), the starter unlocked it, the server's container has neither the vault secret nor its file, and the key
                  the VM showed is the one pinned
    tasks         every SSH task through it: a scan of every host, a signed deploy check, and `vault send-secret` writing a secret
                  on a VM, read back there. The enclave's own count of signatures goes up, by kind of task
    audit         `audit verify` through it: the chain verifies, and the log ends where the enclave last signed it. The release that
                  send-secret caused is an entry the enclave wrote
    no network    the VM was given no network interface and no drive (Firecracker's own configuration and its open files), and the
                  kernel it runs has no IP stack in it at all
    memory        a private key whose bytes this tier knows, imported by a command that holds the secret and then used for a scan,
                  is not in the web app's memory: every readable page of the server's processes is read, as a debugger would, as the
                  scan runs and after
    taken over    the socket asked directly, as a web app that was taken over would: no operation hands out a key, a key cannot be
                  asked for as a secret, one secret asked for too often is refused, a sensitive one is refused without a step-up,
                  and a release whose audit entry is kept back shows in the enclave's own count and opens a notification
    killed        the micro VM killed with the starter stopped: nothing that needs a key works, nothing falls back to keys in the
                  server, and a notification that cannot be muted opens. With the starter back it is unlocked and the scan works
    rebuilt       the image built again from source on sf-ctl gives the hashes the running image has, and the ones the repository records

A check reads its answer from the machine it is about. tiers.py runs it; the stack is put back as it was afterwards, whatever happened.
"""
import base64
import json
import shlex
import time

import demo
import roles
from demo import COMPOSE, ssh

import tiers as t

ENCLAVE = COMPOSE + ' -f docker-compose.enclave.yml'
RUN_DIR = '/run/sf-enclave'


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def compose(stack, rest, stdin=None, check=True):
    return ssh('sf-ctl', f'{stack} {rest}', stdin=stdin, check=check)


def in_server(stack, code, *args, stdin=None):
    """Python in the server's container: the product's own client, as the web app (or what took it over) would use it."""
    return compose(stack, f'exec -T storageforge python -c {shlex.quote(code)} {shlex.join(args)}', stdin=stdin)


def describe(api):
    return api.get('/api/enclave')


def notifications(api):
    return {x['kind']: x for g in api.get('/api/notifications')['groups'] for x in g['items']}


def kvm_gid():
    out = ssh('sf-ctl', 'test -w /dev/kvm -o -r /dev/kvm && stat -c %g /dev/kvm || true', check=False).strip()
    return out if out.isdigit() else None


def tier19(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    nodes = [n for n in roles.build().values() if not n.can('controller')]
    state = {}

    # ── a host without the enclave: today's vault, labelled ─────
    def labelled():
        got = describe(api)
        want(got['on'] is False and got['state'] == 'off', f'the stack without the enclave file says: {got}')
        want(got['label'] == 'Key enclave: off', got['label'])
        # the base stack's containers are given no /dev/kvm: this is a host without KVM as the product sees one
        said = json.loads(in_server(COMPOSE, 'import json; from storageforge_index import enclave; print(json.dumps(enclave.describe()))'))
        want(said['vm_possible'] is False and 'the extra layer is not there' in said['detail'], f'without /dev/kvm it says: {said["detail"]!r}')
        want('/dev/kvm' in said['detail'] or 'not installed' in said['detail'], f'and not why: {said["detail"]!r}')
        t.sql('SELECT count(*) AS n FROM ssh_keys')          # and the vault works as it did: the scans above went through it
        return said['detail'][:150]
    r.check('enclave-labelled', 'sf-ctl', labelled)

    gid = kvm_gid()
    if not gid:
        for check in ('enclave-boots', 'enclave-tasks', 'enclave-audit', 'enclave-no-network', 'enclave-memory', 'enclave-taken-over', 'enclave-killed', 'enclave-rebuilt'):
            r.add(check, 'sf-ctl', None, 'sf-ctl has no usable /dev/kvm: the lab host does not allow nested virtualization')
        return
    env = f'STORAGEFORGE_KVM_GID={gid}'
    stack = ENCLAVE.replace('sudo -n docker', f'sudo -n env {env} docker')

    try:
        # ── the stack with the enclave ──────────────────────────
        def boots():
            compose(stack, 'up -d --wait storageforge starter proxy')
            got = demo.wait('the enclave to be unlocked by the starter', lambda: (lambda d: d if d.get('state') == 'unlocked' else None)(describe(api)), timeout=180)
            want(got['on'] and got['in_vm'], f'what answers is not the micro VM: {got}')
            where = in_server(stack, 'import os; print(os.environ.get("STORAGEFORGE_ENCLAVE"), os.environ.get("STORAGEFORGE_VAULT_SECRET"), os.environ.get("STORAGEFORGE_VAULT_SECRET_FILE") or "-", os.path.exists("/run/sf-secrets/vault_secret"), os.path.exists("/run/sf-vault"))').split()
            want(where[1:] == ['None', '-', 'False', 'False'], f'the server holds the secret or can read its file: {where}')
            want(where[0].startswith('fc:'), f'not under Firecracker: {where[0]}')
            pinned = json.loads(in_server(stack, f'import json; print(open("{RUN_DIR}/enclave.pins").read())'))
            want(list(pinned.values()) == [got['channel']['key']], f'the pinned key is not the one the VM shows: {pinned} / {got["channel"]}')
            procs = ssh('sf-ctl', 'pgrep -a firecracker || true')
            want('--no-api' in procs and 'storageforge-enclave' in procs, f'firecracker is not running as the supervisor starts it: {procs!r}')
            state['signed'] = got['counts']['signed']
            return f'{got["label"]}, version {got.get("version")}, under Firecracker, unlocked by the starter'
        r.check('enclave-boots', 'sf-ctl', boots)

        # ── every SSH task through it ───────────────────────────
        def tasks():
            demo.scan(api, [n.ip for n in nodes])
            host = next(n for n in roles.deployable())
            api.post('/api/deploy/check', {'host': demo.known_as(api, host.name)})          # a signed probe: it fails the check if the host does not answer it
            secret = 'sflab-' + base64.b16encode(json.dumps(time.time()).encode()).decode()[:24].lower()
            admin = f'{stack} run --rm -T admin'
            ssh('sf-ctl', f'{admin} vault secret-add sflab-enclave --step lab --for-host {host.ip}', stdin=secret + '\n')
            # send-secret goes over the operator's own SSH, not a vault key: a key of the lab's for it, which the admin container may read
            ssh('sf-ctl', 'sudo -n rm -f /tmp/sflab-send /tmp/sflab-send.pub && sudo -n ssh-keygen -q -t ed25519 -N "" -f /tmp/sflab-send && sudo -n chown 10001:10001 /tmp/sflab-send')
            demo.install_key(host.name, 'sfadmin', ssh('sf-ctl', 'sudo -n cat /tmp/sflab-send.pub').strip())
            send = (f'{stack} run --rm -T -v /tmp/sflab-send:/tmp/sflab-send:ro admin vault send-secret sflab-enclave --step lab --user sfadmin --key /tmp/sflab-send '
                    '--ssh-option StrictHostKeyChecking=accept-new --ssh-option UserKnownHostsFile=/tmp/sflab-known-hosts')
            ssh('sf-ctl', f'{send} --host {host.ip}')
            there = ssh(host.name, 'sudo -n cat /run/storageforge/secrets/sflab-enclave').strip()
            want(there == secret, f'what is on {host.name} is not the secret that was stored')
            other = next(n for n in nodes if n.name != host.name)
            before = t.sql("SELECT count(*) AS n FROM audit_log WHERE action = 'enclave.release' AND outcome = 'denied'")[0]['n']
            ssh('sf-ctl', f'{send} --host {other.ip}', check=False)          # a host its policy does not name
            after = t.sql("SELECT count(*) AS n FROM audit_log WHERE action = 'enclave.release' AND outcome = 'denied'")[0]['n']
            want(after == before + 1, 'a release for a host the policy does not name was not refused and written up')
            want(ssh(other.name, 'sudo -n test -e /run/storageforge/secrets/sflab-enclave && echo there || echo absent').strip() == 'absent', f'and the secret reached {other.name}')
            got = describe(api)
            want(got['counts']['signed'] > state['signed'], f'the enclave signed nothing for those tasks: {got["counts"]}')
            want(got['tasks'].get('scan', {}).get('signed', 0) >= len(nodes), f'scans are not counted as scans: {got["tasks"]}')
            want('deploy' in got['tasks'], f'the deploy check is not counted: {got["tasks"]}')
            state['host'] = host
            return f'{len(nodes)} scans, a signed check and send-secret on {host.name}: {got["counts"]["signed"]} signatures, by kind {sorted(got["tasks"])}'
        r.check('enclave-tasks', 'sf-ctl', tasks)

        def audit():
            got = api.get('/api/audit/verify')
            want(got['valid'], f'the chain does not verify through the enclave: {got}')
            want(got['head'].get('enclave') and got['head'].get('ok') is not False, f'the log does not end where the enclave signed it: {got["head"]}')
            said = compose(stack, 'exec -T storageforge storageforge-index audit verify')
            want('intact' in said and 'key enclave:' in said, said[-300:])
            made = t.sql("SELECT actor, target_host, detail_json FROM audit_log WHERE action = 'enclave.release' AND outcome = 'ok' ORDER BY audit_id DESC LIMIT 1")
            want(made and made[0]['actor'] == 'enclave', f'send-secret left no release entry written by the enclave: {made}')
            return f'{got["entries_checked"]} entries verify; {got["head"]["why"]}'
        r.check('enclave-audit', 'sf-ctl', audit)

        # ── nothing to reach from inside ────────────────────────
        def no_network():
            conf = json.loads(in_server(stack, f'print(open("{RUN_DIR}/enclave-vm.json").read())'))
            want(conf['network-interfaces'] == [] and conf['drives'] == [], f'the VM was given a device: {conf}')
            want(sorted(conf) == ['boot-source', 'drives', 'machine-config', 'network-interfaces', 'vsock'], f'and something more: {sorted(conf)}')
            pid = ssh('sf-ctl', 'pgrep -o firecracker').strip()
            fds = ssh('sf-ctl', f'sudo -n ls -l /proc/{pid}/fd')
            want('/dev/net/tun' not in fds and 'tap' not in fds, f'firecracker holds a network device open:\n{fds}')
            want('/dev/kvm' in fds, 'and it is not a KVM guest at all')
            # the kernel that is running: no IP stack to give an interface to, were one attached
            code = ('import sys; k = open("/usr/share/storageforge/enclave/vmlinux", "rb").read(); '
                    'print(sum(k.count(s) for s in (b"tcp_v4_rcv", b"inet_init", b"ip_rcv", b"e1000", b"virtio_net")), k.count(b"virtio_transport"))')
            ip, vsock = (int(x) for x in in_server(stack, code).split())
            want(ip == 0 and vsock > 0, f'the kernel has {ip} names of the IP stack or a network driver in it, and {vsock} of vsock')
            return 'no interface, no drive, no tap device held open, and a kernel with no IP stack'
        r.check('enclave-no-network', 'sf-ctl', no_network)

        # ── the key is not in the web app's memory ──────────────
        def memory():
            host = state.get('host') or next(n for n in roles.deployable())
            ssh('sf-ctl', 'rm -f /tmp/sflab-known /tmp/sflab-known.pub && ssh-keygen -q -t ed25519 -N "" -C sflab-known -f /tmp/sflab-known')
            pem = ssh('sf-ctl', 'cat /tmp/sflab-known')
            public = ssh('sf-ctl', 'cat /tmp/sflab-known.pub').strip()
            body = ''.join(line for line in pem.splitlines() if not line.startswith('-----'))
            seed = base64.b64decode(body)[-(32 + 32 + 4 + len('sflab-known') + 7):][:32] if body else b''
            demo.install_key(host.name, 'scan', public)
            admin = f'{stack} run --rm -T admin'
            ssh('sf-ctl', f'{admin} vault add --name sflab-known --key-file -', stdin=pem)          # by a command that holds the secret: not through the web app
            for row in t.sql('SELECT binding_id FROM key_bindings WHERE host_pattern = ' + repr(host.ip)):          # this host is scanned with the known key from here on
                ssh('sf-ctl', f'{admin} vault unbind {row["binding_id"]}')
            ssh('sf-ctl', f'{admin} vault bind --key sflab-known --host {host.ip} --user scan --actions scan')
            scanner = r'''
import os, re, sys
needles = [bytes.fromhex(x) for x in sys.argv[2:]]
found, read = 0, 0
for pid in sys.argv[1].split(","):
    try:
        maps = open(f"/proc/{pid}/maps").read().splitlines()
        mem = open(f"/proc/{pid}/mem", "rb", 0)
    except OSError:
        continue
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (r)", line)
        if not m or "[vvar]" in line or "[vsyscall]" in line:
            continue
        start, end = int(m[1], 16), int(m[2], 16)
        try:
            mem.seek(start)
            data = mem.read(end - start)
        except (OSError, ValueError, OverflowError):
            continue
        read += len(data)
        found += sum(data.count(n) for n in needles)
print(found, read)
'''
            needles = [body[:48].encode().hex(), body[-64:].encode().hex()] + ([seed.hex()] if len(seed) == 32 else [])
            job = api.post('/api/scan', {'host': host.ip})['job_id']
            seen = []
            for _ in range(6):          # as the scan runs, and after it
                pids = ssh('sf-ctl', "sudo -n docker top $(sudo -n docker ps -qf name=storageforge-storageforge) -eo pid,comm | awk '$2 ~ /python|storageforge/ {print $1}' | paste -sd,").strip()
                found, read = (int(x) for x in ssh('sf-ctl', f'sudo -n python3 -c {shlex.quote(scanner)} {pids} {" ".join(needles)}').split())
                seen.append((found, read))
                time.sleep(2)
            demo.wait('the scan with the known key', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), timeout=300)
            want(all(read > 1 << 20 for _, read in seen), f'the server\'s memory could not be read, so nothing was shown: {seen}')
            want(not any(found for found, _ in seen), f'the private key was found in the web app\'s memory: {seen}')
            # the reading itself is shown to find things: the public key, which the web app does hold, is there
            there = int(ssh('sf-ctl', f'sudo -n python3 -c {shlex.quote(scanner)} {pids} {public.split()[1][:40].encode().hex()}').split()[0])
            want(there > 0, 'the same reading does not find the public key either: it proves nothing')
            return f'{len(seen)} readings of {seen[-1][1] >> 20} MiB while it scanned with the key: its private bytes are nowhere, its public half {there} times'
        r.check('enclave-memory', 'sf-ctl', memory)

        # ── the socket asked directly ───────────────────────────
        def taken_over():
            code = r'''
import json, os, time
from storageforge_index import db, enclave, vault
address = enclave.address()
out = {}
e = enclave.Enclave(address)
row = None
d = db.Database(os.environ.get("STORAGEFORGE_DB") or "/app/data/index.db")
conn = d.connect()
k = conn.all("SELECT key_uuid, dek_nonce, wrapped_dek, key_nonce, ciphertext FROM ssh_keys LIMIT 1")[0]
key = {"key_uuid": k[0], "dek_nonce": bytes(k[1]), "wrapped_dek": bytes(k[2]), "key_nonce": bytes(k[3]), "ciphertext": bytes(k[4])}
out["export"] = [e.raw(json.dumps({"op": op, **enclave.Enclave._key(key)}).encode()).get("error") for op in ("export", "decrypt")]
e.close()
head = lambda: e.chain().get("head") or "0" * 64
try:
    e.release(key["key_uuid"], {"dek_nonce": key["dek_nonce"], "wrapped_dek": key["wrapped_dek"], "nonce": key["key_nonce"], "ciphertext": key["ciphertext"]}, {"step": "stolen"}, 1, head())
    out["key_as_secret"] = "released"
except enclave.EnclaveError as exc:
    out["key_as_secret"] = exc.code
c = conn.all("SELECT cred_uuid, dek_nonce, wrapped_dek, nonce, ciphertext, policy_json FROM device_credentials WHERE name = 'sflab-open'")[0]
sealed = {"dek_nonce": bytes(c[1]), "wrapped_dek": bytes(c[2]), "nonce": bytes(c[3]), "ciphertext": bytes(c[4])}
codes = []
for i in range(70):
    try:
        e.release(c[0], sealed, {"step": "stolen"}, 1, head(), policy=c[5])
        codes.append("ok")
    except enclave.EnclaveError as exc:
        codes.append(exc.code)
out["flood"] = [codes.count("ok"), codes[-1]]
s = conn.all("SELECT cred_uuid, dek_nonce, wrapped_dek, nonce, ciphertext, policy_json FROM device_credentials WHERE name = 'sflab-sensitive'")[0]
try:
    e.release(s[0], {"dek_nonce": bytes(s[1]), "wrapped_dek": bytes(s[2]), "nonce": bytes(s[3]), "ciphertext": bytes(s[4])}, {"step": "stolen"}, 1, head(), policy=s[5])
    out["sensitive"] = "released"
except enclave.EnclaveError as exc:
    out["sensitive"] = exc.code
out["status"] = {k: v for k, v in e.status().items() if k in ("bad_requests", "released", "refused", "stepup_missing")}
print(json.dumps(out))
'''
            admin = f'{stack} run --rm -T admin'
            ssh('sf-ctl', f'{admin} vault secret-add sflab-open', stdin='an-open-secret-123456\n')
            ssh('sf-ctl', f'{admin} vault secret-add sflab-sensitive --sensitive', stdin='a-sensitive-secret-123456\n')
            got = json.loads(in_server(stack, code).strip().splitlines()[-1])
            want(got['export'] == ['bad-request', 'bad-request'], f'asking for a key out: {got["export"]}')
            want(got['key_as_secret'] == 'auth', f'a private key asked for as a secret: {got["key_as_secret"]}')
            want(got['flood'][0] <= 61 and got['flood'][1] == 'rate', f'seventy releases of one secret in a row: {got["flood"]}')
            want(got['sensitive'] == 'stepup', f'a sensitive secret with no step-up: {got["sensitive"]}')
            api.post('/api/keys', {'name': f'sflab-after-{int(time.time())}'})          # the next entry the server writes: the log goes on without the ones kept back
            chain = describe(api)['chain']
            want(chain['releases_unwritten'] >= 1, f'releases whose audit entry was kept back are not counted: {chain}')
            now = demo.wait('the notification about a release missing from the log', lambda: notifications(api).get('security-enclave-audit-release'), timeout=420)
            want(now['ignorable'] is False, 'and it can be muted')
            return f'no key out, {got["flood"][0]} of 70 releases then refused, sensitive refused; {chain["releases_unwritten"]} kept-back entries counted and notified'
        r.check('enclave-taken-over', 'sf-ctl', taken_over)

        # ── the micro VM killed ─────────────────────────────────
        def killed():
            host = state.get('host') or next(n for n in roles.deployable())
            compose(stack, 'stop starter')
            ssh('sf-ctl', 'sudo -n pkill -9 -o firecracker')
            got = demo.wait('the enclave to come back, locked', lambda: (lambda d: d if d.get('state') == 'locked' else None)(describe(api)), timeout=120)
            job = api.post('/api/scan', {'host': host.ip})['job_id']
            done = demo.wait('the scan to end', lambda: next((j for j in api.get('/api/jobs')['jobs'] if j['job_id'] == job and j['status'] not in ('queued', 'running')), None), timeout=300)
            want(done['status'] not in ('ok', 'partial'), f'a scan worked with the enclave locked: {done["status"]}')
            want('enclave' in json.dumps(done['result']).lower(), f'and does not say why it failed: {json.dumps(done["result"])[:300]}')
            status, out = api.raw('POST', '/api/keys', {'name': 'sflab-while-locked'})
            want(status >= 400 and 'enclave' in json.dumps(out).lower(), f'a key was made with the enclave locked: {status} {out}')
            note = demo.wait('the notification', lambda: notifications(api).get('security-enclave'), timeout=420)
            want(note['ignorable'] is False, 'the notification can be muted')
            audit = t.sql("SELECT count(*) AS n FROM audit_log WHERE action = 'enclave.down'")[0]['n']
            want(audit >= 1, 'the audit log does not say the enclave went down')
            compose(stack, 'start starter')
            demo.wait('the starter to unlock it again', lambda: describe(api).get('state') == 'unlocked', timeout=180)
            demo.scan(api, [host.ip])
            demo.wait('the notification to leave', lambda: 'security-enclave' not in notifications(api), timeout=420)
            return f'{got["label"]}: the scan failed closed, no key was made, "{note["title"]}" opened and left when the starter unlocked it'
        r.check('enclave-killed', 'sf-ctl', killed)

        # ── the image, rebuilt ──────────────────────────────────
        def rebuilt():
            ssh('sf-ctl', 'cd /opt/storageforge && sudo -n rm -rf /tmp/sflab-enclave && sudo -n env JOBS=2 sh enclave/image/build.sh /tmp/sflab-enclave >/tmp/sflab-enclave.log 2>&1')
            built = dict(reversed(line.split()) for line in ssh('sf-ctl', 'cat /tmp/sflab-enclave/SHA256SUMS').splitlines())
            running = dict(reversed(line.split()) for line in in_server(stack, 'print(open("/usr/share/storageforge/enclave/SHA256SUMS").read())').splitlines() if line.strip())
            recorded = dict(reversed(line.split()) for line in ssh('sf-ctl', 'cat /opt/storageforge/enclave/image/SHA256SUMS').splitlines())
            for name in ('bzImage', 'vmlinux', 'initramfs.cpio.gz'):
                want(built[name] == running[name], f'{name}: built {built[name][:16]}, running {running[name][:16]}')
                want(built[name] == recorded[name], f'{name}: built {built[name][:16]}, recorded in the repository {recorded[name][:16]}')
            return f'the same bytes three ways: built here, running, and recorded ({built["vmlinux"][:16]}…)'
        r.check('enclave-rebuilt', 'sf-ctl', rebuilt)
    finally:
        # the stack as the other tiers expect it: without the enclave, with the vault secret back beside the other secrets
        try:
            secret = ssh('sf-ctl', f'{stack} run --rm -T --entrypoint cat admin /run/sf-vault/vault_secret', check=False).strip()
            if len(secret) >= 32:
                ssh('sf-ctl', 'cd /opt/storageforge && sudo -n install -d -m 0750 secrets && sudo -n tee secrets/vault_secret >/dev/null', stdin=secret)
            compose(stack, 'stop starter', check=False)
            compose(stack, 'rm -f starter', check=False)
            compose(COMPOSE, 'up -d --wait storageforge proxy', check=False)
        except Exception as exc:
            r.add('enclave-restore', 'sf-ctl', False, f'the stack was not put back without the enclave: {type(exc).__name__}: {str(exc)[:150]}')
