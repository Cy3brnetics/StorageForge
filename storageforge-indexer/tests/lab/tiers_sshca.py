#!/usr/bin/env python3
"""Tier 21 of the KVM lab: the SSH certificate authority on real hosts, through the API and the change engine. The tunnel checks of
the same tier are in tiers_tunnels.py, and run at the end of this one.

NOT RUN. This file was written where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is not lab-tested.
What was run is tests/test_sshcerts.py on this machine: the same two steps against a real sshd started by the test, with the real ssh and
ssh-keygen, and the CA signing inside the real enclave program.

What a real host adds to that: the distribution's own sshd_config and its Include line, sshd reloaded by systemd, SELinux on the dnf host,
the rollback timer armed and confirmed by the deploy, and a scan that logs in with a certificate through the whole product.

    trust           an ssh-ca-trust plan from /api/keys/ssh-ca/plan, reported and applied. sshd then names the CA, and the scan key in
                    authorized_keys still logs in: nobody was locked out
    certificate     the host is opted in for scans; with the scan user's authorized_keys moved aside, a scan still gets in, so it was the
                    certificate that logged in. sshd's log names the certificate's key id
    revoke          that certificate is revoked, the list goes out by an ssh-ca-krl plan, and the host's list names the serial
    host cert       a host certificate is issued and installed; another VM that knows only the CA accepts the host's key
    foreign CA      a host with a TrustedUserCAKeys of its own is left exactly as it was
    absent          trust is taken away again, and the key still logs in

A dnf host and an apt-get host are used where the build has them. A host that is not there shows as skip, not as a pass.
"""
import re
import shlex

import demo
import roles

import tiers as t  # noqa: F401  (for the path set-up, as the other tier files do)
from tiers_platform import sudo

CONF = '/etc/ssh/sshd_config.d/50-storageforge-ca.conf'
CA_FILE = '/etc/ssh/storageforge_user_ca.pub'
KRL = '/etc/ssh/storageforge_revoked_keys'


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def sshd_says(node, keyword):
    """What the host's sshd answers for a keyword, whatever case its version prints keywords in."""
    out = sudo(node.name, 'sshd -T 2>/dev/null')
    return next((line.split(None, 1)[1].strip() for line in out.splitlines() if line.lower().startswith(keyword + ' ')), '')


def staged(api, body, title):
    """A plan from the CA's own route, then the whole deploy path: report, apply."""
    made = api.post('/api/keys/ssh-ca/plan', body)
    want(made.get('plan_id'), f'no plan was saved: {made}')
    return demo.deploy(api, 'changes', made['plan_id'], title)


def tier21(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    vms = roles.deployable()
    picked = [n for n in (next((n for n in vms if n.pm == 'apt-get'), None), next((n for n in vms if n.pm == 'dnf'), None)) if n]
    if not picked:
        r.add('sshca', '-', None, 'no apt-get or dnf host that takes deploys in this build')
        return
    made = api.post('/api/keys/ssh-ca', {})
    ca = made['public_key']

    for node in picked:
        name = demo.known_as(api, node.name)

        def trust(node=node, name=name):
            staged(api, {'kind': 'trust', 'hosts': [name], 'users': 'scan'}, f'trust the SSH CA on {node.name}')
            want(sshd_says(node, 'trustedusercakeys') == CA_FILE, f'sshd does not name the CA: {sshd_says(node, "trustedusercakeys")!r}')
            want(sudo(node.name, f'cat {CA_FILE}').strip() == ca, 'the CA key on the host is not the one in the vault')
            want(sudo(node.name, 'cat /etc/ssh/storageforge_principals/scan').strip() == f'scan@{name}', 'the principals of scan are not scan@<this host>')
            want('authorizedkeysfile' not in sudo(node.name, f'grep -vi "^#" {CONF}').lower(), 'the file sets AuthorizedKeysFile, which it must never do')
            demo.scan(api, [node.ip])          # the key in authorized_keys, as before: nobody was locked out
            again = api.post('/api/keys/ssh-ca/plan', {'kind': 'trust', 'hosts': [name], 'users': 'scan'})
            runs = demo.deploy(api, 'changes', again['plan_id'], f'trust the SSH CA on {node.name} again')
            want(runs and all(re.search(r'^\s*ok\s+trusts the StorageForge CA for scan, with revocation list version \d+', x.get('output') or '', re.M) for x in runs), 'a second run did not find it in place')
            return 'sshd names the CA and the principals of scan; the scan key still logs in; a second run changed nothing'
        r.check('sshca-trust', node.name, trust)

        def certificate(node=node, name=name):
            api('PUT', f'/api/keys/ssh-ca/hosts/{name}', {'console': False, 'scan': True})
            home = sudo(node.name, 'getent passwd scan | cut -d: -f6').strip()
            want(home, 'no home for the scan user')
            sudo(node.name, f'mv {shlex.quote(home)}/.ssh/authorized_keys {shlex.quote(home)}/.ssh/authorized_keys.lab')
            try:
                demo.scan(api, [node.ip])      # no key is authorized now: only the certificate can have logged in
            finally:
                sudo(node.name, f'mv {shlex.quote(home)}/.ssh/authorized_keys.lab {shlex.quote(home)}/.ssh/authorized_keys')
            log = sudo(node.name, 'journalctl -u ssh -u sshd --since "-5 min" --no-pager 2>/dev/null; tail -n 200 /var/log/auth.log /var/log/secure 2>/dev/null; true', check=False)
            want(re.search(r'Accepted publickey for scan .*CERT.*ID storageforge[ _]scan', log), 'sshd logged no login of scan by a StorageForge certificate')
            issued = [c for c in api.get('/api/keys/ssh-ca')['certificates'] if c['host'] == name and c['purpose'] == 'scan']
            want(issued and issued[0]['principals'] == [f'scan@{name}'], f'no scan certificate on record for {name}: {issued[:1]}')
            return f'a scan logged in with a certificate for scan@{name} while no key was authorized, and sshd logged its key id'
        r.check('sshca-certificate-logs-in', node.name, certificate)

        def revoke(node=node, name=name):
            cert = next(c for c in api.get('/api/keys/ssh-ca')['certificates'] if c['host'] == name and c['purpose'] == 'scan' and not c['revoked_at'])
            got = api.post(f'/api/keys/ssh-ca/certificates/{cert["serial"]}/revoke', {'reason': 'lab'})
            staged(api, {'kind': 'krl', 'hosts': [name]}, f'revocation list on {node.name}')
            want(sudo(node.name, f'cat {KRL}.version').strip() == str(got['krl_version']), 'the host does not have the version that was sent')
            listed = sudo(node.name, f'ssh-keygen -Q -l -f {KRL}')
            want(str(cert['serial']) in listed, f'the list on the host does not name serial {cert["serial"]}: {listed[-400:]}')
            demo.scan(api, [node.ip])          # a new certificate, and the key: a list on the host refuses neither
            return f'revocation list version {got["krl_version"]} is on the host and names the serial; scans go on'
        r.check('sshca-revoke', node.name, revoke)

        def host_certificate(node=node, name=name):
            api.post(f'/api/keys/ssh-ca/hosts/{name}/certificate', {})
            staged(api, {'kind': 'trust', 'hosts': [name], 'users': 'scan', 'host_cert': True}, f'host certificate on {node.name}')
            want(sshd_says(node, 'hostcertificate'), 'sshd names no HostCertificate')
            other = roles.other_than(node, vms)
            known = f'@cert-authority * {ca}'
            # a client that knows the CA and no key of this host: it must get as far as being refused for who it is, not for who the host is
            out = demo.ssh(other.name, f'f=$(mktemp); printf "%s\\n" {shlex.quote(known)} >$f; ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$f '
                                       f'-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityFile=/dev/null nobody@{node.ip} true 2>&1; rm -f $f; true', check=False)
            want('Host key verification failed' not in out and 'No ED25519 host key is known' not in out, f'the host certificate was not accepted: {out[-300:]}')
            want('Permission denied' in out, f'expected to be refused as nobody, after the host proved itself: {out[-300:]}')
            return f'{other.name}, knowing only the CA, accepted the key of {node.name}'
        r.check('sshca-host-certificate', node.name, host_certificate)

        def absent(node=node, name=name):
            staged(api, {'kind': 'trust', 'hosts': [name], 'users': 'scan'}, f'before taking trust away on {node.name}')
            pid = api.post('/api/changes', {'name': f'lab stop trusting the SSH CA on {node.name}', 'tasks': [
                {'type': 'ssh-ca-trust', 'host': name, 'params': {'users': 'scan', 'state': 'absent', 'rollback': '10'}}]})['id']
            demo.deploy(api, 'changes', pid, f'stop trusting the SSH CA on {node.name}')
            want(sshd_says(node, 'trustedusercakeys') in ('', 'none'), f'sshd still names a CA: {sshd_says(node, "trustedusercakeys")}')
            want(sudo(node.name, f'ls {CONF} {CA_FILE} {KRL} 2>/dev/null; true', check=False).strip() == '', 'files of the CA are still on the host')
            demo.scan(api, [node.ip])          # opted in still, and the host no longer trusts the CA: the key gets in
            api('PUT', f'/api/keys/ssh-ca/hosts/{name}', {'console': False, 'scan': False})
            return 'trust removed with its files, and the scan key still logs in'
        r.check('sshca-absent', node.name, absent)

    # a host that trusts a CA of its own is not StorageForge's to change
    node = picked[0]
    name = demo.known_as(api, node.name)

    def foreign():
        own = '/etc/ssh/sshd_config.d/10-lab-own-ca.conf'
        sudo(node.name, f'cp {shlex.quote("/etc/ssh/ssh_host_ed25519_key.pub")} /etc/ssh/lab_own_ca.pub; printf "TrustedUserCAKeys /etc/ssh/lab_own_ca.pub\\n" >{own}; sshd -t')
        try:
            made = api.post('/api/keys/ssh-ca/plan', {'kind': 'trust', 'hosts': [name], 'users': 'scan'})
            title = f'trust on a host with its own CA ({node.name})'
            group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': made['plan_id'], 'mode': 'report', 'title': title})['group']
            runs = demo.wait(title, lambda: demo.finished(api, group))['runs']
            want(len(runs) == 1 and runs[0]['status'] == 'failed' and '/etc/ssh/lab_own_ca.pub' in runs[0]['output']
                 and 'StorageForge does not replace it' in runs[0]['output'], 'the report did not identify the existing CA conflict')
            want(sshd_says(node, 'trustedusercakeys') == '/etc/ssh/lab_own_ca.pub', 'the CA the host had was replaced')
            want(sudo(node.name, f'ls {CONF} 2>/dev/null; true', check=False).strip() == '', 'a file was written although the step refused')
        finally:
            sudo(node.name, f'rm -f {own} /etc/ssh/lab_own_ca.pub; systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; true', check=False)
        demo.scan(api, [node.ip])
        return 'refused, and the host kept the CA it had'
    r.check('sshca-foreign-ca-left-alone', node.name, foreign)

    # the other half of this tier: exposure through tunnels, and the steps that start one (tiers_tunnels.py)
    import tiers_tunnels
    tiers_tunnels.checks(r, api, node)
