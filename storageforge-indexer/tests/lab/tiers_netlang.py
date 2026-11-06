#!/usr/bin/env python3
"""Tier 17 of the KVM lab: the network language compiled for firewalld and for ufw, applied on a real host of each, and read back from that host.

NOT RUN. This file was written where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is not lab-tested.
What was run is only the compile half, on this machine, in tests/test_netlang_lab.py (what each emitter writes for TEXT, and what it leaves out).

tests/lab/tiers_network.py already gives the nftables and iptables output to `nft -c` and `iptables-restore --test`. Those are dry runs. This tier
goes one step further for the two front ends that have no dry run: it applies the output with the tool's own command line and then asks the tool
what it now holds, which is the same check the nftables and iptables ones make by compiling and handing the text to the real parser.

    ufw host        the first apt-get host. Its rules are added with `ufw`, read with `ufw show added` (so a ufw that is switched off still answers), and deleted again
    firewalld host  the first dnf host. Its rules go into a zone of their own, `sflabnl`, that no interface or source belongs to, so it cannot touch this
                    host's real traffic. They are read with `firewall-cmd --permanent`, and zone and ipset are deleted again

Ports 9301 to 9306 and the network 10.99.0.0/16 are the lab's own, as in tier 12. A host that is not there shows as skip, not as a pass.
"""
import re

import roles

import tiers as t  # noqa: F401  (the other tier files import it for the path set-up, and so does this one)
from storageforge_index import rostranspiler
from tiers_platform import sudo

ZONE = 'sflabnl'
LIST = 'sflabnl'
TEXT = f'''/ip firewall address-list add list={LIST} address=10.99.0.0/16
/ip firewall filter add chain=input protocol=tcp dst-port=9301 src-address=10.99.0.0/16 action=accept comment="sf nl one"
/ip firewall filter add chain=input protocol=udp dst-port=9302 action=drop
/ip firewall filter add chain=input protocol=tcp dst-port=9303 src-address-list={LIST} action=reject
/ip firewall filter add chain=forward protocol=tcp dst-port=9305 action=accept
/ip firewall filter add chain=input connection-state=established action=accept
/ip firewall nat add chain=srcnat action=masquerade
/ip firewall nat add chain=dstnat protocol=tcp dst-port=9306 action=dst-nat to-addresses=10.99.0.1 to-ports=80
'''

# What the host must hold afterwards, as words that every one of its lines must carry. Wording and order are the tool's own, so no exact lines.
FIREWALLD_RICH = [('9301', 'tcp', '10.99.0.0/16', 'accept'), ('9302', 'udp', 'drop'), ('9303', 'tcp', f'ipset="{LIST}"', 'reject')]
UFW_RULES = [('allow', '9301', 'tcp', '10.99.0.0/16'), ('deny', '9302', 'udp'), ('route', 'allow', '9305', 'tcp')]
# Left out by the emitter, and so not on the host. Each is a statement the language has and this front end has not.
FIREWALLD_ABSENT = ['9305']
UFW_ABSENT = ['9303', '9306']


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def compile_for(target, **options):
    got = rostranspiler.emit(rostranspiler.parse(TEXT), target, **options)
    want(got['text'].strip(), f'{target}: nothing compiled: {got["unsupported"]}')
    return got


def has_all(line, words):
    return all(w in line for w in words)


def tier17(r):
    ufw_host = next((n for n in roles.deployable() if n.pm == 'apt-get'), None)
    wall_host = next((n for n in roles.deployable() if n.pm == 'dnf'), None)

    # ── ufw ─────────────────────────────────────────────────────
    def ufw_applied():
        out = compile_for('ufw')
        lines = [x for x in out['text'].splitlines() if x]
        sudo(ufw_host.name, 'command -v ufw >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ufw')
        try:
            for line in lines:
                sudo(ufw_host.name, line)
            held = sudo(ufw_host.name, 'ufw show added').splitlines()
            for words in UFW_RULES:
                want(any(has_all(h, words) for h in held), f'ufw does not hold {words}: {held}')
            for port in UFW_ABSENT:
                want(not any(port in h for h in held), f'ufw holds a rule for {port}, which the language has no ufw form for: {held}')
        finally:
            for line in reversed(lines):
                rule = re.sub(r'\s+comment\s+.*$', '', line)[len('ufw '):]
                # a route rule is deleted as `route delete` in ufw's grammar, and the other order is tried too: it has not been run on a real ufw
                alt = ' || ufw --force delete ' + rule if rule.startswith('route ') else ''
                sudo(ufw_host.name, ('ufw --force route delete ' + rule[len('route '):] + alt) if rule.startswith('route ') else 'ufw --force delete ' + rule, check=False)
        left = [h for h in sudo(ufw_host.name, 'ufw show added').splitlines() if re.search(r'\b930[1-6]\b', h)]
        want(not left, f'the lab rules are still in ufw: {left}')
        return f'ufw on {ufw_host.name} took {len(lines)} rules and showed them back; the {len(out["unsupported"])} it left out were not there; all deleted again'
    if ufw_host:
        r.check('netlang-ufw', ufw_host.name, ufw_applied)
    else:
        r.add('netlang-ufw', '-', None, 'no apt-get host here, so no ufw')

    # ── firewalld ───────────────────────────────────────────────
    def firewalld_applied():
        out = compile_for('firewalld', zone=ZONE)
        fc = 'firewall-cmd --permanent'
        sudo(wall_host.name, 'command -v firewall-cmd >/dev/null || dnf -q -y install firewalld; systemctl enable --now firewalld >/dev/null 2>&1; true')
        sudo(wall_host.name, f'{fc} --delete-zone={ZONE} >/dev/null 2>&1; {fc} --delete-ipset={LIST} >/dev/null 2>&1; {fc} --new-zone={ZONE} && firewall-cmd --reload')
        try:
            sudo(wall_host.name, out['text'])
            zone = sudo(wall_host.name, f'{fc} --zone={ZONE} --list-all')
            rich = sudo(wall_host.name, f'{fc} --zone={ZONE} --list-rich-rules').splitlines()
            for words in FIREWALLD_RICH:
                want(any(has_all(x, words) for x in rich), f'firewalld does not hold {words}: {rich}')
            for port in FIREWALLD_ABSENT:
                want(not any(port in x for x in rich), f'firewalld holds a rule for {port}, which it has no rich rule for: {rich}')
            want('masquerade: yes' in zone, f'no masquerade in the zone: {zone}')
            want('port=9306:proto=tcp:toport=80:toaddr=10.99.0.1' in zone.replace(' ', ''), f'no forward port in the zone: {zone}')
            entries = sudo(wall_host.name, f'{fc} --ipset={LIST} --get-entries').split()
            want('10.99.0.0/16' in entries, f'the ipset holds {entries}')
            # the same, in the running firewall after the reload the output ends with
            running = sudo(wall_host.name, f'firewall-cmd --zone={ZONE} --list-rich-rules')
            want('9301' in running, f'reloaded, and the running zone does not have it: {running!r}')
        finally:
            sudo(wall_host.name, f'{fc} --delete-zone={ZONE} >/dev/null 2>&1; {fc} --delete-ipset={LIST} >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1; true')
        left = sudo(wall_host.name, f'{fc} --get-zones; {fc} --get-ipsets').split()
        want(ZONE not in left and LIST not in left, f'the lab zone or ipset is still there: {left}')
        return f'firewalld on {wall_host.name} took the output in zone {ZONE}, held its rich rules, masquerade, forward port and ipset in the permanent config and the running zone; all deleted again'
    if wall_host:
        r.check('netlang-firewalld', wall_host.name, firewalld_applied)
    else:
        r.add('netlang-firewalld', '-', None, 'no dnf host here, so no firewalld')

    # a front end that has no way to say a thing must say so, and the lab shows what it said
    def said_so():
        for target, left_out in (('ufw', UFW_ABSENT), ('firewalld', FIREWALLD_ABSENT)):
            got = compile_for(target, **({'zone': ZONE} if target == 'firewalld' else {}))
            stated = ' '.join(u['statement'] for u in got['unsupported'])
            for port in left_out:
                want(f'dst-port={port}' in stated, f'{target} left out {port} without saying so: {got["unsupported"]}')
        return 'each front end named what it left out'
    r.check('netlang-says-what-it-left-out', '-', said_so)
