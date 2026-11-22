"""The 0.5.13 Toolbox entries of reverse proxy, TLS and DNS, detection and scanning, and monitoring and alerting (catalog/*.yaml,
tbadapters_b.py, steps_toolbox_b.py): each entry passes the schema and becomes steps whose script is valid Bash; the engine's additions
(a command for a container, NAME_FILE pointing at a declared secret, a daemon unit named with a d, user 0 counted as root); the sections
the adapters add, run as Bash against stand-ins that print what the real programs printed (tests/fixtures/toolbox, recorded from Debian 13
packages, Trivy 0.76 and Grype 0.122), read back; each adapter on that reading, and its actions saved as plans; and the steps of the panels
(caddy-route, ips-decision, trivy-scan) run against stand-in programs on folders standing in for the host's."""
import json
import shutil
import subprocess
import time
import unittest
from pathlib import Path

try:
    from test_toolbox import Base
    from test_toolbox_steps import Steps as StepsBase
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import Base
    from tests.test_toolbox_steps import Steps as StepsBase
from storageforge_index import changes, inframeasure, security, steps_toolbox_b, tbadapters, tbadapters_b, toolbox

FIX = Path(__file__).resolve().parent / 'fixtures' / 'toolbox'
PROXY_DNS = ('caddy', 'traefik', 'nginx-proxy-manager', 'step-ca', 'pi-hole', 'adguard-home', 'unbound', 'coredns', 'dnsmasq', 'chrony')
DETECTION = ('crowdsec', 'fail2ban', 'suricata', 'zeek', 'trivy', 'grype', 'openscap')
MONITORING: tuple = ()


def entry(tid):
    e, problems = toolbox.load_entry((toolbox.CATALOG_DIR / f'{tid}.yaml').read_text())
    assert not problems, (tid, problems)
    return e


class Entries(Base):
    def setUp(self):
        super().setUp()
        for name, pm, tools in (('deb', 'apt', ['podman']), ('fed', 'dnf', ['podman']), ('suse', 'zypper', ['podman']), ('arch', 'pacman', ['podman'])):
            self.host(name, pm, tools)

    def test_each_entry_passes_the_schema_names_its_adapter_and_is_in_the_manifest(self):
        man = json.loads((toolbox.CATALOG_DIR / 'catalog.json').read_text())['entries']
        for tid in PROXY_DNS + DETECTION + MONITORING:
            text = (toolbox.CATALOG_DIR / f'{tid}.yaml').read_text()
            e, problems = toolbox.load_entry(text)
            self.assertEqual(problems, [], tid)
            self.assertEqual(e['id'], tid)
            self.assertIn(e['gui']['adapter'], tbadapters.ADAPTERS, tid)
            self.assertEqual(man.get(tid), toolbox.sha256(text), f'{tid}: python -m storageforge_index.toolbox manifest SERIAL writes the manifest again')
            for m in e['methods']:
                if m['kind'] in ('container', 'quadlet', 'compose'):
                    self.assertRegex(m['image'], r'@sha256:[0-9a-f]{64}$', tid)
            self.assertTrue(e['summary'] and e['notes'], f'{tid} says what it is and what to watch')
            self.assertIn(toolbox.find(self.conn, tid)['trust'], ('packaged', 'release-signed'))

    def test_each_entry_becomes_steps_and_a_valid_script(self):
        for tid in PROXY_DNS + DETECTION + MONITORING:
            e = entry(tid)
            for m in e['methods']:
                pm = next(iter(m['packages'])) if m['kind'] == 'package' else 'apt'
                host = {'apt': 'deb', 'dnf': 'fed', 'zypper': 'suse', 'pacman': 'arch'}[pm]
                kw = {'exposure': 'management', 'bind': '10.0.0.5'} if e['exposure']['default'] == 'management' else {}
                pv = toolbox.preview(self.conn, host, tid, m['kind'], **kw)
                t = next(x for x in pv['tasks'] if x['type'] == 'tool-install')
                words = toolbox.install_words(self.conn, t)
                self.assertEqual(words[0], 'ok', (tid, m['kind'], words[:2]))
                text = changes.script(self.conn, {'name': f'test {tid} {m["kind"]}', 'tasks': pv['tasks']})
                p = subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 0, (tid, m['kind'], p.stderr))
                for s in e['secrets']:
                    self.assertNotIn(f'tool-{tid}-{s["name"]}=', text, 'a secret is named, never given')

    def test_proxy_and_dns_entries_install_as_they_should(self):
        pv = toolbox.preview(self.conn, 'deb', 'pi-hole', exposure='management', bind='10.0.0.5')
        self.assertEqual(pv['method'], 'quadlet', 'port 53 needs root: there is no rootless method')
        unit = toolbox.install_words(self.conn, next(t for t in pv['tasks'] if t['type'] == 'tool-install'))[2]
        self.assertIn('PublishPort=10.0.0.5:53:53/udp', unit)
        self.assertIn('Environment=WEBPASSWORD_FILE=/run/secrets/pi-hole/web-password', unit)
        self.assertIn('Environment=FTLCONF_dns_listeningMode=all', unit)
        self.assertIn('Volume=/srv/toolbox/pi-hole/secrets:/run/secrets/pi-hole:ro,Z', unit)
        sec = next(t for t in pv['tasks'] if t['type'] == 'secret-file')
        self.assertEqual(sec['params']['secret'], 'tool-pi-hole-web-password')
        pv = toolbox.preview(self.conn, 'deb', 'traefik', exposure='loopback')
        self.assertEqual(pv['made']['ports'], ['127.0.0.1:8000:80/tcp', '127.0.0.1:8443:443/tcp'], 'rootless takes ports above 1024')
        unit = toolbox.install_words(self.conn, next(t for t in pv['tasks'] if t['type'] == 'tool-install'))[2]
        self.assertIn('DropCapability=ALL', unit)
        self.assertIn('AddCapability=NET_BIND_SERVICE', unit)
        self.assertNotIn('docker.sock', unit)
        pv = toolbox.preview(self.conn, 'deb', 'chrony')
        nts = next(t for t in pv['tasks'] if t['type'] == 'chrony-nts')
        self.assertEqual(nts['params'], {'servers': 'time.cloudflare.com,nts.netnod.se'})
        pv = toolbox.preview(self.conn, 'deb', 'chrony', inputs={'servers': 'nts.example.org'})
        self.assertEqual(next(t for t in pv['tasks'] if t['type'] == 'chrony-nts')['params']['servers'], 'nts.example.org')
        self.assertEqual(toolbox.preview(self.conn, 'deb', 'step-ca')['method'], 'container')
        self.assertEqual([r['label'] for r in toolbox.risks(entry('step-ca'), 'container')], ['holds-credentials'])
        self.assertIn('runs-as-root', [r['label'] for r in toolbox.risks(entry('step-ca'), 'compose')], 'user 0 under a root engine is root')
        with self.assertRaisesRegex(toolbox.CatalogError, 'no method of CoreDNS fits'):
            toolbox.preview(self.conn, 'deb', 'coredns')
        self.assertEqual(toolbox.preview(self.conn, 'suse', 'coredns', exposure='management', bind='10.0.0.5')['method'], 'package')

    def test_what_the_engine_now_allows_and_still_refuses(self):
        base = ('format: 1\nid: t1\nrevision: 1\nname: T\ncategory: monitoring\nsummary: s\nsecrets:\n  - {name: pw, kind: password}\ninstall:\n  methods:\n'
                '    - kind: container\n      image: docker.io/x/y:1@sha256:' + 'a' * 64 + '\n')
        ok = lambda more: toolbox.load_entry(base + more)[1]     # noqa: E731
        self.assertEqual(ok('      env: {APP_PASSWORD_FILE: /run/secrets/t1/pw}\n'), [])
        self.assertIn('looks like a secret', ' '.join(ok('      env: {APP_PASSWORD_FILE: /run/secrets/t1/other}\n')))
        self.assertIn('looks like a secret', ' '.join(ok('      env: {APP_PASSWORD_FILE: /etc/shadow}\n')))
        self.assertIn('looks like a secret', ' '.join(ok('      env: {APP_PASSWORD: /run/secrets/t1/pw}\n')))
        self.assertEqual(ok('      env: {FTLCONF_dns_listeningMode: all}\n'), [])
        self.assertIn('env lower is NAME', ' '.join(ok('      env: {lower: x}\n')))
        self.assertEqual(ok('      command: [server, --listen, "0.0.0.0:4954"]\n'), [])
        for bad in ('"sh -c id"', '"$(id)"', '"a;b"', '"%h"', "\"it's\""):
            self.assertIn('a word of the command', ' '.join(ok(f'      command: [{bad}]\n')), bad)
        e = toolbox.load_entry(base + '      command: [serve]\n')[0]
        self.assertIn('Exec=serve', toolbox.quadlet_text(e, e['methods'][0], toolbox.resolve(e, e['methods'][0], {}, 'loopback', ''), True))
        pkg = 'format: 1\nid: chrony\nrevision: 1\nname: T\ncategory: dns\nsummary: s\ninstall:\n  methods:\n    - kind: package\n      packages: {apt: [chrony]}\n'
        self.assertEqual(toolbox.load_entry(pkg + '      units: [chronyd.service]\n')[1], [])
        self.assertIn('not named after', ' '.join(toolbox.load_entry(pkg + '      units: [chronydebug.service]\n')[1]))
        self.assertIn('not named after', ' '.join(toolbox.load_entry(pkg + '      units: [sshd.service]\n')[1]))


# ── the sections, run as Bash against stand-ins that print what the real programs printed ──
STAND_INS = {
    'systemctl': r'''if [[ $1 == show ]]; then
  for u in "$@"; do case $u in caddy.service|crowdsec.service|fail2ban.service|chrony.service|unbound.service|smartmontools.service)
    printf "Id=%s\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n" "$u" ;;
  *.service) printf "Id=%s\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n\n" "$u" ;; esac; done
fi; [[ $1 == is-active ]] && exit 0; exit 0''',
    'caddy': 'echo "2.6.2"', 'unbound': 'echo "Version 1.26.2"',
    'chronyd': 'echo "chronyd (chrony) version 4.6.1 (+CMDMON +NTP +NTS)"',
    'cscli': r'''case "$1 $2" in "decisions list") cat "$FIX/cscli-decisions.json" ;; "bouncers list") cat "$FIX/cscli-bouncers.json" ;;
  "version ") echo "2026/11/21 05:49:13 version: v1.4.6-10+b4-debian" ;; esac''',
    'nft': 'printf "table ip crowdsec {\\n set crowdsec-blacklists {\\n elements = { 203.0.113.7 timeout 4h, 198.51.100.0/24 timeout 30m }\\n }\\n}\\n"',
    'fail2ban-client': r'''case $1 in --version) echo "Fail2Ban v1.1.0" ;; status) if [[ -n ${2:-} ]]; then cat "$FIX/f2b-sshd.txt"; else cat "$FIX/f2b-status.txt"; fi ;; esac''',
    'chronyc': r'''case "$*" in "-c tracking") cat "$FIX/chrony-tracking.csv" ;; "-c -n sources") cat "$FIX/chrony-sources.csv" ;; "-c -N authdata") cat "$FIX/chrony-authdata.csv" ;; esac''',
    'unbound-control': r'''case $1 in status) cat "$FIX/unbound-status.txt" ;; stats_noreset) cat "$FIX/unbound-stats.txt"; echo "total.num.prefetch=0" ;; esac''',
    'smartctl': r'''case $1 in --version) echo "smartctl 7.4 2023-08-01 r5530" ;; --scan) printf "/dev/sda -d sat # /dev/sda [SAT], ATA device\n/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n" ;;
  -H) [[ ${@: -1} == /dev/sda ]] && printf "smartctl 7.4\n\nSMART overall-health self-assessment test result: PASSED\n" || printf "SMART overall-health self-assessment test result: FAILED!\n" ;; esac''',
    'curl': 'echo \'{"status":"success","data":{"activeTargets":[{"health":"up"},{"health":"up"},{"health":"down"}]}}\'',
}


def run_sections(d: Path, scans: Path | None = None, eve: Path | None = None) -> tuple[str, dict]:
    bindir = d / 'bin'
    bindir.mkdir(exist_ok=True)
    for name, body in STAND_INS.items():
        (bindir / name).write_text('#!/bin/bash\n' + body + '\n')
        (bindir / name).chmod(0o755)
    body = tbadapters_b.BODY
    if scans:
        body = body.replace(tbadapters_b.SCANS, str(scans))
    if eve:
        body = body.replace('/var/log/suricata/eve.json', str(eve))
    script = ('sec() { printf "\\n@@%s\\n" "$1"; }\nhas() { command -v "$1" >/dev/null; }\ntry() { timeout 30 "$@" 2>/dev/null || :; }\n'
              'capped() { head -c "$1"; }\n' + body)
    p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                       env={'PATH': f'{bindir}:/usr/bin:/bin', 'FIX': str(FIX)})
    return p.stdout, tbadapters_b.sections_of(inframeasure._sections(p.stdout))


class Sections(unittest.TestCase):
    def setUp(self):
        self.d = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_the_sections_are_in_the_reading_and_valid_bash(self):
        text = inframeasure.script()
        for s in tbadapters_b.SECTIONS:
            self.assertIn(f'sec {s}\n', text)
            self.assertIn(s, inframeasure.SECTIONS)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        odd = [line for line in tbadapters_b.BODY.splitlines() if line.count("'") % 2]
        self.assertEqual(odd, [])

    def test_real_output_read_back(self):
        eve = self.d / 'eve.json'
        eve.write_text((FIX / 'eve-alerts.json').read_text())
        out, got = run_sections(self.d, eve=eve)
        self.assertNotIn('api_key', out, 'cscli prints each bouncer key in its JSON: that line never leaves the host')
        self.assertNotIn('STAND-IN-FOR-THE-KEY', out)
        self.assertEqual(got['units']['caddy.service'], {'active': 'active', 'enabled': 'enabled'})
        self.assertNotIn('traefik.service', got['units'])
        self.assertEqual(got['versions']['caddy'], '2.6.2')
        self.assertEqual(got['versions']['cscli'], '1.4.6-10')
        self.assertEqual(got['versions']['fail2ban-client'], '1.1.0')
        c = got['crowdsec']
        self.assertEqual(sorted(d['value'] for d in c['decisions']), ['198.51.100.0/24', '203.0.113.7'])
        self.assertEqual(next(d for d in c['decisions'] if d['value'] == '203.0.113.7')['scenario'], 'storageforge sample')
        self.assertEqual([b['name'] for b in c['bouncers']], ['sample-bouncer'])
        self.assertEqual(c['nft_addresses'], 2)
        self.assertEqual(got['fail2ban']['jails']['sshd'], {'banned_now': 1, 'banned_total': 1, 'banned': ['203.0.113.9']})
        ch = got['chrony']
        self.assertEqual(ch['tracking']['ref'], '162.159.200.1')
        self.assertEqual(ch['tracking']['leap'], 'Normal')
        self.assertEqual(len(ch['sources']), 6)
        self.assertEqual([a['name'] for a in ch['auth'] if a['mode'] == 'NTS'], ['time.cloudflare.com', 'nts.netnod.se'])
        self.assertEqual(got['unbound']['running'], True)
        self.assertEqual(got['unbound']['version'], '1.26.2')
        self.assertEqual(got['unbound']['queries'], 0)
        self.assertEqual(got['suricata']['count'], 1)
        self.assertEqual(got['suricata']['alerts'][0]['signature'], 'StorageForge sample ICMP')
        self.assertEqual(got['suricata']['alerts'][0]['severity'], 3)
        self.assertEqual(got['smart'], [{'device': '/dev/sda', 'type': 'sat', 'health': 'passed'}, {'device': '/dev/nvme0', 'type': 'nvme', 'health': 'failed'}])
        self.assertEqual(got['api'].get('prometheus'), {'up': 2, 'down': 1, 'unknown': 0})

    def test_a_scan_report_read_back(self):
        scans = self.d / 'scans'
        scans.mkdir()
        (scans / 'trivy-a.tsv').write_text('i\tdocker.io/library/alpine:3.18.0\t1795240000\ttrivy\n' + (FIX / 'trivy-alpine.tsv').read_text())
        (scans / 'grype-a.tsv').write_text('i\tdocker.io/library/alpine:3.18.0\t1795240100\tgrype\n' + (FIX / 'grype-alpine.tsv').read_text())
        _, got = run_sections(self.d, scans=scans)
        tv = next(r for r in got['scans'] if r['scanner'] == 'trivy')
        self.assertEqual(tv['image'], 'docker.io/library/alpine:3.18.0')
        self.assertEqual(sum(tv['counts'].values()), 49)
        self.assertGreaterEqual(tv['fixable']['CRITICAL'], 1)
        self.assertEqual(tv['findings'][0]['severity'], 'CRITICAL', 'the worst first')
        gr = next(r for r in got['scans'] if r['scanner'] == 'grype')
        self.assertEqual(sum(gr['counts'].values()), 63)
        self.assertGreater(gr['counts']['HIGH'], 0, 'Grype says High: read as HIGH')

    def test_what_a_host_prints_cannot_pass_for_more(self):
        self.assertIsNone(tbadapters_b.read_crowdsec([]))
        got = tbadapters_b.read_crowdsec(['d\t[{"decisions":[{"value":"1.2.3.4; rm -rf /","type":"ban"},{"value":"10.0.0.1","type":"ban","simulated":true}]}]', 'b\tnot json'])
        self.assertEqual(got['decisions'], [], 'a value that is not an address, and a simulated decision, are left out')
        self.assertIsNone(got['bouncers'], 'unreadable: unknown, never a guess')
        self.assertEqual(tbadapters_b.read_versions(['v\tcaddy\tno number here', 'v\tevil\t1.0', 'v\tcaddy\t2.6.2; id']), {'caddy': '2.6.2'})
        self.assertEqual(tbadapters_b.read_scans(['i\t../../etc\t1\ttrivy', 'v\tCVE-1\tx\t1\t2\tHIGH']), [])
        self.assertEqual(tbadapters_b.read_units(['Id=x;id.service', 'LoadState=loaded', '']), {})
        self.assertEqual(tbadapters_b.read_fail2ban(['s\tsshd\tCurrently banned:\t3']), None)
        self.assertEqual(tbadapters_b.sections_of({'tb_chrony': ['t,' + ','.join(['x'] * 3)]})['chrony'], None)


def reading(d: Path) -> dict:
    eve = d / 'eve.json'
    eve.write_text((FIX / 'eve-alerts.json').read_text())
    scans = d / 'scans'
    scans.mkdir(exist_ok=True)
    (scans / 'trivy-a.tsv').write_text('i\tdocker.io/library/alpine:3.18.0\t1795240000\ttrivy\n' + (FIX / 'trivy-alpine.tsv').read_text())
    _, tb = run_sections(d, scans=scans, eve=eve)
    return {'tools': ['podman', 'caddy', 'nft'], 'listeners': [], 'toolbox': {'health': {'caddy': 200}, **tb},
            'access': {'proxy_routes': [{'proxy': 'caddy', 'site': 'grafana.lab.example', 'upstream': '127.0.0.1:3000'}]},
            'podman_rootless': [{'user': 'sf-trivy', 'containers': [{'name': 'sf-trivy', 'image': 'docker.io/aquasec/trivy:0.76.2@sha256:' + '8' * 64, 'state': 'running',
                                                                     'labels': {'storageforge.tool': 'trivy'}}]}]}


class Adapters(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman', 'caddy'])
        self.r = reading(self.tmp)
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure', self.r)

    def status(self, name):
        a = tbadapters.ADAPTERS[name]
        ctx = tbadapters.context(self.conn, 'box', self.r)
        found = a.detect(self.r, ctx)
        self.assertIsNotNone(found, name)
        return a.status(self.r, ctx, found), a.metrics(self.r, ctx)

    def test_proxy_and_dns_adapters(self):
        st, m = self.status('caddy')
        self.assertEqual(st['health'], 'ok')
        self.assertIn('grafana.lab.example to 127.0.0.1:3000', ' '.join(t['value'] for t in st['tiles']))
        self.assertEqual(m, {'routes': 1})
        st, m = self.status('chrony')
        tiles = {t['label']: t for t in st['tiles']}
        self.assertEqual(tiles['NTS']['value'], '2 of 6 sources authenticated by NTS')
        self.assertEqual(tiles['NTS']['level'], 'ok')
        self.assertEqual(m['nts'], 2)
        st, _ = self.status('unbound')
        self.assertIn('running', ' '.join(t['value'] for t in st['tiles']))
        ctx = tbadapters.context(self.conn, 'box', self.r)
        self.assertIsNone(tbadapters.ADAPTERS['pi-hole'].detect(self.r, ctx), 'not there: not detected')

    def test_actions_become_plans(self):
        got = tbadapters.stage_action(self.conn, 'box', 'caddy', 'add-route', {'site': 'kuma.lab.example', 'port': '3001'}, 'test')
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual(plan['tasks'][0]['type'], 'caddy-route')
        self.assertEqual(changes.check(self.conn, plan)['crit'], 0)
        self.assertIn('kuma.lab.example 3001 present', changes.script(self.conn, plan))
        with self.assertRaisesRegex(ValueError, 'Site is one of'):
            tbadapters.stage_action(self.conn, 'box', 'caddy', 'remove-route', {'site': 'nope.example'}, 'test')
        got = tbadapters.stage_action(self.conn, 'box', 'chrony', 'nts', {'servers': 'time.cloudflare.com, nts.netnod.se'}, 'test')
        self.assertEqual(changes.get_plan(self.conn, got['plan_id'])['tasks'][0]['params'], {'servers': 'time.cloudflare.com,nts.netnod.se'})
        bad = {'name': 'x', 'tasks': [{'host': 'box', 'type': 'caddy-route', 'params': {'site': 'a b', 'port': '0', 'state': 'present'}}]}
        self.assertGreaterEqual(changes.check(self.conn, bad)['crit'], 1)


class Feeds(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman', 'caddy'])
        self.r = reading(self.tmp)
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure', self.r)

    def test_suricata_ingest_and_bouncer_vip_reconciliation(self):
        from storageforge_index import alerts, tbfeeds
        now = int(time.time())
        # add a high-severity Suricata alert and test ingest deduplication
        r2 = json.loads(json.dumps(self.r))
        r2['toolbox']['suricata']['alerts'].append({
            'timestamp': '2026-11-22T01:02:03.000000+0000',
            'src_ip': '198.51.100.44',
            'dest_ip': '10.0.0.5',
            'signature': 'ET EXPLOIT Attempt',
            'signature_id': 99001,
            'severity': 1,
        })
        security._save_measurement(self.conn, 'box', 'infra', now, 'measure', r2)
        self.assertEqual(tbfeeds.ingest(self.conn, 'box', r2, now)['suricata'], 2)
        self.assertEqual(tbfeeds.ingest(self.conn, 'box', r2, now)['suricata'], 0, 'deduped by deterministic uuid')
        evs = security.list_events(self.conn, 'box', 10)
        self.assertTrue(any(e['kind'] == 'suricata_alert' and '198.51.100.44' in e['detail'] for e in evs))

        # VIP overlap in CrowdSec ban + quarantine discrepancy
        security.save_vips(self.conn, ['203.0.113.7/32'], 'test')
        self.conn.execute("INSERT INTO security_quarantine (host, ip_address, reason, added_at, actor) VALUES ('box', '203.0.113.99', 'test', :t, 'a')", {'t': now})
        bv = security.firewall_view(self.conn, 'box')['bouncer']
        self.assertEqual([c['ip'] for c in bv['vip_conflicts']], ['203.0.113.7'])
        self.assertEqual(bv['unsynced_quarantine'], ['203.0.113.99'])
        self.assertIn('203.0.113.9', bv['unsynced_bouncer'])

        probs = alerts.problems(self.conn)
        self.assertIn('toolbox-bouncer-vip:box', probs)
        self.assertIn('toolbox-cve:box', probs)
        self.assertIn('toolbox-suricata:box', probs)

        plan_lift = tbfeeds.reconcile_bouncer(self.db, self.conn, {'host': 'box', 'action': 'unban_vips'}, 'test')
        self.assertEqual(plan_lift['tasks'], 1)
        tasks_lift = changes.get_plan(self.conn, plan_lift['plan_id'])['tasks']
        self.assertEqual(tasks_lift[0]['params']['state'], 'lifted')
        self.assertEqual(tasks_lift[0]['params']['ip'], '203.0.113.7')

        plan_push = tbfeeds.reconcile_bouncer(self.db, self.conn, {'host': 'box', 'action': 'push_quarantine'}, 'test')
        self.assertEqual(plan_push['tasks'], 1)
        tasks_push = changes.get_plan(self.conn, plan_push['plan_id'])['tasks']
        self.assertEqual(tasks_push[0]['params']['state'], 'banned')
        self.assertEqual(tasks_push[0]['params']['ip'], '203.0.113.99')


# ── the panel steps, against stand-in programs ──
class PanelSteps(StepsBase):
    def setUp(self):
        super().setUp()
        (self.root / 'etc/caddy').mkdir(parents=True)
        self.paths['/etc/caddy'] = str(self.root / 'etc/caddy')
        self.paths[steps_toolbox_b.SCANS] = str(self.root / 'scans')
        stub = {
            # caddy validate refuses a file that has BAD in it
            'caddy': r'''if [[ $1 == validate ]]; then ! grep -rq BAD "$(dirname "${@: -1}")"; fi''',
            'cscli': r'''f=$FAKE/cscli; touch "$f"; case "$1 $2" in
  "decisions list") grep -q -- "$4" "$f" && echo "1,cscli,Ip:$4,reason,ban,,,1,3h59m,false,1" ;;
  "decisions add") echo "$3" >>"$f" ;; "decisions delete") grep -v -x -- "$3" "$f" >"$f.n"; mv "$f.n" "$f" ;; esac''',
            'fail2ban-client': r'''f=$FAKE/f2b; touch "$f"; case $1 in
  status) [[ $2 == sshd ]] || exit 1; printf "Status for the jail: sshd\n   \x60- Banned IP list:\t%s\n" "$(tr "\n" " " <"$f")" ;;
  set) if [[ $3 == banip ]]; then echo "$4" >>"$f"; else grep -v -x -- "$4" "$f" >"$f.n"; mv "$f.n" "$f"; fi ;; esac''',
            'trivy': 'case $1 in --version) echo "Version: 0.76.2" ;; image) cat "%s/trivy-alpine.tsv" ;; esac' % FIX,
            'docker': r'''[[ $1 == ps ]] && printf "docker.io/library/alpine:3.18.0\nnot a ref; id\n"''',
            'date': 'echo 1795240000',
        }
        for name, body in stub.items():
            (self.bin / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
            (self.bin / name).chmod(0o755)

    def bash(self):
        text = super().bash() + steps_toolbox_b.BASH
        for a, b in self.paths.items():
            text = text.replace(a, b)
        return text

    def test_a_caddy_route_is_checked_before_caddy_is_reloaded(self):
        main = self.root / 'etc/caddy/Caddyfile'
        main.write_text(':80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n')
        out = self.run_fn(False, 't_caddy_route', ['grafana.lab.example', '3000', 'present'])
        self.assertIn('would: route grafana.lab.example to 127.0.0.1:3000', out)
        self.assertFalse((self.root / 'etc/caddy/conf.d').exists(), 'a report writes nothing')
        out = self.run_fn(True, 't_caddy_route', ['grafana.lab.example', '3000', 'present'])
        self.assertIn('ok: Caddy routes grafana.lab.example to 127.0.0.1:3000', out)
        route = (self.root / 'etc/caddy/conf.d/storageforge-grafana.lab.example.caddy').read_text()
        self.assertIn('grafana.lab.example {\n\treverse_proxy 127.0.0.1:3000\n}', route)
        self.assertIn(f'import {self.root}/etc/caddy/conf.d/*.caddy', main.read_text())
        self.assertIn('caddy validate --adapter caddyfile', self.log())
        out = self.run_fn(True, 't_caddy_route', ['grafana.lab.example', '3000', 'present'])
        self.assertIn('ok: grafana.lab.example goes to 127.0.0.1:3000', out)
        self.assertEqual(main.read_text().count('import '), 1)
        # a configuration caddy refuses is put back as it was
        (self.root / 'etc/caddy/conf.d/other.caddy').write_text('BAD {\n}\n')
        out = self.run_fn(True, 't_caddy_route', ['kuma.lab.example', '3001', 'present'])
        self.assertIn('caddy validate refused the configuration, so it was put back', out)
        self.assertFalse((self.root / 'etc/caddy/conf.d/storageforge-kuma.lab.example.caddy').exists())
        (self.root / 'etc/caddy/conf.d/other.caddy').unlink()
        out = self.run_fn(True, 't_caddy_route', ['grafana.lab.example', '1', 'absent'])
        self.assertIn('ok: Caddy no longer routes grafana.lab.example', out)
        self.assertFalse((self.root / 'etc/caddy/conf.d/storageforge-grafana.lab.example.caddy').exists())


for _name in dir(StepsBase):          # the engine's own step tests run in their own module, not again here
    if _name.startswith('test_'):
        setattr(PanelSteps, _name, None)


if __name__ == '__main__':
    unittest.main()
