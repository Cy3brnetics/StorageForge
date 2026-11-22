"""Adapters of the 0.5.13 Toolbox entries (roadmap section 4.2; docs/toolbox.md): reverse proxy, TLS and DNS, detection and scanning,
monitoring and alerting. The same five parts as tbadapters.py, and the same rule: every part only reads, and an action becomes plan steps
(caddy-route, ips-decision, trivy-scan of steps_toolbox_b.py, chrony-nts of steps_infra.py).

The sections below join the infrastructure reading (inframeasure.py). What they print, and what they never print:
  tb_units     the state of a fixed list of units (systemctl show: loaded, active, enabled), nothing else of them
  tb_versions  the first line with a version number in it, of a fixed list of programs, with every character outside a short set taken out
  tb_crowdsec  cscli decisions (addresses, scenarios, durations) and the bouncers it knows, with every line naming a key dropped first:
               cscli 1.4 prints each bouncer's API key in its JSON, so a line with "api_key" never leaves the host. A JSON printed on
               one line loses that line whole, and the bouncers read as unknown rather than leak
  tb_fail2ban  the jails and their counts and banned addresses
  tb_chrony    chronyc -c tracking, sources and authdata (NTS): addresses, offsets, the authentication mode, no key
  tb_unbound   unbound-control status and three query counters
  tb_suricata  how many alerts the last 5000 EVE events hold, and the time, addresses, signature and severity of the last 30, picked out
               field by field: the packet payload EVE may carry is never printed
  tb_scans     the findings trivy-scan wrote (one line each: id, package, installed and fixed version, severity)
  tb_smart     smartctl --scan and the overall health line of each device, without waking a disk in standby
  tb_api       Prometheus's target health counts, on loopback, where StorageForge installed it or its unit runs
"""
from __future__ import annotations

import json
import re

from .tbadapters import Adapter, _containers, _tile
from .toolbox import TOOLS_HOME

SECTIONS = ('tb_units', 'tb_versions', 'tb_crowdsec', 'tb_fail2ban', 'tb_chrony', 'tb_unbound', 'tb_suricata', 'tb_scans', 'tb_smart', 'tb_api')
UNITS = ('caddy', 'traefik', 'unbound', 'coredns', 'dnsmasq', 'chronyd', 'chrony', 'crowdsec', 'crowdsec-firewall-bouncer', 'fail2ban', 'suricata',
         'prometheus', 'prometheus-node-exporter', 'node_exporter', 'prometheus-smartctl-exporter', 'smartctl_exporter', 'grafana-server', 'loki',
         'netdata', 'smartd', 'smartmontools', 'step-ca', 'adguardhome',
         # the units root Podman makes from the Quadlet files of the container entries
         'nginx-proxy-manager', 'pi-hole', 'adguard-home', 'trivy', 'grafana', 'beszel', 'ntfy', 'gotify', 'apprise')
VERSIONS = (('caddy', 'version'), ('traefik', 'version'), ('unbound', '-V'), ('coredns', '-version'), ('dnsmasq', '--version'), ('chronyd', '-v'),
            ('cscli', 'version'), ('fail2ban-client', '--version'), ('suricata', '-V'), ('zeek', '--version'), ('trivy', '--version'), ('grype', '--version'),
            ('oscap', '--version'), ('prometheus', '--version'), ('prometheus-node-exporter', '--version'), ('node_exporter', '--version'),
            ('grafana-server', '-v'), ('loki', '-version'), ('netdata', '-V'), ('smartctl', '--version'), ('smartctl_exporter', '--version'),
            ('prometheus-smartctl-exporter', '--version'), ('step-ca', 'version'), ('apprise', '--version'), ('adguardhome', '--version'))
SCANS = f'{TOOLS_HOME}/scans'

BODY = r"""
# the Toolbox adapters of 0.5.13 (tbadapters_b.py): states, version lines, counts and addresses only
sec tb_units
has systemctl && try systemctl show -p Id,LoadState,ActiveState,UnitFileState @UNITS@ | capped 30000
sec tb_versions
tbv() { has "$1" || return 0; printf "v\t%s\t%s\n" "$1" "$(timeout 10 "$@" 2>&1 | grep -m1 -E "[0-9]+\.[0-9]+" | tr -cd "[:alnum:] ._:+()/,-" | cut -c1-160)"; }
@VERSIONS@
sec tb_crowdsec
if has cscli; then
  printf "d\t%s\n" "$(timeout 20 cscli decisions list -o json 2>/dev/null | tr -d "\n" | capped 200000)"
  printf "b\t%s\n" "$(timeout 20 cscli bouncers list -o json 2>/dev/null | grep -aviE "key|token|password|secret" | tr -d "\n" | capped 20000)"
  has nft && printf "n\t%s\n" "$(try nft list table ip crowdsec | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?" | wc -l)"
fi
sec tb_fail2ban
if has fail2ban-client; then
  f2b=$(timeout 10 fail2ban-client status 2>/dev/null | sed -n "s/.*Jail list:[[:space:]]*//p" | tr -d " " | tr "," " ")
  printf "j\t%s\n" "$f2b"
  for j in $f2b; do
    timeout 10 fail2ban-client status "$j" 2>/dev/null | grep -E "Currently banned|Total banned|Banned IP list" | head -c 40000 | while IFS= read -r l; do printf "s\t%s\t%s\n" "$j" "$l"; done
  done
fi
sec tb_chrony
if has chronyc; then
  try chronyc -c tracking | head -n 1 | sed "s/^/t,/"
  try chronyc -c -n sources | head -n 50 | sed "s/^/s,/"
  try chronyc -c -N authdata | head -n 50 | sed "s/^/a,/"
fi
sec tb_unbound
if has unbound-control; then
  try unbound-control status | head -n 12 | sed "s/^/s\t/"
  try unbound-control stats_noreset | grep -E "^total\.num\.(queries|cachehits|cachemiss)=" | sed "s/^/n\t/"
fi
sec tb_suricata
if [ -r /var/log/suricata/eve.json ]; then
  printf "c\t%s\n" "$(tail -n 5000 /var/log/suricata/eve.json | grep -c "\"event_type\":\"alert\"")"
  tail -n 5000 /var/log/suricata/eve.json | grep "\"event_type\":\"alert\"" | tail -n 30 | while IFS= read -r l; do
    printf "a\t%s\n" "$(printf "%s" "$l" | grep -oE "\"(timestamp|src_ip|dest_ip|signature)\":\"[^\"]{0,200}\"|\"(severity|signature_id)\":[0-9]{1,10}" | tr "\n" "\t")"
  done
fi
sec tb_scans
for f in @SCANS@/*.tsv; do [ -r "$f" ] && head -n 3000 "$f"; done | capped 400000
sec tb_smart
if has smartctl; then
  try smartctl --scan | head -n 32 | while read -r dev _ typ _; do
    printf "d\t%s\t%s\t%s\n" "$dev" "$typ" "$(timeout 20 smartctl -H -n standby -d "$typ" "$dev" 2>/dev/null | grep -m1 -iE "overall-health|health status|standby" | tr -cd "[:alnum:] .:_/-")"
  done
fi
sec tb_api
tbq() { [ -e "/etc/containers/systemd/$1.container" ] || [ -e "@HOME@/$1/.config/containers/systemd/$1.container" ]; }
if has curl; then
  if tbq prometheus || { has systemctl && systemctl is-active --quiet prometheus 2>/dev/null; }; then
    printf "prometheus\t%s\n" "$(curl -s --max-time 5 "http://127.0.0.1:9090/api/v1/targets?state=active" 2>/dev/null | grep -oE "\"health\":\"[a-z]+\"" | sort | uniq -c | tr -s " " | tr "\n" ",")"
  fi
fi
""".replace('@UNITS@', ' '.join(f'{u}.service' for u in UNITS)).replace('@VERSIONS@', '\n'.join(f'tbv {a} {b}' for a, b in VERSIONS)) \
   .replace('@SCANS@', SCANS).replace('@HOME@', TOOLS_HOME)

VERSION = re.compile(r'v?(\d+\.\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.]{1,20})?)')
IPNET = re.compile(r'[0-9a-fA-F:.]{2,45}(/\d{1,3})?')
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
WORD = re.compile(r'[^\t\0\r\n\x1b]{0,200}')


def _word(v, limit: int = 200) -> str:
    v = str(v or '')[:limit]
    return v if WORD.fullmatch(v) else ''


# ── reading what the sections print ─────────────────────────────────
def read_units(lines: list[str]) -> dict:
    """systemctl show blocks: the units that are there, with their state."""
    out, cur = {}, {}
    for line in lines + ['']:
        if not line.strip():
            if cur.get('Id') and cur.get('LoadState') == 'loaded' and re.fullmatch(r'[A-Za-z0-9_.@-]{1,120}\.service', cur['Id']):
                out[cur['Id']] = {'active': _word(cur.get('ActiveState'), 20), 'enabled': _word(cur.get('UnitFileState'), 20)}
            cur = {}
            continue
        k, _, v = line.partition('=')
        cur[k.strip()] = v.strip()
    return out


def read_versions(lines: list[str]) -> dict:
    out = {}
    names = {a for a, _ in VERSIONS}
    for line in lines:
        f = line.split('\t')
        if len(f) == 3 and f[0] == 'v' and f[1] in names:
            m = VERSION.search(f[2])
            if m:
                out[f[1]] = m[1]
    return out


def _json(text: str):
    try:
        return json.loads(re.sub(r',\s*([}\]])', r'\1', text or ''))
    except ValueError:
        return None


def read_crowdsec(lines: list[str]) -> dict | None:
    """Local decisions (cscli decisions list: alerts, each with its decisions), the bouncers, and how many addresses the bouncer's nftables
    table holds."""
    out: dict = {}
    for line in lines:
        tag, _, rest = line.partition('\t')
        if tag == 'd':
            got = _json(rest)
            if rest.strip() and got is None:
                out['decisions_error'] = 'cscli printed something that is not JSON'
            decisions = []
            for alert in got if isinstance(got, list) else []:
                for d in (alert or {}).get('decisions') or []:
                    value = str(d.get('value') or '')
                    if not IPNET.fullmatch(value) or d.get('simulated'):
                        continue
                    decisions.append({'id': d.get('id') if isinstance(d.get('id'), int) else None, 'value': value, 'scope': _word(d.get('scope'), 20),
                                      'type': _word(d.get('type'), 20), 'origin': _word(d.get('origin'), 30), 'scenario': _word(d.get('scenario'), 120),
                                      'duration': _word(d.get('duration'), 40)})
            out['decisions'] = decisions[:2000]
        elif tag == 'b':
            got = _json(rest)
            out['bouncers'] = None if got is None and rest.strip() else [
                {'name': _word(b.get('name'), 60), 'last_pull': _word(b.get('last_pull'), 40), 'type': _word(b.get('type'), 60),
                 'version': _word(b.get('version'), 40), 'revoked': bool(b.get('revoked'))} for b in got or [] if isinstance(b, dict)]
        elif tag == 'n' and rest.strip().isdigit():
            out['nft_addresses'] = int(rest.strip())
    return out or None


def read_fail2ban(lines: list[str]) -> dict | None:
    jails: dict = {}
    seen = False
    for line in lines:
        f = line.split('\t')
        if f[0] == 'j' and len(f) >= 2:
            seen = True
            for j in f[1].split():
                if re.fullmatch(r'[A-Za-z0-9_.@-]{1,60}', j):
                    jails.setdefault(j, {'banned_now': None, 'banned_total': None, 'banned': []})
        elif f[0] == 's' and len(f) >= 3 and f[1] in jails:
            text = '\t'.join(f[2:])
            m = re.search(r'(Currently banned|Total banned|Banned IP list):\s*(.*)$', text)
            if not m:
                continue
            if m[1] == 'Banned IP list':
                jails[f[1]]['banned'] = [x for x in m[2].split() if IPNET.fullmatch(x)][:2000]
            elif m[2].strip().isdigit():
                jails[f[1]]['banned_now' if m[1] == 'Currently banned' else 'banned_total'] = int(m[2].strip())
    return {'jails': jails} if seen else None


def _float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def read_chrony(lines: list[str]) -> dict | None:
    """chronyc -c: tracking (reference, stratum, offset, leap), sources (mode, state, address, stratum), authdata (name, NTS or not, cookies)."""
    out: dict = {'sources': [], 'auth': []}
    for line in lines:
        f = line.split(',')
        if f[0] == 't' and len(f) >= 15:
            out['tracking'] = {'ref_id': _word(f[1], 20), 'ref': _word(f[2], 80), 'stratum': int(f[3]) if f[3].isdigit() else None,
                               'offset': _float(f[5]), 'leap': _word(f[14], 30)}
        elif f[0] == 's' and len(f) >= 11:
            out['sources'].append({'mode': _word(f[1], 2), 'state': _word(f[2], 2), 'address': _word(f[3], 80), 'stratum': int(f[4]) if f[4].isdigit() else None,
                                   'reach': _word(f[6], 4), 'offset': _float(f[8])})
        elif f[0] == 'a' and len(f) >= 11:
            out['auth'].append({'name': _word(f[1], 120), 'mode': _word(f[2], 10), 'key_id': _word(f[3], 20), 'cookies': int(f[9]) if f[9].isdigit() else 0})
    if 'tracking' not in out and not out['sources'] and not out['auth']:
        return None
    out['sources'], out['auth'] = out['sources'][:50], out['auth'][:50]
    return out


def read_unbound(lines: list[str]) -> dict | None:
    out: dict = {}
    for line in lines:
        tag, _, rest = line.partition('\t')
        if tag == 's':
            if re.match(r'unbound \(pid \d+\) is running', rest):
                out['running'] = True
            elif 'is stopped' in rest:
                out['running'] = False
            m = re.fullmatch(r'(version|uptime|threads):\s*(.{0,60})', rest.strip())
            if m:
                out[m[1]] = _word(m[2], 60)
        elif tag == 'n':
            m = re.fullmatch(r'total\.num\.(queries|cachehits|cachemiss)=(\d{1,15})', rest.strip())
            if m:
                out[m[1]] = int(m[2])
    return out or None


def read_suricata(lines: list[str]) -> dict | None:
    out: dict = {'alerts': []}
    seen = False
    for line in lines:
        tag, _, rest = line.partition('\t')
        if tag == 'c' and rest.strip().isdigit():
            out['count'], seen = int(rest.strip()), True
        elif tag == 'a':
            a = {}
            for part in rest.split('\t'):
                m = re.fullmatch(r'"(timestamp|src_ip|dest_ip|signature)":"([^"]{0,200})"|"(severity|signature_id)":(\d{1,10})', part)
                if not m:
                    continue
                key, val = (m[1], m[2]) if m[1] else (m[3], int(m[4]))
                a.setdefault(key, val if isinstance(val, int) else _word(val))
            if a.get('signature'):
                out['alerts'].append(a)
    if not seen and not out['alerts']:
        return None
    out['alerts'] = out['alerts'][-30:]
    return out


def read_scans(lines: list[str]) -> list[dict]:
    """trivy-scan's reports: one image a report, with counts by severity, what a fix exists for, and the findings most worth a look first."""
    images, cur = [], None
    for line in lines:
        f = line.split('\t')
        if f[0] == 'i' and len(f) >= 4:
            ref = f[1]
            if not re.fullmatch(r'[a-z0-9][a-z0-9._/:@-]{0,300}', ref):
                cur = None
                continue
            cur = {'image': ref, 'scanned_at': int(f[2]) if f[2].isdigit() else None, 'scanner': f[3] if f[3] in ('trivy', 'grype') else 'trivy',
                   'counts': dict.fromkeys(SEVERITIES, 0), 'fixable': dict.fromkeys(SEVERITIES, 0), 'findings': []}
            images.append(cur)
        elif f[0] == 'v' and len(f) >= 6 and cur is not None:
            vid = f[1] if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{2,60}', f[1]) else None
            if not vid:
                continue
            sev = f[5].strip().upper() if f[5].strip().upper() in SEVERITIES else 'UNKNOWN'
            if sev == 'NEGLIGIBLE':
                sev = 'LOW'
            fixed = _word(f[4], 120)
            cur['counts'][sev] += 1
            if fixed:
                cur['fixable'][sev] += 1
            cur['findings'].append({'id': vid, 'package': _word(f[2], 120), 'installed': _word(f[3], 80), 'fixed': fixed, 'severity': sev})
    for img in images:
        # what matters first: the worst, and those a fix exists for. The counts keep the rest
        img['findings'].sort(key=lambda x: (SEVERITIES.index(x['severity']), not x['fixed'], x['id']))
        seen, keep = set(), []
        for x in img['findings']:
            if (x['id'], x['package']) not in seen:
                seen.add((x['id'], x['package']))
                keep.append(x)
        img['findings'] = keep[:200]
    return images[-100:]


def read_smart(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        f = line.split('\t')
        if len(f) >= 4 and f[0] == 'd' and re.fullmatch(r'/dev/[A-Za-z0-9/_.-]{1,60}', f[1]):
            text = f[3].upper()
            health = 'passed' if ('PASSED' in text or text.endswith(' OK')) else 'failed' if ('FAILED' in text or 'FAILING' in text) else \
                'standby' if 'STANDBY' in text else 'unknown'
            out.append({'device': f[1], 'type': _word(f[2], 30), 'health': health})
    return out[:32]


def read_api(lines: list[str]) -> dict:
    out: dict = {}
    for line in lines:
        tool, _, rest = line.partition('\t')
        if tool == 'prometheus':
            counts = {m[2]: int(m[1]) for m in re.finditer(r'(\d+) "health":"([a-z]+)"', rest)}
            out['prometheus'] = {'up': counts.get('up', 0), 'down': counts.get('down', 0), 'unknown': counts.get('unknown', 0)}
    return out


def sections_of(sections: dict) -> dict:
    """What the reading keeps of these sections, beside tbadapters.sections_of. One that cannot be read is left out: it costs only its tool."""
    out: dict = {}
    for key, reader, name in (('units', read_units, 'tb_units'), ('versions', read_versions, 'tb_versions'), ('crowdsec', read_crowdsec, 'tb_crowdsec'),
                              ('fail2ban', read_fail2ban, 'tb_fail2ban'), ('chrony', read_chrony, 'tb_chrony'), ('unbound', read_unbound, 'tb_unbound'),
                              ('suricata', read_suricata, 'tb_suricata'), ('scans', read_scans, 'tb_scans'), ('smart', read_smart, 'tb_smart'), ('api', read_api, 'tb_api')):
        try:
            out[key] = reader(sections.get(name, []))
        except Exception:                                   # noqa: BLE001  a reader that fails on what a host printed costs its own tool only
            out[key] = None
    return out


# ── the adapters ────────────────────────────────────────────────────
def _tb(reading: dict) -> dict:
    return reading.get('toolbox') or {}


class Tool(Adapter):
    """A tool seen by its units, its container or its program: a status of the units' states, the container, the version and the health
    check. The adapters below add what each tool can say of itself."""
    level = 'status'

    def __init__(self, name: str, units=(), programs=(), image: str | None = None, level: str = 'status'):
        self.name, self.units, self.programs, self.image, self.level = name, tuple(f'{u}.service' for u in units), tuple(programs), image, level

    def detect(self, reading, ctx):
        tb = _tb(reading)
        units = {u: s for u, s in (tb.get('units') or {}).items() if u in self.units}
        cs = _containers(ctx, self.name, self.image) if self.image else [c for c in ctx.get('containers') or [] if (c.get('labels') or {}).get('storageforge.tool') == self.name]
        version = next(((tb.get('versions') or {}).get(p) for p in self.programs if (tb.get('versions') or {}).get(p)), None)
        if not units and not cs and not version:
            return None
        if cs and not version:
            tag = (cs[0].get('image') or '').split('@')[0].rsplit(':', 1)
            version = tag[1] if len(tag) == 2 and '/' not in tag[1] else None
        running = (any(s['active'] == 'active' for s in units.values()) or any(c.get('state') == 'running' for c in cs)) if (units or cs) else True
        how = 'container' if cs else 'package' if units else 'program'
        managed = any((c.get('labels') or {}).get('storageforge.tool') == self.name for c in cs)
        return {'running': running, 'how': cs[0].get('how') if cs else how, 'units': units, 'container': cs[0].get('name') if cs else None,
                'version': version, 'managed': managed}

    def status(self, reading, ctx, found):
        tiles = []
        for u, s in sorted(found['units'].items()):
            tiles.append(_tile(u, f'{s["active"]}, {s["enabled"] or "unknown"} at boot', 'ok' if s['active'] == 'active' else 'crit'))
        if found.get('container'):
            tiles.append(_tile('Container', f'{found["container"]}, {"running" if found["running"] else "stopped"}', 'ok' if found['running'] else 'crit'))
        if found['how'] == 'program':
            tiles.append(_tile('Installed', 'a program run when asked: nothing runs all the time', 'ok'))
        tiles.append(_tile('Version', found.get('version') or 'unknown'))
        code = (ctx.get('health') or {}).get(self.name)
        if code is not None:
            tiles.append(_tile('Health check', f'HTTP {code}' if code else 'no answer', 'ok' if 200 <= code < 400 else 'crit'))
        health = 'ok' if found['running'] and (code is None or 200 <= code < 400) else 'down'
        return {'health': health, 'version': found.get('version'), 'tiles': tiles + self.more(reading, ctx, found)}

    def more(self, reading, ctx, found) -> list[dict]:
        return []

    def metrics(self, reading, ctx):
        found = self.detect(reading, ctx) or {}
        return {'running': 1 if found.get('running') else 0}


class Caddy(Tool):
    """Caddy with routes StorageForge writes: each to the loopback port of a tool on the same host (caddy-route)."""

    def routes(self, reading):
        return [r for r in ((reading.get('access') or {}).get('proxy_routes') or []) if r.get('proxy') == 'caddy']

    def more(self, reading, ctx, found):
        rs = self.routes(reading)
        tiles = [_tile('Routes', f'{len(rs)}: ' + ', '.join(f'{r["site"]} to {r["upstream"]}' for r in rs[:6]) if rs else 'none yet: add one for a tool on this host')]
        wide = [r for r in rs if not re.match(r'(127\.0\.0\.1|localhost|\[::1\]):', r.get('upstream') or '')]
        if wide:
            tiles.append(_tile('Upstreams off loopback', ', '.join(r['upstream'] for r in wide[:4]) + ': the tool behind it listens on more than loopback', 'warn'))
        return tiles

    def actions(self, reading, ctx):
        sites = sorted({r['site'] for r in self.routes(reading)})
        return [{'id': 'add-route', 'label': 'Route a site to a tool on this host', 'fields': [
                    {'name': 'site', 'kind': 'text', 'label': 'Site (a name that points at this host)', 'required': True},
                    {'name': 'port', 'kind': 'number', 'label': 'Loopback port of the tool', 'required': True}]},
                {'id': 'remove-route', 'label': 'Remove a route', 'fields': [{'name': 'site', 'kind': 'choice', 'label': 'Site', 'options': sites, 'required': True}]}]

    def tasks(self, action, values, host, reading):
        site, port = str(values.get('site') or ''), str(values.get('port') or '')
        if action == 'add-route':
            return [{'host': host, 'type': 'caddy-route', 'params': {'site': site, 'port': port, 'state': 'present'}, 'note': 'Caddy routes, from the Toolbox'}]
        if action == 'remove-route':
            return [{'host': host, 'type': 'caddy-route', 'params': {'site': site, 'port': '1', 'state': 'absent'}, 'note': 'Caddy routes, from the Toolbox'}]
        raise ValueError(f'caddy has no action {action}')

    def metrics(self, reading, ctx):
        return {'routes': len(self.routes(reading))}


class Unbound(Tool):
    def more(self, reading, ctx, found):
        u = _tb(reading).get('unbound')
        if not u:
            return [_tile('unbound-control', 'not answering: the control socket is off, so only the unit state is known', 'warn')]
        tiles = [_tile('Resolver', ('running' if u.get('running') else 'stopped') + (f', up {u["uptime"]}' if u.get('uptime') else ''), 'ok' if u.get('running') else 'crit')]
        if u.get('queries') is not None:
            hits = u.get('cachehits') or 0
            tiles.append(_tile('Queries', f'{u["queries"]}' + (f', {round(100 * hits / u["queries"])}% from the cache' if u['queries'] else '')))
        return tiles

    def metrics(self, reading, ctx):
        u = _tb(reading).get('unbound') or {}
        return {k: u[k] for k in ('queries', 'cachehits', 'cachemiss') if k in u}


class Chrony(Tool):
    """Chrony and its NTS sources: the source in use, its offset, and how many sources are authenticated by NTS. Setting the NTS servers is
    the chrony-nts step, the one the clock guard asks for."""
    level = 'status+actions'

    def more(self, reading, ctx, found):
        c = _tb(reading).get('chrony')
        if not c:
            return []
        t = c.get('tracking') or {}
        nts = [a for a in c['auth'] if a['mode'] == 'NTS']
        good = [a for a in nts if a['cookies'] > 0]
        tiles = []
        if t:
            off = t.get('offset')
            tiles.append(_tile('In use', f'{t.get("ref") or t.get("ref_id")}, stratum {t.get("stratum")}' + (f', {off * 1000:+.3f} ms' if off is not None else ''),
                               'ok' if t.get('leap') == 'Normal' else 'warn'))
        tiles.append(_tile('Sources', f'{len(c["sources"])}, {sum(1 for s in c["sources"] if s["state"] in ("*", "+"))} usable'))
        tiles.append(_tile('NTS', f'{len(good)} of {len(c["auth"])} sources authenticated by NTS' if c['auth'] else 'no source is authenticated',
                           'ok' if good else 'warn'))
        return tiles

    def actions(self, reading, ctx):
        return [{'id': 'nts', 'label': 'Use NTS time sources', 'fields': [
            {'name': 'servers', 'kind': 'text', 'label': 'NTS servers, comma separated', 'required': True}]}]

    def tasks(self, action, values, host, reading):
        if action != 'nts':
            raise ValueError(f'chrony has no action {action}')
        return [{'host': host, 'type': 'chrony-nts', 'params': {'servers': str(values.get('servers') or '').replace(' ', '')}, 'note': 'Chrony, from the Toolbox'}]

    def metrics(self, reading, ctx):
        c = _tb(reading).get('chrony') or {}
        return {'sources': len(c.get('sources') or []), 'nts': sum(1 for a in c.get('auth') or [] if a['mode'] == 'NTS' and a['cookies'] > 0),
                'offset_ms': round(((c.get('tracking') or {}).get('offset') or 0) * 1000, 3)}


class CrowdSec(Tool):
    """CrowdSec: its local decisions, the bouncers that pull them, and whether the nftables bouncer holds any. Bans and lifts are
    ips-decision steps; the Quarantine view shows them beside StorageForge's own quarantine (tbfeeds.py)."""
    level = 'status+actions'

    def more(self, reading, ctx, found):
        c = _tb(reading).get('crowdsec') or {}
        ds = c.get('decisions') or []
        tiles = [_tile('Decisions', f'{len(ds)} local: ' + ', '.join(f'{d["value"]} ({d["scenario"] or d["origin"]})' for d in ds[:4]) if ds else 'no local decision now')]
        bs = c.get('bouncers')
        if bs is None:
            tiles.append(_tile('Bouncers', 'unknown: cscli did not list them in a form that could be read without its keys', 'warn'))
        else:
            live = [b for b in bs if not b['revoked']]
            tiles.append(_tile('Bouncers', ', '.join(b['name'] for b in live) or 'none: decisions are made and nothing enforces them', 'ok' if live else 'warn'))
        if 'nft_addresses' in c:
            tiles.append(_tile('nftables', f'{c["nft_addresses"]} addresses in the bouncer table', 'ok' if c['nft_addresses'] or not ds else 'warn'))
        if c.get('decisions_error'):
            tiles.append(_tile('cscli', c['decisions_error'], 'warn'))
        return tiles

    def actions(self, reading, ctx):
        values = sorted({d['value'] for d in (_tb(reading).get('crowdsec') or {}).get('decisions') or []})
        return [{'id': 'ban', 'label': 'Ban an address in CrowdSec', 'fields': [
                    {'name': 'ip', 'kind': 'cidr', 'label': 'Address or network', 'required': True}, {'name': 'duration', 'kind': 'text', 'label': 'For (such as 4h)'},
                    {'name': 'reason', 'kind': 'text', 'label': 'Reason'}]},
                {'id': 'lift', 'label': 'Lift a CrowdSec ban', 'fields': [{'name': 'ip', 'kind': 'choice', 'label': 'Address', 'options': values, 'required': True}]}]

    def tasks(self, action, values, host, reading):
        if action not in ('ban', 'lift'):
            raise ValueError(f'crowdsec has no action {action}')
        return [{'host': host, 'type': 'ips-decision', 'params': {'tool': 'crowdsec', 'ip': str(values.get('ip') or ''), 'state': 'banned' if action == 'ban' else 'lifted',
                                                                 'jail': '', 'duration': str(values.get('duration') or '4h'), 'reason': str(values.get('reason') or 'from StorageForge')},
                 'note': 'CrowdSec, from the Toolbox'}]

    def metrics(self, reading, ctx):
        c = _tb(reading).get('crowdsec') or {}
        return {'decisions': len(c.get('decisions') or []), 'bouncers': len(c.get('bouncers') or []), 'nft_addresses': c.get('nft_addresses')}


class Fail2ban(Tool):
    level = 'status+actions'

    def jails(self, reading):
        return ((_tb(reading).get('fail2ban') or {}).get('jails')) or {}

    def more(self, reading, ctx, found):
        js = self.jails(reading)
        if not js:
            return [_tile('Jails', 'none is on', 'warn')]
        return [_tile(f'Jail {j}', f'{v["banned_now"] if v["banned_now"] is not None else "?"} banned now, {v["banned_total"] if v["banned_total"] is not None else "?"} in all'
                      + (': ' + ', '.join(v['banned'][:5]) if v['banned'] else '')) for j, v in sorted(js.items())]

    def actions(self, reading, ctx):
        names = sorted(self.jails(reading))
        jail = {'name': 'jail', 'kind': 'choice', 'label': 'Jail', 'options': names, 'required': True}
        return [{'id': 'ban', 'label': 'Ban an address in a jail', 'fields': [jail, {'name': 'ip', 'kind': 'cidr', 'label': 'Address', 'required': True}]},
                {'id': 'lift', 'label': 'Lift a ban in a jail', 'fields': [jail, {'name': 'ip', 'kind': 'cidr', 'label': 'Address', 'required': True}]}]

    def tasks(self, action, values, host, reading):
        if action not in ('ban', 'lift'):
            raise ValueError(f'fail2ban has no action {action}')
        return [{'host': host, 'type': 'ips-decision', 'params': {'tool': 'fail2ban', 'ip': str(values.get('ip') or ''), 'state': 'banned' if action == 'ban' else 'lifted',
                                                                 'jail': str(values.get('jail') or ''), 'duration': '', 'reason': ''}, 'note': 'fail2ban, from the Toolbox'}]

    def metrics(self, reading, ctx):
        js = self.jails(reading)
        return {'jails': len(js), 'banned': sum(v['banned_now'] or 0 for v in js.values())}


class Suricata(Tool):
    def more(self, reading, ctx, found):
        s = _tb(reading).get('suricata')
        if not s:
            return [_tile('EVE log', 'not read: /var/log/suricata/eve.json is not there yet', 'warn')]
        last = s['alerts'][-3:]
        return [_tile('Alerts', f'{s.get("count", 0)} in the last 5000 events', 'warn' if s.get('count') else 'ok'),
                *[_tile('Alert', f'{a.get("signature")} from {a.get("src_ip")} to {a.get("dest_ip")}', 'crit' if a.get('severity') == 1 else 'warn') for a in reversed(last)]]

    def metrics(self, reading, ctx):
        return {'alerts': (_tb(reading).get('suricata') or {}).get('count') or 0}


class Scanner(Tool):
    """Trivy and Grype: the images scanned on this host, what was found, and what a fix exists for. A scan is a trivy-scan step."""
    level = 'full'

    def reports(self, reading):
        return [r for r in _tb(reading).get('scans') or [] if r['scanner'] == self.name]

    def more(self, reading, ctx, found):
        rs = self.reports(reading)
        if not rs:
            return [_tile('Scans', 'none yet: scan the images of this host', 'warn')]
        crit = sum(r['fixable']['CRITICAL'] for r in rs)
        high = sum(r['fixable']['HIGH'] for r in rs)
        tiles = [_tile('Images scanned', str(len(rs))),
                 _tile('Fixable', f'{crit} critical, {high} high', 'crit' if crit else 'warn' if high else 'ok')]
        for r in sorted(rs, key=lambda r: (-r['fixable']['CRITICAL'], -r['fixable']['HIGH']))[:4]:
            c = r['counts']
            tiles.append(_tile(r['image'][:80], f'{c["CRITICAL"]} critical, {c["HIGH"]} high, {c["MEDIUM"]} medium', 'crit' if c['CRITICAL'] else 'warn' if c['HIGH'] else 'ok'))
        return tiles

    def actions(self, reading, ctx):
        return [{'id': 'scan-running', 'label': 'Scan the images of the running containers', 'fields': []},
                {'id': 'scan-images', 'label': 'Scan images by name', 'fields': [
                    {'name': 'images', 'kind': 'text', 'label': 'Images, separated by spaces', 'required': True}]}]

    def tasks(self, action, values, host, reading):
        if action == 'scan-running':
            params = {'target': 'running', 'images': '', 'scanner': self.name}
        elif action == 'scan-images':
            params = {'target': 'listed', 'images': '\n'.join(str(values.get('images') or '').replace(',', ' ').split()), 'scanner': self.name}
        else:
            raise ValueError(f'{self.name} has no action {action}')
        return [{'host': host, 'type': 'trivy-scan', 'params': params, 'note': f'{self.name}, from the Toolbox'}]

    def metrics(self, reading, ctx):
        rs = self.reports(reading)
        return {'images': len(rs), **{f'fixable_{s.lower()}': sum(r['fixable'][s] for r in rs) for s in ('CRITICAL', 'HIGH')}}


class Smart(Tool):
    def more(self, reading, ctx, found):
        ds = _tb(reading).get('smart') or []
        if not ds:
            return [_tile('Disks', 'smartctl found none it can read here (a VM shows none)', 'warn')]
        bad = [d for d in ds if d['health'] == 'failed']
        return [_tile('Disks', f'{len(ds)}: ' + ', '.join(f'{d["device"]} {d["health"]}' for d in ds[:8]), 'crit' if bad else 'ok')]

    def status(self, reading, ctx, found):
        st = super().status(reading, ctx, found)
        if any(d['health'] == 'failed' for d in _tb(reading).get('smart') or []):
            st['health'] = 'down'
        return st

    def metrics(self, reading, ctx):
        ds = _tb(reading).get('smart') or []
        return {'disks': len(ds), 'failed': sum(1 for d in ds if d['health'] == 'failed')}


class Prometheus(Tool):
    def more(self, reading, ctx, found):
        p = (_tb(reading).get('api') or {}).get('prometheus')
        if not p:
            return []
        return [_tile('Targets', f'{p["up"]} up, {p["down"]} down', 'warn' if p['down'] else 'ok')]


ADAPTERS = {a.name: a for a in (
    Caddy('caddy', ['caddy'], ['caddy'], level='full'),
    Tool('traefik', ['traefik'], ['traefik'], 'library/traefik'),
    Tool('nginx-proxy-manager', ['nginx-proxy-manager'], (), 'jc21/nginx-proxy-manager'),
    Tool('step-ca', ['step-ca'], ['step-ca'], 'smallstep/step-ca'),
    Tool('pi-hole', ['pi-hole'], (), 'pihole/pihole'),
    Tool('adguard-home', ['adguard-home', 'adguardhome'], ['adguardhome'], 'adguard/adguardhome'),
    Unbound('unbound', ['unbound'], ['unbound']),
    Tool('coredns', ['coredns'], ['coredns']),
    Tool('dnsmasq', ['dnsmasq'], ['dnsmasq']),
    Chrony('chrony', ['chronyd', 'chrony'], ['chronyd'], level='status+actions'),
    CrowdSec('crowdsec', ['crowdsec', 'crowdsec-firewall-bouncer'], ['cscli'], level='status+actions'),
    Fail2ban('fail2ban', ['fail2ban'], ['fail2ban-client'], level='status+actions'),
    Suricata('suricata', ['suricata'], ['suricata']),
    Tool('zeek', (), ['zeek']),
    Scanner('trivy', ['trivy'], ['trivy'], 'aquasec/trivy', level='full'),
    Scanner('grype', (), ['grype'], level='full'),
    Tool('openscap', (), ['oscap']),
    Prometheus('prometheus', ['prometheus'], ['prometheus'], 'prom/prometheus'),
    Tool('node-exporter', ['prometheus-node-exporter', 'node_exporter'], ['prometheus-node-exporter', 'node_exporter']),
    Tool('grafana', ['grafana', 'grafana-server'], ['grafana-server'], 'grafana/grafana'),
    Tool('loki', ['loki'], ['loki'], 'grafana/loki'),
    Tool('beszel', ['beszel'], (), 'henrygd/beszel'),
    Tool('netdata', ['netdata'], ['netdata']),
    Smart('smartd', ['smartd', 'smartmontools'], ['smartctl']),
    Tool('smartctl-exporter', ['prometheus-smartctl-exporter', 'smartctl_exporter'], ['smartctl_exporter', 'prometheus-smartctl-exporter']),
    Tool('ntfy', ['ntfy'], (), 'binwiederhier/ntfy'),
    Tool('gotify', ['gotify'], (), 'gotify/server'),
    Tool('apprise', ['apprise'], ['apprise'], 'caronc/apprise'),
)}
