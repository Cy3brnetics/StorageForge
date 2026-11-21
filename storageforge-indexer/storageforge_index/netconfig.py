"""What a host's network files say, beside what the kernel has: netplan, NetworkManager, systemd-networkd and ifupdown.

netfacts.py reads them in the same scan session, as the scan user, so a file only root can read (netplan wants 0600, and
NetworkManager keeps its keyfiles so) is listed as unreadable and never taken as empty. netplan writes what it means into
/run/systemd/network or into NetworkManager, and both of those are read too, so a host whose netplan files are closed to the
scan user still shows what they configure. Each parser reads what it can of text from a machine StorageForge does not
control and never throws (tests/test_props_parsers.py holds them to that).

The result, per interface: where it is set up, its kind, DHCP for each family, the addresses and routes it is given, a bond's
or bridge's members and mode, a VLAN's parent and id. The map shows it beside the live state, and the network steps check
against it.
"""
from __future__ import annotations

import ipaddress
import re

MAX_FILES = 64
KINDS = {'ethernets': 'ethernet', 'bonds': 'bond', 'bridges': 'bridge', 'vlans': 'vlan', 'wifis': 'wifi', 'tunnels': 'tunnel', 'vrfs': 'vrf', 'dummy-devices': 'dummy'}

# POSIX sh: appended to netfacts.SCRIPT. A file the scan user cannot read is named, so it is never taken as empty.
SCRIPT = r"""
echo; echo '@@manager'
command -v netplan >/dev/null 2>&1 && echo netplan=1
command -v nmcli >/dev/null 2>&1 && echo "nm=$(t nmcli -t -f RUNNING general)"
command -v systemctl >/dev/null 2>&1 && echo "networkd=$(t systemctl is-active systemd-networkd)"
command -v ifup >/dev/null 2>&1 && echo ifup=1
sf_files() { for f in "$@"; do [ -e "$f" ] || continue; if [ -r "$f" ]; then echo "@@>file $f"; head -c 65536 "$f"; echo; else echo "@@>unreadable $f"; fi; done; }
echo; echo '@@netplan'; sf_files /etc/netplan/*.yaml /etc/netplan/*.yml
echo; echo '@@networkd'; sf_files /etc/systemd/network/*.network /etc/systemd/network/*.netdev /etc/systemd/network/*.network.d/*.conf /run/systemd/network/*.network /run/systemd/network/*.netdev /run/systemd/network/*.network.d/*.conf
echo; echo '@@nm'
if command -v nmcli >/dev/null 2>&1; then
  t nmcli -t -f UUID connection show | head -n 64 | while read -r u; do
    echo "@@>con $u"
    t nmcli -t -f connection.id,connection.interface-name,connection.type,connection.master,connection.slave-type,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.routes,ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.routes,bond.options,vlan.parent,vlan.id connection show "$u"
  done
fi
echo; echo '@@ifupdown'; sf_files /etc/network/interfaces /etc/network/interfaces.d/*
"""
SECTIONS = ('manager', 'netplan', 'networkd', 'nm', 'ifupdown')


def _files(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """The @@>file blocks of a section: [(path, text)], and the paths named unreadable."""
    files, unreadable, cur, lines = [], [], None, []
    for line in (text or '').splitlines():
        if line.startswith('@@>file '):
            if cur:
                files.append((cur, '\n'.join(lines)))
            cur, lines = line[8:].strip(), []
        elif line.startswith('@@>unreadable '):
            unreadable.append(line[14:].strip())
        elif cur is not None:
            lines.append(line)
    if cur:
        files.append((cur, '\n'.join(lines)))
    return files[:MAX_FILES], unreadable[:MAX_FILES]


def _iface(out: dict, name, source: str, kind: str | None = None) -> dict | None:
    if not isinstance(name, str) or not name or len(name) > 64:
        return None
    return out.setdefault(name, {'source': source, 'kind': kind, 'dhcp4': None, 'dhcp6': None, 'addresses': [], 'gateway': [], 'routes': [],
                                 'members': [], 'mode': None, 'parent': None, 'vlan_id': None})


def _bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ('true', 'yes', 'on', '1'):
        return True
    if isinstance(v, str) and v.lower() in ('false', 'no', 'off', '0'):
        return False
    return None


def _text(v) -> str | None:
    return v if isinstance(v, str) and v and len(v) < 200 and '\n' not in v else None


def _route(to, via, metric) -> dict | None:
    to, via = _text(to), _text(via)
    if not to and not via:
        return None
    try:
        metric = int(metric) if metric not in (None, '') else None
    except (TypeError, ValueError):
        metric = None
    return {'to': 'default' if to in ('0.0.0.0/0', '::/0') else to, 'via': via, 'metric': metric}


def _add(lst: list, v):
    if v and v not in lst:
        lst.append(v)


# ── netplan ─────────────────────────────────────────────────────────
def parse_netplan(text: str) -> dict:
    """{'interfaces': {name: {...}}, 'unreadable': [paths], 'renderer': str|None}. Files in name order, as netplan reads them: a
    later file adds addresses and routes and overrides what it says again."""
    import yaml
    files, unreadable = _files(text)
    out, renderer, bad = {}, None, []
    for path, body in sorted(files, key=lambda f: f[0].rsplit('/', 1)[-1]):
        try:
            doc = yaml.safe_load(body)
        except Exception:          # yaml raises its own errors, and recursion and type errors on odd input
            bad.append(path)
            continue
        net = doc.get('network') if isinstance(doc, dict) else None
        if not isinstance(net, dict):
            continue
        renderer = _text(net.get('renderer')) or renderer
        for section, kind in KINDS.items():
            defs = net.get(section)
            if not isinstance(defs, dict):
                continue
            for name, conf in defs.items():
                i = _iface(out, name, path, kind)
                if i is None or not isinstance(conf, dict):
                    continue
                i['kind'] = kind
                for fam in ('dhcp4', 'dhcp6'):
                    if _bool(conf.get(fam)) is not None:
                        i[fam] = _bool(conf.get(fam))
                for a in conf.get('addresses') or [] if isinstance(conf.get('addresses'), list) else []:
                    _add(i['addresses'], _text(a) or (_text(next(iter(a), None)) if isinstance(a, dict) and a else None))
                for g in ('gateway4', 'gateway6'):
                    _add(i['gateway'], _text(conf.get(g)))
                for r in conf.get('routes') or [] if isinstance(conf.get('routes'), list) else []:
                    if isinstance(r, dict):
                        _add(i['routes'], _route(r.get('to'), r.get('via'), r.get('metric')))
                for m in conf.get('interfaces') or [] if isinstance(conf.get('interfaces'), list) else []:
                    _add(i['members'], _text(m))
                params = conf.get('parameters')
                if isinstance(params, dict) and _text(params.get('mode')):
                    i['mode'] = params['mode']
                if kind == 'vlan':
                    i['parent'] = _text(conf.get('link')) or i['parent']
                    i['vlan_id'] = conf.get('id') if isinstance(conf.get('id'), int) and not isinstance(conf.get('id'), bool) else i['vlan_id']
    return {'interfaces': out, 'unreadable': unreadable + bad, 'renderer': renderer, 'files': [f for f, _ in files]}


# ── systemd-networkd ────────────────────────────────────────────────
def _ini(body: str, start: int = 0) -> list[tuple[str, str, str, int]]:
    """[(section, key, value, n)] in order, n counting section headers: networkd repeats keys and sections ([Route] once per
    route), so this is a list and not a dict."""
    out, sec, n = [], '', start
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            sec, n = line[1:-1].strip(), n + 1
        elif '=' in line:
            k, _, v = line.partition('=')
            out.append((sec, k.strip(), v.strip(), n))
    return out


def parse_networkd(text: str) -> dict:
    """The .network files that match each interface (the first in name order wins, a file in /etc over one of the same name in
    /run), with their drop-ins, and the .netdev files that make bonds, bridges and VLANs."""
    files, unreadable = _files(text)
    by_name: dict[str, tuple[str, str]] = {}
    dropins: dict[str, list[tuple[str, str]]] = {}
    netdevs = []
    for path, body in files:
        base = path.rsplit('/', 1)[-1]
        if '.network.d/' in path:
            dropins.setdefault(path.split('.network.d/')[0].rsplit('/', 1)[-1] + '.network', []).append((path, body))
        elif base.endswith('.network') and (base not in by_name or path.startswith('/etc/')):
            by_name[base] = (path, body)
        elif base.endswith('.netdev'):
            netdevs.append((path, body))
    out: dict[str, dict] = {}
    for _, (path, body) in sorted(by_name.items()):
        rows = _ini(body)
        for _, sub in sorted(dropins.get(path.rsplit('/', 1)[-1], [])):
            rows += _ini(sub, len(rows) + 1000)
        names = [n for s, k, v, _ in rows if s == 'Match' and k == 'Name' for n in v.split()]
        for name in names:
            if name in out:
                continue                   # an earlier file matched it: networkd uses that one alone
            i = _iface(out, name, path)
            if i is None:
                continue
            routes: dict[int, dict] = {}
            for s, k, v, n in rows:
                if s == 'Network' and k == 'DHCP':
                    want = v.lower()
                    i['dhcp4'] = want in ('yes', 'true', 'ipv4', 'both')
                    i['dhcp6'] = want in ('yes', 'true', 'ipv6', 'both')
                elif (s, k) in (('Network', 'Address'), ('Address', 'Address')):
                    _add(i['addresses'], _text(v))
                elif s == 'Network' and k == 'Gateway':
                    _add(i['gateway'], _text(v))
                elif s == 'Network' and k in ('Bond', 'Bridge'):
                    i['master'] = _text(v)
                elif s == 'Network' and k == 'VLAN':
                    i.setdefault('vlans', []).append(v)
                elif s == 'Route' and k in ('Destination', 'Gateway', 'Metric'):
                    routes.setdefault(n, {})[k] = v
            for r in routes.values():
                _add(i['routes'], _route(r.get('Destination') or ('default' if r.get('Gateway') else None), r.get('Gateway'), r.get('Metric')))
    for path, body in netdevs:
        rows = _ini(body)
        name = next((v for s, k, v, _ in rows if s == 'NetDev' and k == 'Name'), None)
        i = _iface(out, name, path)
        if i is None:
            continue
        i['kind'] = next((v for s, k, v, _ in rows if s == 'NetDev' and k == 'Kind'), i['kind'])
        i['mode'] = next((v for s, k, v, _ in rows if s == 'Bond' and k == 'Mode'), i['mode'])
        vid = next((v for s, k, v, _ in rows if s == 'VLAN' and k == 'Id'), None)
        i['vlan_id'] = int(vid) if vid and vid.isdigit() else i['vlan_id']
    for name, i in out.items():            # a bond's or bridge's members are the interfaces that name it, a VLAN's parent the one that lists it
        if i.get('master') in out:
            _add(out[i['master']]['members'], name)
        for v in i.pop('vlans', []):
            if v in out:
                out[v]['parent'] = name
    return {'interfaces': out, 'unreadable': unreadable, 'files': [f for f, _ in files]}


# ── NetworkManager ──────────────────────────────────────────────────
def _nm_value(v: str) -> str:
    return v.replace('\\:', ':').replace('\\\\', '\\').strip()


def _nm_routes(v: str) -> list[dict]:
    out = []
    for block in re.findall(r'\{([^}]*)\}', v) or [x for x in v.split(',') if x.strip()]:
        if '=' in block:
            kv = dict((a.strip(), b.strip()) for a, _, b in (p.partition('=') for p in block.split(',')))
            r = _route(kv.get('ip') or kv.get('dst'), kv.get('nh'), kv.get('mt'))
        else:
            w = block.split()
            r = _route(w[0] if w else None, w[1] if len(w) > 1 else None, w[2] if len(w) > 2 else None)
        if r:
            out.append(r)
    return out


def parse_nm(text: str) -> dict:
    """nmcli -t connection show <uuid>, one block per connection after its @@>con line. A connection names its interface, or it
    is listed by its own name."""
    out, cur = {}, None
    blocks: list[dict] = []
    for line in (text or '').splitlines():
        if line.startswith('@@>con '):
            cur = {'uuid': line[7:].strip()}
            blocks.append(cur)
        elif cur is not None and ':' in line:
            k, _, v = line.partition(':')
            cur[k.strip()] = _nm_value(v)
    for b in blocks[:MAX_FILES]:
        name = b.get('connection.interface-name') or b.get('connection.id')
        i = _iface(out, name, f'NetworkManager: {b.get("connection.id") or b.get("uuid")}')
        if i is None:
            continue
        kind = b.get('connection.type') or ''
        i['kind'] = {'802-3-ethernet': 'ethernet', 'ethernet': 'ethernet', 'bond': 'bond', 'bridge': 'bridge', 'vlan': 'vlan', '802-11-wireless': 'wifi', 'wifi': 'wifi'}.get(kind, kind or None)
        for fam in ('4', '6'):
            m = b.get(f'ipv{fam}.method')
            if m:
                i[f'dhcp{fam}'] = m in ('auto', 'dhcp')
            for a in (b.get(f'ipv{fam}.addresses') or '').split(','):
                _add(i['addresses'], _text(a.strip()))
            g = b.get(f'ipv{fam}.gateway')
            _add(i['gateway'], _text(g) if g and g != '--' else None)
            for r in _nm_routes(b.get(f'ipv{fam}.routes') or ''):
                _add(i['routes'], r)
        master = b.get('connection.master')
        if master and master != '--':
            i['master'] = master
        opts = dict(p.partition('=')[::2] for p in (b.get('bond.options') or '').split(',') if '=' in p)
        i['mode'] = opts.get('mode') or i['mode']
        if b.get('vlan.parent') and b['vlan.parent'] != '--':
            i['parent'] = b['vlan.parent']
        if (b.get('vlan.id') or '').isdigit():
            i['vlan_id'] = int(b['vlan.id'])
    for name, i in out.items():
        if i.get('master') in out:
            _add(out[i['master']]['members'], name)
    return {'interfaces': out, 'unreadable': [], 'files': []}


# ── ifupdown ────────────────────────────────────────────────────────
def _with_prefix(addr: str, mask: str | None) -> str:
    if '/' in addr or not mask:
        return addr
    try:
        return str(ipaddress.ip_interface(f'{addr}/{mask}'))
    except ValueError:
        return addr


def parse_ifupdown(text: str) -> dict:
    """/etc/network/interfaces and interfaces.d: each iface stanza, its method and options. Several stanzas for one interface
    all apply, as ifupdown does."""
    files, unreadable = _files(text)
    out = {}
    for path, body in files:
        cur, fam, addr, mask = None, None, None, None

        def close():
            if cur is not None and addr:
                _add(cur['addresses'], _with_prefix(addr, mask))
        for raw in body.splitlines():
            line = raw.split('#', 1)[0].strip()
            w = line.split()
            if not w:
                continue
            if w[0] == 'iface' and len(w) >= 4:
                close()
                cur, fam, addr, mask = _iface(out, w[1], path), w[2], None, None
                if cur is not None and w[2] in ('inet', 'inet6'):
                    cur[f'dhcp{"6" if w[2] == "inet6" else "4"}'] = w[3] in ('dhcp', 'auto')
            elif w[0] in ('auto', 'allow-hotplug', 'source', 'source-directory', 'mapping') or w[0].startswith('allow-'):
                close()
                cur = None
            elif cur is not None and len(w) >= 2:
                k, v = w[0], ' '.join(w[1:])
                if k == 'address':
                    close()
                    addr, mask = v, None
                elif k == 'netmask':
                    mask = v
                elif k == 'gateway':
                    _add(cur['gateway'], _text(v))
                elif k in ('bond-slaves', 'bridge_ports', 'bridge-ports'):
                    for m in w[1:]:
                        if m not in ('none', 'all'):
                            _add(cur['members'], m)
                    cur['kind'] = 'bond' if k == 'bond-slaves' else 'bridge'
                elif k == 'bond-mode':
                    cur['mode'] = v
                elif k in ('vlan-raw-device', 'vlan_raw_device'):
                    cur['parent'], cur['kind'] = v, 'vlan'
                elif k in ('up', 'post-up') and len(w) >= 6 and w[1:4] == ['ip', 'route', 'add']:
                    via = w[w.index('via') + 1] if 'via' in w[:-1] else None
                    _add(cur['routes'], _route(w[4], via, w[w.index('metric') + 1] if 'metric' in w[:-1] else None))
        close()
    return {'interfaces': out, 'unreadable': unreadable, 'files': [f for f, _ in files]}


# ── all of it ───────────────────────────────────────────────────────
def manager_of(text: str, found: dict) -> str:
    """Which one keeps the network, in the order the network steps look: netplan, NetworkManager, systemd-networkd, ifupdown."""
    says = dict(line.partition('=')[::2] for line in (text or '').splitlines() if '=' in line)
    if says.get('netplan') and (found['netplan']['files'] or found['netplan']['unreadable']):
        return 'netplan'
    if says.get('nm', '').strip() == 'running':
        return 'nm'
    if says.get('networkd', '').strip() == 'active':
        return 'networkd'
    if says.get('ifup') and any(n != 'lo' for n in found['ifupdown']['interfaces']):
        return 'ifupdown'
    return 'none'


def read(sections: dict) -> dict | None:
    """netfacts' sections, as one record, or None for a reading made before these were read."""
    if not any(k in sections for k in SECTIONS):
        return None
    found = {'netplan': parse_netplan(sections.get('netplan', '')), 'networkd': parse_networkd(sections.get('networkd', '')),
             'nm': parse_nm(sections.get('nm', '')), 'ifupdown': parse_ifupdown(sections.get('ifupdown', ''))}
    manager = manager_of(sections.get('manager', ''), found)
    # what the manager says first; what netplan rendered (networkd or NetworkManager) fills in what its closed files hide
    order = {'netplan': ('netplan', 'networkd', 'nm'), 'nm': ('nm',), 'networkd': ('networkd',), 'ifupdown': ('ifupdown',)}.get(manager, ())
    interfaces: dict[str, dict] = {}
    for key in order:
        for name, i in found[key]['interfaces'].items():
            if name not in interfaces:
                interfaces[name] = {**i, 'managed_by': key}
    return {'manager': manager, 'renderer': found['netplan']['renderer'], 'interfaces': interfaces,
            'files': sorted({f for v in found.values() for f in v['files']}), 'unreadable': sorted({f for v in found.values() for f in v['unreadable']})}
