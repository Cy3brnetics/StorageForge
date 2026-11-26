"""Toolbox adapters (roadmap section 4.1; docs/toolbox.md): what StorageForge can say of a tool on a host, and do to it.

An adapter has up to five parts, and every one only reads:
  detect    whether the tool is on the host, installed by StorageForge or not, and how it runs
  status    health, the version running, and the tiles the Toolbox view shows
  actions   what can be done to it; each action becomes ordinary plan steps (wg-peer, wg-rotate, unit-state), staged and deployed as
            any plan is, with its report first. An adapter changes nothing by itself
  links     the way to its own UI, from the entry's url_template and how it is exposed
  metrics   a few numbers, for the tiles and the API

They read the infrastructure reading (inframeasure.py), the signed, read-only run every host with deploy access gets: the sections
below are added to it, written here in the code and never taken from an entry. A tool whose entry names a platform connection kind
(gui.panel.api) is read through section 13's connection (apiconn.py, apiread.py) instead, with that kind's permission guide; its
token stays in the vault. Credentials are never stored here. An adapter that fails says "status unavailable", and the reading, the
scan and the other tools go on.
"""
from __future__ import annotations

import json
import re
import shlex
import time

from . import errlog
from .db import Conn

SECTIONS = ('tb_cockpit', 'tb_health')
# what each adapter adds to the reading: no secret can be printed here (unit states, a version line)
BODY = r"""
# the Toolbox adapters (tbadapters.py): unit states and version lines only
sec tb_cockpit
if has systemctl && systemctl cat cockpit.socket >/dev/null 2>&1; then
  printf 's\t%s\t%s\n' "$(systemctl is-active cockpit.socket 2>/dev/null)" "$(systemctl is-enabled cockpit.socket 2>/dev/null)"
  printf 'w\t%s\n' "$(systemctl is-active cockpit.service 2>/dev/null)"
  has cockpit-bridge && printf 'v\t%s\n' "$(cockpit-bridge --version 2>/dev/null | sed -n 's/^Version: *//p' | head -n 1)"
fi
"""
HEALTH_URL = re.compile(r'(https?)://127\.0\.0\.1:(\d{1,5})(/[A-Za-z0-9._/-]{0,100})?')
STALE = 3 * 60          # a WireGuard handshake older than this is a peer that is not connected now


def health_body(checks: list[tuple[str, str]]) -> str:
    """The loopback health checks of the tools installed on one host, as a section of its reading: the status code only, never the body.
    Each URL was checked against HEALTH_URL, and goes in as a quoted word."""
    lines = ['sec tb_health', 'if has curl; then', '  :']
    for tool, url in checks:
        if not HEALTH_URL.fullmatch(url) or not re.fullmatch(r'[a-z0-9-]{1,41}', tool):
            continue
        lines.append(f'  printf "h\\t%s\\t%s\\n" {shlex.quote(tool)} "$(curl -ks -o /dev/null -w "%{{http_code}}" -L --max-time 5 {shlex.quote(url)} 2>/dev/null)"')
    lines.append('fi')
    return '\n'.join(lines) + '\n'


def read_health(lines: list[str]) -> dict:
    out = {}
    for line in lines:
        f = line.split('\t')
        if len(f) == 3 and f[0] == 'h' and re.fullmatch(r'[a-z0-9-]{1,41}', f[1]):
            out[f[1]] = int(f[2]) if f[2].isdigit() else 0
    return out


def read_cockpit(lines: list[str]) -> dict | None:
    out: dict = {}
    for line in lines:
        f = line.split('\t')
        if f[0] == 's' and len(f) >= 3:
            out['socket'], out['enabled'] = f[1][:20], f[2][:20]
        elif f[0] == 'w' and len(f) >= 2:
            out['service'] = f[1][:20]
        elif f[0] == 'v' and len(f) >= 2 and re.fullmatch(r'[0-9.]{1,12}', f[1]):
            out['version'] = f[1]
    return out or None


READERS: dict = {}       # name -> reader of the sections other adapter modules add (tbadapters_c.py)


def sections_of(sections: dict) -> dict:
    """What the reading keeps of the adapters' sections (inframeasure.parse)."""
    return {'cockpit': read_cockpit(sections.get('tb_cockpit', [])), 'health': read_health(sections.get('tb_health', [])),
            **tbadapters_a.sections_of(sections), **tbadapters_b.sections_of(sections),
            **{k: fn(sections) for k, fn in READERS.items()}}


# ── the adapters ────────────────────────────────────────────────────
def _tile(label: str, value, level: str = 'ok') -> dict:
    return {'label': label, 'value': str(value), 'level': level}


class Adapter:
    name = ''
    level = 'status'

    def detect(self, reading: dict, ctx: dict) -> dict | None:
        return None

    def status(self, reading: dict, ctx: dict, found: dict) -> dict:
        return {'health': 'unknown', 'version': None, 'tiles': []}

    def actions(self, reading: dict, ctx: dict) -> list[dict]:
        return []

    def tasks(self, action: str, values: dict, host: str, reading: dict) -> list[dict]:
        raise ValueError(f'{self.name} has no action {action}')

    def metrics(self, reading: dict, ctx: dict) -> dict:
        return {}


def _containers(ctx: dict, tool: str, image_part: str) -> list[dict]:
    return [c for c in ctx.get('containers') or [] if (c.get('labels') or {}).get('storageforge.tool') == tool or c.get('name') == f'sf-{tool}'
            or image_part in (c.get('image') or '')]


class UptimeKuma(Adapter):
    name = 'uptime-kuma'

    def detect(self, reading, ctx):
        cs = _containers(ctx, 'uptime-kuma', 'louislam/uptime-kuma')
        if not cs:
            return None
        c = cs[0]
        managed = (c.get('labels') or {}).get('storageforge.tool') == 'uptime-kuma'
        tag = (c.get('image') or '').split('@')[0].rsplit(':', 1)
        return {'running': c.get('state') == 'running', 'how': c.get('how') or 'container', 'container': c.get('name'), 'managed': managed,
                'version': tag[1] if len(tag) == 2 else None}

    def status(self, reading, ctx, found):
        code = ctx.get('health', {}).get('uptime-kuma')
        tiles = [_tile('Container', f'{found["container"]}, {"running" if found["running"] else "stopped"}', 'ok' if found['running'] else 'crit'),
                 _tile('Version', found.get('version') or 'unknown', 'ok')]
        if code is not None:
            tiles.append(_tile('Health check', f'HTTP {code}' if code else 'no answer', 'ok' if code == 200 else 'crit'))
        health = 'ok' if found['running'] and code in (None, 200) else 'down'
        return {'health': health, 'version': found.get('version'), 'tiles': tiles}

    def metrics(self, reading, ctx):
        return {'containers': len(_containers(ctx, 'uptime-kuma', 'louislam/uptime-kuma'))}


class Cockpit(Adapter):
    name = 'cockpit'
    level = 'status+actions'

    def detect(self, reading, ctx):
        c = (reading.get('toolbox') or {}).get('cockpit')
        if not c:
            return None
        return {'running': c.get('socket') == 'active', 'how': 'package', 'version': c.get('version'), 'enabled': c.get('enabled'),
                'service': c.get('service')}

    def status(self, reading, ctx, found):
        code = ctx.get('health', {}).get('cockpit')
        tiles = [_tile('cockpit.socket', f'{"listening" if found["running"] else "not listening"}, {found.get("enabled") or "unknown"} at boot', 'ok' if found['running'] else 'crit'),
                 _tile('Sessions', 'someone is signed in' if found.get('service') == 'active' else 'nobody signed in', 'ok'),
                 _tile('Version', found.get('version') or 'unknown', 'ok')]
        if code is not None:
            tiles.append(_tile('Health check', f'HTTP {code}' if code else 'no answer', 'ok' if code == 200 else 'crit'))
        return {'health': 'ok' if found['running'] and code in (None, 200) else 'down', 'version': found.get('version'), 'tiles': tiles}

    def actions(self, reading, ctx):
        return [{'id': 'restart', 'label': 'Restart Cockpit (signs everyone out)', 'fields': []},
                {'id': 'stop', 'label': 'Stop Cockpit until it is next asked for', 'fields': []}]

    def tasks(self, action, values, host, reading):
        if action not in ('restart', 'stop'):
            raise ValueError(f'cockpit has no action {action}')
        return [{'host': host, 'type': 'unit-state', 'params': {'unit': 'cockpit.service', 'state': 'restarted' if action == 'restart' else 'stopped'},
                 'note': f'Cockpit: {action}, from the Toolbox'}]


class WireGuard(Adapter):
    """The peer manager: interfaces, peers, handshake age, key rotation. Peers are added by their public key: a private key is never made,
    sent or shown here. Each action is a wg-peer or wg-rotate step."""
    name = 'wireguard'
    level = 'full'

    def _ifaces(self, reading):
        return ((reading.get('access') or {}).get('wireguard')) or []

    def detect(self, reading, ctx):
        ifaces = self._ifaces(reading)
        if not ifaces and 'wg' not in (reading.get('tools') or []):
            return None
        return {'running': bool(ifaces), 'how': 'kernel', 'interfaces': [i['name'] for i in ifaces]}

    def peer_config(self, iface: dict, peer: dict, host: str = '') -> str:
        addr = ', '.join(peer.get('allowed_ips') or ['10.8.0.2/32'])
        port = iface.get('listen_port') or 51820
        endpoint = f'{host}:{port}' if host else f'<host>:{port}'
        lines = [
            '# Peer configuration template (fill PrivateKey on the peer device; never stored on StorageForge)',
            '[Interface]',
            f'Address = {addr}',
            'PrivateKey = <replace-on-peer-device>',
            '',
            '[Peer]',
            f'PublicKey = {iface.get("public_key") or ""}',
            'AllowedIPs = 0.0.0.0/0, ::/0',
            f'Endpoint = {endpoint}',
        ]
        return '\n'.join(lines) + '\n'

    def status(self, reading, ctx, found):
        from . import qrsvg
        now = ctx.get('now') or time.time()
        host = str(ctx.get('host') or '')
        tiles, peers, live = [], 0, 0
        for i in self._ifaces(reading):
            n = len(i.get('peers') or [])
            up = sum(1 for p in i.get('peers') or [] if p.get('handshake') and now - p['handshake'] < STALE)
            peers, live = peers + n, live + up
            tiles.append(_tile(i['name'], f'port {i.get("listen_port") or "?"}, {up} of {n} peer{"s" if n != 1 else ""} connected'
                               + (', a key rotation waits' if i.get('next_public_key') else ''), 'ok'))
        if not tiles:
            tiles.append(_tile('Interfaces', 'wg is installed and no interface is up', 'warn'))
        peer_rows = []
        for i in self._ifaces(reading):
            for p in i.get('peers') or []:
                cfg = self.peer_config(i, p, host)
                peer_rows.append({'iface': i['name'], 'public_key': p['public_key'], 'endpoint': p.get('endpoint'),
                                  'allowed_ips': p.get('allowed_ips') or [], 'handshake': p.get('handshake'),
                                  'config': cfg, 'qr_svg': qrsvg.svg(cfg)})
        return {'health': 'ok' if tiles and self._ifaces(reading) else 'warn', 'version': None, 'tiles': tiles,
                'peers': peer_rows}

    def actions(self, reading, ctx):
        names = [i['name'] for i in self._ifaces(reading)]
        iface = {'name': 'iface', 'kind': 'choice', 'label': 'Interface', 'options': names, 'required': True}
        return [{'id': 'add-peer', 'label': 'Add a peer', 'fields': [iface, {'name': 'pubkey', 'kind': 'wgkey', 'label': 'Its public key (wg pubkey on the peer)', 'required': True},
                                                                     {'name': 'allowed', 'kind': 'cidrs', 'label': 'Addresses it may use', 'required': True},
                                                                     {'name': 'endpoint', 'kind': 'endpoint', 'label': 'Where to call it, if it can be called'},
                                                                     {'name': 'keepalive', 'kind': 'number', 'label': 'Keepalive, seconds'}]},
                {'id': 'revoke-peer', 'label': 'Revoke a peer', 'fields': [iface, {'name': 'pubkey', 'kind': 'wgkey', 'label': 'Its public key', 'required': True}]},
                {'id': 'rotate-prepare', 'label': 'Make the next key of an interface', 'fields': [iface]},
                {'id': 'rotate-switch', 'label': 'Switch an interface to its next key', 'fields': [iface, {'name': 'pubkey', 'kind': 'wgkey', 'label': 'The next public key', 'required': True}]}]

    def tasks(self, action, values, host, reading):
        v = {k: str(values.get(k) or '') for k in ('iface', 'pubkey', 'allowed', 'endpoint', 'keepalive')}
        if action == 'add-peer':
            return [{'host': host, 'type': 'wg-peer', 'params': {'iface': v['iface'], 'pubkey': v['pubkey'], 'allowed': v['allowed'], 'state': 'present',
                                                               'endpoint': v['endpoint'], 'keepalive': v['keepalive']}, 'note': 'WireGuard peer manager'}]
        if action == 'revoke-peer':
            return [{'host': host, 'type': 'wg-peer', 'params': {'iface': v['iface'], 'pubkey': v['pubkey'], 'allowed': '', 'state': 'absent'}, 'note': 'WireGuard peer manager'}]
        if action == 'rotate-prepare':
            return [{'host': host, 'type': 'wg-rotate', 'params': {'iface': v['iface'], 'phase': 'prepare', 'pubkey': ''}, 'note': 'WireGuard peer manager'}]
        if action == 'rotate-switch':
            return [{'host': host, 'type': 'wg-rotate', 'params': {'iface': v['iface'], 'phase': 'switch', 'pubkey': v['pubkey']}, 'note': 'WireGuard peer manager'}]
        raise ValueError(f'wireguard has no action {action}')

    def metrics(self, reading, ctx):
        now = ctx.get('now') or time.time()
        ps = [p for i in self._ifaces(reading) for p in i.get('peers') or []]
        return {'interfaces': len(self._ifaces(reading)), 'peers': len(ps), 'connected': sum(1 for p in ps if p.get('handshake') and now - p['handshake'] < STALE)}


ADAPTERS: dict[str, Adapter] = {a.name: a for a in (UptimeKuma(), Cockpit(), WireGuard())}
from . import tbadapters_a, tbadapters_b  # noqa: E402  the 0.5.13 adapters and their reading sections
ADAPTERS.update(tbadapters_a.ADAPTERS)
ADAPTERS.update(tbadapters_b.ADAPTERS)
SECTIONS = SECTIONS + tbadapters_a.SECTIONS + tbadapters_b.SECTIONS
BODY = BODY + tbadapters_a.BODY + tbadapters_b.BODY


def api_status(conn: Conn, host: str, kind: str) -> dict:
    """A tool read through a platform connection (section 13): what the last read of a connection of that kind for this host found.
    Without one, the tile says how to make one, least privilege first, and links its permission guide."""
    from . import apiconn, apiread
    rows = [c for c in apiconn.listing(conn) if c['kind'] == kind and (c.get('host') or '').lower() == host.lower()]
    if not rows:
        title = apiconn.KINDS[kind].get('title', kind)
        return {'health': 'unknown', 'version': None, 'connection': None, 'guide': f'/api/keys/platforms/guide/{kind}',
                'tiles': [_tile('Platform connection', f'none for {host}: add a {title} connection under Keys, Platform connections. The guide shows the least the token needs', 'warn')]}
    c = rows[0]
    objects = apiread.objects(conn, c['conn_id'])
    counts: dict = {}
    for o in objects:
        counts[o.get('kind') or 'object'] = counts.get(o.get('kind') or 'object', 0) + 1
    tiles = [_tile('Connection', f'{c["name"]}: {c["state"]}', 'ok' if c['state'] == 'ok' else 'warn')]
    tiles += [_tile(k, n) for k, n in sorted(counts.items())]
    return {'health': 'ok' if c['state'] == 'ok' else 'warn' if c['state'] == 'not-read' else 'down', 'version': None, 'connection': c['name'],
            'read_at': c.get('read_at'), 'tiles': tiles}


# ── the context an adapter reads, and the refresh after each reading ──
def context(conn: Conn, host: str, reading: dict) -> dict:
    """The containers the scan and the reading saw on the host, and the health checks, for every adapter at once."""
    from . import workloads   # here, not at the top: inframeasure imports this module
    cs = [{'name': c.get('name'), 'image': c.get('image'), 'state': c.get('state'), 'labels': c.get('labels') or {}, 'how': how}
          for c, how in workloads.containers_with_how(conn, host, reading=reading)]
    return {'host': host, 'containers': cs, 'health': (reading.get('toolbox') or {}).get('health') or {}, 'now': time.time()}


def refresh(conn: Conn, host: str, reading: dict | None) -> dict:
    """After a reading of host: each tool's status, from its adapter, into toolbox_status; staged installs found running become installed.
    One adapter that fails costs only its own tile."""
    from . import toolbox
    if not reading:
        return {}
    ctx = context(conn, host, reading)
    now = int(time.time())
    out = {}
    insts = {i['tool']: i for i in toolbox.installs(conn, host)}
    for row in toolbox.catalog(conn):
        e = row.get('entry')
        if not e or not (e['gui']['adapter'] or e['gui']['api']):
            continue
        tid = e['id']
        found, st, error = None, None, None
        try:
            if e['gui']['api']:
                st = api_status(conn, host, e['gui']['api'])
                found = {'running': st['health'] == 'ok'} if st.get('connection') else None
            else:
                a = ADAPTERS[e['gui']['adapter']]
                found = a.detect(reading, ctx)
                if found:
                    st = a.status(reading, ctx, found)
                    st['metrics'] = a.metrics(reading, ctx)
        except Exception:                                   # noqa: BLE001  an adapter that fails says so and costs nothing else
            errlog.trace()
            error = 'status unavailable: the adapter could not read what the host reported'
        inst = insts.get(tid)
        if not found and not inst and not error:
            conn.execute('DELETE FROM toolbox_status WHERE host = :h AND tool_id = :t', {'h': host, 't': tid})
            continue
        if error:
            health, tiles = 'unavailable', [_tile('Status', 'unavailable', 'warn')]
        elif not found:
            health, tiles = ('staged' if inst and inst['status'] == 'staged' else 'missing'), [_tile('Installed', 'not found on the host at the last reading', 'warn' if inst and inst['status'] == 'staged' else 'crit')]
        else:
            health, tiles = st['health'], st['tiles']
        extra = {k: v for k, v in (st or {}).items() if k in ('peers', 'connection', 'guide', 'read_at')}
        row_p = {'h': host, 't': tid, 'c': now, 'd': 1 if found else 0, 'hl': health, 'v': (st or {}).get('version'), 'tj': json.dumps({'tiles': tiles, **extra}),
                 'mj': json.dumps((st or {}).get('metrics') or {}), 'e': error}
        with conn.tx():
            conn.execute('DELETE FROM toolbox_status WHERE host = :h AND tool_id = :t', row_p)
            conn.execute("""INSERT INTO toolbox_status (host, tool_id, checked_at, detected, health, version_running, tiles_json, metrics_json, error)
                            VALUES (:h, :t, :c, :d, :hl, :v, :tj, :mj, :e)""", row_p)
        if inst and found and found.get('running') and inst['status'] == 'staged':
            conn.execute("UPDATE toolbox_installs SET status = 'installed', updated_at = :n WHERE id = :i", {'n': now, 'i': inst['id']})
        elif inst and not found and inst['status'] == 'remove-staged':
            conn.execute("UPDATE toolbox_installs SET status = 'removed', updated_at = :n WHERE id = :i", {'n': now, 'i': inst['id']})
        elif inst and not found and inst['status'] == 'installed':
            conn.execute("UPDATE toolbox_installs SET status = 'missing', updated_at = :n WHERE id = :i", {'n': now, 'i': inst['id']})
        elif inst and found and inst['status'] == 'missing':
            conn.execute("UPDATE toolbox_installs SET status = 'installed', updated_at = :n WHERE id = :i", {'n': now, 'i': inst['id']})
        out[tid] = health
    return out


def status_rows(conn: Conn, host: str | None = None) -> list[dict]:
    rows = conn.all(f"""SELECT host, tool_id, checked_at, detected, health, version_running, tiles_json, metrics_json, error FROM toolbox_status
                        {'WHERE host = :h' if host else ''} ORDER BY host, tool_id""", {'h': host})
    out = []
    for r in rows:
        tj = json.loads(r[6] or '{}')
        tj = tj if isinstance(tj, dict) else {'tiles': tj}
        out.append({'host': r[0], 'tool': r[1], 'checked_at': r[2], 'detected': bool(r[3]), 'health': r[4], 'version': r[5], 'tiles': tj.get('tiles') or [],
                    'metrics': json.loads(r[7] or '{}'), 'error': r[8], **{k: v for k, v in tj.items() if k != 'tiles'}})
    return out


def _host_port(e: dict, method: str | None, ports: dict, port: int) -> int:
    """The host port the entry's own number becomes under the host's overrides. Overrides are keyed by container port,
    and the entry's health URL and link name the host port, so the container port behind it comes first."""
    for m in e.get('methods') or []:
        if method and m['kind'] != method:
            continue
        for p in m.get('ports') or []:
            if p['host'] == port and p['container'] in ports:
                return ports[p['container']]
    return port


def health_checks(conn: Conn, host: str) -> list[tuple[str, str]]:
    """(tool, loopback URL) for each tool installed or staged on the host whose entry has a health check, with its port as overridden."""
    from . import toolbox
    out = []
    cat = {x['id']: x for x in toolbox.catalog(conn)}
    for i in toolbox.installs(conn, host):
        e = (cat.get(i['tool']) or {}).get('entry')
        if not e or not e['health'] or i['status'] in ('removed',):
            continue
        url = e['health']['url']
        m = HEALTH_URL.fullmatch(url)
        ovr_row = toolbox.override_row(conn, host, i['tool'])
        ports = (toolbox.load_override(ovr_row['text'])[0].get('ports') if ovr_row else None) or {}
        if m and (now := _host_port(e, i['method'], ports, int(m[2]))) != int(m[2]):
            url = f'{m[1]}://127.0.0.1:{now}{m[3] or ""}'
        out.append((i['tool'], url))
    return out


def links(conn: Conn, host: str, e: dict, inst: dict | None) -> list[dict]:
    """The way to the tool's own UI. Bound to loopback, the link is to this machine's end of an SSH tunnel, with the command for it.
    sso-link needs an identity provider from the catalog, which comes with 0.5.13: until one is installed the link is a plain one."""
    from . import toolbox
    native = e['gui'].get('native')
    if not native:
        return []
    made = (inst or {}).get('params') or {}
    exposure = made.get('exposure') or e['exposure']['default']
    port = native.get('port')
    ovr_row = toolbox.override_row(conn, host, e['id'])
    ports = (toolbox.load_override(ovr_row['text'])[0].get('ports') if ovr_row else None) or {}
    port = _host_port(e, (inst or {}).get('method'), ports, port) if port else port
    addr = conn.scalar('SELECT COALESCE(ip_address, ssh_host, hostname) FROM hosts WHERE hostname = :h', {'h': host}) or host
    if exposure == 'management':
        addr = next((p.split(':')[0] for p in made.get('ports') or [] if p.count(':') >= 2), addr)
    url = native['url_template'].replace('{host}', '127.0.0.1' if exposure == 'loopback' else addr).replace('{port}', str(port or ''))
    out = {'kind': 'link', 'label': f'Open {e["name"]}', 'url': url, 'exposure': exposure}
    if exposure == 'loopback' and port:
        out['tunnel'] = f'ssh -L {port}:127.0.0.1:{port} {addr}'
        out['label'] = f'Open {e["name"]} through an SSH tunnel'
    if native.get('sso') in ('oidc', 'forward-auth'):
        idp = [i for i in toolbox.installs(conn) if i['status'] == 'installed' and ((toolbox.find(conn, i['tool']) or {}).get('category') == 'identity')]
        out['sso'] = 'an identity provider is installed: register this tool with it' if idp else 'no identity provider from the catalog is installed yet, so this is a plain link'
    return [out]


def read_status(conn: Conn, host: str, tool_id: str) -> dict:
    """What the Toolbox view shows of one tool on one host: its status row, its links and its actions."""
    from . import inframeasure, toolbox
    row = toolbox.find(conn, tool_id)
    if not row or not row['entry']:
        raise LookupError(f'no catalog entry {tool_id}')
    e = row['entry']
    inst = toolbox.install_of(conn, host, tool_id)
    st = next((s for s in status_rows(conn, host) if s['tool'] == tool_id), None)
    acts: list = []
    if e['gui']['adapter'] and e['gui']['level'] in ('status+actions', 'full'):
        try:
            reading = inframeasure.reading(conn, host) or {}
            acts = ADAPTERS[e['gui']['adapter']].actions(reading, context(conn, host, reading))
        except Exception:                                   # noqa: BLE001
            errlog.trace()
            acts = []
    return {'host': host, 'tool': tool_id, 'name': e['name'], 'level': e['gui']['level'], 'install': inst, 'status': st, 'links': links(conn, host, e, inst),
            'actions': acts, 'lab': row['lab']}


def exposure(conn: Conn) -> list[dict]:
    """What each tool StorageForge installed exposes, as staged and as the last reading of its host saw it: the addresses its ports
    listen on, and whether that is more than was staged."""
    from . import inframeasure, toolbox
    out = []
    readings: dict = {}
    for i in toolbox.installs(conn):
        if i['status'] in ('removed',):
            continue
        if i['host'] not in readings:
            readings[i['host']] = inframeasure.reading(conn, i['host']) or {}
        listeners = readings[i['host']].get('listeners') or []
        staged = i['params'].get('exposure') or 'loopback'
        ports = []
        for p in i['params'].get('ports') or []:
            m = re.fullmatch(r'(?:([0-9a-f.:]+):)?(\d+):\d+/(tcp|udp)', p)
            if m:
                ports.append((int(m[2]), m[3]))
        sock = (i['params'].get('socket') or {}).get('port')
        if sock:
            ports.append((int(sock), 'tcp'))
        if not ports:            # a tool that publishes nothing itself (WireGuard): the ports its entry says it needs
            e = (toolbox.find(conn, i['tool']) or {}).get('entry') or {}
            ports = [(p['port'], p['proto']) for p in (e.get('requires') or {}).get('ports') or []]
        seen = [{'proto': x['proto'], 'addr': x['addr'], 'port': x['port'], 'scope': x.get('scope')} for x in listeners if (x['port'], x['proto']) in ports]
        wider = [x for x in seen if staged == 'loopback' and x.get('scope') not in ('loopback',)]
        out.append({'host': i['host'], 'tool': i['tool'], 'status': i['status'], 'staged': staged, 'ports': [f'{p}/{q}' for p, q in ports], 'listening': seen,
                    'wider_than_staged': bool(wider), 'read': bool(readings[i['host']])})
    return out


def stage_action(conn: Conn, host: str, tool_id: str, action: str, values: dict, actor: str) -> dict:
    """An adapter action as a saved plan: ordinary steps, checked when saved and deployed like any plan."""
    from . import changes, inframeasure, toolbox
    host = toolbox.host_name(conn, host)
    row = toolbox.find(conn, tool_id)
    if not row or not row['entry'] or not row['entry']['gui']['adapter']:
        raise LookupError(f'{tool_id} has no adapter with actions')
    e = row['entry']
    if e['gui']['level'] not in ('status+actions', 'full'):
        raise ValueError(f'{e["name"]} is shown at the {e["gui"]["level"]} level, which has no actions')
    a = ADAPTERS[e['gui']['adapter']]
    reading = inframeasure.reading(conn, host) or {}
    known = {x['id']: x for x in a.actions(reading, context(conn, host, reading))}
    if action not in known:
        raise ValueError(f'{e["name"]} has no action {action}')
    for f in known[action]['fields']:
        if f.get('required') and not str((values or {}).get(f['name']) or '').strip():
            raise ValueError(f'{f["label"]} is required')
        if f['kind'] == 'choice' and values.get(f['name']) not in f['options']:
            raise ValueError(f'{f["label"]} is one of {", ".join(f["options"]) or "nothing yet: no interface was read"}')
    tasks = a.tasks(action, values or {}, host, reading)
    plan_id = changes.save_plan(conn, {'name': toolbox._plan_name(conn, f'Toolbox: {e["name"]} on {host}, {known[action]["label"].lower()}'), 'tasks': tasks}, actor)
    return {'plan_id': plan_id, 'tasks': tasks}


def dashboard_summary(conn: Conn, host: str | None = None) -> dict:
    """Toolbox status summary tile payload for custom dashboards (matches secplus tile shape)."""
    from . import toolbox
    rows = status_rows(conn, host)
    insts = toolbox.installs(conn, host)
    if not rows and not insts:
        return {'none': 'No Toolbox tools installed or measured yet'}
    ok = sum(1 for r in rows if r['health'] == 'ok')
    warn = sum(1 for r in rows if r['health'] in ('warn', 'unavailable', 'unknown'))
    down = sum(1 for r in rows if r['health'] in ('down', 'missing'))
    staged = sum(1 for i in insts if i['status'] == 'staged')
    return {
        'stats': [{'label': 'Running', 'value': ok}, {'label': 'Attention', 'value': warn + down}, {'label': 'Staged', 'value': staged}],
        'rows': [{'label': f'{r["tool"]} ({r["version"] or r["health"]})', 'value': r['health'], 'host': r['host']} for r in rows[:8]],
    }


def tool_tile(conn: Conn, tool_id: str, host: str | None = None) -> dict:
    """Single catalog tool tile payload for custom dashboards (matches secplus tile shape)."""
    from . import toolbox
    row = toolbox.find(conn, tool_id)
    if not row:
        raise LookupError(f'no catalog entry {tool_id}')
    statuses = [s for s in status_rows(conn, host) if s['tool'] == tool_id]
    insts = [i for i in toolbox.installs(conn, host) if i['tool'] == tool_id]
    if not statuses and not insts:
        return {'none': f'{row["name"]}: not installed or measured yet'}
    if statuses:
        rows = []
        for s in statuses[:8]:
            first = (s.get('tiles') or [{}])[0]
            val = first.get('value') or s['version'] or s['health']
            rows.append({'label': s['host'], 'value': f'{s["health"]}: {val}' if first.get('value') else val})
        return {'rows': rows}
    return {'rows': [{'label': i['host'], 'value': i['status']} for i in insts[:8]]}


from . import tbadapters_c  # noqa: E402,F401  the adapters of the backup, secrets, provisioning, storage and offline entries
