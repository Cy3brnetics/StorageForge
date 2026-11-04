"""Routers, switches and firewalls: what they are, reading them, and changing them with a way back.

A device has a row in `hosts` too, so the map, reach and exposure treat it as they treat any host: its reading lands in host_network and in a measurement of kind `infra`. It is
not scanned (it has no filesystem to walk) and takes no deploys: signed deploys are for hosts with sh and storageforge-run. Facts only devices have are a measurement of kind `device`.

Reading uses what the vault binds for `scan` to the device's address, or its stored credential. Changing uses the `deploy` binding: give a read-only account the first and an
administrator the second, and reading can't change anything. Every change goes report first, then apply, and on apply the DEVICE holds the way back: a timer on it reverts the change
unless StorageForge confirms it afterwards, so a change that cuts StorageForge off undoes itself, even if StorageForge is gone.
"""
from __future__ import annotations

import contextlib
import json
import re
import shlex
import threading
import time
from xml.etree import ElementTree

from . import cisco, exposure, openwrt, pfsense, rostranspiler, routeros, security, traffic
from .db import Conn, loads
from .keyinstall import HOST
from .nettransport import DirectTransport, NetworkTransport, TelnetTransport
from .remote import RemoteError, Transport

PLATFORMS = {'routeros': {'target': 'routeros', 'transport': 'direct', 'profile': 'routeros', 'label': 'MikroTik RouterOS', 'adapter': routeros},
             'openwrt': {'target': 'openwrt', 'transport': 'sh', 'profile': 'openwrt', 'label': 'OpenWrt', 'adapter': openwrt},
             'pfsense': {'target': 'pfsense', 'transport': 'sh', 'profile': 'pfsense', 'label': 'pfSense', 'adapter': pfsense},
             'opnsense': {'target': 'pfsense', 'transport': 'sh', 'profile': 'pfsense', 'label': 'OPNsense', 'adapter': pfsense},
             'cisco': {'target': 'cisco', 'transport': 'cli', 'profile': 'cisco', 'label': 'Cisco IOS', 'adapter': cisco}}
TRANSPORTS = ('default', 'cli', 'telnet')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
USER = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
READ_EVERY = 3600
READ_OFTEN = 300          # with traffic monitoring on
OFF_KEY = 'devices.read.off'
MIN_ROLLBACK, MAX_ROLLBACK, DEFAULT_ROLLBACK = 60, 3600, 180
CONFIRM_TRIES = 3
_lock = threading.Lock()


class DeviceError(ValueError):
    pass


# ── the registry ────────────────────────────────────────────────────
COLUMNS = 'device_id, name, platform, address, port, transport, username, credential, legacy, wan_json, last_read_at, last_error, created_by, created_at'
FIELDS = ('id', 'name', 'platform', 'address', 'port', 'transport', 'username', 'credential', 'legacy', 'wan', 'last_read_at', 'last_error', 'created_by', 'created_at')


def _row(r) -> dict:
    d = dict(zip(FIELDS, r))
    d['legacy'] = bool(d['legacy'])
    d['wan'] = loads(d['wan']) if isinstance(d['wan'], str) else (d['wan'] or [])
    d['label'] = PLATFORMS.get(d['platform'], {}).get('label', d['platform'])
    d['encrypted'] = d['transport'] != 'telnet'
    return d


def list_devices(conn: Conn) -> list[dict]:
    return [_row(r) for r in conn.all(f'SELECT {COLUMNS} FROM network_devices ORDER BY name')]


def get(conn: Conn, name: str) -> dict:
    rows = conn.all(f'SELECT {COLUMNS} FROM network_devices WHERE lower(name) = lower(:n)', {'n': str(name or '')})
    if not rows:
        raise DeviceError(f'no device named {str(name or "")[:64]!r}')
    return _row(rows[0])


def names(conn: Conn) -> dict:
    """{name: platform}: for what must treat a device differently from a host."""
    return dict(conn.all('SELECT name, platform FROM network_devices'))


def is_device(conn: Conn, host: str) -> bool:
    return bool(conn.scalar('SELECT count(*) FROM network_devices WHERE lower(name) = lower(:n)', {'n': host}))


def add(conn: Conn, body: dict, actor: str) -> dict:
    name, platform, address = str(body.get('name') or '').strip(), str(body.get('platform') or ''), str(body.get('address') or '').strip()
    if not NAME.fullmatch(name):
        raise DeviceError('a device name is letters, digits, dot, dash and underscore')
    if platform not in PLATFORMS:
        raise DeviceError('platform is one of ' + ', '.join(PLATFORMS))
    if not HOST.fullmatch(address) or address.startswith('-'):
        raise DeviceError('address must be a hostname or IP address')
    transport = str(body.get('transport') or 'default')
    if transport not in TRANSPORTS:
        raise DeviceError('transport is default, cli or telnet')
    default_port = 23 if transport == 'telnet' else 22
    port = body.get('port') or default_port
    if not isinstance(port, int) or not 0 < port < 65536:
        raise DeviceError('port is a number from 1 to 65535')
    username = body.get('username')
    if username is not None and not USER.fullmatch(str(username)):
        raise DeviceError('that user name holds characters a login would not take')
    credential = body.get('credential') or None
    if transport == 'telnet' and not credential:
        raise DeviceError('Telnet has no keys: this device needs a stored credential')
    wan = body.get('wan') or []
    if not isinstance(wan, list) or not all(isinstance(x, str) and rostranspiler.NAME.fullmatch(x) for x in wan):
        raise DeviceError('wan is a list of interface names')
    if conn.scalar('SELECT count(*) FROM hosts h WHERE lower(h.hostname) = lower(:n) AND NOT EXISTS (SELECT 1 FROM network_devices d WHERE lower(d.name) = lower(h.hostname))', {'n': name}):
        raise DeviceError(f'{name} is already a scanned host: pick another name')
    conn.execute("""INSERT INTO network_devices (name, platform, address, port, transport, username, credential, legacy, wan_json, created_by, created_at)
                    VALUES (:n, :pl, :a, :p, :t, :u, :c, :l, :w, :by, :at)
                    ON CONFLICT (name) DO UPDATE SET platform = excluded.platform, address = excluded.address, port = excluded.port, transport = excluded.transport,
                        username = excluded.username, credential = excluded.credential, legacy = excluded.legacy, wan_json = excluded.wan_json""",
                 {'n': name, 'pl': platform, 'a': address, 'p': port, 't': transport, 'u': username, 'c': credential, 'l': 1 if body.get('legacy') else 0, 'w': json.dumps(wan), 'by': actor[:60], 'at': int(time.time())})
    return get(conn, name)


def remove(conn: Conn, name: str) -> dict:
    d = get(conn, name)
    with conn.tx():
        conn.execute('DELETE FROM network_devices WHERE device_id = :i', {'i': d['id']})
        conn.execute('DELETE FROM security_measurements WHERE host = :h AND kind IN (:a, :b)', {'h': d['name'], 'a': 'infra', 'b': 'device'})
        conn.execute("DELETE FROM graph_edges WHERE built_by = :b", {'b': f'infra:{d["name"]}'})
        conn.execute('DELETE FROM graph_nodes WHERE host = :h', {'h': d['name']})
        conn.execute('DELETE FROM hosts WHERE hostname = :h', {'h': d['name']})
    return {'ok': True, 'name': d['name']}


def warnings(conn: Conn) -> list[dict]:
    """What is worth telling someone about how a device is reached."""
    out = []
    for d in list_devices(conn):
        if not d['encrypted']:
            out.append({'device': d['name'], 'level': 'warn', 'text': f'{d["name"]} is managed over Telnet: everything, its password too, crosses the network in the clear'})
        if d['legacy']:
            out.append({'device': d['name'], 'level': 'note', 'text': f'{d["name"]} is reached with old SSH ciphers, which are broken'})
    return out


# ── a session ───────────────────────────────────────────────────────
@contextlib.contextmanager
def session(db, conn: Conn, d: dict, action: str = 'scan', timeout: int = 120):
    """Yields run(command) → text. action is `scan` to read and `deploy` to change: each comes with its own account, unless the device has one stored credential for both."""
    from .runner import ephemeral_agent, known_hosts_path
    from .vault import NoBinding, Vault
    spec = PLATFORMS[d['platform']]
    known = str(known_hosts_path())
    with Vault(db, conn).unlock() as v:
        secret = v.credential(d['credential']) if d['credential'] else None
        user = d['username'] or (secret or {}).get('username')
        host, port = d['address'], d['port']
        if d['transport'] == 'telnet':
            t = TelnetTransport(host, user, secret['password'], profile=spec['profile'], port=port, enable_password=secret.get('enable'), command_timeout=timeout)
            try:
                if spec['profile'] == 'cisco':
                    t.enable(secret.get('enable'))
                    t.run('terminal length 0')
                yield t.run
            finally:
                t.close()
            return
        if secret:
            from .hostkeys import require_confirmed
            require_confirmed(conn, host, port)         # whoever receives a password has the account, so a person has compared this key first
            if spec['transport'] == 'cli' or d['transport'] == 'cli':
                t = NetworkTransport(host, user, profile=spec['profile'], port=port, password=secret['password'], known_hosts=known, legacy=d['legacy'], enable_password=secret.get('enable'), command_timeout=timeout)
                try:
                    if spec['profile'] == 'cisco':
                        t.enable(secret.get('enable'))
                    yield t.run
                finally:
                    t.close()
                return
            t = DirectTransport(host=host, user=_login(user, spec), port=port, known_hosts=known, isolated=True, strict=True, legacy=d['legacy'], password=secret['password'], posix=spec['transport'] == 'sh')
            try:
                yield lambda c, timeout=timeout: t.run(c, timeout=timeout)
            finally:
                t.close()
            return
        try:
            b = v.resolve(host, action)
        except NoBinding as exc:
            raise DeviceError(f'{d["name"]}: {exc}') from None
        with ephemeral_agent(v.decrypt_key(b.key_id), ttl=max(600, timeout + 60)) as sock:
            who = d['username'] if action == 'scan' and d['username'] else b.user
            if spec['transport'] == 'cli' or d['transport'] == 'cli':
                t = NetworkTransport(host, who, profile=spec['profile'], port=b.port or port, agent_sock=sock, known_hosts=known, legacy=d['legacy'], command_timeout=timeout)
                try:
                    yield t.run
                finally:
                    t.close()
                return
            t = DirectTransport(host=host, user=_login(who, spec), port=b.port or port, agent_sock=sock, known_hosts=known, isolated=True, legacy=d['legacy'], posix=spec['transport'] == 'sh')
            try:
                yield lambda c, timeout=timeout: t.run(c, timeout=timeout)
            finally:
                t.close()


def _login(user: str | None, spec: dict) -> str | None:
    from .nettransport import PROFILES
    return f'{user}{PROFILES[spec["profile"]].user_suffix}' if user else None


# ── reading ─────────────────────────────────────────────────────────
def read(db, conn: Conn, name: str, actor: str = 'system') -> dict:
    d = get(conn, name)
    try:
        with session(db, conn, d, 'scan') as run:
            data = PLATFORMS[d['platform']]['adapter'].collect(run)
    except Exception as exc:
        text = str(exc)[:500]
        conn.execute('UPDATE network_devices SET last_error = :e WHERE device_id = :i', {'e': text, 'i': d['id']})
        return {'ok': False, 'device': d['name'], 'error': text}
    return store(db, conn, d, data)


def store(db, conn: Conn, d: dict, data: dict) -> dict:
    """A reading, in every table a host's would be in. Keeps the last good reading of what this one couldn't read."""
    now = int(time.time())
    net, fw = data['net'], data['firewall']
    facts = data.get('facts') or {}
    if d.get('wan'):
        facts['wan'] = d['wan']
    infra = {'tools': [], 'firewall': fw, 'listeners': net.get('listeners') or [], 'storage_clients': [], 'libvirt': [], 'libvirt_networks': [], 'libvirt_pools': [], 'incus': [], 'lxc': [], 'proxmox': [], 'podman_rootless': [],
             'access': {'wireguard': [], 'tailscale': None, 'netbird': False, 'headscale': False, 'proxy_routes': [], 'units': []}, 'device': d['platform']}
    with conn.tx():
        conn.execute(f"""INSERT INTO hosts (hostname, ip_address, os_info, ssh_host, ssh_user, ssh_port, last_scanned_at) VALUES (:h, :ip, :os, :sh, :su, :sp, {db.ts(':t')})
                        ON CONFLICT (hostname) DO UPDATE SET ip_address = excluded.ip_address, os_info = excluded.os_info, ssh_host = excluded.ssh_host, ssh_user = excluded.ssh_user, ssh_port = excluded.ssh_port, last_scanned_at = excluded.last_scanned_at""",
                     {'h': d['name'], 'ip': d['address'], 'os': data.get('os'), 'sh': d['address'], 'su': d['username'], 'sp': d['port'], 't': now})
        hid = conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': d['name']})
        conn.execute('DELETE FROM host_network WHERE host_id = :h', {'h': hid})
        conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, NULL, :t)', {'h': hid, 'd': json.dumps(net), 't': now})
        security._save_measurement(conn, d['name'], 'infra', now, 'device', infra)
        security._save_measurement(conn, d['name'], 'device', now, 'device', {**{k: v for k, v in facts.items() if k != 'counters'}, 'config': data.get('config')})
        conn.execute('UPDATE network_devices SET last_read_at = :t, last_error = NULL WHERE device_id = :i', {'t': now, 'i': d['id']})
    traffic.record(conn, d['name'], facts.get('counters') or [], now)
    from .graph import rebuild_host
    rebuild_host(db, conn, d['name'])
    return {'ok': True, 'device': d['name'], 'os': data.get('os'), 'identity': data.get('identity'), 'interfaces': len(net['interfaces']), 'routes': len(net['routes']), 'rules': len(fw['rules']), 'nat': len(fw['nat']), 'read_at': now, 'unreadable': net.get('unreadable') or []}


def facts_of(conn: Conn, name: str) -> dict | None:
    return security.measurement(conn, name, 'device')


def off_devices(conn: Conn) -> list[str]:
    from .alerts import get_setting
    return list(get_setting(conn, OFF_KEY) or [])


def tick(db) -> int:
    from . import errlog
    conn = db.connect()
    done = 0
    try:
        every = READ_OFTEN if traffic.enabled(conn) else READ_EVERY
        off, now = set(off_devices(conn)), int(time.time())
        for d in list_devices(conn):
            if d['name'] in off or (d['last_read_at'] and now - d['last_read_at'] < every):
                continue
            try:
                done += bool(read(db, conn, d['name'])['ok'])
            except Exception:
                errlog.trace()
    finally:
        conn.close()
    return done


# ── what routers forward ────────────────────────────────────────────
def wan_of(net: dict, facts: dict | None, wan: list | None = None) -> list[str]:
    """Which interfaces are outside: what the operator said, then what the device says, then wherever its default route goes."""
    if wan:
        return list(wan)
    if facts and facts.get('wan'):
        return list(facts['wan'])
    return sorted({r['dev'] for r in net.get('routes') or [] if r.get('dst') == 'default' and r.get('dev') and r.get('table', 'main') == 'main'})


def forwards(conn: Conn) -> list[dict]:
    """Every port forward on every device, with whether the router's forward rules let it through."""
    out = []
    for d in list_devices(conn):
        from . import inframeasure, netfacts
        net, m = netfacts.reading(conn, d['name']), inframeasure.reading(conn, d['name'])
        fw = (m or {}).get('firewall')
        if not net or not fw:
            continue
        out += exposure.forwards_of(d['name'], fw, wan_of(net, facts_of(conn, d['name']), d['wan']), net)
    return out


# ── what a change would do ──────────────────────────────────────────
def compile_for(conn: Conn, name: str, text: str, **options) -> dict:
    d = get(conn, name)
    stmts = rostranspiler.parse(text)
    extra = {}
    facts = facts_of(conn, d['name']) or {}
    if d['platform'] == 'openwrt':
        zones = {}
        for z in facts.get('zones') or []:
            for n in z.get('networks') or []:
                zones[n] = z['name']
        extra['zones'] = zones
    return {**rostranspiler.emit(stmts, PLATFORMS[d['platform']]['target'], **{**extra, **options}), 'statements': [s.text() for s in stmts], 'device': d['name'], 'platform': d['platform']}


def _controller_ips(conn: Conn, name: str) -> list[str]:
    from .steps_infra import _controller_ips as ips
    try:
        return ips(conn, {'name': name})
    except Exception:
        return []


def cuts_off(conn: Conn, d: dict, stmts: list) -> dict | None:
    """Would this block SSH from where StorageForge comes in? Worked out from the rules already read, with the new ones appended, as RouterOS and fw4 would add them."""
    from . import inframeasure, netfacts
    m, net = inframeasure.reading(conn, d['name']), netfacts.reading(conn, d['name'])
    fw = (m or {}).get('firewall')
    if not fw or not fw.get('readable') or not net:
        return {'cuts': None, 'why': 'its firewall has not been read'}
    added = rostranspiler.to_model_rules(stmts, max([r.get('order') or 0 for r in fw['rules']] or [0]))
    combined = {**fw, 'rules': fw['rules'] + added['rules']}
    iif = next((i['name'] for i in net.get('interfaces') or [] for a in i.get('addresses') or [] if a.get('ip') == d['address']), None)
    src = next(iter(_controller_ips(conn, d['name'])), None)
    flow = {'proto': 'tcp', 'port': d['port'], 'iif': iif, 'daddr': d['address'], 'saddr': src, 'family': 'ip'}
    before, after = exposure.kernel_path(fw, 'input', flow), exposure.kernel_path(combined, 'input', flow)
    return {'cuts': before['verdict'] == 'accept' and after['verdict'] != 'accept', 'rule': after.get('rule')}


def report(db, conn: Conn, name: str, text: str, actor: str) -> dict:
    """The report half: what it compiles to, what it can't express, and whether it cuts StorageForge off. Saved, so an apply applies exactly this. Reads nothing new from the device."""
    d = get(conn, name)
    stmts = rostranspiler.parse(text)
    if not stmts:
        raise DeviceError('nothing to do')
    compiled = compile_for(conn, name, text)
    risk = cuts_off(conn, d, stmts)
    now = int(time.time())
    result = {'statements': compiled['statements'], 'native': _redacted(compiled, stmts), 'unsupported': compiled['unsupported'], 'notes': compiled['notes'], 'cuts_off': risk, 'platform': d['platform']}
    secret = any(s.get(k) for s in stmts for k in rostranspiler.SECRET_ATTRS)
    cid = conn.scalar("""INSERT INTO network_changes (device, dsl, source, report_json, status, actor, created_at) VALUES (:d, :s, :src, :r, 'reported', :a, :t) RETURNING change_id""",
                      {'d': d['name'], 's': json.dumps(compiled['statements']), 'src': None if secret else text, 'r': json.dumps(result), 'a': actor[:60], 't': now})
    if secret:           # a private key is never written down in the clear: this report only lasts as long as this process
        _SOURCES[cid] = text
    return {'id': cid, 'device': d['name'], **result, 'can_apply': not compiled['unsupported']}


_SOURCES: dict = {}


def _redacted(compiled: dict, stmts: list) -> str:
    text = compiled['text']
    for s in stmts:
        for k in rostranspiler.SECRET_ATTRS:
            if s.get(k):
                text = text.replace(s[k], '<hidden>')
    return text


def change(conn: Conn, cid: int) -> dict:
    rows = conn.all('SELECT change_id, device, dsl, report_json, status, actor, created_at, applied_at, rollback_at, finished_at, output FROM network_changes WHERE change_id = :i', {'i': cid})
    if not rows:
        raise DeviceError('no such change')
    r = rows[0]
    return {'id': r[0], 'device': r[1], 'statements': loads(r[2]) if isinstance(r[2], str) else r[2], 'report': loads(r[3]) if isinstance(r[3], str) else r[3], 'status': r[4], 'actor': r[5], 'created_at': r[6], 'applied_at': r[7], 'rollback_at': r[8], 'finished_at': r[9], 'output': r[10]}


def changes_of(conn: Conn, device: str | None = None, limit: int = 50) -> list[dict]:
    rows = conn.all('SELECT change_id FROM network_changes ' + ('WHERE device = :d ' if device else '') + 'ORDER BY change_id DESC LIMIT :l', {'d': device, 'l': limit} if device else {'l': limit})
    return [change(conn, r[0]) for r in rows]


def _set(conn: Conn, cid: int, **f):
    keys = ', '.join(f'{k} = :{k}' for k in f)
    conn.execute(f'UPDATE network_changes SET {keys} WHERE change_id = :id', {**f, 'id': cid})


# ── applying, per platform. Each plants the way back on the device first ──
class RouterOsApply:
    """A backup, then a scheduler on the router that loads it when the time is up, which reboots the router into what it had. Confirming removes the scheduler."""

    def __init__(self, cid: int):
        self.tag = f'sf-{cid}'

    def plant(self, run, secs: int):
        out = [run(f'/system/backup/save name={self.tag} dont-encrypt=yes')]
        run(f'/system/scheduler/remove [find name={self.tag}]')
        out.append(run(f'/system/scheduler/add name={self.tag} interval={secs}s on-event="/system/backup/load name={self.tag} password=\\"\\""'))
        return out

    def apply(self, run, compiled: dict) -> list[str]:
        out = []
        for line in compiled['text'].splitlines():
            if line.strip():
                got = run(line)
                if re.search(r'(?:failure|bad command|syntax error|expected|invalid value|not enough permissions|no such item|input does not match)', got or ''):
                    raise DeviceError(f'the router refused `{line[:120]}`: {got.strip()[:200]}')
                out.append(got)
        return out

    def confirm(self, run):
        run(f'/system/scheduler/remove [find name={self.tag}]')
        run(f'/file/remove [find name="{self.tag}.backup"]')

    def alive(self, run):
        return 'ok' in run(':put ok', timeout=20)


class OpenWrtApply:
    """A copy of /etc/config and a background shell that puts it back and reloads when the time is up. Confirming kills it."""

    def __init__(self, cid: int):
        self.dir = f'/tmp/sf-{cid}'

    def plant(self, run, secs: int):
        script = f"""mkdir -p {self.dir}/config && cp -a /etc/config/. {self.dir}/config/ &&
cat > {self.dir}/back.sh <<'SFEOF'
#!/bin/sh
sleep {int(secs)}
cp -a {self.dir}/config/. /etc/config/
/etc/init.d/network reload; /etc/init.d/firewall restart; /etc/init.d/dropbear restart
touch {self.dir}/rolled
SFEOF
chmod +x {self.dir}/back.sh; start-stop-daemon -S -b -m -p {self.dir}/pid -x {self.dir}/back.sh; echo planted"""
        got = run(script)
        if 'planted' not in got:
            raise DeviceError(f'could not plant the rollback: {got[:200]}')
        return [got]

    def apply(self, run, compiled: dict) -> list[str]:
        script = 'set -e\n' + compiled['text'] + "\n(sleep 1; /etc/init.d/network reload; /etc/init.d/firewall restart) >/dev/null 2>&1 &\necho applied\n"
        got = run(script)
        if 'applied' not in got:
            raise DeviceError(f'the router refused it: {got[-300:]}')
        return [got]

    def confirm(self, run):
        run(f'[ -f {self.dir}/pid ] && kill $(cat {self.dir}/pid) 2>/dev/null; pkill -f "{self.dir}/back.sh" 2>/dev/null; rm -rf {self.dir}; true')

    def alive(self, run):
        return 'ok' in run('echo ok', timeout=20)


class PfApply:
    """A copy of config.xml and a background shell that restores it and reloads the filter when the time is up. The fragments go into the XML here, not on the device, and go back whole."""

    def __init__(self, cid: int):
        self.dir = f'/tmp/sf-{cid}'

    def plant(self, run, secs: int):
        script = f"""mkdir -p {self.dir} && cp /cf/conf/config.xml {self.dir}/config.xml && cat > {self.dir}/back.sh <<'SFEOF'
#!/bin/sh
sleep {int(secs)}
cp {self.dir}/config.xml /cf/conf/config.xml; rm -f /tmp/config.cache
/etc/rc.filter_configure 2>/dev/null || pluginctl -c filter
touch {self.dir}/rolled
SFEOF
chmod +x {self.dir}/back.sh; nohup {self.dir}/back.sh >/dev/null 2>&1 & echo $! > {self.dir}/pid; echo planted"""
        got = run(script)
        if 'planted' not in got:
            raise DeviceError(f'could not plant the rollback: {got[:200]}')
        return [got]

    def apply(self, run, compiled: dict) -> list[str]:
        import base64
        merged = merge_config(run('cat /cf/conf/config.xml'), compiled['files'])
        blob = base64.b64encode(merged.encode()).decode()
        got = run(f"printf %s {shlex.quote(blob)} | b64decode -r > {self.dir}/new.xml 2>/dev/null || printf %s {shlex.quote(blob)} | openssl base64 -d -A > {self.dir}/new.xml; cp {self.dir}/new.xml /cf/conf/config.xml; rm -f /tmp/config.cache; /etc/rc.filter_configure 2>/dev/null || pluginctl -c filter; echo applied")
        if 'applied' not in got:
            raise DeviceError(f'the firewall refused it: {got[-300:]}')
        return [got]

    def confirm(self, run):
        run(f'[ -f {self.dir}/pid ] && kill $(cat {self.dir}/pid) 2>/dev/null; rm -rf {self.dir}; true')

    def alive(self, run):
        return 'ok' in run('echo ok', timeout=20)


def merge_config(xml: str, fragments: dict) -> str:
    """Puts the new rules at the end of their sections. Anything else in config.xml goes back as it came."""
    root = pfsense.load_xml(xml)
    for section, text in (fragments or {}).items():
        if section == 'dnsserver':
            parent = root.find('system')
            for node in ElementTree.fromstring(f'<x>{text}</x>'):
                parent.append(node)
            continue
        parent = root.find(section)
        if parent is None:
            parent = ElementTree.SubElement(root, section)
        for node in ElementTree.fromstring(f'<x>{text}</x>'):
            parent.append(node)
    return ElementTree.tostring(root, encoding='unicode')


class CiscoApply:
    """IOS holds the timer itself: `configure terminal revert timer` reverts unless `configure confirm` comes. Needs an archive path, which this sets."""

    def __init__(self, cid: int):
        self.cid = cid

    def plant(self, run, secs: int):
        minutes = max(1, secs // 60)
        out = [run('configure terminal'), run('archive'), run('path flash:sf-archive'), run('end')]
        got = run(f'configure terminal revert timer {minutes}')
        if cisco.ERROR.search(got or ''):
            raise DeviceError(f'this IOS has no revert timer: {got.strip()[:200]}. Nothing was changed')
        return [*out, got]

    def apply(self, run, compiled: dict) -> list[str]:
        out = []
        for line in compiled['text'].splitlines():
            if line.strip():
                got = run(line)
                if cisco.ERROR.search(got or ''):
                    raise DeviceError(f'IOS refused `{line[:120]}`: {got.strip()[:200]}')
                out.append(got)
        out.append(run('end'))
        return out

    def confirm(self, run):
        run('configure confirm')

    def alive(self, run):
        return bool(run('show clock', timeout=20) is not None)


APPLIERS = {'routeros': RouterOsApply, 'openwrt': OpenWrtApply, 'pfsense': PfApply, 'opnsense': PfApply, 'cisco': CiscoApply}


def apply(db, conn: Conn, cid: int, actor: str, rollback: int = DEFAULT_ROLLBACK, hold: bool = False, wait: bool = False) -> dict:
    """Plants the way back, applies, then in the background checks the device still answers and confirms. hold: leave the confirming to a person, who has until the timer runs out."""
    c = change(conn, cid)
    if c['status'] != 'reported':
        raise DeviceError(f'this change is {c["status"]}: report it again')
    if c['report'].get('unsupported'):
        raise DeviceError('this target can\'t express all of it: see `unsupported`')
    text = _SOURCES.get(cid) or conn.scalar('SELECT source FROM network_changes WHERE change_id = :i', {'i': cid})
    if text is None:
        raise DeviceError('this report held a secret, and is from before the last restart: report it again')
    if not isinstance(rollback, int) or not MIN_ROLLBACK <= rollback <= MAX_ROLLBACK:
        raise DeviceError(f'the rollback timer is {MIN_ROLLBACK} to {MAX_ROLLBACK} seconds')
    d = get(conn, c['device'])
    compiled = compile_for(conn, d['name'], text)
    applier = APPLIERS[d['platform']](cid)
    now = int(time.time())
    _set(conn, cid, status='applying', applied_at=now, rollback_at=now + rollback, actor=actor[:60])
    try:
        with session(db, conn, d, 'deploy') as run:
            applier.plant(run, rollback)
            try:
                applier.apply(run, compiled)
            except Exception as exc:
                # a refusal part-way: the timer stays set, and takes it back to the start
                _set(conn, cid, status='rolling-back', output=str(exc)[:2000])
                return {'ok': False, 'id': cid, 'status': 'rolling-back', 'error': str(exc)[:500]}
    except (RemoteError, DeviceError, OSError) as exc:
        # the session may have died because the change cut it off, which is what the timer is for
        _set(conn, cid, status='unconfirmed', output=str(exc)[:2000])
    else:
        _set(conn, cid, status='unconfirmed')
    _SOURCES.pop(cid, None)
    conn.execute('UPDATE network_changes SET source = NULL WHERE change_id = :i', {'i': cid})
    if hold:
        return {'ok': True, 'id': cid, 'status': 'unconfirmed', 'rollback_at': now + rollback, 'message': 'Confirm it before the timer runs out, or the device goes back.'}
    worker = threading.Thread(target=_settle, args=(db, cid, rollback), daemon=True)
    worker.start()
    if wait:
        worker.join(rollback + 400)
        return change(conn, cid)
    return {'ok': True, 'id': cid, 'status': 'unconfirmed', 'rollback_at': now + rollback}


def _settle(db, cid: int, rollback: int) -> None:
    """If it answers from a new connection, keep the change. If it doesn't, leave the timer to do its work, and wait to see it back."""
    from . import errlog
    conn = db.connect()
    try:
        c = change(conn, cid)
        d = get(conn, c['device'])
        applier = APPLIERS[d['platform']](cid)
        time.sleep(5)
        for _ in range(CONFIRM_TRIES):
            try:
                with session(db, conn, d, 'deploy', timeout=30) as run:
                    if applier.alive(run):
                        applier.confirm(run)
                        _set(conn, cid, status='confirmed', finished_at=int(time.time()))
                        read(db, conn, d['name'])
                        return
            except Exception:
                errlog.trace()
            time.sleep(10)
        _set(conn, cid, status='rolling-back', output='the device stopped answering after the change: its timer will take it back')
        until = int(time.time()) + rollback + 300
        time.sleep(max(0, (c['rollback_at'] or 0) - time.time()))
        while time.time() < until:
            try:
                with session(db, conn, d, 'deploy', timeout=20) as run:
                    if applier.alive(run):
                        _set(conn, cid, status='rolled-back', finished_at=int(time.time()), output='the device went back to what it had, and answers again')
                        read(db, conn, d['name'])
                        return
            except Exception:
                pass
            time.sleep(10)
        _set(conn, cid, status='lost', finished_at=int(time.time()), output='the device has not answered since its timer ran out')
    except Exception:
        errlog.trace()
    finally:
        conn.close()


def confirm(db, conn: Conn, cid: int) -> dict:
    c = change(conn, cid)
    if c['status'] != 'unconfirmed':
        raise DeviceError(f'this change is {c["status"]}')
    d = get(conn, c['device'])
    with session(db, conn, d, 'deploy', timeout=30) as run:
        APPLIERS[d['platform']](cid).confirm(run)
    _set(conn, cid, status='confirmed', finished_at=int(time.time()))
    read(db, conn, d['name'])
    return change(conn, cid)


def as_dsl(conn: Conn, name: str) -> str:
    """Whatever this host or device runs, in the one syntax."""
    from . import inframeasure, netfacts
    return rostranspiler.from_model(netfacts.reading(conn, name), (inframeasure.reading(conn, name) or {}).get('firewall'))
