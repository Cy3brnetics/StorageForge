"""Web routes: network devices, the one network language, the management planner's fleet view, the opt-in scanner and traffic statistics. Reading a device runs commands on it; only
/api/devices/changes/<id>/apply changes one, and only with a rollback timer already planted on it."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import current_user, login_required

from . import changes, deploy, exposure, hostkeys, inframeasure, netdevice, netfacts, netscan, reach, rostranspiler, traffic, workloads
from .vault import Vault


def fleet(conn) -> dict:
    """Everything the management planner starts from: every machine StorageForge knows, and what it can do with each."""
    devices = {d['name']: d for d in netdevice.list_devices(conn)}
    access = {a['host']: a['state'] for a in deploy.access(conn)}
    forwards = netdevice.forwards(conn)
    rows = []
    for name, os_info, ip, last in conn.all('SELECT hostname, os_info, ip_address, last_scanned_at FROM hosts ORDER BY hostname'):
        d = devices.get(name)
        net, infra = netfacts.reading(conn, name), inframeasure.reading(conn, name)
        fw = (infra or {}).get('firewall') or {}
        report = exposure.host_report(net, infra, workloads.containers_of(conn, name), name, forwards)
        exposed = [i for i in report['items'] if i['level'] == 'any']
        rows.append({'name': name, 'kind': 'device' if d else 'host', 'platform': d['platform'] if d else None, 'label': d['label'] if d else 'Linux host', 'os': os_info, 'address': ip,
                     'backends': fw.get('backends') or [], 'firewall_read': bool(fw.get('readable')), 'interfaces': len((net or {}).get('interfaces') or []), 'routes': len((net or {}).get('routes') or []),
                     'rules': len(fw.get('rules') or []), 'nat': len(fw.get('nat') or []), 'exposed': len(exposed), 'read_at': (d or {}).get('last_read_at') or (net or {}).get('read_at'),
                     'deploy': access.get(name), 'encrypted': d['encrypted'] if d else True, 'error': (d or {}).get('last_error'), 'target': rostranspiler_target(d, fw)})
    pending = [c for c in netdevice.changes_of(conn, limit=20) if c['status'] in ('unconfirmed', 'applying', 'rolling-back')]
    for name, d in devices.items():
        if not any(r['name'] == name for r in rows):       # added, never read
            rows.append({'name': name, 'kind': 'device', 'platform': d['platform'], 'label': d['label'], 'os': None, 'address': d['address'], 'backends': [], 'firewall_read': False, 'interfaces': 0, 'routes': 0, 'rules': 0, 'nat': 0, 'exposed': 0,
                         'read_at': None, 'deploy': None, 'encrypted': d['encrypted'], 'error': d['last_error'], 'target': netdevice.PLATFORMS[d['platform']]['target']})
    rows.sort(key=lambda r: (r['kind'] != 'device', r['name']))
    return {'machines': rows, 'pending': pending, 'warnings': netdevice.warnings(conn), 'forwards': forwards, 'scanner': {k: v for k, v in netscan.settings(conn).items() if k in ('enabled', 'nmap')}, 'traffic': traffic.enabled(conn), 'anomalies': traffic.anomalies(conn) if traffic.enabled(conn) else []}


def rostranspiler_target(device: dict | None, fw: dict) -> str:
    """Which emitter suits this machine."""
    if device:
        return netdevice.PLATFORMS[device['platform']]['target']
    for b in ('firewalld', 'ufw', 'nftables', 'iptables'):
        if b in (fw.get('backends') or []):
            return b
    return 'nftables'


def tasks_of(stmts: list) -> tuple[list, list]:
    """What's expressible as the plan steps a Linux host deploys through: its firewall rules, each as an fw_rule step with its own checks and rollback. The rest goes back to say so."""
    tasks, left = [], []
    for s in stmts:
        action = {'accept': 'allow', 'drop': 'deny', 'reject': 'deny'}.get(s.get('action')) if s.path == rostranspiler.FILTER else None
        plain = action and s['chain'] in ('input', 'forward') and s.get('protocol') in ('tcp', 'udp') and s.get('dst-port') and not (set(s.attrs) - {'chain', 'action', 'protocol', 'dst-port', 'src-address', 'in-interface', 'comment'})
        if plain and not str(s.get('src-address', '')).startswith('!') and not str(s.get('in-interface', '')).startswith('!') and '-' not in s.get('src-address', '') and not s['dst-port'].startswith('!'):
            for port in s['dst-port'].split(','):       # a step takes one port or range, so a list is several steps
                tasks.append({'type': 'fw-rule', 'params': {'hook': s['chain'], 'action': action, 'proto': s['protocol'], 'port': port, 'source': s.get('src-address', ''), 'iface': s.get('in-interface', ''), 'state': 'present'}})
        else:
            left.append(s.text())
    return tasks, left


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    @web.errorhandler(netdevice.DeviceError)
    @web.errorhandler(rostranspiler.DslError)
    @web.errorhandler(netscan.ScanRefused)
    def refused(exc):
        return jsonify(error=str(exc)), 400

    # ── the fleet and its devices ───────────────────────────────────
    @web.get('/api/fleet')
    @login_required
    def api_fleet():
        data = fleet(conn())
        if 'security.view' not in current_user.permissions:     # what gets in is for those who may see firewall rules
            data['forwards'] = []
            for m in data['machines']:
                m.pop('exposed', None)
            data['pending'] = [{k: c[k] for k in ('id', 'device', 'status', 'actor', 'rollback_at')} for c in data['pending']]
        return jsonify(data)

    @web.get('/api/devices')
    @login_required
    def api_devices():
        return jsonify(devices=netdevice.list_devices(conn()), platforms={k: v['label'] for k, v in netdevice.PLATFORMS.items()}, warnings=netdevice.warnings(conn()))

    @web.post('/api/devices')
    @login_required
    @password_confirmed
    def api_device_add():
        d = netdevice.add(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'device.add', 'ok', d['name'], {'platform': d['platform'], 'address': d['address'], 'transport': d['transport']})
        return jsonify(d)

    @web.get('/api/devices/credentials')
    @login_required
    def api_device_credentials():
        with Vault(db, conn()).unlock() as v:
            return jsonify(credentials=v.list_credentials())

    @web.post('/api/devices/credentials')
    @login_required
    @password_confirmed
    def api_device_credential_add():
        """Sealed in the vault. Nothing returns it: not this, not the list."""
        body = json_body()
        with Vault(db, conn()).unlock() as v:
            res = v.store_credential(str(body.get('name') or ''), body.get('username') or None, str(body.get('password') or ''), body.get('enable') or None)
        core.audit(conn(), actor(), 'device.credential', 'ok', None, {'name': res['name']})
        return jsonify(res)

    @web.delete('/api/devices/credentials/<name>')
    @login_required
    @password_confirmed
    def api_device_credential_remove(name):
        with Vault(db, conn()).unlock() as v:
            n = v.remove_credential(name)
        core.audit(conn(), actor(), 'device.credential.remove', 'ok', None, {'name': name})
        return jsonify(ok=bool(n))

    @web.post('/api/devices/<name>/hostkey')
    @login_required
    @password_confirmed
    def api_device_hostkey(name):
        """What this device's SSH key is, for someone to compare, before a password goes to it. hostkeys.py is the same step a host has."""
        d = netdevice.get(conn(), name)
        body = json_body()
        if body.get('confirm'):
            got = hostkeys.confirm(conn(), d['address'], d['port'], body['confirm'], actor())
            core.audit(conn(), actor(), 'device.hostkey', 'ok', d['name'], {'fingerprint': body['confirm']})
            return jsonify(got)
        return jsonify(keys=hostkeys.offered(d['address'], d['port']))

    @web.get('/api/devices/changes/<int:change_id>')
    @login_required
    def api_device_change(change_id):
        return jsonify(netdevice.change(conn(), change_id))

    @web.post('/api/devices/changes/<int:change_id>/apply')
    @login_required
    @password_confirmed
    def api_device_apply(change_id):
        body = json_body()
        rollback = body.get('rollback', netdevice.DEFAULT_ROLLBACK)
        res = netdevice.apply(db, conn(), change_id, actor(), rollback, body.get('hold') is True)
        core.audit(conn(), actor(), 'device.apply', 'ok' if res.get('ok') else 'failed', netdevice.change(conn(), change_id)['device'], {'change': change_id, 'rollback': rollback, 'status': res.get('status')})
        return jsonify(res), 200 if res.get('ok') else 409

    @web.post('/api/devices/changes/<int:change_id>/confirm')
    @login_required
    @password_confirmed
    def api_device_confirm(change_id):
        res = netdevice.confirm(db, conn(), change_id)
        core.audit(conn(), actor(), 'device.confirm', 'ok', res['device'], {'change': change_id})
        return jsonify(res)

    @web.get('/api/devices/<name>')
    @login_required
    def api_device(name):
        d = netdevice.get(conn(), name)
        secure = 'security.view' in current_user.permissions
        infra = inframeasure.reading(conn(), d['name']) or {}
        facts = netdevice.facts_of(conn(), d['name']) or {}
        history = netdevice.changes_of(conn(), d['name'], 20)
        if not secure:         # a rule is how to get in
            history = [{k: c[k] for k in ('id', 'device', 'status', 'actor', 'created_at', 'applied_at', 'finished_at')} for c in history]
        return jsonify(device=d, network=netfacts.reading(conn(), d['name']), firewall=infra.get('firewall') if secure else None, facts={k: v for k, v in facts.items() if secure or k != 'config'},
                       changes=history, dsl=netdevice.as_dsl(conn(), d['name']) if secure else None)

    @web.delete('/api/devices/<name>')
    @login_required
    @password_confirmed
    def api_device_remove(name):
        res = netdevice.remove(conn(), name)
        core.audit(conn(), actor(), 'device.remove', 'ok', res['name'], {})
        return jsonify(res)

    @web.post('/api/devices/<name>/read')
    @login_required
    def api_device_read(name):
        res = netdevice.read(db, conn(), name, actor())
        core.audit(conn(), actor(), 'device.read', 'ok' if res['ok'] else 'failed', res['device'], {'error': res.get('error')})
        return jsonify(res), 200 if res['ok'] else 409

    @web.post('/api/devices/<name>/report')
    @login_required
    def api_device_report(name):
        body = json_body()
        res = netdevice.report(db, conn(), name, str(body.get('dsl') or ''), actor())
        core.audit(conn(), actor(), 'device.report', 'ok', res['device'], {'change': res['id']})
        return jsonify(res)

    # ── the one language ────────────────────────────────────────────
    @web.post('/api/dsl/compile')
    @login_required
    def api_dsl_compile():
        """What it would be on each target asked for. Sends nothing anywhere."""
        body = json_body()
        stmts = rostranspiler.parse(str(body.get('dsl') or ''))
        wanted = body.get('targets') or list(rostranspiler.TARGETS)
        out = {t: rostranspiler.emit(stmts, t) for t in wanted}
        for got in out.values():         # a private key stays out of what's shown
            for s in stmts:
                for k in rostranspiler.SECRET_ATTRS:
                    if s.get(k):
                        got['text'] = got['text'].replace(s[k], '<hidden>')
                        got['files'] = {n: v.replace(s[k], '<hidden>') for n, v in got['files'].items()}
        return jsonify(statements=[s.text() for s in stmts], targets=out)

    @web.get('/api/dsl/of')
    @login_required
    def api_dsl_of():
        """What a host or device runs, in the one syntax."""
        return jsonify(host=request.args.get('host'), dsl=netdevice.as_dsl(conn(), str(request.args.get('host') or '')))

    @web.post('/api/dsl/whatif')
    @login_required
    def api_dsl_whatif():
        """A reach question before and after these rules go on this machine. Reads the index only."""
        body = json_body()
        host, a, b, port = str(body.get('host') or ''), body.get('from'), body.get('to'), body.get('port')
        if not a or not b or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError('asks for host, from, to and a port')
        stmts = rostranspiler.parse(str(body.get('dsl') or ''))
        proto = 'udp' if body.get('proto') == 'udp' else 'tcp'
        fleet_now = reach.load(conn())
        before = reach.query(fleet_now, a, b, port, proto)
        if host in fleet_now.hosts and (fleet_now.hosts[host].get('infra') or {}).get('firewall'):
            fw = fleet_now.hosts[host]['infra']['firewall']
            add = rostranspiler.to_model_rules(stmts, max([r.get('order') or 0 for r in fw['rules']] or [0]))
            # RouterOS appends, so a rule below a chain's final drop means nothing: the operator sees the same order the device would have
            chains = fw.get('chains') or [{'backend': 'dsl', 'table': 'filter', 'name': h, 'hook': h, 'prio': 0, 'policy': 'accept', 'family': None} for h in ('input', 'forward', 'output')]     # a host with no firewall has no chains yet
            fleet_now.hosts[host]['infra']['firewall'] = {**fw, 'rules': fw['rules'] + add['rules'], 'nat': fw['nat'] + add['nat'], 'chains': chains, 'backends': fw.get('backends') or ['dsl']}
        after = reach.query(fleet_now, a, b, port, proto)
        return jsonify(before=before, after=after, changed=before['verdict'] != after['verdict'])

    @web.post('/api/dsl/stage')
    @login_required
    def api_dsl_stage():
        """A Linux host's firewall rules, as steps in Changes, where they get a report and a signed deploy like any other."""
        body = json_body()
        host = body.get('host')
        known = conn().scalar('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h)', {'h': str(host or '')})
        if not known or netdevice.is_device(conn(), known):
            raise ValueError('that is not a scanned Linux host: a device takes a report, from its own page')
        tasks, left = tasks_of(rostranspiler.parse(str(body.get('dsl') or '')))
        if not tasks:
            return jsonify(ok=False, tasks=0, left=left, message='nothing here is a plain firewall rule with a port')
        for t in tasks:
            t['host'] = known
        name = f'Network: {known}'[:80]
        pid = conn().scalar('SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': name})
        have = changes.get_plan(conn(), pid).get('tasks') if pid else []
        plan_id = changes.save_plan(conn(), {'name': name, 'tasks': have + tasks}, actor(), pid)
        core.audit(conn(), actor(), 'dsl.stage', 'ok', known, {'plan': plan_id, 'steps': len(tasks)})
        return jsonify(ok=True, plan_id=plan_id, tasks=len(tasks), left=left, check=changes.check(conn(), changes.get_plan(conn(), plan_id)))

    # ── the scanner, which is off until someone turns it on ─────────
    @web.get('/api/netscan')
    @login_required
    def api_netscan():
        return jsonify(settings=netscan.settings(conn()), scans=netscan.scans(conn()), results=netscan.results(conn(), request.args.get('scan', type=int)))

    @web.post('/api/netscan/settings')
    @login_required
    @password_confirmed
    def api_netscan_settings():
        res = netscan.save_settings(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'netscan.settings', 'ok', None, {'enabled': res['enabled'], 'ranges': res['ranges']})
        return jsonify(res)

    @web.post('/api/netscan/run')
    @login_required
    def api_netscan_run():
        res = netscan.run(db, conn(), json_body().get('target'), actor())
        core.audit(conn(), actor(), 'netscan.run', 'ok', None, {'targets': res['targets'], 'scan': res['scan_id']})
        return jsonify(res)

    @web.get('/api/netscan/graph')
    @login_required
    def api_netscan_graph():
        return jsonify(netscan.graph(conn(), request.args.get('scan', type=int)))

    # ── traffic ─────────────────────────────────────────────────────
    @web.get('/api/traffic')
    @login_required
    def api_traffic():
        return jsonify(enabled=traffic.enabled(conn()), interfaces=traffic.stats(conn(), request.args.get('host') or None), anomalies=traffic.anomalies(conn()))

    @web.post('/api/traffic/settings')
    @login_required
    @password_confirmed
    def api_traffic_settings():
        res = traffic.set_enabled(conn(), json_body().get('enabled') is True, actor())
        core.audit(conn(), actor(), 'traffic.settings', 'ok', None, res)
        return jsonify(res)
