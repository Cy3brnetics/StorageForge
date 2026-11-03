"""Web routes: ransomware defense. Deploying the sentinel and its decoys goes through /api/deploy/start (kind security).

What runs on a host asks for a fresh password and takes mode: preview shows the script, report dry-runs it, apply does it.
Nothing but the outcome goes in the audit detail: never the offline key, and never whole request bodies.
"""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import security


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed, limiter = (ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed, ctx.limiter)
    step_up = ctx.step_up

    def audit(action: str, res: dict, **detail):
        """Previews change nothing and run nothing, so they leave no row."""
        if res.get('mode') != 'preview':
            core.audit(conn(), actor(), action, 'ok' if res.get('ok') else 'failed', res.get('host'), {**detail, 'mode': res.get('mode'), 'run': res.get('run_id')})
        core.alerts_wake.set()
        return jsonify(res), 200 if res.get('ok') else 409

    def host_arg():
        return request.args.get('host') or None

    def must_host():
        return security.known_host(conn(), request.args.get('host'))

    # ── the whole picture ───────────────────────────────────────────────
    @web.get('/api/security/posture')
    @login_required
    def api_security_posture():
        return jsonify(security.posture(conn(), host_arg()))

    @web.get('/api/security/events')
    @login_required
    def api_security_events():
        return jsonify(events=security.list_events(conn(), host_arg(), include_info=request.args.get('all') == '1'))

    @web.post('/api/security/events/<int:event_id>/ack')
    @login_required
    @password_confirmed
    def api_security_event_ack(event_id):
        return audit('security.event.ack', security.acknowledge_event(conn(), event_id, actor()), event=event_id)

    @web.post('/api/security/measure')
    @login_required
    @password_confirmed
    def api_security_measure():
        return audit('security.measure', security.measure(db, conn(), json_body().get('host'), actor()))

    @web.post('/api/security/report')
    @limiter.limit('120 per minute')
    def api_security_report():
        """A sentinel on a host: its token says which host, so it can only speak for itself."""
        auth = request.headers.get('Authorization', '')
        host = security.report_host(conn(), auth[7:].strip() if auth.startswith('Bearer ') else '')
        if not host:
            return jsonify(error='unknown report token'), 401
        lines = json_body().get('lines')
        if not isinstance(lines, list) or len(lines) > 100 or not all(isinstance(x, str) and len(x) < 32768 for x in lines):
            return jsonify(error='expected up to 100 event lines'), 400
        new = security.ingest_events(conn(), host, '\n'.join(lines), f'report:{request.remote_addr}'[:60])
        if new:
            core.alerts_wake.set()
        return jsonify(ok=True, new=new)

    # ── retention holds ─────────────────────────────────────────────────
    @web.get('/api/security/worm/holds')
    @login_required
    def api_security_worm_holds():
        return jsonify(security.worm_view(conn(), host_arg()))

    @web.post('/api/security/worm/hold')
    @login_required
    @password_confirmed
    def api_security_worm_hold():
        res = security.apply_hold(db, conn(), json_body(), actor())
        return audit('security.worm.hold', res, snapshot=res.get('snapshot'), tag=res.get('hold_tag'))

    @web.post('/api/security/worm/release')
    @login_required
    @password_confirmed
    @step_up
    def api_security_worm_release():
        body = json_body()
        res = security.request_release(db, conn(), body, actor())
        return audit('security.worm.release', res, hold=body.get('hold_id'), timelock=res.get('timelock_id'))

    @web.post('/api/security/worm/quorum/approve')
    @login_required
    @password_confirmed
    @step_up
    def api_security_worm_approve():
        body = json_body()
        return audit('security.worm.approve', security.approve(db, conn(), body, actor()), timelock=body.get('timelock_id'))

    @web.post('/api/security/worm/abort')
    @login_required
    @password_confirmed
    def api_security_worm_abort():
        body = json_body()
        return audit('security.worm.abort', security.abort(conn(), body, actor()), timelock=body.get('timelock_id'))

    @web.post('/api/security/worm/break-glass')
    @login_required
    @password_confirmed
    @step_up
    def api_security_worm_break_glass():
        body = json_body()
        return audit('security.worm.break_glass', security.use_break_glass(db, conn(), body, actor()), timelock=body.get('timelock_id'))

    @web.post('/api/security/worm/break-glass/key')
    @login_required
    @password_confirmed
    @step_up
    def api_security_worm_key():
        res = security.mint_break_glass(conn(), actor())
        return audit('security.worm.key', res, minted='break_glass_key' in res, timelock=res.get('timelock_id'))

    @web.post('/api/security/worm/cool-off')
    @login_required
    @password_confirmed
    def api_security_worm_cool_off():
        res = security.set_cool_off(conn(), json_body().get('hours'), actor())
        return audit('security.worm.cool_off', res, hours=res.get('hours'))

    @web.post('/api/security/worm/clock/clear')
    @login_required
    @password_confirmed
    def api_security_clock_clear():
        body = json_body()
        res = security.clear_controller_clock(conn(), actor()) if body.get('controller') is True else security.clear_clock(conn(), body.get('host'), actor())
        return audit('security.clock.clear', res, controller=body.get('controller') is True, reason=res.get('reason'), hosts=res.get('hosts_cleared'))

    # ── decoys and the sentinel ─────────────────────────────────────────
    @web.get('/api/security/canaries')
    @login_required
    def api_security_canaries():
        return jsonify(security.canaries_view(conn(), host_arg()))

    @web.post('/api/security/sentinel')
    @login_required
    @password_confirmed
    def api_security_sentinel():
        body = json_body()
        res = security.save_sentinel_config(conn(), body.get('host'), body, actor())
        return audit('security.sentinel.config', res, armed=res.get('armed'), folders=len(res.get('folders') or ()))

    @web.post('/api/security/canaries/test')
    @login_required
    @password_confirmed
    def api_security_canaries_test():
        res = security.test_sentinel(db, conn(), json_body(), actor())
        return audit('security.sentinel.test', res, latency_ms=res.get('latency_ms'))

    # ── access control ──────────────────────────────────────────────────
    @web.get('/api/security/mac/status')
    @login_required
    def api_security_mac_status():
        return jsonify(security.mac_view(conn(), must_host()))

    @web.post('/api/security/mac/remediate')
    @login_required
    @password_confirmed
    def api_security_mac_remediate():
        body = json_body()
        res = security.remediate_mac(db, conn(), body, actor())
        return audit('security.mac.remediate', res, boolean=body.get('boolean'), path=res.get('path'), type=res.get('type'))

    # ── firewall ────────────────────────────────────────────────────────
    @web.get('/api/security/firewall/quarantine')
    @login_required
    def api_security_quarantine_get():
        return jsonify(security.firewall_view(conn(), host_arg()))

    @web.post('/api/security/firewall/quarantine')
    @login_required
    @password_confirmed
    def api_security_quarantine_post():
        res = security.quarantine(db, conn(), json_body(), actor())
        return audit('security.quarantine.add', res, ip=res.get('ip_address'))

    @web.delete('/api/security/firewall/quarantine/<path:ip>')
    @login_required
    @password_confirmed
    def api_security_quarantine_delete(ip):
        res = security.lift_quarantine(db, conn(), request.args.get('host'), ip, request.args.get('mode') or 'report', actor())
        return audit('security.quarantine.lift', res, ip=res.get('ip_address'))

    @web.post('/api/security/firewall/vip')
    @login_required
    @password_confirmed
    def api_security_vip():
        res = security.save_vips(conn(), json_body().get('vips'), actor())
        return audit('security.vip', res, vips=res.get('vips'))

    @web.post('/api/security/firewall/airgap')
    @login_required
    @password_confirmed
    @step_up
    def api_security_airgap():
        body = json_body()
        res = security.airgap(db, conn(), body, actor())
        return audit('security.airgap', res, enabled=body.get('enabled') is not False, airgap=res.get('airgap'))

    # ── behaviour ───────────────────────────────────────────────────────
    @web.get('/api/security/behavior')
    @login_required
    def api_security_behavior():
        return jsonify(security.behavior_view(conn(), must_host()))

    @web.post('/api/security/behavior/entropy')
    @login_required
    @password_confirmed
    def api_security_entropy():
        res = security.sample_entropy(db, conn(), json_body(), actor())
        return audit('security.entropy', res, read=res.get('read'), flagged=res.get('flagged'))

    @web.post('/api/security/behavior/diff-scan')
    @login_required
    @password_confirmed
    def api_security_diff_scan():
        res = security.diff_scan(db, conn(), json_body(), actor())
        return audit('security.diff_scan', res, scanned=res.get('scanned'), found=res.get('found'))

    # ── integrity ───────────────────────────────────────────────────────
    @web.get('/api/security/integrity')
    @login_required
    def api_security_integrity():
        return jsonify(security.integrity_view(conn(), must_host()))

    @web.post('/api/security/integrity/run')
    @login_required
    @password_confirmed
    def api_security_integrity_run():
        res = security.run_tool(db, conn(), json_body(), actor())
        return audit('security.integrity', res, tool=res.get('tool'))

    # ── compliance ──────────────────────────────────────────────────────
    @web.get('/api/security/compliance/standards')
    @login_required
    def api_security_compliance_standards():
        return jsonify(security.compliance_standards(conn()))

    @web.get('/api/security/compliance/status/<host>')
    @login_required
    def api_security_compliance_status(host):
        return jsonify(security.compliance_status(conn(), host, request.args.get('profile') or None))

    @web.post('/api/security/compliance/init')
    @login_required
    @password_confirmed
    def api_security_compliance_init():
        res = security.compliance_init(db, conn(), json_body(), actor())
        return audit('security.compliance.init', res, profile=res.get('profile'))

    # ── an incident ─────────────────────────────────────────────────────
    @web.get('/api/security/incident/blast-radius')
    @login_required
    def api_security_blast_radius():
        at = request.args.get('at')
        return jsonify(security.blast_radius(conn(), request.args.get('host'), int(at) if at and at.isdigit() else None))

    @web.post('/api/security/incident/brake')
    @login_required
    @password_confirmed
    def api_security_brake():
        res = security.brake(db, conn(), json_body(), actor())
        return audit('security.brake', res, steps=res.get('steps'))

    @web.post('/api/security/incident/clean-room')
    @login_required
    @password_confirmed
    def api_security_clean_room():
        res = security.clean_room(db, conn(), json_body(), actor())
        return audit('security.clean_room', res, snapshot=res.get('snapshot'), mount=res.get('mount'))
