"""Web routes: ClamAV on hosts. Installing and removing it go through /api/deploy/start (kind clamav)."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import clamav, deploy


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def answer(res):
        core.alerts_wake.set()
        return jsonify(res), 200 if res.get('ok') else 409

    @web.get('/api/clamav')
    @login_required
    def api_clamav():
        host = request.args.get('host') or None
        return jsonify(hosts=clamav.hosts(conn(), host), detections=clamav.detections(conn(), host, request.args.get('closed') == '1'))

    @web.post('/api/clamav/hosts/<host>/config')
    @login_required
    @password_confirmed
    def api_clamav_config(host):
        name = deploy.canonical(conn(), host)
        cfg = clamav.save_config(conn(), name, json_body(), actor())
        core.audit(conn(), actor(), 'clamav.config', 'ok', name, cfg)
        return jsonify(cfg)

    @web.post('/api/clamav/hosts/<host>/collect')
    @login_required
    def api_clamav_collect(host):
        res = clamav.collect(db, conn(), host, actor())
        core.audit(conn(), actor(), 'clamav.collect', 'ok' if res['ok'] else 'failed', host, {'new': bool(res.get('new'))})
        return answer(res)

    @web.post('/api/clamav/detections/<int:did>/quarantine')
    @login_required
    @password_confirmed
    def api_clamav_quarantine(did):
        host = clamav.get_detection(conn(), did)['host']
        res = clamav.quarantine(db, conn(), did, actor(), json_body().get('allow_system') is True)
        core.audit(conn(), actor(), 'clamav.quarantine', 'ok' if res['ok'] else 'failed', host, {'detection': did})
        return answer(res)

    @web.post('/api/clamav/detections/<int:did>/restore')
    @login_required
    @password_confirmed
    def api_clamav_restore(did):
        host = clamav.get_detection(conn(), did)['host']
        res = clamav.restore(db, conn(), did, actor())
        core.audit(conn(), actor(), 'clamav.restore', 'ok' if res['ok'] else 'failed', host, {'detection': did})
        return answer(res)

    @web.post('/api/clamav/detections/<int:did>/ignore')
    @login_required
    @password_confirmed
    def api_clamav_ignore(did):
        body = json_body()
        ignored, reason = body.get('ignore') is not False, str(body.get('reason') or '')
        host = clamav.get_detection(conn(), did)['host']
        clamav.set_ignored(conn(), did, ignored, reason, actor())
        core.audit(conn(), actor(), 'clamav.ignore', 'ok', host, {'detection': did, 'ignore': ignored, 'reason': reason[:200]})
        core.alerts_wake.set()
        return jsonify(ok=True)
