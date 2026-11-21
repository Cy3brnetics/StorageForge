"""Web routes: log rules (logrules.py), the monitoring view (logmonitor.py) and the hosts netconsole packets are taken from
(netconsole.py). Reading takes hostlogs.view; saving and deleting take hostlogs.rules and are audited. A rule changes nothing on a host,
so none asks for the password again. A netconsole source does: it decides whose name unsigned packets are stored in, so it asks for
the password typed in the last minutes, as trusting a scan signing key does."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import logmonitor, logrules, netconsole


def register(web, ctx):
    core, conn, actor, json_body, password_confirmed = ctx.core, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    @web.get('/api/hostlogs/monitor')
    @login_required
    def api_hostlogs_monitor():
        return jsonify(logmonitor.monitor(conn(), host=(request.args.get('host') or '').strip()[:200] or None))

    @web.get('/api/hostlogs/rules')
    @login_required
    def api_logrules():
        return jsonify(rules=logrules.rules(conn()), levels=list(logrules.LEVELS), rule_levels=list(logrules.RULE_LEVELS))

    def save_with_audit(rule_id=None):
        try:
            got = logrules.save(conn(), json_body(), actor(), rule_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'logrule.save', 'ok', None, {k: got[k] for k in ('id', 'name', 'builtin', 'enabled', 'threshold', 'window_secs', 'level')})
        core.alerts_wake.set()
        return jsonify(got)

    @web.post('/api/hostlogs/rules')
    @login_required
    def api_logrule_new():
        return save_with_audit()

    @web.put('/api/hostlogs/rules/<int:rule_id>')
    @login_required
    def api_logrule_save(rule_id):
        return save_with_audit(rule_id)

    @web.delete('/api/hostlogs/rules/<int:rule_id>')
    @login_required
    def api_logrule_delete(rule_id):
        try:
            got = logrules.delete(conn(), rule_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'logrule.delete', 'ok', None, {'id': got['id'], 'name': got['name']})
        core.alerts_wake.set()
        return jsonify(ok=True)

    @web.get('/api/hostlogs/netconsole')
    @login_required
    def api_netconsole():
        return jsonify(sources=netconsole.sources(conn()), receiver=netconsole.status(), default_port=netconsole.DEFAULT_PORT,
                       default_source_port=netconsole.DEFAULT_SOURCE_PORT)

    @web.put('/api/hostlogs/netconsole/<host>')
    @login_required
    @password_confirmed
    def api_netconsole_save(host):
        b = json_body()
        try:
            got = netconsole.save_source(conn(), host, b.get('address'), b.get('port'), actor(), bool(b.get('enabled', True)), b.get('note') or '')
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'netconsole.source.save', 'ok', got['host'], {k: got[k] for k in ('address', 'port', 'enabled')})
        return jsonify(got)

    @web.delete('/api/hostlogs/netconsole/<host>')
    @login_required
    @password_confirmed
    def api_netconsole_delete(host):
        if not netconsole.delete_source(conn(), host):
            return jsonify(error='no netconsole source for that host'), 404
        core.audit(conn(), actor(), 'netconsole.source.delete', 'ok', host, {})
        return jsonify(ok=True)
