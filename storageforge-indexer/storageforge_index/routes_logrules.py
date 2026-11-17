"""Web routes: log rules (logrules.py). Reading takes hostlogs.view; saving and deleting take hostlogs.rules and are audited. A rule changes
nothing on a host, so none asks for the password again."""
from __future__ import annotations

from flask import jsonify
from flask_login import login_required

from . import logrules


def register(web, ctx):
    core, conn, actor, json_body = ctx.core, ctx.conn, ctx.actor, ctx.json_body

    @web.get('/api/hostlogs/rules')
    @login_required
    def api_logrules():
        return jsonify(rules=logrules.rules(conn()), levels=list(logrules.LEVELS), rule_levels=list(logrules.RULE_LEVELS))

    def saved(rule_id=None):
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
        return saved()

    @web.put('/api/hostlogs/rules/<int:rule_id>')
    @login_required
    def api_logrule_save(rule_id):
        return saved(rule_id)

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
