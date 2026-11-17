"""Web routes: the notification center (notifications.py). Reading takes deploy.view, as the alerts in /api/deploy always have; acknowledging,
snoozing and muting take notifications.manage and go in the audit log. None of them changes a host, so none asks for the password again."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import notifications


def register(web, ctx):
    core, conn, actor, json_body = ctx.core, ctx.conn, ctx.actor, ctx.json_body

    def refused(exc):
        return jsonify(error=str(exc)), 404 if isinstance(exc, LookupError) else 400

    @web.get('/api/notifications')
    @login_required
    def api_notifications():
        try:
            return jsonify(notifications.center(conn(), request.args.get('host') or None, request.args.get('kind') or None, request.args.get('level') or None))
        except ValueError as exc:
            return refused(exc)

    @web.get('/api/notifications/summary')
    @login_required
    def api_notifications_summary():
        return jsonify(notifications.summary(conn()))

    @web.get('/api/notifications/history')
    @login_required
    def api_notifications_history():
        a = request.args
        try:
            return jsonify(notifications.history(conn(), a.get('q') or None, a.get('host') or None, a.get('kind') or None, a.get('event') or None,
                                                 int(a.get('limit') or 100), int(a.get('offset') or 0)))
        except ValueError as exc:
            return refused(exc)

    def with_audit(key, action, fn):          # every write here goes through this: done or refused, it is in the audit log
        try:
            got = fn()
        except (ValueError, LookupError) as exc:
            core.audit(conn(), actor(), f'notification.{action}', 'denied', None, {'key': key, 'why': str(exc)})
            return refused(exc)
        core.audit(conn(), actor(), f'notification.{action}', 'ok', got.get('host'), {'key': key, 'kind': got.get('kind'), 'level': got.get('level')})
        return jsonify(got)

    @web.post('/api/notifications/ack/<path:key>')
    @login_required
    def api_notification_ack(key):
        return with_audit(key, 'acknowledge', lambda: notifications.acknowledge(conn(), key, actor(), str(json_body().get('note') or '')))

    @web.delete('/api/notifications/ack/<path:key>')
    @login_required
    def api_notification_unack(key):
        return with_audit(key, 'unacknowledge', lambda: notifications.unacknowledge(conn(), key, actor()))

    @web.post('/api/notifications/snooze/<path:key>')
    @login_required
    def api_notification_snooze(key):
        body = json_body()
        return with_audit(key, 'snooze', lambda: notifications.snooze(conn(), key, float(body.get('hours') or 0) * 3600, actor(), str(body.get('note') or '')))

    @web.delete('/api/notifications/snooze/<path:key>')
    @login_required
    def api_notification_unsnooze(key):
        return with_audit(key, 'unsnooze', lambda: notifications.unsnooze(conn(), key, actor()))

    @web.post('/api/notifications/fix/<path:key>')
    @login_required
    def api_notification_fix(key):
        return with_audit(key, 'fix', lambda: notifications.prepare_fix(conn(), key, actor()))

    @web.post('/api/notifications/undo/<int:plan_id>')
    @login_required
    def api_notification_undo(plan_id):
        return with_audit(f'plan {plan_id}', 'undo', lambda: notifications.prepare_undo(conn(), plan_id, actor()))

    @web.post('/api/notifications/mutes')
    @login_required
    def api_notification_mute():
        body = json_body()
        try:
            got = notifications.mute(conn(), body.get('host') or '*', body.get('kind') or '*', actor(), str(body.get('note') or ''), body.get('days'))
        except (ValueError, TypeError) as exc:
            core.audit(conn(), actor(), 'notification.mute', 'denied', None, {'host': str(body.get('host')), 'kind': str(body.get('kind')), 'why': str(exc)})
            return refused(ValueError(str(exc)))
        core.audit(conn(), actor(), 'notification.mute', 'ok', None if got['host'] == '*' else got['host'], got)
        return jsonify(got)

    @web.delete('/api/notifications/mutes/<int:mute_id>')
    @login_required
    def api_notification_unmute(mute_id):
        gone = notifications.unmute(conn(), mute_id)
        core.audit(conn(), actor(), 'notification.unmute', 'ok' if gone else 'denied', None, {'mute': mute_id})
        return (jsonify(ok=True), 200) if gone else (jsonify(error='no such mute'), 404)
