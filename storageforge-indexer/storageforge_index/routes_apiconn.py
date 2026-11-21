"""Web routes: platform API connections (apiconn.py), under Keys. Listing, the guide and a certificate fetch take keys.view; adding,
accepting a certificate, turning an action on, reading and removing take keys.manage, and each is in the audit log. Adding, accepting
a certificate, turning an action on and removing also take a fresh password.

The token's secret comes in once, in the request that adds the connection (or replaces its token), and goes straight into the vault:
no answer, audit row or error message holds it."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import apiconn, apiguide, apiread
from .vault import Vault, VaultError


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def found(conn_id):
        row = apiconn.get(conn(), conn_id)
        if not row:
            raise LookupError('no such connection')
        return row

    @web.get('/api/keys/platforms')
    @login_required
    def api_platforms():
        return jsonify(connections=apiconn.listing(conn()), kinds=apiguide.kinds())

    @web.get('/api/keys/platforms/guide/<kind>')
    @login_required
    def api_platform_guide(kind):
        try:
            return jsonify(apiguide.guide(kind, user=request.args.get('user') or 'storageforge', token=request.args.get('token') or 'storageforge',
                                          scope=request.args.get('scope') or None))
        except apiguide.GuideError as exc:
            return jsonify(error=str(exc)), 400

    @web.get('/api/keys/platforms/guide/<kind>/<action>')
    @login_required
    def api_platform_action_guide(kind, action):
        try:
            return jsonify(steps=apiguide.action_steps(kind, action))
        except apiguide.GuideError as exc:
            return jsonify(error=str(exc)), 400

    @web.post('/api/keys/platforms')
    @login_required
    @password_confirmed
    def api_platform_add():
        """Stores the token and sends it nowhere: the answer carries the certificate the server presents, for a person to compare."""
        body = json_body()
        secret = body.pop('token', None)
        try:
            with Vault(db, conn()).unlock() as v:
                row = apiconn.add(v, conn(), str(body.get('kind') or ''), str(body.get('name') or ''), str(body.get('url') or ''),
                                  str(body.get('token_id') or ''), secret if isinstance(secret, str) else '', actor(), body.get('host') or None)
        except (apiconn.ConnError, VaultError) as exc:
            return jsonify(error=str(exc)), 400
        finally:
            secret = None
        core.audit(conn(), actor(), 'platform.add', 'ok', row['host'], {'name': row['name'], 'kind': row['kind'], 'url': row['base_url'], 'token_id': row['token_id']})
        try:
            cert, why = apiconn.offered(row['base_url']), ''
        except apiconn.ApiError as exc:
            cert, why = None, str(exc)
        resp = jsonify(connection=row, certificate=cert, certificate_error=why)
        resp.headers['Cache-Control'] = 'no-store'
        return resp, 201

    @web.get('/api/keys/platforms/<int:conn_id>/certificate')
    @login_required
    def api_platform_certificate(conn_id):
        row = found(conn_id)
        try:
            return jsonify(certificate=apiconn.offered(row['base_url']), pinned=row['cert_sha256'], file=apiconn.KINDS[row['kind']]['cert_file'])
        except apiconn.ApiError as exc:
            return jsonify(error=str(exc)), 502

    @web.post('/api/keys/platforms/<int:conn_id>/certificate')
    @login_required
    @password_confirmed
    def api_platform_pin(conn_id):
        row = found(conn_id)
        body = json_body()
        try:
            got = apiconn.pin(conn(), conn_id, str(body.get('sha256') or ''), actor())
        except apiconn.ConnError as exc:
            core.audit(conn(), actor(), 'platform.certificate', 'failed', row['host'], {'name': row['name'], 'why': str(exc)[:200]})
            return jsonify(error=str(exc)), 409
        except apiconn.ApiError as exc:
            return jsonify(error=str(exc)), 502
        core.audit(conn(), actor(), 'platform.certificate', 'ok', row['host'], {'name': row['name'], 'sha256': got['cert_sha256'], 'was': row['cert_sha256']})
        return jsonify(connection=got)

    @web.put('/api/keys/platforms/<int:conn_id>/actions')
    @login_required
    @password_confirmed
    def api_platform_actions(conn_id):
        """Turning an action on says what it needs on the platform, now and not before; the read-back checks the token has it."""
        row = found(conn_id)
        body = json_body()
        try:
            got = apiconn.set_actions(conn(), conn_id, body.get('actions') or [])
        except apiconn.ConnError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'platform.actions', 'ok', row['host'], {'name': row['name'], 'actions': got['actions'], 'was': row['actions']})
        return jsonify(connection=got, needs={a: apiguide.action_steps(got['kind'], a) for a in got['actions']})

    @web.get('/api/keys/platforms/<int:conn_id>')
    @login_required
    def api_platform(conn_id):
        row = found(conn_id)
        return jsonify(connection=row, objects=apiread.objects(conn(), conn_id))

    @web.post('/api/keys/platforms/<int:conn_id>/read')
    @login_required
    def api_platform_read(conn_id):
        """The read-back of what the token can do, then everything the platform's reader takes. Changes nothing on the platform."""
        row = found(conn_id)
        json_body()
        try:
            got = apiread.read(db, conn(), row)
        except apiconn.ApiError as exc:
            core.audit(conn(), actor(), 'platform.read', 'failed', row['host'], {'name': row['name'], 'why': str(exc)[:200]})
            return jsonify(error=str(exc), connection=apiconn.get(conn(), conn_id)), 502
        except VaultError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'platform.read', 'ok', row['host'], {'name': row['name'], 'verdict': got['readback']['verdict'], 'counts': got['counts']})
        return jsonify(connection=apiconn.get(conn(), conn_id), **got)

    @web.delete('/api/keys/platforms/<int:conn_id>')
    @login_required
    @password_confirmed
    def api_platform_remove(conn_id):
        row = apiconn.remove(conn(), conn_id)
        if not row:
            return jsonify(error='no such connection'), 404
        core.audit(conn(), actor(), 'platform.remove', 'ok', row['host'], {'name': row['name'], 'kind': row['kind'], 'token_id': row['token_id']})
        return jsonify(ok=True, note=f'The token {row["token_id"]} still works on the platform until it is deleted there.')
