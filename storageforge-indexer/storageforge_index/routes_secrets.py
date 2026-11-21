"""Web routes: the secret store (secretstore.py), under Keys. Listing and a rotation's dry run take keys.view and give no value.
Making a secret, rotating it and removing it take keys.manage and a fresh password, and each is in the audit log; rotating also takes
deploy.apply, since it is a signed run as root on every host the secret went to. A value leaves the server twice only: in the answer to
the request that made it, and in the answer to the rotation that replaced it."""
from __future__ import annotations

from flask import jsonify
from flask_login import login_required

from . import enclave, secretstore
from .vault import Vault, VaultError


def _policy(body: dict) -> dict | None:
    def names(key):
        v = body.get(key) or []
        if isinstance(v, str):
            v = [w for w in v.replace(',', ' ').split() if w]
        if not isinstance(v, list) or not all(isinstance(w, str) for w in v):
            raise secretstore.SecretError(f'{key} is a list of names')
        return v
    steps, hosts, platforms = names('steps'), names('hosts'), names('platforms')
    if not (steps or hosts or platforms or body.get('sensitive')):
        return None
    return {'steps': steps, 'hosts': hosts, 'platforms': platforms, 'sensitive': bool(body.get('sensitive'))}


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed, need = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed, ctx.need

    @web.get('/api/keys/secrets')
    @login_required
    def api_secrets():
        return jsonify(secrets=secretstore.listing(conn()), kinds=secretstore.kinds(), enclave=bool(enclave.configured()))

    @web.post('/api/keys/secrets')
    @login_required
    @password_confirmed
    def api_secret_make():
        """The value is in this answer and in no other: not the list, not the audit log, not a later request."""
        body = json_body()
        try:
            policy = _policy(body)
            with Vault(db, conn()).unlock() as v:
                row, value = secretstore.make(v, conn(), str(body.get('name') or ''), str(body.get('kind') or 'password'), body.get('length'), policy)
        except (secretstore.SecretError, VaultError) as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'secret.generate', 'ok', None, {'name': row['name'], 'kind': row['kind'], 'length': row['length'], 'policy': row['policy']})
        resp = jsonify(secret=row, value=value)
        del value
        resp.headers['Cache-Control'] = 'no-store'
        return resp, 201

    @web.get('/api/keys/secrets/<name>/rotate')
    @login_required
    def api_secret_rotate_plan(name):
        try:
            return jsonify(secretstore.rotate_plan(conn(), name))
        except LookupError as exc:
            return jsonify(error=exc.args[0]), 404

    @web.post('/api/keys/secrets/<name>/rotate')
    @login_required
    @password_confirmed
    def api_secret_rotate(name):
        need('deploy.apply')            # a signed run as root on each host it went to
        json_body()
        try:
            with Vault(db, conn()).unlock() as v:
                got = secretstore.rotate(db, conn(), v, name, actor())
        except LookupError as exc:
            return jsonify(error=exc.args[0]), 404
        except (secretstore.SecretError, VaultError) as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'secret.rotate', 'ok' if got['rotated'] else 'failed', None,
                   {'name': name, 'hosts': [r['host'] for r in got.get('results', [])], 'why': got['why'][:200]})
        resp = jsonify(got if got['rotated'] else {**got, 'error': f'not rotated: {got["why"]}'})
        got.pop('value', None)
        resp.headers['Cache-Control'] = 'no-store'
        return resp, 200 if got['rotated'] else 409

    @web.delete('/api/keys/secrets/<name>')
    @login_required
    @password_confirmed
    def api_secret_remove(name):
        n = secretstore.remove(conn(), name)
        core.audit(conn(), actor(), 'secret.remove', 'ok' if n else 'failed', None, {'name': name})
        return (jsonify(ok=True), 200) if n else (jsonify(error=f'no secret named {name}'), 404)
