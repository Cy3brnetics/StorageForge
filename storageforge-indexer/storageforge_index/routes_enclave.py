"""Web routes: the key enclave (roadmap section 14; enclave.py, enclave_start.py). Reading its state takes keys.view. Unlocking and
locking it take keys.manage and a fresh password, and go in the audit log. The vault secret a person types crosses this process once,
on its way in, and is checked nowhere but inside the enclave."""
from __future__ import annotations

from flask import jsonify
from flask_login import current_user, login_required

from . import enclave, enclave_start
from .vault import VaultError, VaultLocked

UNLOCK_LIMIT = '6 per minute'          # the enclave's own limit is the same, and it is the one that cannot be raised


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed, limiter = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed, ctx.limiter

    @web.get('/api/enclave')
    @login_required
    def api_enclave():
        return jsonify(enclave.describe())

    @web.post('/api/enclave/unlock')
    @login_required
    @password_confirmed
    @limiter.limit(UNLOCK_LIMIT, key_func=lambda: f'enclave-unlock:{current_user.get_id()}')
    def api_enclave_unlock():
        secret = str(json_body().get('secret') or '')
        try:
            state = enclave_start.typed(db, conn(), secret)
        except VaultLocked as exc:
            core.audit(conn(), actor(), 'enclave.unlock', 'denied', None, {'why': str(exc)[:200]})
            return jsonify(error=str(exc)), 403
        except VaultError as exc:
            core.audit(conn(), actor(), 'enclave.unlock', 'failed', None, {'why': str(exc)[:200]})
            return jsonify(error=str(exc)), 400
        finally:
            del secret
        core.audit(conn(), actor(), 'enclave.unlock', 'ok', None, {'state': state, 'by': 'typed'})
        core.alerts_wake.set()
        return jsonify(enclave.describe())

    @web.post('/api/enclave/lock')
    @login_required
    @password_confirmed
    def api_enclave_lock():
        json_body()
        try:
            address = enclave.configured()
        except enclave.EnclaveError as exc:
            return jsonify(error=str(exc)), 409
        if not address:
            return jsonify(error='this installation has no key enclave'), 400
        # written before it locks, while the entry can still be keyed: what follows a lock is chained without the key
        core.audit(conn(), actor(), 'enclave.lock', 'ok', None, {})
        try:
            with enclave.Enclave(address) as e:
                e.lock()
        except enclave.EnclaveError as exc:
            core.audit(conn(), actor(), 'enclave.lock', 'failed', None, {'why': str(exc)[:200]})
            return jsonify(error=str(exc)), 409
        core.alerts_wake.set()
        return jsonify(enclave.describe())
