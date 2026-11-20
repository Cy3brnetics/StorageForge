"""Web routes: the key enclave (roadmap section 14; enclave.py, enclave_start.py, enclave_stepup.py). Reading its state takes keys.view.
Unlocking and locking it take keys.manage and a fresh password, and go in the audit log. The vault secret a person types crosses this
process once, on its way in, and is checked nowhere but inside the enclave.

Step-up: what the enclave wants a person's own proof for answers 403 with `stepup: true`. The page then asks for the password (or a
security key) and posts it to /api/enclave/stepup; the enclave checks it and gives a token, which is kept here for that session, never
in the cookie, and goes with what the session asks next. It runs out by itself after five minutes."""
from __future__ import annotations

import time

from flask import jsonify, request, session
from flask_login import current_user, login_required

from . import enclave, enclave_start, enclave_stepup, users, vault
from .vault import StepUpNeeded, VaultError, VaultLocked

UNLOCK_LIMIT = '6 per minute'          # the enclave's own limit is the same, and it is the one that cannot be raised
STEPUP_LIMIT = '5 per minute'


def follow_password(conn, core, actor: str, username: str, old: str, new: str) -> None:
    """An account's password changed. Where that person has a step-up record, the enclave is given the new one, on the proof of the
    old: otherwise the password it checks would stay the one from before. Best effort, and said in the audit log either way."""
    address = enclave.address()
    if not address or enclave_stepup.record_of(conn, username) is None:
        return
    try:
        token = enclave_stepup.check(conn, address, username, password=old)['token']
        enclave_stepup.enroll(conn, address, username, new, token=token)
        core.audit(conn, actor, 'enclave.stepup.enroll', 'ok', None, {'user': username, 'why': 'password changed'})
    except enclave.EnclaveError as exc:
        core.audit(conn, actor, 'enclave.stepup.enroll', 'failed', None, {'user': username, 'why': f'password changed: {exc.code}'})


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed, limiter = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed, ctx.limiter

    tokens: dict = {}          # session id → (the enclave's token for it, when it runs out here)

    def session_token() -> str | None:
        sid = session.get('sid')
        got = tokens.get(sid)
        if got and got[1] > time.time():
            return got[0]
        tokens.pop(sid, None)
        return None

    @web.before_request
    def present_enclave_token():
        vault.present_token(session_token() if tokens else None)

    @web.teardown_request
    def forget_enclave_token(_exc):
        vault.present_token(None)

    @web.errorhandler(StepUpNeeded)
    def on_stepup(exc):
        return jsonify(error=str(exc), stepup=True), 403

    def described() -> dict:
        out = enclave.describe()
        if out['on']:
            people = enclave_stepup.enrolled(conn())
            mine = next((p for p in people if p['username'] == current_user.username), None)
            out['stepup'] = {**(out.get('stepup') or {}), 'people': len(people), 'enrolled': mine is not None, 'security_keys': mine['security_keys'] if mine else 0,
                             'stale_keys': enclave_stepup.stale_keys(conn(), current_user.username), 'fresh': session_token() is not None}
        return out

    def rp():          # as routes_secplus.py names this site to a FIDO2 token
        return request.host.split(':')[0].strip('[]'), request.host_url.rstrip('/')

    @web.get('/api/enclave')
    @login_required
    def api_enclave():
        return jsonify(described())

    @web.post('/api/enclave/stepup/begin')
    @login_required
    def api_enclave_stepup_begin():
        json_body()
        address = enclave.address()
        keys = enclave_stepup.fido_keys(conn(), current_user.username)
        if not address or not keys or enclave_stepup.record_of(conn(), current_user.username) is None:
            return jsonify(error='no security key of yours is enrolled with the key enclave'), 409
        try:
            with enclave.Enclave(address) as e:
                challenge = e.challenge()
        except enclave.EnclaveError as exc:
            return jsonify(error=str(exc)), 429 if exc.code == 'rate' else 409
        core.audit(conn(), actor(), 'enclave.stepup.ask', 'ok', None, {})
        return jsonify(challenge=challenge, rpId=rp()[0], timeout=60000, userVerification='discouraged', allowCredentials=[{'type': 'public-key', 'id': k['id']} for k in keys])

    @web.post('/api/enclave/stepup')
    @login_required
    @limiter.limit(STEPUP_LIMIT, key_func=lambda: f'enclave-stepup:{current_user.get_id()}', deduct_when=lambda resp: resp.status_code == 403,
                   error_message='too many step-up attempts; try again later')
    def api_enclave_stepup():
        body = json_body()
        address = enclave.address()
        if not address:
            return jsonify(error='this installation has no key enclave'), 400
        password, fido = body.get('password'), body.get('fido')
        if isinstance(fido, dict):          # as the browser sends an assertion; the enclave takes the bytes as base64
            try:
                fido = {'id': str(fido['id']), **{to: enclave.b64_of_url(str(fido[frm])) for to, frm in (('authenticator_data', 'authenticatorData'), ('client_data', 'clientDataJSON'), ('signature', 'signature'))}}
            except (KeyError, ValueError):
                raise ValueError('a security key answer has id, authenticatorData, clientDataJSON and signature') from None
        elif not isinstance(password, str) or not password:
            raise ValueError('a step-up is a password or a security key')
        try:
            got = enclave_stepup.check(conn(), address, current_user.username, password=None if isinstance(fido, dict) else password, fido=fido if isinstance(fido, dict) else None)
        except enclave.EnclaveError as exc:
            core.audit(conn(), actor(), 'enclave.stepup', 'denied', None, {'why': exc.code})
            if exc.code == 'rate':
                return jsonify(error=str(exc)), 429
            return jsonify(error=str(exc), enroll=exc.code == 'stepup'), 403
        tokens[session.get('sid')] = (got['token'], time.time() + max(1, int(got['seconds']) - 2))
        for sid in [k for k, (_, until) in tokens.items() if until <= time.time()]:
            tokens.pop(sid, None)
        core.audit(conn(), actor(), 'enclave.stepup', 'ok', None, {'by': 'security key' if isinstance(fido, dict) else 'password'})
        return jsonify(ok=True, seconds=got['seconds'])

    @web.post('/api/enclave/stepup/enroll')
    @login_required
    @password_confirmed
    @limiter.limit(STEPUP_LIMIT, key_func=lambda: f'enclave-enroll:{current_user.get_id()}')
    def api_enclave_stepup_enroll():
        body = json_body()
        address = enclave.address()
        if not address:
            return jsonify(error='this installation has no key enclave'), 400
        password, secret = str(body.get('password') or ''), str(body.get('secret') or '').strip()
        if not users.confirm(conn(), current_user.user_id, password):          # the enclave is given this account's own password, not another
            core.audit(conn(), actor(), 'enclave.stepup.enroll', 'denied', None, {'why': 'not the account password'})
            return jsonify(error='that is not your account password'), 403
        host, origin = rp()
        try:
            meta = vault.Vault(db, conn())._meta() if secret else None
            got = enclave_stepup.enroll(conn(), address, current_user.username, password, host, origin, token=session_token(), secret=secret.encode() if secret else None, meta=meta)
        except enclave.EnclaveError as exc:
            core.audit(conn(), actor(), 'enclave.stepup.enroll', 'denied', None, {'why': exc.code})
            if exc.code == 'stepup':          # someone is enrolled already: a step-up of yours, or the vault secret, vouches for a new record
                return jsonify(error=str(exc), stepup=True), 403
            return jsonify(error=str(exc)), 429 if exc.code == 'rate' else 409
        finally:
            del secret
        core.audit(conn(), actor(), 'enclave.stepup.enroll', 'ok', None, {'user': current_user.username, 'security_keys': got['security_keys'], 'replaced': got['replaced']})
        return jsonify(described())

    @web.post('/api/enclave/unlock')
    @login_required
    @password_confirmed
    @limiter.limit(UNLOCK_LIMIT, key_func=lambda: f'enclave-unlock:{current_user.get_id()}')
    def api_enclave_unlock():
        body = json_body()
        secret, proof = str(body.get('secret') or ''), None
        record = enclave_stepup.record_of(conn(), current_user.username) if enclave.address() else None
        if record is not None and body.get('password'):          # this person's own proof, which lifting a lock-down takes once step-up is on
            proof = {'user': current_user.username, 'record': record, 'password': str(body['password'])}
        try:
            state = enclave_start.typed(db, conn(), secret, proof)
        except StepUpNeeded as exc:
            core.audit(conn(), actor(), 'enclave.unlock', 'denied', None, {'why': 'step-up'})
            return jsonify(error=str(exc), password=True), 403
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

    @web.post('/api/enclave/chain/accept')
    @login_required
    @password_confirmed
    def api_enclave_chain_accept():
        """The audit log no longer ends where the enclave last signed it, and a person who has looked at why takes it as it is now.
        Said in the log first, so the entry that says who accepted it is the one the enclave is then set to."""
        json_body()
        address = enclave.address()
        if not address:
            return jsonify(error='this installation has no key enclave'), 400
        log = vault.AuditLog(db, conn(), vault.EnclaveMacKey(address))
        before = log.head_check()
        core.audit(conn(), actor(), 'audit.head.accept', 'ok', None, {'was': before.get('why')})
        try:
            log.accept_head(session_token())
        except StepUpNeeded:
            raise
        except VaultError as exc:
            return jsonify(error=str(exc)), 409
        core.alerts_wake.set()
        return jsonify(head=log.head_check())

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
