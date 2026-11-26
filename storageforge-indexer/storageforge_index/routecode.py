"""Sensitive routes that move (roadmap section 14, "Layers").

A request that changes keys, bindings, the key enclave, deploys, consoles, host access or security keys carries a code that changes
every 30 seconds. The code is made from a secret of the one session, the method, the route and the half minute:

    code = first 8 hex digits of HMAC-SHA256(route key, "METHOD /api/route|" + floor(time / 30))

and it rides in the path, as a 2FA code does: POST /api/keys is sent as POST /api/~1a2b3c4d/keys. The server takes the code out of the
path before anything routes, so every rule that names a route still names it. A URL that was recorded, or guessed, is dead half a
minute later, and a code for one route is no code for another.

The route key is given to a browser once, in the answer to its sign-in, and kept in that browser. A session that asked for it at
sign-in (the sign-in page does) must send the code from then on: the mark is in the signed session cookie and cannot be taken off.
A browser that lost its key gets it again from POST /api/routecode, which takes the password in its body (a recent sign-in is not enough, and
wrong passwords are limited the way POST /api/reauth limits them). So a session cookie alone, copied to
another machine, changes nothing on a sensitive route: it has no route key, and getting one takes the password.

What it is worth: it binds a sensitive request to a live session, a browser that holds that session's key, and a moment, on top of
the cookie, the same-origin check and the fresh-password rule. What it is not: a defence against someone who runs code in the page
or in the web app, who can read the key or skip the check. A client that signs in without asking (a script using the API) is not
asked for codes: for it nothing changes.

The server's clock is the one that counts: sign-in and every refusal say what time it is, and the browser keeps the difference.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time

from flask import jsonify, request, session
from flask_login import current_user, login_required

from . import users

WINDOW = 30
SENSITIVE = re.compile(r'/api/(keys|bindings|enclave|deploy|console|access|security/webauthn)(/.*)?')
RIDES = re.compile(r'/api/~([0-9a-f]{8})(/.*)')
ENV = 'storageforge.route_code'


def key_for(master: str, sid, login_at) -> str:
    """The route key of one session: from the server's session secret and what only that session has."""
    return hmac.new(master.encode(), f'storageforge:route\0{sid}\0{login_at}'.encode(), hashlib.sha256).hexdigest()


def code(key: str, method: str, path: str, window: int) -> str:
    return hmac.new(bytes.fromhex(key), f'{method.upper()} {path}|{window}'.encode(), hashlib.sha256).hexdigest()[:8]


def good(key: str, method: str, path: str, given: str, now: float | None = None) -> bool:
    """This half minute, or the one before or after: a request in flight as the half minute turns is not refused."""
    window = int((time.time() if now is None else now) // WINDOW)
    return any(hmac.compare_digest(code(key, method, path, w), given or '') for w in (window - 1, window, window + 1))


def sensitive(method: str, path: str) -> bool:
    return method not in ('GET', 'HEAD', 'OPTIONS') and bool(SENSITIVE.fullmatch(path))


def issued(master: str, sess) -> dict:
    """What a browser is given: its session's route key, and the server's time."""
    return {'route_key': key_for(master, sess.get('sid'), sess.get('login_at')), 'now': time.time()}


class _OutOfThePath:
    """The code is taken out of the path before anything routes, and kept beside the request."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        m = RIDES.fullmatch(environ.get('PATH_INFO') or '')
        if m:
            environ[ENV], environ['PATH_INFO'] = m[1], '/api' + m[2]
        return self.app(environ, start_response)


def register(web, ctx, master: str) -> None:
    core, conn, actor, json_body, limiter = ctx.core, ctx.conn, ctx.actor, ctx.json_body, ctx.limiter
    web.wsgi_app = _OutOfThePath(web.wsgi_app)

    @web.before_request
    def the_code_of_the_moment():
        if not session.get('rc') or not sensitive(request.method, request.path) or not current_user.is_authenticated:
            return None
        given = request.environ.get(ENV) or request.headers.get('X-SF-Code', '')
        if given and good(key_for(master, session.get('sid'), session.get('login_at')), request.method, request.path, given):
            return None
        return jsonify(error='this request needs the code of the moment, which this browser makes from its route key: reload the page, or sign in again',
                       routecode=True, now=time.time()), 403

    @web.post('/api/routecode')
    @login_required
    @limiter.limit(ctx.login_limit_user, key_func=lambda: f'routecode:{current_user.get_id()}',
                   deduct_when=lambda resp: resp.status_code == 403, error_message='too many wrong passwords; try again later')
    def api_routecode():
        """The route key again, for a browser that lost it: the request carries the password, which is checked here every time. A cookie
        that was copied, even one whose owner typed the password a minute ago, cannot ask without it."""
        ok = users.confirm(conn(), current_user.user_id, str(json_body().get('password', '')))
        if not ok:
            core.audit(conn(), actor(), 'web.routecode', 'denied', None, {})
            return jsonify(error='wrong password'), 403     # not 401: the session itself is still good
        session['rc'] = 1
        core.audit(conn(), actor(), 'web.routecode', 'ok', None, {})
        return jsonify(issued(master, session))
