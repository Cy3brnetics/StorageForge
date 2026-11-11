"""Web routes: accounts, invite links and roles. See permissions.py for who may reach them."""
from __future__ import annotations

import time

from flask import Response, abort, jsonify, request
from flask_login import current_user, login_required

from . import permissions, users


def register(web, ctx):
    core, db, limiter, conn, actor, need, json_body, arg_num = ctx.core, ctx.db, ctx.limiter, ctx.conn, ctx.actor, ctx.need, ctx.json_body, ctx.arg_num
    password_stale, password_confirmed, need_for_commands, may_hand_out = ctx.password_stale, ctx.password_confirmed, ctx.need_for_commands, ctx.may_hand_out

    def account_rows():
        return jsonify(users=[dict(zip(('username', 'created_at', 'last_login_at', 'disabled_at', 'role'), r)) for r in users.listing(conn())])

    # Reading the account and invite lists needs no fresh password: opening Audit asked for one, and Cancel still showed
    # the panel, so the prompt guarded nothing. Every change to an account or invite still asks.
    @web.route('/api/users', methods=['GET', 'POST'])
    @login_required
    def api_users():
        if request.method == 'POST':
            stale = password_stale()
            if stale:
                return stale
            body = json_body()
            name, role = str(body.get('username') or ''), str(body.get('role') or 'viewer')
            may_hand_out(role)
            users.create(conn(), name, str(body.get('password') or ''), role)
            core.audit(conn(), actor(), 'user.add', 'ok', None, {'username': name, 'role': role})
        return account_rows()

    @web.route('/api/users/<name>', methods=['PUT', 'DELETE'])
    @login_required
    @password_confirmed
    def api_user(name):
        may_hand_out(users.role_of(conn(), name) or '')
        if request.method == 'DELETE':
            users.keep_an_admin(conn(), name)
            users.remove(conn(), name)
            core.audit(conn(), actor(), 'user.remove', 'ok', None, {'username': name})
            return jsonify(removed=name)
        body = json_body()
        if 'role' in body:
            may_hand_out(str(body['role']))
        if ('role' in body and body['role'] != 'admin') or body.get('disabled'):
            users.keep_an_admin(conn(), name)
        if 'role' in body:
            users.set_role(conn(), name, str(body['role']))
        if 'disabled' in body:
            users.set_disabled(conn(), name, bool(body['disabled']))
        core.audit(conn(), actor(), 'user.update', 'ok', None, {'username': name, **{k: body[k] for k in ('role', 'disabled') if k in body}})
        return account_rows()

    @web.post('/api/users/<name>/reset-link')
    @login_required
    @password_confirmed
    def api_user_reset(name):
        may_hand_out(users.role_of(conn(), name) or '')
        invite_id, token = users.create_reset(conn(), name, current_user.username)
        core.audit(conn(), actor(), 'user.reset-link', 'ok', None, {'username': name, 'invite': invite_id})
        return jsonify(id=invite_id, token=token)

    @web.route('/api/invites', methods=['GET', 'POST'])
    @login_required
    def api_invites():
        if request.method == 'GET':
            return jsonify(invites=users.list_invites(conn()), now=int(time.time()))
        stale = password_stale()
        if stale:
            return stale
        body = json_body()
        role = str(body.get('role') or '')
        may_hand_out(role)
        try:
            hours = int(body.get('hours') or users.INVITE_HOURS)
        except (TypeError, ValueError):
            raise ValueError('hours must be a number') from None
        invite_id, token = users.create_invite(conn(), role, current_user.username, hours, str(body.get('note') or ''))
        core.audit(conn(), actor(), 'invite.create', 'ok', None, {'invite': invite_id, 'role': role, 'hours': hours})
        return jsonify(id=invite_id, token=token)

    @web.delete('/api/invites/<int:invite_id>')
    @login_required
    @password_confirmed
    def api_invite_revoke(invite_id):
        may_hand_out(users.invite_role(conn(), invite_id) or '')
        users.revoke_invite(conn(), invite_id)
        core.audit(conn(), actor(), 'invite.revoke', 'ok', None, {'invite': invite_id})
        return jsonify(revoked=invite_id)

    @web.route('/api/roles', methods=['GET', 'POST'])
    @login_required
    def api_roles():
        if request.method == 'POST':
            stale = password_stale()
            if stale:
                return stale
            save_role(str(json_body().get('name') or ''), new=True)
        catalog = [dict(group=g, permissions=[dict(name=n, text=t, high_risk=r) for n, t, r in ps]) for g, ps in permissions.CATALOG]
        return jsonify(roles=users.list_roles(conn()), catalog=catalog)

    def save_role(name: str, new: bool):
        body = json_body()
        wanted = body.get('permissions')
        if isinstance(wanted, list) and not ({str(p) for p in wanted} & permissions.ALL) <= current_user.permissions:
            abort(403, description='a role cannot allow what your account cannot do')
        if not new:
            may_hand_out(name)
        users.save_role(conn(), name, str(body.get('description') or ''), wanted, current_user.username, new)
        core.audit(conn(), actor(), 'role.add' if new else 'role.update', 'ok', None, {'role': name, 'permissions': wanted})

    @web.route('/api/roles/<name>', methods=['PUT', 'DELETE'])
    @login_required
    @password_confirmed
    def api_role(name):
        if request.method == 'PUT':
            save_role(name, new=False)
            return jsonify(saved=name)
        may_hand_out(name)
        users.remove_role(conn(), name)
        core.audit(conn(), actor(), 'role.remove', 'ok', None, {'role': name})
        return jsonify(removed=name)

    # links for people without an account: bad tokens count like failed sign-ins
    def bad_link(resp: Response) -> bool:
        return resp.status_code == 403

    @web.post('/api/enroll/check')
    @limiter.limit(ctx.login_limit, deduct_when=bad_link, error_message='too many tries; try again later')
    def api_enroll_check():
        invite = users.open_invite(conn(), str(json_body().get('token') or ''))
        if not invite:
            return jsonify(error='this link is not valid: it may have expired or been used'), 403
        return jsonify(invite)

    @web.post('/api/enroll')
    @limiter.limit(ctx.login_limit, deduct_when=bad_link, error_message='too many tries; try again later')
    def api_enroll():
        body = json_body()
        try:
            done = users.enroll(conn(), str(body.get('token') or ''), str(body.get('username') or '').strip(), str(body.get('password') or ''))
        except users.InviteError as exc:
            core.audit(conn(), f'web:{request.remote_addr}', 'user.enroll', 'denied', None, {})
            return jsonify(error=str(exc)), 403
        core.audit(conn(), f'web:{request.remote_addr}', 'user.reset' if done['reset'] else 'user.enroll', 'ok', None, done)
        return jsonify(done)
