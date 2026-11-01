"""Web routes: the Git Inspector. Each runs git on a host, so each is POST, limited and audited."""
from __future__ import annotations

from flask import jsonify
from flask_login import current_user, login_required

from . import deploy, gitrepos

GIT_LIMIT = '60 per minute'         # each call unlocks the vault and opens SSH


def register(web, ctx):
    core, db, limiter, conn, actor, need, json_body, arg_num = ctx.core, ctx.db, ctx.limiter, ctx.conn, ctx.actor, ctx.need, ctx.json_body, ctx.arg_num
    password_stale, password_confirmed, need_for_commands, may_hand_out = ctx.password_stale, ctx.password_confirmed, ctx.need_for_commands, ctx.may_hand_out

    def git_args(*names) -> list[str]:
        """From a JSON body: these run commands on hosts, so no GET can start one."""
        body = json_body()
        vals = [str(body.get(n) or '') for n in names]
        if not all(vals):
            raise ValueError(' and '.join(names) + ' are required')
        return vals

    def git_call(what: str, host: str, path: str, work, **detail):
        """Every Git route: one audit row whatever happened, and an audit that fails stops the answer."""
        try:
            res = work()
            outcome, code = ('ok' if res.get('ok', True) else 'failed'), 200
        except deploy.DeployError as exc:
            res, outcome, code = {'error': str(exc)}, 'failed', 409
        except ValueError as exc:
            res, outcome, code = {'error': str(exc)}, 'failed', 400
        except LookupError as exc:
            res, outcome, code = {'error': str(exc)}, 'denied', 404
        except Exception as exc:
            res, outcome, code = {'error': str(exc)}, 'failed', 502
        core.audit(conn(), actor(), what, outcome, host, {'path': path[:500], **detail})
        return jsonify(res), code

    def git_limit():
        return f'git:{current_user.get_id()}'

    @web.post('/api/git/status')
    @login_required
    @limiter.limit(GIT_LIMIT, key_func=git_limit)
    def api_git_status():
        host, path = git_args('host', 'path')
        return git_call('git.status', host, path, lambda: gitrepos.repo_status(db, host, path, actor()))

    @web.post('/api/git/sync')
    @login_required
    @password_confirmed
    @limiter.limit(GIT_LIMIT, key_func=git_limit)
    def api_git_sync():
        host, path = git_args('host', 'path')
        action = str(json_body().get('action') or 'sync')
        return git_call('git.sync', host, path, lambda: gitrepos.repo_sync(db, host, path, action, actor()), action=action[:20])

    @web.post('/api/git/history')
    @login_required
    @limiter.limit(GIT_LIMIT, key_func=git_limit)
    def api_git_history():
        host, path = git_args('host', 'path')
        try:
            most = max(1, min(int(json_body().get('max') or 50), 200))
        except (TypeError, ValueError):
            most = 50
        return git_call('git.history', host, path, lambda: gitrepos.repo_history(db, host, path, most))

    @web.post('/api/git/commit')
    @login_required
    @limiter.limit(GIT_LIMIT, key_func=git_limit)
    def api_git_commit():
        host, path, sha = git_args('host', 'path', 'sha')
        return git_call('git.commit', host, path, lambda: gitrepos.repo_commit(db, host, path, sha), sha=sha[:64])
