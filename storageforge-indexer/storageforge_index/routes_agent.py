"""Web routes: the optional agent (sfagent.py, docs/agent.md). Reading takes keys.view. Everything else takes keys.manage and a fresh
password, because enrolling an agent pins a key and gives a host a new way to speak to the controller: switching the agent on for
a host, setting it up there, starting and stopping it, and removing it. Each is in the audit log.

Nothing here is a GET that reaches a host: asking a host for its agent's status is a POST."""
from __future__ import annotations

from flask import jsonify
from flask_login import login_required

from . import deploy, sfagent


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def refused(exc):
        return jsonify(error=str(exc), code=getattr(exc, 'code', None)), 404 if isinstance(exc, LookupError) else 409

    @web.get('/api/agents')
    @login_required
    def api_agents():
        image = None
        try:
            image = sfagent.agent_image()
        except sfagent.AgentError:
            pass
        return jsonify(agents=sfagent.view(conn()), image=image, manager=sfagent.MANAGER, agent_user=sfagent.AGENT_USER)

    @web.put('/api/agents/<host>')
    @login_required
    @password_confirmed
    def api_agent_switch(host):
        on = json_body().get('enabled') is True
        try:
            got = sfagent.switch(conn(), host, on, actor())
        except (LookupError, sfagent.AgentError) as exc:
            return refused(exc)
        core.audit(conn(), actor(), 'agent.switch', 'ok', got['host'], {'enabled': on})
        return jsonify(got | {'public_key': None, 'hint': sfagent.runtime_hint(conn(), got['host']) if on else None})

    @web.post('/api/agents/<host>/install')
    @login_required
    @password_confirmed
    def api_agent_install(host):
        b = json_body()
        name = deploy.canonical(conn(), host)
        row = sfagent.get(conn(), name)
        try:      # what can be refused without touching the host is refused here, where the answer is seen at once
            if not row or not row['enabled']:
                raise sfagent.AgentError(f'the agent is switched off for {name}: switch it on for this host first')
            if not deploy.ready(conn(), name):
                raise sfagent.AgentError(f'{name} has no deploy access yet, and the agent is set up through it: set up deploy access first')
            sfagent.agent_image()
            sfagent.image_signature()
            sfagent.agentctl_program(sfagent.host_arch(conn(), name))
        except sfagent.AgentError as exc:
            return refused(exc)
        gid = sfagent.start_install(db, name, actor(), install_podman=b.get('install_podman') is True, accept_new_key=b.get('accept_new_key') is True)
        return jsonify(host=name, group_id=gid), 202

    @web.post('/api/agents/<host>/<any("start", "stop", "restart", "status"):verb>')
    @login_required
    @password_confirmed
    def api_agent_lifecycle(host, verb):
        json_body()
        try:
            got = sfagent.lifecycle(db, host, verb, actor())
        except (LookupError, sfagent.AgentError) as exc:
            core.audit(conn(), actor(), f'agent.{verb}', 'failed', host, {'error': str(exc)[:300]})
            return refused(exc)
        if verb == 'status':
            core.audit(conn(), actor(), 'agent.status', 'ok', got['host'], {'running': got['running'], 'key_matches': got['key_matches']})
        return jsonify(got)

    @web.delete('/api/agents/<host>')
    @login_required
    @password_confirmed
    def api_agent_remove(host):
        try:
            return jsonify(sfagent.remove(db, host, actor()))
        except (LookupError, sfagent.AgentError) as exc:
            return refused(exc)
