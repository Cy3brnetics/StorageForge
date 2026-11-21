"""Web routes: the optional agent (sfagent.py, docs/agent.md). Reading takes keys.view. Everything else takes keys.manage and a fresh
password, because enrolling an agent pins a key and gives a host a new way to speak to the controller: switching the agent on for
a host, setting it up there, starting and stopping it, checking it from outside, choosing its plugins, and removing it. A plugin that
declares privileges on the host, a receiver key that changed, and enrolling an agent again where one was wiped (roadmap 11.3) need
agent.privilege as well. Each is in the audit log. What an agent reported is read
with hosts.view, every row labelled as the agent's claim.

Nothing here is a GET that reaches a host: asking a host for its agent's status is a POST."""
from __future__ import annotations

import json

from flask import jsonify, request
from flask_login import current_user, login_required

from . import agentaction, agentguard, agentwatch, deploy, sfagent


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
            if (row['state'] == 'wiped' or row.get('wiped_at')) and 'agent.privilege' not in current_user.permissions:
                # only an admin enrolls an agent again where one was wiped (roadmap 11.3)
                core.audit(conn(), actor(), 'agent.install', 'denied', name, {'after_wipe': True})
                return jsonify(error=f'the agent on {name} was wiped: enrolling one there again takes agent.privilege, which admins hold', code='privilege'), 403
            if not deploy.ready(conn(), name):
                raise sfagent.AgentError(f'{name} has no deploy access yet, and the agent is set up through it: set up deploy access first')
            sfagent.agent_image()
            sfagent.image_signature()
            sfagent.agentctl_program(sfagent.host_arch(conn(), name))
        except sfagent.AgentError as exc:
            return refused(exc)
        gid = sfagent.start_install(db, name, actor(), install_podman=b.get('install_podman') is True, accept_new_key=b.get('accept_new_key') is True)
        return jsonify(host=name, group_id=gid), 202

    @web.post('/api/agents/<host>/<any("start", "stop", "restart", "status", "check"):verb>')
    @login_required
    @password_confirmed
    def api_agent_lifecycle(host, verb):
        json_body()
        if verb == 'check':
            # the check from outside, now rather than on the timer; any finding wipes the agent (roadmap 11.3)
            got = agentguard.check(db, host, actor())
            core.audit(conn(), actor(), 'agent.check', 'ok' if got.get('checked') else 'failed', got['host'],
                       {'clean': got.get('clean'), 'findings': len(got.get('findings') or []), 'why': got.get('why')})
            return jsonify(got)
        try:
            got = sfagent.lifecycle(db, host, verb, actor())
        except (LookupError, sfagent.AgentError) as exc:
            core.audit(conn(), actor(), f'agent.{verb}', 'failed', host, {'error': str(exc)[:300]})
            return refused(exc)
        if verb == 'status':
            core.audit(conn(), actor(), 'agent.status', 'ok', got['host'], {'running': got['running'], 'key_matches': got['key_matches']})
        return jsonify(got)

    @web.get('/api/agents/<host>/records')
    @login_required
    def api_agent_records(host):
        """What the host's agent reported, each row labelled as its claim, and the receiver's own count of what came."""
        name = deploy.canonical(conn(), host)
        plugin = request.args.get('plugin') or None
        return jsonify(host=name, label=agentwatch.LABEL, peer=agentwatch.peer(conn(), name),
                       records=agentwatch.records(conn(), name, plugin=plugin, limit=request.args.get('limit', 100, type=int)),
                       actions=agentaction.recent(conn(), name, 20))

    @web.post('/api/agents/<host>/plugins')
    @login_required
    @password_confirmed
    def api_agent_plugins(host):
        """Which signed plugins of the release the host's agent runs. A plugin that declares any privilege (a mount, a capability, a
        device, the host's network or process table, a host group), and taking a receiver key that changed, need agent.privilege
        as well, which only admins hold: privilege needs a person (roadmap 11.2)."""
        b = json_body()
        names = b.get('plugins') if isinstance(b.get('plugins'), list) else []
        accept = b.get('accept_new_key') is True
        name = deploy.canonical(conn(), host)
        try:
            chosen = [sfagent.release_plugin(sfagent.host_arch(conn(), name), str(n)) for n in names[:32]]
        except (LookupError, sfagent.AgentError) as exc:
            return refused(exc)
        privileged = sorted(json.loads(d)['name'] for d, _s, _k in chosen if json.loads(d).get('needs'))
        if (privileged or accept) and 'agent.privilege' not in current_user.permissions:
            core.audit(conn(), actor(), 'agent.plugins', 'denied', name, {'privileged': privileged, 'accept_new_key': accept})
            why = (f'{", ".join(privileged)} declares privileges on the host' if privileged else 'taking a new receiver key') + ': that takes agent.privilege, which admins hold'
            return jsonify(error=why, code='privilege'), 403
        try:
            got = sfagent.apply(db, name, chosen, actor=actor(), accept_new_key=accept)
        except (LookupError, sfagent.AgentError) as exc:
            core.audit(conn(), actor(), 'agent.plugins', 'failed', name, {'plugins': names[:32], 'error': str(exc)[:300]})
            return refused(exc)
        core.audit(conn(), actor(), 'agent.plugins', 'ok', name, {'plugins': [json.loads(d)['name'] for d, _s, _k in chosen], 'privileged': privileged,
                                                                   'accept_new_key': accept})
        return jsonify(got)

    @web.delete('/api/agents/<host>')
    @login_required
    @password_confirmed
    def api_agent_remove(host):
        try:
            return jsonify(sfagent.remove(db, host, actor()))
        except (LookupError, sfagent.AgentError) as exc:
            return refused(exc)
