"""Web routes: the SSH certificate authority (sshcerts.py). Reading takes keys.view. Making the CA, saying which hosts are given
certificates, issuing a host certificate and revoking take keys.manage and a fresh password, and each is in the audit log. Nothing
here reaches a host: what changes one is the ssh-ca-trust and ssh-ca-krl plan steps, and /plan saves a plan with them."""
from __future__ import annotations

from flask import jsonify
from flask_login import login_required

from . import sshcerts
from .vault import Vault


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    @web.get('/api/keys/ssh-ca')
    @login_required
    def api_sshca():
        return jsonify(sshcerts.view(conn()))

    @web.post('/api/keys/ssh-ca')
    @login_required
    @password_confirmed
    def api_sshca_create():
        json_body()
        with Vault(db, conn()).unlock() as v:
            made = sshcerts.ensure_ca(v)
            enclave = bool(v.enclave)
        if made['made']:
            core.audit(conn(), actor(), 'sshca.create', 'ok', None, {'fingerprint': made['fingerprint'], 'enclave': enclave})
        return jsonify(made), 201 if made['made'] else 200

    @web.put('/api/keys/ssh-ca/hosts/<host>')
    @login_required
    @password_confirmed
    def api_sshca_host(host):
        got = sshcerts.set_host(conn(), host, json_body(), actor())
        core.audit(conn(), actor(), 'sshca.host', 'ok', got['host'], {'console': got['console'], 'scan': got['scan']})
        return jsonify(got)

    @web.post('/api/keys/ssh-ca/hosts/<host>/certificate')
    @login_required
    @password_confirmed
    def api_sshca_host_certificate(host):
        json_body()
        with Vault(db, conn()).unlock() as v:
            made = sshcerts.issue_host(v, host, actor())
        core.audit(conn(), actor(), 'sshca.issue', 'ok', made['host'], {'kind': 'host', 'serial': str(made['serial']), 'principals': made['principals'], 'expires_at': made['expires_at']})
        return jsonify(made | {'serial': str(made['serial'])}), 201

    @web.post('/api/keys/ssh-ca/certificates/<int:serial>/revoke')
    @login_required
    @password_confirmed
    def api_sshca_revoke(serial):
        got = sshcerts.revoke(conn(), serial, actor(), str(json_body().get('reason') or ''))
        core.audit(conn(), actor(), 'sshca.revoke', 'ok', got['host'], {'serial': str(serial), 'kind': got['kind'], 'key_id': got['key_id'], 'krl_version': got['krl_version']})
        core.alerts_wake.set()
        return jsonify(got | {'serial': str(serial)})

    @web.post('/api/keys/ssh-ca/plan')
    @login_required
    def api_sshca_plan():
        made = sshcerts.plan(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'sshca.plan', 'ok', None, {'plan_id': made['plan_id'], 'tasks': made['tasks'], 'name': made['name']})
        return jsonify(made)
