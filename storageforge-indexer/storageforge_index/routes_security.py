"""Web routes: Ransomware defense, WORM retention, canaries, MAC, firewall, FIM, compliance, and SOC center.
Routes and permissions mapped from ransomware-defense-roadmap.md Section 6.1.
"""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import security


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def answer(res):
        core.alerts_wake.set()
        code = 200 if res.get('ok', True) else 409
        return jsonify(res), code

    # ── Posture & SOC Command Center ──────────────────────────────────────────
    @web.get('/api/security/posture')
    @login_required
    def api_security_posture():
        host = request.args.get('host') or None
        return jsonify(security.security_posture(conn(), host))

    @web.get('/api/security/incident/blast-radius')
    @login_required
    def api_security_blast_radius():
        host = request.args.get('host') or None
        return jsonify(security.blast_radius(conn(), host))

    @web.post('/api/security/incident/clean-room')
    @login_required
    @password_confirmed
    def api_security_clean_room():
        body = json_body()
        res = security.stage_clean_room(conn(), body, actor())
        core.audit(conn(), actor(), 'security.clean_room', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.post('/api/security/incident/brake')
    @login_required
    @password_confirmed
    def api_security_brake():
        body = json_body()
        res = security.execute_emergency_brake(conn(), body, actor())
        core.audit(conn(), actor(), 'security.emergency_brake', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.get('/api/security/playbooks')
    @login_required
    def api_security_playbooks_get():
        return jsonify(playbooks=security.list_playbooks(conn()))

    @web.post('/api/security/playbooks')
    @login_required
    @password_confirmed
    def api_security_playbooks_post():
        body = json_body()
        res = security.save_playbook(conn(), body, actor())
        core.audit(conn(), actor(), 'security.playbook.save', 'ok', None, {'name': res.get('name')})
        return answer(res)

    # ── Layer 1: WORM Holds, Clock Guard, & Adaptive Quorum ───────────────────
    @web.get('/api/security/worm/holds')
    @login_required
    def api_security_worm_holds():
        host = request.args.get('host') or None
        return jsonify(security.worm_holds(conn(), host))

    @web.post('/api/security/worm/hold')
    @login_required
    @password_confirmed
    def api_security_worm_hold():
        body = json_body()
        res = security.apply_worm_hold(conn(), body, actor())
        core.audit(conn(), actor(), 'security.worm.hold', 'ok', res.get('host'), {'snapshot': res.get('snapshot'), 'tag': res.get('hold_tag')})
        return answer(res)

    @web.post('/api/security/worm/release')
    @login_required
    @password_confirmed
    def api_security_worm_release():
        body = json_body()
        res = security.request_worm_release(conn(), body, actor())
        core.audit(conn(), actor(), 'security.worm.release', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.post('/api/security/worm/quorum/approve')
    @login_required
    @password_confirmed
    def api_security_worm_approve():
        body = json_body()
        res = security.approve_worm_quorum(conn(), body, actor())
        core.audit(conn(), actor(), 'security.worm.approve', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.post('/api/security/worm/break-glass')
    @login_required
    @password_confirmed
    def api_security_worm_break_glass():
        body = json_body()
        res = security.break_glass_worm(conn(), body, actor())
        core.audit(conn(), actor(), 'security.worm.break_glass', 'ok' if res.get('ok') else 'failed', res.get('host'), {'timelock_id': body.get('timelock_id')})
        return answer(res)

    @web.post('/api/security/worm/abort')
    @login_required
    @password_confirmed
    def api_security_worm_abort():
        body = json_body()
        res = security.abort_worm_release(conn(), body, actor())
        core.audit(conn(), actor(), 'security.worm.abort', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    # ── Layer 2: Canary Decoys, VSS Traps, & Auditd Watchers ──────────────────
    @web.get('/api/security/canaries')
    @login_required
    def api_security_canaries_get():
        host = request.args.get('host') or None
        return jsonify(security.list_canaries(conn(), host))

    @web.post('/api/security/canaries/deploy')
    @login_required
    @password_confirmed
    def api_security_canaries_deploy():
        body = json_body()
        res = security.deploy_canaries(conn(), body, actor())
        core.audit(conn(), actor(), 'security.canaries.deploy', 'ok', res.get('host'), {'count': res.get('count')})
        return answer(res)

    @web.post('/api/security/canaries/test')
    @login_required
    def api_security_canaries_test():
        body = json_body()
        res = security.test_canary_tripwire(conn(), body, actor())
        core.audit(conn(), actor(), 'security.canaries.test', 'ok', res.get('host'), body)
        return answer(res)

    # ── Layer 3: Mandatory Access Control & AVC Denials ───────────────────────
    @web.get('/api/security/mac/status')
    @login_required
    def api_security_mac_status():
        host = request.args.get('host') or None
        return jsonify(security.mac_status(conn(), host))

    @web.get('/api/security/mac/identity-anomalies')
    @login_required
    def api_security_mac_identities():
        host = request.args.get('host') or None
        return jsonify(security.identity_anomalies(conn(), host))

    @web.get('/api/security/mac/avc')
    @login_required
    def api_security_mac_avc():
        host = request.args.get('host') or None
        return jsonify(security.avc_events(conn(), host))

    @web.post('/api/security/mac/remediate')
    @login_required
    @password_confirmed
    def api_security_mac_remediate():
        body = json_body()
        res = security.remediate_mac(conn(), body, actor())
        core.audit(conn(), actor(), 'security.mac.remediate', 'ok', res.get('host'), body)
        return answer(res)

    # ── Layer 4: Storage Firewall & Network Quarantine ────────────────────────
    @web.get('/api/security/firewall/quarantine')
    @login_required
    def api_security_quarantine_get():
        host = request.args.get('host') or None
        return jsonify(security.list_quarantine(conn(), host))

    @web.post('/api/security/firewall/quarantine')
    @login_required
    @password_confirmed
    def api_security_quarantine_post():
        body = json_body()
        res = security.quarantine_ip(conn(), body, actor())
        core.audit(conn(), actor(), 'security.quarantine.add', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.delete('/api/security/firewall/quarantine/<path:ip>')
    @login_required
    @password_confirmed
    def api_security_quarantine_delete(ip):
        host = request.args.get('host') or None
        res = security.release_quarantine_ip(conn(), ip, host, actor())
        core.audit(conn(), actor(), 'security.quarantine.release', 'ok', host, {'ip': ip})
        return answer(res)

    @web.post('/api/security/firewall/airgap')
    @login_required
    @password_confirmed
    def api_security_airgap():
        body = json_body()
        res = security.trigger_airgap(conn(), body, actor())
        core.audit(conn(), actor(), 'security.airgap', 'ok', res.get('host'), body)
        return answer(res)

    # ── Layer 5: Runtime Threat Detection & Behavioral eBPF ───────────────────
    @web.get('/api/security/ebpf/events')
    @login_required
    def api_security_ebpf_events():
        host = request.args.get('host') or None
        return jsonify(security.ebpf_events(conn(), host))

    # ── Layer 6: Host Integrity & Hardening (AIDE & Lynis) ────────────────────
    @web.get('/api/security/integrity/aide')
    @login_required
    def api_security_aide_get():
        host = request.args.get('host') or None
        return jsonify(security.aide_status(conn(), host))

    @web.post('/api/security/integrity/aide/init')
    @login_required
    @password_confirmed
    def api_security_aide_init():
        body = json_body()
        res = security.aide_init(conn(), body, actor())
        core.audit(conn(), actor(), 'security.aide.init', 'ok', res.get('host'), body)
        return answer(res)

    @web.get('/api/security/integrity/lynis')
    @login_required
    def api_security_lynis():
        host = request.args.get('host') or None
        return jsonify(security.lynis_status(conn(), host))

    # ── Layer 7: Differential Malware & YARA Quarantine ───────────────────────
    @web.get('/api/security/malware/quarantine')
    @login_required
    def api_security_malware_quarantine():
        host = request.args.get('host') or None
        return jsonify(security.malware_quarantine_list(conn(), host))

    @web.post('/api/security/malware/restore')
    @login_required
    @password_confirmed
    def api_security_malware_restore():
        body = json_body()
        res = security.malware_restore(conn(), body, actor())
        core.audit(conn(), actor(), 'security.malware.restore', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    @web.delete('/api/security/malware/shred')
    @login_required
    @password_confirmed
    def api_security_malware_shred():
        body = json_body()
        res = security.malware_shred(conn(), body, actor())
        core.audit(conn(), actor(), 'security.malware.shred', 'ok' if res.get('ok') else 'failed', res.get('host'), body)
        return answer(res)

    # ── Layer 8: Compliance Standards & Init Script ───────────────────────────
    @web.get('/api/security/compliance/standards')
    @login_required
    def api_security_compliance_standards():
        return jsonify(security.compliance_standards(conn()))

    @web.get('/api/security/compliance/status/<host>')
    @login_required
    def api_security_compliance_status(host):
        return jsonify(security.compliance_status(conn(), host))

    @web.post('/api/security/compliance/init')
    @login_required
    @password_confirmed
    def api_security_compliance_init():
        body = json_body()
        res = security.stage_compliance_init(conn(), body, actor())
        core.audit(conn(), actor(), 'security.compliance.init', 'ok', res.get('host'), {'profile': res.get('profile')})
        return answer(res)
