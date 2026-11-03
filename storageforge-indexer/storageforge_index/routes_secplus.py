"""Web routes: the operator's security policy, Falco, YARA, playbooks, identity, evidence, dashboards and hardware keys. What runs on a
host takes a fresh password and a mode, as routes_security.py does, and nothing but the outcome goes in the audit detail."""
from __future__ import annotations

import functools
import json
import secrets
import time

from flask import Response, jsonify, request, session
from flask_login import current_user, login_required

from . import alerts, clamav, deploy, secplus, secscripts as sx, security, webauthn


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def audit(action: str, res: dict, **detail):
        if res.get('mode') != 'preview':
            core.audit(conn(), actor(), action, 'ok' if res.get('ok') else 'failed', res.get('host'), {**detail, 'mode': res.get('mode'), 'run': res.get('run_id')})
        core.alerts_wake.set()
        return jsonify(res), 200 if res.get('ok') else 409

    def note_audit(action: str, res: dict, **detail):
        core.audit(conn(), actor(), action, 'ok', res.get('host') if isinstance(res.get('host'), str) else None, detail)
        return jsonify(res)

    def must_host():
        return security.known_host(conn(), request.args.get('host'))

    # ── step-up: a touch on a hardware key, for those who enrolled one ──
    def rp():
        return request.host.split(':')[0].strip('[]'), request.host_url.rstrip('/')

    def stepped_up() -> bool:
        return time.time() - session.get('webauthn_at', 0) <= webauthn.FRESH

    def step_up(view):
        """After the fresh password. It says so plainly, so the page can ask for the touch and try again."""
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if webauthn.required(conn(), current_user.username) and not stepped_up():
                return jsonify(error='touch your security key first', webauthn=True), 403
            return view(*args, **kwargs)
        return wrapped
    ctx.step_up = step_up

    @web.get('/api/security/webauthn')
    @login_required
    def api_webauthn():
        return jsonify(keys=[{k: v for k, v in x.items() if k in ('id', 'name', 'created_at')} for x in webauthn.keys_of(conn(), current_user.username)], required=webauthn.required(conn(), current_user.username), stepped_up=stepped_up())

    @web.post('/api/security/webauthn/register/begin')
    @login_required
    @password_confirmed
    def api_webauthn_register_begin():
        host, _ = rp()
        options, challenge = webauthn.register_options(current_user.username, host, [k['credential_id'] for k in webauthn.keys_of(conn(), current_user.username)])
        session['webauthn_challenge'] = challenge
        core.audit(conn(), actor(), 'security.webauthn.begin', 'ok', None, {})
        return jsonify(options)

    @web.post('/api/security/webauthn/register/finish')
    @login_required
    @password_confirmed
    def api_webauthn_register_finish():
        body = json_body()
        host, origin = rp()
        try:
            cred = webauthn.register_finish(body, session.pop('webauthn_challenge', ''), origin, host)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f'that key could not be enrolled: {exc}') from None
        kid = webauthn.add_key(conn(), current_user.username, cred, security.clean_text(body.get('name') or 'security key', 60))
        core.audit(conn(), actor(), 'security.webauthn.enroll', 'ok', None, {'key': kid})
        session['webauthn_at'] = time.time()
        return jsonify(ok=True, id=kid)

    @web.post('/api/security/webauthn/assert/begin')
    @login_required
    def api_webauthn_assert_begin():
        host, _ = rp()
        keys = webauthn.keys_of(conn(), current_user.username)
        if not keys:
            return jsonify(error='this account has no security key enrolled'), 409
        options, challenge = webauthn.assert_options(host, [k['credential_id'] for k in keys])
        session['webauthn_challenge'] = challenge
        core.audit(conn(), actor(), 'security.webauthn.ask', 'ok', None, {})
        return jsonify(options)

    @web.post('/api/security/webauthn/assert/finish')
    @login_required
    def api_webauthn_assert_finish():
        body = json_body()
        host, origin = rp()
        key = next((k for k in webauthn.keys_of(conn(), current_user.username) if k['credential_id'] == body.get('id')), None)
        if not key:
            return jsonify(error='that is not a key on this account'), 403
        try:
            count = webauthn.assert_finish(body, session.pop('webauthn_challenge', ''), origin, host, key['public_key'], key['sign_count'])
        except (KeyError, ValueError, TypeError) as exc:
            core.audit(conn(), actor(), 'security.webauthn.touch', 'failed', None, {'why': str(exc)[:100]})
            return jsonify(error=f'that did not check out: {exc}'), 403
        conn().execute('UPDATE security_webauthn SET sign_count = :c WHERE id = :i', {'c': count, 'i': key['id']})
        session['webauthn_at'] = time.time()
        core.audit(conn(), actor(), 'security.webauthn.touch', 'ok', None, {'key': key['id']})
        return jsonify(ok=True)

    @web.delete('/api/security/webauthn/<int:key_id>')
    @login_required
    @password_confirmed
    def api_webauthn_delete(key_id):
        webauthn.delete_key(conn(), current_user.username, key_id)
        core.audit(conn(), actor(), 'security.webauthn.remove', 'ok', None, {'key': key_id})
        return jsonify(ok=True)

    # ── waivers and profiles ────────────────────────────────────────
    @web.get('/api/security/waivers')
    @login_required
    def api_waivers():
        return jsonify(waivers=secplus.list_waivers(conn(), request.args.get('host') or None, include_expired=True))

    @web.post('/api/security/waivers')
    @login_required
    @password_confirmed
    def api_waivers_save():
        res = secplus.save_waiver(conn(), json_body(), actor())
        return note_audit('security.waiver.save', res, finding=res['finding'])

    @web.delete('/api/security/waivers/<int:waiver_id>')
    @login_required
    @password_confirmed
    def api_waivers_delete(waiver_id):
        secplus.delete_waiver(conn(), waiver_id)
        return note_audit('security.waiver.delete', {'ok': True}, id=waiver_id)

    @web.get('/api/security/profiles')
    @login_required
    def api_profiles():
        return jsonify(profiles=secplus.list_profiles(conn()), presets=secplus.PROFILE_PRESETS)

    @web.post('/api/security/profiles')
    @login_required
    @password_confirmed
    def api_profiles_save():
        res = secplus.save_profile(conn(), json_body(), actor())
        return note_audit('security.profile.save', res, name=res['name'])

    @web.delete('/api/security/profiles/<int:profile_id>')
    @login_required
    @password_confirmed
    def api_profiles_delete(profile_id):
        secplus.delete_profile(conn(), profile_id)
        return note_audit('security.profile.delete', {'ok': True}, id=profile_id)

    @web.post('/api/security/compliance/reconverge')
    @login_required
    def api_reconverge():
        res = secplus.reconverge(conn(), json_body(), actor())
        return note_audit('security.compliance.reconverge', res, plan=res['plan_id'])

    @web.get('/api/security/compliance/script')
    @login_required
    def api_compliance_script():
        host = must_host()
        profile = request.args.get('profile') or 'cis-l1'
        secplus.std_for(conn(), profile)
        return Response(sx.compliance_script(profile, host), mimetype='text/x-shellscript', headers={'Content-Disposition': 'attachment; filename="sf-init-compliance.sh"'})

    @web.get('/api/security/trend')
    @login_required
    def api_trend():
        return jsonify(host=must_host(), lynis=secplus.trend(conn(), must_host(), 'lynis'), compliance=secplus.trend(conn(), must_host(), 'compliance'))

    @web.post('/api/security/integrity/stage')
    @login_required
    def api_integrity_stage():
        res = secplus.stage_lynis(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'security.lynis.stage', 'ok' if res.get('ok') else 'failed', res.get('host'), {'plan': res.get('plan_id')})
        return jsonify(res), 200 if res.get('ok') else 409

    @web.get('/api/security/integrity/aide/watch')
    @login_required
    def api_aide_watch():
        return jsonify(paths=secplus.aide_watch(conn()))

    @web.post('/api/security/integrity/aide/watch')
    @login_required
    @password_confirmed
    def api_aide_watch_save():
        res = secplus.save_aide_watch(conn(), json_body(), actor())
        return note_audit('security.aide.watch', res, paths=len(res['paths']))

    # ── retention ───────────────────────────────────────────────────
    @web.get('/api/security/worm/policies')
    @login_required
    def api_policies():
        return jsonify(policies=secplus.list_policies(conn()), targets=secplus.policy_targets(conn(), must_host()) if request.args.get('host') else [])

    @web.post('/api/security/worm/policies')
    @login_required
    @password_confirmed
    def api_policies_save():
        res = secplus.save_policy(conn(), json_body(), actor())
        return note_audit('security.policy.save', res, id=res['id'])

    @web.delete('/api/security/worm/policies/<int:policy_id>')
    @login_required
    @password_confirmed
    def api_policies_delete(policy_id):
        secplus.delete_policy(conn(), policy_id)
        return note_audit('security.policy.delete', {'ok': True}, id=policy_id)

    @web.post('/api/security/worm/policies/apply')
    @login_required
    @password_confirmed
    def api_policies_apply():
        return audit('security.policy.apply', secplus.apply_policies(db, conn(), json_body(), actor()))

    @web.post('/api/security/worm/freeze')
    @login_required
    @password_confirmed
    def api_freeze():
        res = secplus.freeze(db, conn(), json_body(), actor())
        return audit('security.freeze', res, target=res.get('target'), held=res.get('held'))

    @web.post('/api/security/worm/preview')
    @login_required
    @password_confirmed
    def api_preview():
        return audit('security.rollback.preview', secplus.rollback_preview(db, conn(), json_body(), actor()))

    @web.post('/api/security/worm/preview/stage')
    @login_required
    def api_preview_stage():
        res = secplus.stage_rollback(conn(), json_body(), actor())
        return note_audit('security.rollback.stage', res, plan=res['plan_id'])

    @web.get('/api/security/evidence')
    @login_required
    def api_evidence():
        since, until = request.args.get('from'), request.args.get('to')
        out = secplus.evidence(db, conn(), request.args.get('host') or None, int(since) if since and since.isdigit() else None, int(until) if until and until.isdigit() else None, actor())
        core.audit(conn(), actor(), 'security.evidence', 'ok', request.args.get('host') or None, {})
        return jsonify(out)

    # ── identity ────────────────────────────────────────────────────
    @web.get('/api/security/mac/identity-anomalies')
    @login_required
    def api_identity():
        return jsonify(secplus.identity_view(conn(), must_host()))

    @web.post('/api/security/mac/identity/deploy')
    @login_required
    @password_confirmed
    def api_identity_deploy():
        return audit('security.identity', secplus.identity_deploy(db, conn(), json_body(), actor()))

    @web.post('/api/security/mac/noise')
    @login_required
    @password_confirmed
    def api_avc_noise():
        res = secplus.save_avc_noise(conn(), json_body(), actor())
        return note_audit('security.avc.noise', res, rules=len(res['rules']))

    @web.post('/api/security/mac/context')
    @login_required
    @password_confirmed
    def api_context():
        res = secplus.save_context_map(conn(), json_body(), actor())
        return note_audit('security.context.map', res, rules=len(res['rules']))

    @web.post('/api/security/mac/context/stage')
    @login_required
    def api_context_stage():
        res = secplus.stage_context(conn(), json_body(), actor())
        return note_audit('security.context.stage', res, plan=res.get('plan_id'))

    # ── firewall ────────────────────────────────────────────────────
    @web.get('/api/security/firewall/shares')
    @login_required
    def api_share_matrix():
        return jsonify(secplus.share_matrix(conn(), must_host()))

    @web.post('/api/security/firewall/shares/stage')
    @login_required
    def api_share_stage():
        res = secplus.stage_fence(conn(), json_body(), actor())
        return note_audit('security.fence.stage', res, plan=res['plan_id'])

    @web.get('/api/security/firewall/tiers')
    @login_required
    def api_ban_tiers():
        return jsonify(tiers=secplus.ban_tiers(conn()))

    @web.post('/api/security/firewall/tiers')
    @login_required
    @password_confirmed
    def api_ban_tiers_save():
        res = secplus.save_ban_tiers(conn(), json_body(), actor())
        return note_audit('security.tiers', res)

    # ── behaviour ───────────────────────────────────────────────────
    @web.post('/api/security/behavior/thresholds')
    @login_required
    @password_confirmed
    def api_thresholds():
        res = secplus.save_thresholds(conn(), json_body(), actor())
        return note_audit('security.thresholds', res)

    @web.post('/api/security/behavior/filters')
    @login_required
    @password_confirmed
    def api_filters():
        body = json_body()
        skip = security._int(body.get('skip_over_mb'), 500)
        if skip is None or not 1 <= skip <= 1_000_000:
            raise ValueError('skip_over_mb is 1 to 1000000')
        exts = lambda key: sorted({('.' + str(x).lstrip('.')).lower()[:16] for x in (body.get(key) or [])[:100] if str(x).strip()})  # noqa: E731
        res = {'skip_over_mb': skip, 'skip_ext': exts('skip_ext'), 'deep_ext': exts('deep_ext')}
        alerts.set_setting(conn(), secplus.SCAN_FILTERS, res, actor())
        return note_audit('security.filters', {'ok': True, **res})

    @web.post('/api/security/behavior/falco')
    @login_required
    @password_confirmed
    def api_falco():
        return audit('security.falco', secplus.falco_deploy(db, conn(), json_body(), actor()))

    @web.post('/api/security/behavior/yara')
    @login_required
    @password_confirmed
    def api_yara_scan():
        res = secplus.yara_scan(db, conn(), json_body(), actor())
        return audit('security.yara', res, scanned=res.get('scanned'), found=res.get('found'), dry=res.get('dry'))

    @web.get('/api/security/behavior/yara/rules')
    @login_required
    def api_yara_rules():
        return jsonify(rules=secplus.list_yara(conn()), example=secplus.DEFAULT_YARA)

    @web.post('/api/security/behavior/yara/rules')
    @login_required
    @password_confirmed
    def api_yara_save():
        res = secplus.save_yara(conn(), json_body(), actor())
        return note_audit('security.yara.rule', res, name=res['name'])

    @web.delete('/api/security/behavior/yara/rules/<int:rule_id>')
    @login_required
    @password_confirmed
    def api_yara_delete(rule_id):
        secplus.delete_yara(conn(), rule_id)
        return note_audit('security.yara.rule.delete', {'ok': True}, id=rule_id)

    @web.post('/api/security/malware/preview')
    @login_required
    @password_confirmed
    def api_malware_preview():
        """The first bytes and any readable text of a detected file, read on the host. Only reads, and nothing runs it."""
        did = security._int(json_body().get('id'))
        d = clamav.get_detection(conn(), did)
        path = d.get('quarantine_path') or d['path']
        script = ('#!/usr/bin/env bash\n# Written by StorageForge. Only reads.\nset -u\nexport LC_ALL=C\n' f'p=$(base64 -d <<<{sx.b64(path)!r})\n' r"""[[ -f $p && ! -L $p ]] || { echo "GONE"; exit 0; }
sha256sum -- "$p" | cut -d' ' -f1 | sed 's/^/SHA /'; stat -c 'SIZE %s %a %U:%G' -- "$p"
echo "@@HEX"; head -c 512 -- "$p" | od -An -tx1 -v
echo "@@STRINGS"; head -c 1048576 -- "$p" | LC_ALL=C tr -c '[:print:]\n' '\n' | grep -aE '.{6,}' | head -n 40 | cut -c1-120
""")
        res = security._run(db, d['host'], script, ref=f'preview:{did}', mode='report', actor=actor(), timeout=60)
        out = {**security._result(res, 'report'), 'host': d['host'], 'id': did}
        return audit('security.malware.preview', out, id=did)

    # ── playbooks ───────────────────────────────────────────────────
    @web.get('/api/security/playbooks')
    @login_required
    def api_playbooks():
        return jsonify(playbooks=secplus.list_playbooks(conn()), triggers=secplus.TRIGGERS, actions=secplus.ACTIONS, runs=secplus.playbook_runs(conn()), pending=secplus.pending_runs(conn()))

    @web.post('/api/security/playbooks')
    @login_required
    @password_confirmed
    def api_playbooks_save():
        res = secplus.save_playbook(conn(), json_body(), actor())
        return note_audit('security.playbook.save', res, name=res['name'])

    @web.delete('/api/security/playbooks/<int:playbook_id>')
    @login_required
    @password_confirmed
    def api_playbooks_delete(playbook_id):
        secplus.delete_playbook(conn(), playbook_id)
        return note_audit('security.playbook.delete', {'ok': True}, id=playbook_id)

    @web.post('/api/security/playbooks/runs/<int:run_id>')
    @login_required
    @password_confirmed
    def api_playbook_decide(run_id):
        body = json_body()
        res = secplus.decide_run(db, conn(), run_id, body.get('confirm') is True, actor())
        return audit('security.playbook.decide', res, run=run_id, outcome=res.get('outcome'))

    # ── packages ────────────────────────────────────────────────────
    @web.get('/api/security/packages')
    @login_required
    def api_packages():
        host = must_host()
        return jsonify(host=host, reading=security.measurement(conn(), host, 'packages'))

    @web.post('/api/security/packages/check')
    @login_required
    @password_confirmed
    def api_packages_check():
        return audit('security.packages.check', secplus.package_check(db, conn(), json_body(), actor()))

    @web.post('/api/security/packages/bundle')
    @login_required
    @password_confirmed
    def api_packages_bundle():
        return audit('security.packages.bundle', secplus.bundle(db, conn(), json_body(), actor()))

    # ── dashboards and the timeline ─────────────────────────────────
    @web.get('/api/security/timeline')
    @login_required
    def api_timeline():
        return jsonify(rows=secplus.timeline(conn(), request.args))

    @web.get('/api/security/badges')
    @login_required
    def api_badges():
        from . import infragraph
        return jsonify(hosts=infragraph.security_badges(conn()), mounts=infragraph.mount_badges(conn()))

    @web.get('/api/security/dash/tiles')
    @login_required
    def api_tile_kinds():
        return jsonify(tiles=secplus.TILES)

    @web.get('/api/security/dash/tile/<kind>')
    @login_required
    def api_tile(kind):
        return jsonify(secplus.tile(conn(), kind, request.args.get('host') or None))

    @web.get('/api/security/dash')
    @login_required
    def api_dashboards():
        return jsonify(dashboards=secplus.list_dashboards(conn(), current_user.username))

    @web.post('/api/security/dash')
    @login_required
    def api_dashboards_save():
        res = secplus.save_dashboard(conn(), json_body(), current_user.username)
        return note_audit('security.dashboard.save', res, name=res['name'])

    @web.delete('/api/security/dash/<int:dash_id>')
    @login_required
    def api_dashboards_delete(dash_id):
        secplus.delete_dashboard(conn(), dash_id, current_user.username)
        return note_audit('security.dashboard.delete', {'ok': True}, id=dash_id)

    @web.post('/api/security/incident/clean-room/sweep')
    @login_required
    @password_confirmed
    def api_clean_room_sweep():
        res = secplus.clean_room_sweep(db, conn(), json_body(), actor())
        return audit('security.clean_room.sweep', res, clean=res.get('clean'), hits=len(res.get('hits') or ()))

    _ = (json, secrets, deploy)
