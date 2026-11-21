"""Web routes for the Toolbox (roadmap section 4.1; toolbox.py, tbadapters.py, docs/toolbox.md).

Reads take workloads.view, and exposure security.view, since it says how to get in. Staging an install, a removal or an adapter action
saves a change plan, as /api/changes does, and takes plans.edit: deploying it asks for the password again. Writing a custom entry,
attaching its signature, adding an operator key and taking a catalog update take hosts.command and a fresh password, since a custom
entry is root on the host by another name. Staging a custom entry takes hosts.command too, and accepting an unsigned one for a host a
fresh password as well. Nothing here signs anything: the operator signs on their own machine, and the controller only verifies.
"""
from __future__ import annotations

from flask import abort, jsonify, request
from flask_login import current_user, login_required

from . import tbadapters, toolbox


def register(web, ctx):
    core, conn, actor, json_body, password_confirmed, password_stale = ctx.core, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed, ctx.password_stale

    def bad(exc, code=400):
        return jsonify(error=str(exc)), code

    @web.get('/api/toolbox/catalog')
    @login_required
    def api_toolbox_catalog():
        off = toolbox.official(conn())
        return jsonify(entries=[toolbox.public(r) for r in toolbox.catalog(conn())], categories=list(toolbox.CATEGORIES), levels=list(toolbox.GUI_LEVELS),
                       official={k: off.get(k) for k in ('state', 'why', 'serial', 'origin')}, signers=len(toolbox.signers(conn())),
                       may_write=('hosts.command' in current_user.permissions))

    @web.get('/api/toolbox/catalog/<tool>')
    @login_required
    def api_toolbox_entry(tool):
        row = toolbox.find(conn(), tool)
        if not row:
            return bad('no such catalog entry', 404)
        out = toolbox.public(row, full=True)
        if row['source'] == 'custom':
            out['sign'] = toolbox.sign_command(tool)
        return jsonify(out)

    @web.post('/api/toolbox/catalog/validate')
    @login_required
    def api_toolbox_validate():
        """Schema, lint, risk labels and the signature given, for the editor. Saves nothing."""
        b = json_body()
        return jsonify(toolbox.validate(conn(), str(b.get('yaml') or ''), str(b.get('signature') or '') or None))

    @web.post('/api/toolbox/catalog/custom')
    @login_required
    @password_confirmed
    def api_toolbox_custom_save():
        b = json_body()
        try:
            got = toolbox.save_custom(conn(), str(b.get('yaml') or ''), str(b.get('signature') or '') or None, actor())
        except toolbox.CatalogError as exc:
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.custom.save', 'ok', None, {'tool': got['id'], 'sha256': got['sha256'], 'trust': got['state']})
        return jsonify(got), 201

    @web.delete('/api/toolbox/catalog/custom/<tool>')
    @login_required
    @password_confirmed
    def api_toolbox_custom_remove(tool):
        if not toolbox.remove_custom(conn(), tool):
            return bad('no such custom entry', 404)
        core.audit(conn(), actor(), 'toolbox.custom.remove', 'ok', None, {'tool': tool})
        return jsonify(removed=tool)

    @web.post('/api/toolbox/catalog/sign')
    @login_required
    @password_confirmed
    def api_toolbox_sign():
        """The signature the operator made on their own machine (ssh-keygen -Y sign), verified against the operator keys and kept."""
        b = json_body()
        try:
            got = toolbox.sign_custom(conn(), str(b.get('id') or ''), str(b.get('signature') or ''))
        except LookupError as exc:
            return bad(exc, 404)
        except toolbox.CatalogError as exc:
            core.audit(conn(), actor(), 'toolbox.custom.sign', 'failed', None, {'tool': str(b.get('id') or '')[:60], 'why': str(exc)[:200]})
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.custom.sign', 'ok', None, {'tool': got['id'], 'why': got['why']})
        return jsonify(got)

    @web.post('/api/toolbox/catalog/update')
    @login_required
    @password_confirmed
    def api_toolbox_update():
        """An update of the official catalog: its manifest, the release key's signature over it, and its entries."""
        b = json_body()
        try:
            got = toolbox.take_update(conn(), str(b.get('manifest') or ''), str(b.get('signature') or ''), b.get('entries') or {}, actor())
        except toolbox.CatalogError as exc:
            core.audit(conn(), actor(), 'toolbox.catalog.update', 'failed', None, {'why': str(exc)[:200]})
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.catalog.update', 'ok', None, got)
        return jsonify(got)

    @web.get('/api/toolbox/signers')
    @login_required
    def api_toolbox_signers():
        return jsonify(signers=toolbox.signers(conn()), namespace=toolbox.NAMESPACE)

    @web.post('/api/toolbox/signers')
    @login_required
    @password_confirmed
    def api_toolbox_signer_add():
        b = json_body()
        try:
            got = toolbox.add_signer(conn(), str(b.get('name') or ''), str(b.get('public_key') or ''), actor())
        except toolbox.CatalogError as exc:
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.signer.add', 'ok', None, {'name': got['name'], 'fingerprint': got['fingerprint']})
        return jsonify(got), 201

    @web.delete('/api/toolbox/signers/<name>')
    @login_required
    @password_confirmed
    def api_toolbox_signer_remove(name):
        if not toolbox.remove_signer(conn(), name):
            return bad('no such signer', 404)
        core.audit(conn(), actor(), 'toolbox.signer.remove', 'ok', None, {'name': name})
        return jsonify(removed=name)

    @web.get('/api/toolbox/installed')
    @login_required
    def api_toolbox_installed():
        host = request.args.get('host') or None
        names = [r[0] for r in conn().all('SELECT hostname FROM hosts ORDER BY hostname')]
        return jsonify(installs=toolbox.installs(conn(), host), status=tbadapters.status_rows(conn(), host), hosts=names)

    @web.get('/api/toolbox/installed/<host>/<tool>/status')
    @login_required
    def api_toolbox_status(host, tool):
        try:
            return jsonify(tbadapters.read_status(conn(), toolbox.host_name(conn(), host), tool))
        except LookupError as exc:
            return bad(exc, 404)

    @web.post('/api/toolbox/preview')
    @login_required
    def api_toolbox_preview():
        """The plan an install would be and its report, saving nothing. With yaml, of an entry that is not in the catalog yet: the editor's dry run."""
        b = json_body()
        try:
            row = None
            if b.get('yaml'):
                text = toolbox.normal_text(str(b['yaml']))
                e, problems = toolbox.load_entry(text)
                if problems:
                    return jsonify(error='; '.join(problems[:6]), problems=problems), 400
                row = {'id': e['id'], 'entry': e, 'trust': 'unsigned', 'trust_why': 'a dry run of an entry not saved yet', 'sha256': toolbox.sha256(text),
                       'lab': 'not lab-tested', 'name': e['name'], 'revision': e['revision']}
            got = toolbox.preview(conn(), str(b.get('host') or ''), str(b.get('tool') or (row or {}).get('id') or ''), b.get('method') or None, b.get('inputs') or {},
                                  b.get('exposure') or None, b.get('bind') or None, b.get('allow_from') or None, row=row)
        except LookupError as exc:
            return bad(exc, 404)
        except (toolbox.CatalogError, ValueError) as exc:
            return bad(exc)
        if row:
            from . import changes
            try:
                plan = changes.normalize({'name': 'dry run', 'tasks': [t for t in got['tasks'] if t['type'] != 'tool-install']}) if len(got['tasks']) > 1 else None
                got['check'] = changes.check(conn(), plan) if plan else None
            except ValueError as exc:
                got['check'] = {'error': str(exc)}
            got['words'] = 'the install step itself runs only from a saved and trusted entry'
        return jsonify(got)

    @web.post('/api/toolbox/stage')
    @login_required
    def api_toolbox_stage():
        """Saves the plan of an install (action install, the default) or a removal (action remove). Deploying it asks again."""
        b = json_body()
        host, tool, action = str(b.get('host') or ''), str(b.get('tool') or ''), b.get('action') or 'install'
        try:
            if action == 'remove':
                got = toolbox.stage_remove(conn(), host, tool, actor(), bool(b.get('with_data')))
                core.audit(conn(), actor(), 'toolbox.stage.remove', 'ok', got['host'], {'tool': tool, 'plan': got['plan_id'], 'with_data': bool(b.get('with_data'))})
                return jsonify(got), 201
            if action != 'install':
                return bad('action is install or remove')
            row = toolbox.find(conn(), tool)
            if row and row['source'] == 'custom' and 'hosts.command' not in current_user.permissions:
                abort(403, description='a custom entry is root on the host by another name: staging one takes hosts.command')
            accept = bool(b.get('accept_unsigned'))
            if accept:
                if 'hosts.command' not in current_user.permissions:
                    abort(403, description='accepting an unsigned entry takes hosts.command')
                stale = password_stale()
                if stale:
                    return stale
            got = toolbox.stage(conn(), host, tool, actor(), method=b.get('method') or None, inputs=b.get('inputs') or {}, exposure=b.get('exposure') or None,
                                bind=b.get('bind') or None, allow_from=b.get('allow_from') or None, accept_unsigned=accept)
        except LookupError as exc:
            return bad(exc, 404)
        except (toolbox.CatalogError, ValueError) as exc:
            core.audit(conn(), actor(), 'toolbox.stage', 'failed', host[:80] or None, {'tool': tool[:60], 'why': str(exc)[:200]})
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.stage', 'ok', got['host'], {'tool': tool, 'method': got['method'], 'plan': got['plan_id'], 'sha256': got['sha256'],
                                                                         'trust': got['trust'], 'unsigned_accepted': accept and got['trust'] == 'unsigned'})
        return jsonify(got), 201

    @web.get('/api/toolbox/<host>/<tool>/actions')
    @login_required
    def api_toolbox_actions(host, tool):
        try:
            st = tbadapters.read_status(conn(), toolbox.host_name(conn(), host), tool)
        except LookupError as exc:
            return bad(exc, 404)
        return jsonify(host=st['host'], tool=tool, level=st['level'], actions=st['actions'])

    @web.post('/api/toolbox/<host>/<tool>/actions/<action>')
    @login_required
    def api_toolbox_action(host, tool, action):
        b = json_body()
        try:
            got = tbadapters.stage_action(conn(), host, tool, action, b.get('values') or {}, actor())
        except LookupError as exc:
            return bad(exc, 404)
        except ValueError as exc:
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.action', 'ok', host[:80], {'tool': tool, 'action': action, 'plan': got['plan_id']})
        return jsonify(got), 201

    @web.get('/api/toolbox/overrides/<host>/<tool>')
    @login_required
    def api_toolbox_override(host, tool):
        try:
            return jsonify(override=toolbox.override_row(conn(), toolbox.host_name(conn(), host), tool), keys=list(toolbox.OVERRIDE_KEYS))
        except LookupError as exc:
            return bad(exc, 404)

    @web.put('/api/toolbox/overrides/<host>/<tool>')
    @login_required
    def api_toolbox_override_set(host, tool):
        """Kept apart from the entry, so a catalog update leaves it. An image of another digest takes hosts.command: it runs other code."""
        b = json_body()
        text = str(b.get('yaml') or '')
        try:
            name = toolbox.host_name(conn(), host)
            if not toolbox.find(conn(), tool):
                raise LookupError('no such catalog entry')
            parsed, _ = toolbox.load_override(text)
            if 'image' in parsed and 'hosts.command' not in current_user.permissions:
                abort(403, description='an override of the image runs other code: it takes hosts.command')
            got = toolbox.set_override(conn(), name, tool, text, actor())
        except LookupError as exc:
            return bad(exc, 404)
        except toolbox.CatalogError as exc:
            return bad(exc)
        core.audit(conn(), actor(), 'toolbox.override', 'ok', name, {'tool': tool, 'sha256': got['sha256'] if got else None, 'keys': sorted(parsed)})
        return jsonify(override=got)

    @web.get('/api/toolbox/updates')
    @login_required
    def api_toolbox_updates():
        return jsonify(updates=toolbox.updates(conn()), cve='not built: image scanning comes with the Trivy entry (0.5.13)')

    @web.get('/api/toolbox/exposure')
    @login_required
    def api_toolbox_exposure():
        return jsonify(exposure=tbadapters.exposure(conn()))
