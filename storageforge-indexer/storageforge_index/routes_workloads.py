"""Web routes for workloads (roadmap section 6): placement advice for a deploy form, and adopting a workload by capturing its definition,
with its drift. Every read is from the index; nothing here runs on a host. Adopting and forgetting a capture take plans.edit and are in the
audit log: a capture sits in the database, as a saved plan does."""
from __future__ import annotations

from flask import Response, jsonify, request
from flask_login import login_required

from . import placement, wlcapture


def register(web, ctx):
    core, conn, actor, json_body = ctx.core, ctx.conn, ctx.actor, ctx.json_body

    @web.get('/api/workloads/placement')
    @login_required
    def api_workloads_placement():
        """?host=&path=&use=vm|database|data: what the index says of putting that data there."""
        try:
            return jsonify(placement.for_host(conn(), request.args.get('host') or '', request.args.get('path') or '', request.args.get('use') or 'data'))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @web.get('/api/workloads/capture')
    @login_required
    def api_workloads_capture_preview():
        """?host=&runtime=&name=&format=: the definition as it would be captured, saved nowhere."""
        w = wlcapture.find(conn(), request.args.get('host') or '', request.args.get('runtime') or '', request.args.get('name') or '')
        if not w:
            return jsonify(error='no such workload in the index'), 404
        try:
            fmt, text = wlcapture.render(w, request.args.get('format') or None)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(format=fmt, definition=text, facts=wlcapture.facts(w))

    @web.get('/api/workloads/captures')
    @login_required
    def api_workloads_captures():
        return jsonify(captures=wlcapture.captures(conn(), request.args.get('host') or None))

    @web.get('/api/workloads/captures/<int:cid>')
    @login_required
    def api_workloads_capture_get(cid):
        c = wlcapture.get(conn(), cid)
        if not c:
            return jsonify(error='no such capture'), 404
        if request.args.get('raw'):
            return Response(c['definition'], mimetype='text/plain')
        return jsonify(c)

    @web.post('/api/workloads/captures')
    @login_required
    def api_workloads_adopt():
        b = json_body()
        try:
            got = wlcapture.adopt(conn(), str(b.get('host') or ''), str(b.get('runtime') or ''), str(b.get('name') or ''), b.get('format') or None, actor(), str(b.get('note') or ''))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'workload.adopt', 'ok', None, {'host': got['host'], 'runtime': got['runtime'], 'name': got['name'], 'format': got['format']})
        return jsonify(got)

    @web.get('/api/changes/<int:plan_id>/export/<any("terraform", "opentofu", "puppet"):target>')
    @login_required
    def api_change_export(plan_id, target):
        """A change plan's workload steps as main.tf (Terraform or OpenTofu) or a Puppet manifest, to download."""
        from . import changes, wlexport
        try:
            plan = changes.get_plan(conn(), plan_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        name, text = wlexport.render(plan, target)
        core.audit(conn(), actor(), f'changes.export.{target}', 'ok', None, {'plan': plan_id})
        return Response(text, mimetype='text/plain', headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.delete('/api/workloads/captures/<int:cid>')
    @login_required
    def api_workloads_capture_forget(cid):
        c = wlcapture.get(conn(), cid)
        if not c or not wlcapture.forget(conn(), cid):
            return jsonify(error='no such capture'), 404
        core.audit(conn(), actor(), 'workload.forget', 'ok', None, {'host': c['host'], 'runtime': c['runtime'], 'name': c['name']})
        return jsonify(ok=True)
