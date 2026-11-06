"""Web routes: saved versions of a planner design (design_versions.py). Reading takes plans.view, saving, restoring and deleting plans.edit
(storageforge_index/permissions.py). The ones that carry a design have no id in the path, so BODY_LIMITS in server.py can name them."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import design_versions as versions


def register(web, ctx):
    core, db, conn, actor, json_body = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body

    def who() -> str:
        """The account's name, as a person reads it: the audit log keeps the 'web:' that says how they came in."""
        return actor().removeprefix('web:')

    def version_id(body: dict) -> int:
        try:
            return int(body.get('id') or 0)
        except (TypeError, ValueError):
            raise ValueError('id must be the number of a saved version') from None

    @web.get('/api/planner/versions')
    @login_required
    def api_planner_versions():
        host = request.args.get('host', '').strip()
        return jsonify(host=host, versions=versions.list_versions(conn(), host), max_versions=versions.MAX_VERSIONS)

    @web.get('/api/planner/versions/<int:vid>')
    @login_required
    def api_planner_version(vid):
        return jsonify(versions.get(conn(), vid))

    @web.post('/api/planner/versions')
    @login_required
    def api_planner_version_save():
        body = json_body()
        v = versions.save(conn(), body.get('host'), body.get('blueprint'), who(), body.get('name'), body.get('note'))
        core.audit(conn(), actor(), 'planner.version.save', 'ok', v['host'], {'version': v['id'], 'name': v['name'], 'bytes': v['size_bytes']})
        return jsonify(v), 201

    @web.post('/api/planner/versions/compare')
    @login_required
    def api_planner_version_compare():
        body = json_body()
        return jsonify(versions.compare_with(conn(), version_id(body), body.get('blueprint')))

    @web.post('/api/planner/versions/restore')
    @login_required
    def api_planner_version_restore():
        body = json_body()
        res = versions.restore(db, conn(), version_id(body), who(), body.get('current'))
        core.audit(conn(), actor(), 'planner.version.restore', 'ok', res['restored']['host'],
                   {'version': res['restored']['id'], 'name': res['restored']['name'], 'kept': (res['kept'] or {}).get('id'), 'graph': res['graph']})
        return jsonify(res)

    @web.delete('/api/planner/versions/<int:vid>')
    @login_required
    def api_planner_version_delete(vid):
        v = versions.delete(conn(), vid)
        core.audit(conn(), actor(), 'planner.version.delete', 'ok', v['host'], {'version': v['id'], 'name': v['name']})
        return jsonify(ok=True)
