"""Web routes: copies on other hosts (copies.py). The list of pairs, which side of one changed last, and preparing a sync for one.
Reading takes files.browse, as the duplicates views do. Preparing a sync saves a Moves plan and takes plans.edit: nothing reaches a
host until that plan is deployed in Moves, which asks for the password."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import copies


def register(web, ctx):
    core, conn, actor, json_body = ctx.core, ctx.conn, ctx.actor, ctx.json_body

    @web.get('/api/copies')
    @login_required
    def api_copies():
        return jsonify(copies.overview(conn(), ctx.fleet_twins()))

    @web.get('/api/copies/sides')
    @login_required
    def api_copies_sides():
        hosts, paths = request.args.getlist('host'), request.args.getlist('path')
        if len(hosts) != len(paths):
            raise ValueError('give a host for each path')
        return jsonify(copies.sides(conn(), [{'host': h, 'path': p} for h, p in zip(hosts, paths)], single_file=request.args.get('kind') == 'file'))

    @web.post('/api/copies/sync')
    @login_required
    def api_copies_sync():
        body = json_body()
        detail = {'src': body.get('src'), 'dst': body.get('dst'), 'delete': bool(body.get('delete'))}
        try:
            got = copies.prepare_sync(conn(), body.get('src'), body.get('dst'), actor(), delete=bool(body.get('delete')),
                                      schedule=str(body.get('schedule') or 'daily'), keep_replaced=bool(body.get('keep_replaced')),
                                      single_file=body.get('kind') == 'file')
        except ValueError as exc:
            core.audit(conn(), actor(), 'copies.sync-prepare', 'denied', None, {**detail, 'why': str(exc)[:300]})
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'copies.sync-prepare', 'ok', got['dst']['host'], {**detail, 'plan': got['plan'], 'existing': got['existing']})
        return jsonify(got), 200 if got['existing'] else 201

    @web.post('/api/copies/dismiss')
    @login_required
    def api_copies_dismiss():
        body = json_body()
        try:
            got = copies.dismiss(conn(), body.get('copies'), actor(), body.get('dismissed', True) is not False)
        except ValueError as exc:
            core.audit(conn(), actor(), 'copies.dismiss', 'denied', None, {'why': str(exc)[:300]})
            return jsonify(error=str(exc)), 400
        core.audit(conn(), actor(), 'copies.dismiss', 'ok', None, got)
        core.alerts_wake.set()               # the notification counts what is left to answer
        return jsonify(got)
