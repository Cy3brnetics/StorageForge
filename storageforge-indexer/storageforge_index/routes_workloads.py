"""Web routes for workloads (roadmap section 6): placement advice for a deploy form. Every read is from the index; nothing here runs on
a host."""
from __future__ import annotations

from flask import jsonify, request
from flask_login import login_required

from . import placement


def register(web, ctx):
    conn = ctx.conn

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
