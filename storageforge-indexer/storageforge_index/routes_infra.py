"""Web routes: workloads, networks, firewall rules and exposure. Views read the index. Only /api/infra/measure runs anything on a host."""
from __future__ import annotations

import json
import time

from flask import Response, jsonify, request
from flask_login import current_user, login_required

from . import changes, exposure, graph, infragraph, inframeasure, mapdesign, mapexport, netfacts, reach, security, whatif, workloads


def register(web, ctx):
    core, db, conn, actor, json_body, password_confirmed = ctx.core, ctx.db, ctx.conn, ctx.actor, ctx.json_body, ctx.password_confirmed

    def must_host():
        return security.known_host(conn(), request.args.get('host'))

    def map_graph():
        """What this account may see. Firewall rules and exposure say how to get in, so they stay behind security.view."""
        wanted = [x for x in (request.args.get('layers') or ','.join(infragraph.LAYERS)).split(',') if x in infragraph.LAYERS] or list(infragraph.LAYERS)
        secure = 'security.view' in current_user.permissions
        layers = [x for x in wanted if secure or x != 'firewall']
        at = request.args.get('at')
        if at and at.isdigit():                     # the timeline: what was read then, and nothing of today's
            g = infragraph.at_time(conn(), int(at), request.args.get('host') or None)
            g['nodes'] = [n for n in g['nodes'] if n['kind'] == 'Host' or n.get('layer') in layers]
            ids = {n['id'] for n in g['nodes']}
            g['edges'] = [e for e in g['edges'] if e['src'] in ids and e['dst'] in ids]
            if not secure:
                for n in g['nodes']:
                    for k in ('exposure', 'rule', 'why', 'bypasses_frontend'):
                        n['props'].pop(k, None)
            return g
        g = graph.load(conn(), request.args.get('host') or None, layers=tuple(set(layers) | {'storage'}))
        if 'manual' in layers and not request.args.get('host'):
            extra = infragraph.manual_nodes(conn())
            g['nodes'] += extra['nodes']
            known = {n['id'] for n in g['nodes']}
            g['edges'] += [e for e in extra['edges'] if e['dst'] in known]
        if 'storage' not in layers:           # the hosts everything hangs from stay, and the rest of storage goes
            g['nodes'] = [n for n in g['nodes'] if n['layer'] != 'storage' or n['kind'] == 'Host']
            ids = {n['id'] for n in g['nodes']}
            g['edges'] = [e for e in g['edges'] if e['src'] in ids and e['dst'] in ids]
        if not secure:
            for n in g['nodes']:
                for k in ('exposure', 'rule', 'why', 'bypasses_frontend'):
                    n['props'].pop(k, None)
        else:
            badges = infragraph.security_badges(conn())
            mounts = infragraph.mount_badges(conn())
            for n in g['nodes']:
                if n['kind'] == 'Host' and n['label'] in badges:
                    n['props']['security'] = badges[n['label']]
                elif n['kind'] == 'MountPoint' and (m := mounts.get(n.get('host'), {}).get(n['label'])):
                    n['props']['security'] = m
        return g

    @web.get('/api/map')
    @login_required
    def api_map():
        g = map_graph()
        return jsonify(mapexport.redact(g) if request.args.get('redact') == '1' else g)

    @web.get('/api/map/export')
    @login_required
    def api_map_export():
        fmt = request.args.get('format') or 'json'
        if fmt not in mapexport.FORMATS:
            raise ValueError('format is one of ' + ', '.join(mapexport.FORMATS))
        redacted = request.args.get('redact') == '1'
        g = mapexport.redact(map_graph()) if redacted else map_graph()
        mime, ext, render = mapexport.FORMATS[fmt]
        core.audit(conn(), actor(), 'map.export', 'ok', request.args.get('host') or None, {'format': fmt, 'redacted': redacted})
        return Response(render(g), mimetype=mime, headers={'Content-Disposition': f'attachment; filename="storageforge-map.{ext}"'})

    @web.get('/api/map/formats')
    @login_required
    def api_map_formats():
        return jsonify(formats=list(mapexport.FORMATS))

    def _visible(node_id):
        """An id is only worth answering if this account may see that layer."""
        g = map_graph()
        return g, next((n for n in g['nodes'] if n['id'] == node_id), None)

    @web.get('/api/map/node/<path:node_id>')
    @login_required
    def api_map_node(node_id):
        g, node = _visible(node_id)
        if not node:
            return jsonify(error='nothing with that id on the map'), 404
        names = {n['id']: n['label'] for n in g['nodes']}
        links = [{**e, 'src_label': names.get(e['src']), 'dst_label': names.get(e['dst'])} for e in g['edges'] if e['src'] == node_id or e['dst'] == node_id]
        return jsonify(node=node, edges=links, history=infragraph.history_of(conn(), node_id))

    @web.get('/api/map/edge')
    @login_required
    def api_map_edge():
        g = map_graph()
        edge = next((e for e in g['edges'] if e['src'] == request.args.get('src') and e['dst'] == request.args.get('dst') and e['rel'] == request.args.get('rel')), None)
        if not edge:
            return jsonify(error='no such link on the map'), 404
        return jsonify(edge=edge)

    @web.get('/api/map/exposure')
    @login_required
    def api_map_exposure():
        scope = request.args.get('scope') or 'all'
        if scope not in ('all', 'lan', 'vpn', 'any'):
            raise ValueError('scope is lan, vpn or any')
        names = [security.known_host(conn(), request.args['host'])] if request.args.get('host') else [r[0] for r in conn().all('SELECT hostname FROM hosts ORDER BY hostname')]
        reports = [exposure.host_report(netfacts.reading(conn(), n), inframeasure.reading(conn(), n), workloads.containers_of(conn(), n), n) for n in names]
        for r in reports:
            r['items'] = [i for i in r['items'] if i['level'] not in ('loopback', 'blocked') and exposure.in_scope(i['level'], scope)]
        return jsonify(scope=scope, hosts=reports)

    @web.get('/api/map/reach')
    @login_required
    def api_map_reach():
        a, b = request.args.get('from'), request.args.get('to')
        port = request.args.get('port') or ''
        if not a or not b or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError('asks for from, to and a port')
        return jsonify(reach.query(reach.load(conn()), a, b, int(port), 'udp' if request.args.get('proto') == 'udp' else 'tcp'))

    @web.post('/api/map/whatif')
    @login_required
    def api_map_whatif():
        """Reads only: a draft plan against a copy of the facts."""
        return jsonify(whatif.run(conn(), json_body()))

    @web.get('/api/map/coverage')
    @login_required
    def api_map_coverage():
        return jsonify(coverage=infragraph.coverage(conn(), request.args.get('host') or None), warnings=infragraph.warnings(conn()))

    @web.post('/api/map/stage')
    @login_required
    def api_map_stage():
        """A step from the map, added to a plan in Changes. It only sits in the database until someone applies it."""
        body = json_body()
        name = str(body.get('plan') or 'From the map').strip()[:80]
        new = body.get('tasks') or []
        pid = conn().scalar('SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': name})
        tasks = (changes.get_plan(conn(), pid).get('tasks') if pid else []) + new
        plan_id = changes.save_plan(conn(), {'name': name, 'tasks': tasks}, actor(), pid)
        core.audit(conn(), actor(), 'map.stage', 'ok', None, {'plan': plan_id, 'steps': len(new)})
        return jsonify(ok=True, plan_id=plan_id, tasks=len(tasks), check=changes.check(conn(), changes.get_plan(conn(), plan_id)))

    @web.post('/api/map/placeholders/<path:node_id>/promote')
    @login_required
    @password_confirmed
    def api_map_promote(node_id):
        """Starts enrolling something only ever seen from elsewhere. A name proves nothing, so it goes through the normal first scan:
        host key confirmation, a bound key, and consent on that machine. Its edges turn solid when a scan holds its address."""
        rows = conn().all("SELECT label, props_json FROM graph_nodes WHERE node_id = :i", {'i': node_id})
        if not rows or not json.loads(rows[0][1] or '{}').get('placeholder'):
            return jsonify(error='that is not a placeholder'), 404
        address = rows[0][0]
        core.audit(conn(), actor(), 'map.promote', 'ok', address, {'node': node_id})
        return jsonify(ok=True, address=address, message=f'To add {address}: bind a key to it in Keys, then scan it. Its host key is shown for you to confirm, and its lines turn solid after the first scan.', next={'scan': address})

    @web.get('/api/map/manual')
    @login_required
    def api_map_manual():
        return jsonify(infragraph.manual_nodes(conn()))

    @web.post('/api/map/manual')
    @login_required
    @password_confirmed
    def api_map_manual_save():
        res = infragraph.save_manual(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'map.manual.save', 'ok', None, {'id': res['id']})
        return jsonify(res)

    @web.delete('/api/map/manual/<int:manual_id>')
    @login_required
    @password_confirmed
    def api_map_manual_delete(manual_id):
        conn().execute('DELETE FROM map_manual WHERE id = :i', {'i': manual_id})
        core.audit(conn(), actor(), 'map.manual.delete', 'ok', None, {'id': manual_id})
        return jsonify(ok=True)

    @web.get('/api/map/annotations')
    @login_required
    def api_map_annotations():
        return jsonify(annotations=infragraph.annotations(conn()))

    @web.post('/api/map/annotations')
    @login_required
    def api_map_annotations_save():
        res = infragraph.save_annotation(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'map.annotation.save', 'ok', None, {'id': res['id']})
        return jsonify(res)

    @web.delete('/api/map/annotations/<int:note_id>')
    @login_required
    def api_map_annotations_delete(note_id):
        conn().execute('DELETE FROM map_annotations WHERE id = :i', {'i': note_id})
        core.audit(conn(), actor(), 'map.annotation.delete', 'ok', None, {'id': note_id})
        return jsonify(ok=True)

    # ── designs ─────────────────────────────────────────────────────
    @web.get('/api/map/designs')
    @login_required
    def api_map_designs():
        return jsonify(designs=mapdesign.list_designs(conn()))

    @web.get('/api/map/designs/<int:design_id>')
    @login_required
    def api_map_design(design_id):
        return jsonify(mapdesign.get_design(conn(), design_id))

    @web.post('/api/map/designs')
    @login_required
    def api_map_design_save():
        res = mapdesign.save_design(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'map.design.save', 'ok', None, {'name': res['name']})
        return jsonify(res)

    @web.delete('/api/map/designs/<int:design_id>')
    @login_required
    def api_map_design_delete(design_id):
        mapdesign.delete_design(conn(), design_id)
        core.audit(conn(), actor(), 'map.design.delete', 'ok', None, {'id': design_id})
        return jsonify(ok=True)

    @web.get('/api/map/designs/<int:design_id>/compare')
    @login_required
    def api_map_design_compare(design_id):
        d = mapdesign.get_design(conn(), design_id)
        res = mapdesign.compare(conn(), d['doc'])
        mapdesign.mark_compared(conn(), design_id, res['compared_at'])
        return jsonify(name=d['name'], **res)

    @web.post('/api/map/designs/<int:design_id>/stage')
    @login_required
    def api_map_design_stage(design_id):
        d = mapdesign.get_design(conn(), design_id)
        tasks = mapdesign.missing_tasks(conn(), d['doc'])
        if not tasks:
            return jsonify(ok=True, plan_id=None, tasks=0, message='nothing in this design is missing')
        name = f'Design: {d["name"]}'[:80]
        pid = conn().scalar('SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': name})
        plan_id = changes.save_plan(conn(), {'name': name, 'tasks': tasks}, actor(), pid)
        core.audit(conn(), actor(), 'map.design.stage', 'ok', None, {'plan': plan_id, 'steps': len(tasks)})
        return jsonify(ok=True, plan_id=plan_id, tasks=len(tasks))

    @web.get('/api/map/designs/<int:design_id>/export')
    @login_required
    def api_map_design_export(design_id):
        d = mapdesign.get_design(conn(), design_id)
        target = request.args.get('target') or 'bash'
        plan = {'name': f'Design {d["name"]}', 'tasks': mapdesign.tasks_of(d['doc'])}
        if target == 'bash':
            text, ext, mime = changes.script(conn(), plan), 'sh', 'text/x-shellscript'
        elif target == 'ansible':
            text, ext, mime = changes.ansible(conn(), plan), 'yml', 'text/yaml'
        elif target == 'terraform':
            text, ext, mime = mapdesign.terraform(d['doc']), 'tf', 'text/plain'
        elif target == 'puppet':
            text, ext, mime = mapdesign.puppet(d['doc']), 'pp', 'text/plain'
        else:
            raise ValueError('target is bash, ansible, terraform or puppet')
        core.audit(conn(), actor(), 'map.design.export', 'ok', None, {'id': design_id, 'target': target})
        return Response(text, mimetype=mime, headers={'Content-Disposition': f'attachment; filename="design-{design_id}.{ext}"'})

    @web.get('/api/map/snapshots')
    @login_required
    def api_map_snapshots():
        return jsonify(changes=infragraph.timeline(conn(), request.args.get('host') or None))

    @web.get('/api/map/views')
    @login_required
    def api_map_views():
        return jsonify(views=[{'id': i, 'name': n, 'owner': o, 'body': json.loads(b), 'updated_at': t} for i, n, o, b, t in conn().all('SELECT id, name, owner, body_json, updated_at FROM map_views ORDER BY name')])

    @web.post('/api/map/views')
    @login_required
    def api_map_views_save():
        body = json_body()
        name = str(body.get('name') or '').strip()[:80]
        if not name or any(c in name for c in '<>"`') or any(ord(c) < 32 for c in name):
            raise ValueError('a view needs a plain name')
        keep = {k: body.get(k) for k in ('layers', 'filter', 'positions', 'host', 'mode', 'group', 'shared', 'rules') if k in (body or {})}
        text = json.dumps(keep)
        if len(text) > 200_000:
            raise ValueError('that view is too large to save')
        conn().execute("""INSERT INTO map_views (name, owner, body_json, updated_at) VALUES (:n, :o, :b, :t)
                          ON CONFLICT (name) DO UPDATE SET body_json = excluded.body_json, owner = excluded.owner, updated_at = excluded.updated_at""",
                       {'n': name, 'o': actor(), 'b': text, 't': int(time.time())})
        core.audit(conn(), actor(), 'map.view.save', 'ok', None, {'name': name})
        return jsonify(ok=True, name=name)

    @web.delete('/api/map/views/<int:view_id>')
    @login_required
    def api_map_views_delete(view_id):
        conn().execute('DELETE FROM map_views WHERE id = :i', {'i': view_id})
        core.audit(conn(), actor(), 'map.view.delete', 'ok', None, {'id': view_id})
        return jsonify(ok=True)

    @web.get('/api/workloads')
    @login_required
    def api_workloads():
        return jsonify(workloads.listing(conn(), request.args.get('host') or None))

    @web.get('/api/network')
    @login_required
    def api_network():
        name = must_host()
        return jsonify(host=name, network=netfacts.reading(conn(), name))

    @web.get('/api/firewall')
    @login_required
    def api_firewall():
        name = must_host()
        m = inframeasure.reading(conn(), name)
        return jsonify(host=name, firewall=(m or {}).get('firewall'), measured_at=(m or {}).get('measured_at'), stale=(m or {}).get('stale'))

    @web.get('/api/exposure')
    @login_required
    def api_exposure():
        names = [security.known_host(conn(), request.args['host'])] if request.args.get('host') else [r[0] for r in conn().all('SELECT hostname FROM hosts ORDER BY hostname')]
        return jsonify(hosts=[exposure.host_report(netfacts.reading(conn(), n), inframeasure.reading(conn(), n), workloads.containers_of(conn(), n), n) for n in names])

    @web.post('/api/infra/measure')
    @login_required
    @password_confirmed
    def api_infra_measure():
        res = inframeasure.measure(db, conn(), json_body().get('host'), actor())
        core.audit(conn(), actor(), 'infra.measure', 'ok' if res.get('ok') else 'failed', res.get('host'), {'run_id': res.get('run_id')})
        return jsonify(res), 200 if res.get('ok') else 409

    @web.get('/api/infra/settings')
    @login_required
    def api_infra_settings():
        return jsonify(off=inframeasure.off_hosts(conn()))

    @web.post('/api/infra/settings')
    @login_required
    @password_confirmed
    def api_infra_settings_set():
        body = json_body()
        res = inframeasure.set_off(conn(), body.get('host'), body.get('off') is True, actor())
        core.audit(conn(), actor(), 'infra.settings', 'ok', res['host'], {'off': res['off']})
        return jsonify(res)
