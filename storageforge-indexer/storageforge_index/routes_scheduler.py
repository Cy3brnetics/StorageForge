"""Web routes: schedules and their run reports."""
from __future__ import annotations

from flask import Response, jsonify, request
from flask_login import current_user, login_required

from . import alerts, deploy, preflight, scheduler


def register(web, ctx):
    core, db, limiter, conn, actor, need, json_body, arg_num = ctx.core, ctx.db, ctx.limiter, ctx.conn, ctx.actor, ctx.need, ctx.json_body, ctx.arg_num
    password_stale, password_confirmed, need_for_commands, may_hand_out = ctx.password_stale, ctx.password_confirmed, ctx.need_for_commands, ctx.may_hand_out

    def need_to_read_commands(sched: dict):
        """A command schedule's script holds what schedule_view masks."""
        if sched['task_type'] == 'command':
            need('plans.edit')

    # ── Scheduler API ──────────────────────────────────────────────────────────
    def schedule_view(sched: dict) -> dict:
        """Commands and env values can hold secrets: only those who may edit a schedule read them."""
        return sched if 'plans.edit' in current_user.permissions else scheduler.masked(sched)

    @web.route('/api/scheduler/schedules', methods=['GET', 'POST'])
    @login_required
    def api_scheduler_schedules():
        c = conn()
        if request.method == 'POST':
            stale = password_stale()         # a schedule is a command on a host, on a timer
            if stale:
                return stale
            body = json_body()
            if scheduler.normalize_schedule(body)['task_type'] == 'command':
                need('hosts.command')
            sched, token = scheduler.create_schedule(c, body, actor())
            core.audit(c, actor(), 'scheduler.create', 'ok', sched['host'], {'schedule_id': sched['schedule_id'], 'name': sched['name']})
            return jsonify(schedule=sched, token=token), 201
        h = request.args.get('host') or None
        t = request.args.get('task_type') or None
        p = None if request.args.get('paused') is None else (request.args.get('paused').lower() in ('1', 'true'))
        return jsonify(schedules=[schedule_view(s) for s in scheduler.list_schedules(c, host=h, task_type=t, paused=p)],
                       installed=scheduler.installed(c))

    @web.route('/api/scheduler/schedules/<int:schedule_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_scheduler_schedule(schedule_id):
        c = conn()
        if request.method != 'GET':
            stale = password_stale()
            if stale:
                return stale
        try:
            if request.method == 'PUT':
                body = json_body()
                curr = scheduler.get_schedule(c, schedule_id)
                if 'command' in (scheduler.normalize_schedule(scheduler.merged(curr, body))['task_type'], curr['task_type']):
                    need('hosts.command')
                sched = scheduler.update_schedule(c, schedule_id, body, actor())
                core.audit(c, actor(), 'scheduler.update', 'ok', sched['host'], {'schedule_id': schedule_id, 'name': sched['name']})
                return jsonify(sched)
            elif request.method == 'DELETE':
                sched = scheduler.get_schedule(c, schedule_id)
                try:
                    scheduler.delete_schedule(c, schedule_id, actor())
                except scheduler.StillDeployed as exc:
                    return jsonify(error=str(exc)), 409
                core.audit(c, actor(), 'scheduler.delete', 'ok', sched['host'], {'schedule_id': schedule_id, 'name': sched['name']})
                return jsonify(deleted=schedule_id)
            return jsonify(schedule_view(scheduler.get_schedule(c, schedule_id)))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/scheduler/schedules/<int:schedule_id>/pause')
    @login_required
    @password_confirmed
    def api_scheduler_schedule_pause(schedule_id):
        c = conn()
        try:
            body = json_body()
            paused = bool(body.get('paused', True))
            # stopping is allowed, but it deploys what the schedule says now: an edit since the last deploy is a deploy like any other
            if not paused or scheduler.changed_since_deploy(c, scheduler.get_schedule(c, schedule_id)):
                need_for_commands(c, 'schedules', schedule_id)
            sched = scheduler.pause_schedule(c, schedule_id, paused, actor())
            who = actor()
            core.audit(c, who, 'scheduler.pause', 'ok', sched['host'], {'schedule_id': schedule_id, 'paused': paused})
            if not scheduler.installed(c).get(str(schedule_id)):
                return jsonify(sched)
            # the timer is on the host, so this only happens when the host has been told
            items = scheduler.deploy_items(db, c, sched, 'apply', alerts.get_setting(c, 'report_url'), who)
            missing = sorted({it['host'] for it in items if not deploy.ready(c, it['host'])})
            if missing:
                return jsonify({**sched, 'host_pending': missing})
            gid = deploy.start_group(db, items, who, stop_on_failure=True, after=lambda h: core.enqueue(h, who),
                                     title=f'{"pause" if paused else "resume"} schedule {sched["name"]}', kind='schedules',
                                     ref=str(schedule_id), mode='apply', options={}, digest=scheduler.schedule_hash(c, sched))
            return jsonify({**sched, 'group': gid, 'hosts': [it['host'] for it in items]})
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/scheduler/schedules/<int:schedule_id>/token')
    @login_required
    @password_confirmed
    def api_scheduler_schedule_token(schedule_id):
        c = conn()
        try:
            token = scheduler.token_for_schedule(c, schedule_id, actor())
            sched = scheduler.get_schedule(c, schedule_id)
            core.audit(c, actor(), 'scheduler.token_rotate', 'ok', sched['host'], {'schedule_id': schedule_id})
            return jsonify(token=token, schedule_id=schedule_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/scheduler/schedules/<int:schedule_id>/run')
    @login_required
    @password_confirmed
    def api_scheduler_schedule_run(schedule_id):
        c = conn()
        try:
            sched = scheduler.get_schedule(c, schedule_id)
            need_for_commands(c, 'schedules', schedule_id)
            who = actor()
            report_url = alerts.get_setting(c, 'report_url')
            items = scheduler.deploy_items(db, c, sched, 'apply', report_url, who, run_now=True)
            missing = [it['host'] for it in items if not deploy.ready(c, it['host'])]
            if missing:
                return jsonify(error='set up deploy access first on: ' + ', '.join(sorted(set(missing))),
                               hosts=sorted(set(missing))), 409
            blocked = preflight.blockers(c, [it['host'] for it in items], 'schedules')
            if blocked:
                return jsonify(error='; '.join(f'{b["host"]}: {b["text"]}' for b in blocked), blockers=blocked), 409
            digest = scheduler.schedule_hash(c, sched)
            gid = deploy.start_group(db, items, who, stop_on_failure=True, after=lambda h: core.enqueue(h, who),
                                     title=f'run schedule {sched["name"]}', kind='schedules', ref=str(schedule_id),
                                     mode='apply', options={'run': True}, digest=digest)
            core.audit(c, who, 'scheduler.run', 'ok', sched['host'], {'schedule_id': schedule_id, 'group': gid})
            return jsonify(group=gid, hosts=[it['host'] for it in items], schedule_id=schedule_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/scheduler/schedules/<int:schedule_id>/verify')
    @login_required
    def api_scheduler_schedule_verify(schedule_id):
        c = conn()
        try:
            body = (request.get_json(silent=True) or {}) if request.is_json else {}
            run_id = body.get('run_id')
            if run_id is not None:
                res = scheduler.reverify_run(c, int(run_id), schedule_id)
            else:
                res = scheduler.verify_schedule(c, schedule_id)
            sched = scheduler.get_schedule(c, schedule_id)
            core.audit(c, actor(), 'scheduler.verify', 'ok', sched['host'],
                       {'schedule_id': schedule_id, 'run_id': res.get('run_id'), 'status': res.get('status')})
            core.alerts_wake.set()
            return jsonify(res)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/scheduler/schedules/<int:schedule_id>/script')
    @login_required
    def api_scheduler_schedule_script(schedule_id):
        c = conn()
        try:
            sched = scheduler.get_schedule(c, schedule_id)
            need_to_read_commands(sched)
            script, args = scheduler.generate_task_script(c, sched)
            core.audit(c, actor(), 'scheduler.script', 'ok', sched['host'], {'schedule_id': schedule_id})
            return Response(script, mimetype='text/x-shellscript',
                            headers={'Content-Disposition': f'attachment; filename="task-{schedule_id}.sh"'})
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/scheduler/schedules/<int:schedule_id>/install-script')
    @login_required
    def api_scheduler_schedule_install_script(schedule_id):
        c = conn()
        try:
            sched = scheduler.get_schedule(c, schedule_id)
            need_to_read_commands(sched)
            # A GET changes nothing, so this carries no token and the host reports through scans. To report directly, rotate
            # the token and add it to the config on the host, or deploy over SSH
            scr = scheduler.generate_install_script(c, sched, alerts.get_setting(c, 'report_url'), '')
            core.audit(c, actor(), 'scheduler.install-script', 'ok', sched['host'], {'schedule_id': schedule_id})
            return Response(scr, mimetype='text/x-shellscript',
                            headers={'Content-Disposition': f'attachment; filename="install-schedule-{schedule_id}.sh"'})
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/scheduler/schedules/<int:schedule_id>/cron')
    @login_required
    def api_scheduler_schedule_cron(schedule_id):
        c = conn()
        try:
            sched = scheduler.get_schedule(c, schedule_id)
            cron = scheduler.generate_cron_entry(sched)
            return Response(cron, mimetype='text/plain')
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/scheduler/schedules/<int:schedule_id>/runs')
    @login_required
    def api_scheduler_schedule_runs(schedule_id):
        c = conn()
        lim = arg_num('limit', 50, 1, 500)
        return jsonify(runs=scheduler.get_schedule_runs(c, schedule_id=schedule_id, limit=lim))

    @web.get('/api/scheduler/runs')
    @login_required
    def api_scheduler_runs():
        c = conn()
        h = request.args.get('host') or None
        lim = arg_num('limit', 50, 1, 500)
        return jsonify(runs=scheduler.get_schedule_runs(c, host=h, limit=lim))

    @web.post('/api/scheduler/report')
    @limiter.limit('120 per minute')
    def api_scheduler_report():
        auth = request.headers.get('Authorization', '')
        token = auth[7:].strip() if auth.startswith('Bearer ') else ''
        sched = scheduler.schedule_for_token(conn(), token)
        if not sched:
            return jsonify(error='unknown scheduler token'), 401
        body = json_body()
        if int(body.get('schedule_id') or 0) != sched['schedule_id']:
            return jsonify(error='token does not match schedule_id'), 403
        res = scheduler.ingest_report(conn(), body, f'report:{request.remote_addr}'[:60])
        if res.get('auto_rescan'):
            core.enqueue(sched['host'], 'scheduler')
        core.alerts_wake.set()
        return jsonify(ok=True, **res)
