"""storageforge-index: agentless file indexing over SSH, fast search, and architecture reports."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

from . import __version__
from .capacity import fmt_bin, parse_size
from .db import Database, epoch
from .remote import DEFAULT_EXCLUDE_NAMES, DEFAULT_EXCLUDE_PATHS, RemoteError, Transport
from .scanner import ScanOptions, scan_host
from .search import SearchQuery, run_changes, run_dupes, run_search

DEFAULT_DB = os.environ.get('STORAGEFORGE_DB', '~/.local/share/storageforge/index.db')


def parse_age(text: str) -> int:
    m = re.fullmatch(r'\s*(\d+(?:\.\d+)?)\s*([smhdwy]?)\s*', text or '')
    if not m:
        raise argparse.ArgumentTypeError(f'bad age {text!r}; use e.g. 90m, 36h, 7d, 2w, 1y')
    return int(float(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800, 'y': 31557600}[m.group(2)])


def size_arg(text: str) -> int:
    try:
        return parse_size(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def open_db(args):
    db = Database(args.db)
    conn = db.connect()
    db.migrate(conn)
    return db, conn


def when(ts) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime('%Y-%m-%d %H:%M') if ts is not None else '—'


# commands

def scans_here(args, host: str) -> bool:
    """A loopback address with its own port is an SSH server (the demo target, a VM, a tunnel), not this machine."""
    return args.local or (host in ('localhost', '127.0.0.1', '::1') and not args.user and not args.key and args.port == 22)


def cmd_scan(args) -> int:
    opts = ScanOptions(
        roots=args.path or [],
        exclude_paths=([] if args.no_default_excludes else list(DEFAULT_EXCLUDE_PATHS)) + (args.exclude_path or []),
        exclude_names=([] if args.no_default_excludes else list(DEFAULT_EXCLUDE_NAMES)) + (args.exclude_name or []),
        include_network=args.include_network, include_tmpfs=args.include_tmpfs,
        include_fstypes=[x for v in args.include_fstype or [] for x in v.split(',')], parallel=args.parallel,
        batch_size=args.batch_size, checksum=args.checksum, checksum_min_size=args.checksum_min_size,
        nice=not args.no_nice, dry_run=args.dry_run, max_delete_ratio=args.max_delete_ratio)
    db = Database(args.db)
    conn = db.connect()
    db.migrate(conn)
    conn.close()
    failures = 0
    for host in args.host:
        local = scans_here(args, host)
        if not local and not args.key and not opts.dry_run:
            # no key on the command line: use the vault binding for this host
            from .runner import scan_via_vault
            from .vault import VaultError
            try:
                result = scan_via_vault(db, host, opts)
                if result and result['status'] != 'ok':
                    failures += 1
                if result and args.json:
                    print(json.dumps(result))
            except (RemoteError, ValueError, VaultError) as exc:
                print(f'{host}: {exc}', file=sys.stderr)
                failures += 1
            continue
        t = Transport(host=host, user=args.user, key=args.key, port=args.port, local=local, extra_opts=args.ssh_option or [])
        try:
            result = scan_host(db, t, opts)
            if result and not opts.dry_run:
                _audit_plain_scan(db, host, args.key, result)
            if result and result['status'] != 'ok':
                failures += 1
            if result and args.json:
                print(json.dumps(result))
        except (RemoteError, ValueError) as exc:
            print(f'{host}: {exc}', file=sys.stderr)
            failures += 1
        finally:
            t.close()
    return 1 if failures else 0


def _audit_plain_scan(db, host, key, result):
    """Scans with --key or --local still land in the audit log (HMAC-chained when the vault unlocks)."""
    from .graph import rebuild_host
    from .vault import AuditLog, Vault, VaultError, actor_name
    conn = db.connect()
    try:
        try:
            with Vault(db, conn).unlock() as v:
                AuditLog(db, conn, v.audit_key).append(actor_name(), 'ssh.scan', 'ok' if result['status'] == 'ok' else 'failed',
                                                       host, None, {'key_file': key, 'scan_id': result['scan_id'],
                                                                    'entries': result['entries']})
        except VaultError:
            AuditLog(db, conn, None).append(actor_name(), 'ssh.scan', 'ok' if result['status'] == 'ok' else 'failed',
                                            host, None, {'key_file': key, 'scan_id': result['scan_id'], 'entries': result['entries']})
        rebuild_host(db, conn, result['host'])
    finally:
        conn.close()


def cmd_search(args) -> int:
    pattern = args.name or args.pattern
    q = SearchQuery(pattern=pattern, hosts=args.host or [], size_gt=args.size_gt, size_lt=args.size_lt, ftype=args.type,
                    exts=[e for x in args.ext or [] for e in x.split(',') if e], under=args.under,
                    path_contains=args.path_contains, newer_than=args.newer_than, older_than=args.older_than,
                    limit=args.limit, sort=args.sort, desc=args.desc)
    db, conn = open_db(args)
    rows = run_search(db, conn, q)
    if args.format == 'json':
        for r in rows:
            print(json.dumps(r))
    elif args.format == 'paths':
        for r in rows:
            print(f'{r["host"]}:{r["path"]}')
    else:
        if not rows:
            print('No matches.', file=sys.stderr)
            return 1
        hw = max(len(r['host']) for r in rows)
        for r in rows:
            kind = {'dir': 'd', 'symlink': 'l', 'file': '-'}[r['type']]
            target = f' -> {r["symlink_target"]}' if r['symlink_target'] else ''
            path = r['path'].replace('\n', '\\n')
            print(f'{kind} {fmt_bin(r["size"]):>11}  {when(r["modified_at"])}  {r["host"]:<{hw}}  {path}{target}')
        if len(rows) == args.limit:
            print(f'(first {args.limit} matches; raise --limit for more)', file=sys.stderr)
    return 0


def cmd_changes(args) -> int:
    _, conn = open_db(args)
    scan, rows = run_changes(conn, args.host, args.scan, args.limit)
    if not scan:
        print(f'No completed scans for {args.host}.', file=sys.stderr)
        return 1
    if args.format == 'json':
        print(json.dumps({'scan': scan, 'changes': rows}))
        return 0
    print(f'scan #{scan["scan_id"]} ({scan["status"]}, {when(scan["started_at"])}): '
          f'+{scan["added"]:,} ~{scan["modified"]:,} -{scan["deleted"]:,}')
    sym = {'added': '+', 'modified': '~', 'deleted': '-'}
    for r in rows:
        size = fmt_bin(r['new_size'] if r['new_size'] is not None else r['old_size'])
        print(f'{sym[r["change"]]} {size:>11}  {r["path"]}')
    return 0


def cmd_dupes(args) -> int:
    _, conn = open_db(args)
    groups = run_dupes(conn, args.host, args.min_size, args.limit)
    if args.format == 'json':
        for g in groups:
            print(json.dumps(g))
        return 0
    if not groups:
        print('No duplicate groups. Scan with --checksum to hash size-collision candidates first.', file=sys.stderr)
        return 1
    for g in groups:
        print(f'{g["copies"]}× {fmt_bin(g["size"])}  reclaim {fmt_bin(g["reclaimable"])}  sha256 {g["sha256"][:16]}…')
        for f in g['files']:
            print(f'    {f}')
    return 0


def cmd_folders(args) -> int:
    from .folders import duplicate_folders
    _, conn = open_db(args)
    r = duplicate_folders(conn, args.host, args.min_files, args.min_size, args.limit, args.include_system)
    if args.format == 'json':
        print(json.dumps(r))
        return 0
    if not r['groups']:
        print(f'No duplicate folders among {r["folders_checked"]:,} folders.', file=sys.stderr)
        return 1
    for g in r['groups']:
        print(f'{g["count"]}× {g["files"]:,} files {fmt_bin(g["bytes"])}  {g["scope"]}'
              + (f'  reclaim {fmt_bin(g["reclaimable"])}' if g['scope'] == 'same host' else ''))
        for c in g['copies']:
            print(f'    {c["host"]}:{c["path"]}')
    print(f'{r["total_groups"]} group(s); {fmt_bin(r["reclaimable_same_host"])} reclaimable within hosts', file=sys.stderr)
    return 0


def cmd_access(args) -> int:
    from . import access
    _, conn = open_db(args)
    if args.access_cmd == 'status':
        for h in access.status(conn, args.host, limit=args.limit):
            print(f'{h["host"]}: {h["access"] or "unknown"} access as {h["scan_user"] or "?"} · '
                  f'{h["denied_total"]} unreadable folder(s) in scan #{h["scan_id"]}')
            for d in h['denied']:
                print(f'    {d["path"]}')
        return 0
    user = args.user
    if not user:
        if not args.host:
            raise SystemExit('give --host (to use its scan user) or --user')
        from .vault import Vault
        with Vault(Database(args.db), conn).unlock() as v:
            from .runner import connect_address
            user = v.resolve(connect_address(conn, args.host), 'scan').user
    print((access.remove_script if args.remove else access.setup_script)(user), end='')
    return 0


def cmd_moves(args) -> int:
    from . import moves
    _, conn = open_db(args)
    if args.moves_cmd == 'list':
        for p in moves.list_plans(conn):
            print(f'#{p["id"]:<4} {p["name"]}  ({p["steps"]} step{"s" if p["steps"] != 1 else ""})')
        return 0
    if args.moves_cmd == 'import':
        body = json.loads(Path(args.file).read_text())
        pid = moves.save_plan(conn, body, f'cli:{os.environ.get("USER", "?")}', args.id)
        print(f'saved move plan #{pid}')
        return 0
    plan = moves.get_plan(conn, args.id)
    if args.moves_cmd == 'check':
        c = moves.check(conn, plan)
        for st in c['steps']:
            print(f'step {st["step"]}' + (f' (runs on {st["runner"]})' if st.get('runner') else ''))
            for it in st['items']:
                print(f'  {it["level"]:<5} {it["text"]}')
        print(f'{moves._fmt(c["bytes"])} in all · {c["crit"]} critical · {c["warn"]} warning(s)')
        return 1 if c['crit'] else 0
    text = moves.script(conn, plan)
    if args.output in (None, '-'):
        print(text, end='')
    else:
        Path(args.output).write_text(text)
        os.chmod(args.output, 0o755)
        print(f'wrote {args.output}', file=sys.stderr)
    return 0


def cmd_tasks(args) -> int:
    from . import tasks
    _, conn = open_db(args)
    if args.tasks_cmd == 'list':
        for t in tasks.list_tasks(conn):
            print(f'#{t["id"]:<4} {t["name"]}  on {t["host"] or "no host"}  ({t["schedule"] or "by hand"})')
        return 0
    if args.tasks_cmd == 'import':
        body = json.loads(Path(args.file).read_text())
        tid = tasks.save_task(conn, body, f'cli:{os.environ.get("USER", "?")}', args.id)
        print(f'saved storage task #{tid}')
        return 0
    task = tasks.get_task(conn, args.id)
    if args.tasks_cmd == 'check':
        c = tasks.check(conn, task)
        for it in c['general']:
            print(f'{it["level"]:<5} {it["text"]}')
        for b in c['blocks']:
            print(b['label'])
            for it in b['items']:
                print(f'  {it["level"]:<5} {it["text"]}')
        print(f'{c["crit"]} critical · {c["warn"]} warning(s)')
        return 1 if c['crit'] else 0
    text = tasks.script(conn, task)
    if args.output in (None, '-'):
        print(text, end='')
    else:
        Path(args.output).write_text(text)
        os.chmod(args.output, 0o755)
        print(f'wrote {args.output}', file=sys.stderr)
    return 0


def cmd_git(args) -> int:
    from . import gitrepos
    _, conn = open_db(args)
    r = gitrepos.listing(conn, args.host)
    if args.format == 'json':
        print(json.dumps(r))
        return 0
    for g in r['repos']:
        copies = ', '.join(f'{c["host"]}:{c["path"]}{" (bare)" if c["bare"] else ""}' for c in g['copies'])
        print(f'{g["state"]:<12} {g["host"]}:{g["path"]}  [{g["branch"] or "-"}]' + (f'  copies: {copies}' if copies else ''))
    print(' · '.join(f'{v} {k}' for k, v in r['summary'].items() if v), file=sys.stderr)
    return 0


def cmd_shares(args) -> int:
    from . import shares
    _, conn = open_db(args)
    if args.shares_cmd == 'check':
        c = shares.check(conn, args.host)
        for it in c['items']:
            e = c['exports'][it['export']]
            print(f'{it["level"]:<5} {e["proto"]} {e["name"] or e["path"]}: {it["text"]}')
        return 1 if c['crit'] else 0
    text = shares.script(conn, args.host)
    if args.output in (None, '-'):
        print(text, end='')
    else:
        Path(args.output).write_text(text)
        os.chmod(args.output, 0o755)
        print(f'wrote {args.output}', file=sys.stderr)
    return 0


def cmd_plan(args) -> int:
    from . import changes
    _, conn = open_db(args)
    if args.changes_cmd == 'list':
        for p in changes.list_plans(conn):
            print(f'#{p["id"]:<4} {p["name"]}  ({p["tasks"]} task{"s" if p["tasks"] != 1 else ""})')
        return 0
    if args.changes_cmd == 'types':
        for k, t in changes.TYPES.items():
            print(f'{k:<15} {t["group"]:<18} {t["label"]}' + ('  (destructive)' if t.get('destructive') else ''))
            print(f'{"":<15} fields: ' + ', '.join(f['name'] + ('*' if f.get('required') else '') for f in t['fields']))
        return 0
    if args.changes_cmd == 'import':
        pid = changes.save_plan(conn, json.loads(Path(args.file).read_text()), f'cli:{os.environ.get("USER", "?")}', args.id)
        print(f'saved change plan #{pid}')
        return 0
    plan = changes.get_plan(conn, args.id)
    if args.changes_cmd == 'check':
        c = changes.check(conn, plan)
        for t in c['tasks']:
            print(f'{t["task"]:>2}. {t["title"]}' + (f'  [{t["host"]}]' if t.get('host') else ''))
            for it in t['items']:
                print(f'      {it["level"]:<5} {it["text"]}')
        print(f'{c["crit"]} critical · {c["warn"]} warning(s)')
        return 1 if c['crit'] else 0
    text = changes.script(conn, plan) if args.changes_cmd == 'script' else changes.ansible(conn, plan)
    if args.output in (None, '-'):
        print(text, end='')
    else:
        Path(args.output).write_text(text)
        if args.changes_cmd == 'script':
            os.chmod(args.output, 0o755)
        print(f'wrote {args.output}', file=sys.stderr)
    return 0


def cmd_deploy(args) -> int:
    from . import alerts, deploy, jobs
    db, conn = open_db(args)
    if args.deploy_cmd == 'setup-script':
        print(deploy.remove_script() if args.remove else deploy.setup_for_download(db, conn), end='')
        return 0
    if args.deploy_cmd == 'alerts':
        r = alerts.evaluate(db)
        for a in alerts.list_alerts(conn):
            print(f'{a["kind"]:<11} {a["title"]}  {a["message"] or ""}')
        print(f'{r["open"]} open alert(s), {r["new"]} new')
        return 1 if r['open'] else 0
    for a in deploy.access(conn):
        print(f'{a["host"]:<28} deploy access: {a["state"]}')
    for j in jobs.overview(conn):
        last = j['last'] or {}
        print(f'  {j["state"]:<9} {j["id"]:<14} {j["name"]}  last run: '
              + (time.strftime('%Y-%m-%d %H:%M', time.localtime(last['end'] or last['start'])) + f' rc={last["rc"]}' if last else 'none'))
    for d in alerts.drift(conn):
        print(f'  drift     {d["host"]}: {d["text"]}')
    return 0


def cmd_docker(args) -> int:
    from . import docker
    _, conn = open_db(args)
    if args.path:
        if not args.host:
            raise SystemExit('give --host with --path')
        for u in docker.users_of(conn, args.host, args.path):
            print(f'{u["state"]:<8} {u["container"]:<28} {u["path"]} -> {u["dest"]} ({"rw" if u["rw"] else "ro"})'
                  + (f'  [stack {u["stack"]}]' if u['stack'] else ''))
        return 0
    for h in docker.listing(conn, args.host):
        print(f'{h["host"]}: {h["engine"] or "no engine"} ({h["access"]}) · {h["running"]}/{h["containers"]} running · '
              f'{len(h["volumes"])} volumes, {len(h["unused_volumes"])} unused')
        for s in h['stacks']:
            print(f'  {s["state"]:<15} {s["project"] or "(standalone)":<22} {s["manager"]:<9} {s["running"]}/{len(s["containers"])}'
                  + (f'  {s["dir"]}' if s['dir'] else '') + ('  [docker socket]' if s['socket'] else ''))
    return 0


def cmd_backup(args) -> int:
    from . import backup, site
    db = Database(args.db)
    if args.backup_cmd == 'list':
        for b in backup.listing(Path(args.dir) if args.dir else None):
            print(f'{dt.datetime.fromtimestamp(b["created"]):%Y-%m-%d %H:%M}  {b["kind"]:<10} {fmt_bin(b["bytes"]):>10}  {b["path"]}')
        return 0
    _, conn = open_db(args)
    site.ensure(conn)      # so this backup can be told from another client's
    conn.close()
    r = backup.create(db, 'full' if args.full else 'essentials', Path(args.dir) if args.dir else None, args.keep)
    print(f'wrote {r["path"]} ({fmt_bin(r["bytes"])}, {r["seconds"]} s)' + (f'; removed {len(r["removed"])} old' if r['removed'] else ''))
    print('the vault secret is not in it, on purpose: back up secrets/vault_secret separately', file=sys.stderr)
    return 0


def cmd_config(args) -> int:
    from . import hostconfig, reinstall
    db = Database(args.db)
    conn = db.connect()
    try:
        if args.config_cmd == 'list':
            for v in hostconfig.versions(conn, args.host):
                print(f'{v["config_id"]:>6}  {dt.datetime.fromtimestamp(v["captured_at"]):%Y-%m-%d %H:%M}  {v["host"]:<24} '
                      f'{v["mounts"]} mounts, {v["shares"]} shares, {v["users"]} users, {v["links"]} links')
            return 0
        if args.config_cmd == 'diff':
            old, new = hostconfig.get(conn, args.old), hostconfig.get(conn, args.new)
            if not old or not new:
                raise SystemExit('no such version: see storageforge-index config list')
            for d in hostconfig.diff(old['body'], new['body']):
                print(f'== {d["name"]}')
                print('\n'.join(d['lines']))
            return 0
        if args.config_cmd == 'export':
            data = hostconfig.bundle(conn, [args.host] if args.host else None, args.id)
            Path(args.output).write_bytes(data)
            os.chmod(args.output, 0o600)
            print(f'wrote {args.output} ({fmt_bin(len(data))})')
            return 0
        v = hostconfig.get(conn, args.id) if args.id else hostconfig.latest(conn, args.host)
        if not v:
            raise SystemExit(f'nothing captured for {args.host}: scan it first')
        text = reinstall.script(v)
        if args.output:
            Path(args.output).write_text(text, errors='surrogateescape')
            os.chmod(args.output, 0o755)
            print(f'wrote {args.output}', file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0
    finally:
        conn.close()


def cmd_site(args) -> int:
    from . import site
    from .vault import actor_name
    _, conn = open_db(args)
    try:
        if args.site_cmd == 'rename':
            print(site.rename(conn, args.name, actor_name()))
        else:
            print(f'{site.name(conn) or "(no name)"}  {site.ensure(conn)}')
        return 0
    finally:
        conn.close()


def cmd_reset(args) -> int:
    from . import reset
    if not args.yes:
        print(f'This archives everything of the current site and starts "{args.site_name}" with an empty database, a '
              'new vault and a new vault secret. Stop the server first (docker compose stop storageforge proxy), then '
              'rerun with --yes.', file=sys.stderr)
        return 2
    r = reset.run(Database(args.db), args.site_name, args.archive or os.environ.get('STORAGEFORGE_ARCHIVE_DIR'),
                  args.abandon_deployed)
    print(f'{r["name"]} is ready. The old site is in {r["archive"]}: it holds the old keys and their secret, so move it '
          'off this machine.')
    if r['abandoned']:
        print(f'warning: {r["abandoned"]} deployment(s) are still on the old machines; see left-behind.json', file=sys.stderr)
    if r['left']['keys_on_hosts']:
        print(f'{len(r["left"]["keys_on_hosts"])} key binding(s) mean old public keys are still in authorized_keys over '
              'there; see left-behind.json', file=sys.stderr)
    if not r['secret_installed']:
        print('Switch STORAGEFORGE_VAULT_SECRET to the value of STORAGEFORGE_VAULT_NEW_SECRET before starting the server.')
    print('Back up the new vault secret: backups never contain it.')
    print(f'First admin, once and within 3 days: https://<this machine>/enroll#{r["token"]}')
    return 0


def cmd_restore(args) -> int:
    from . import backup
    if not args.yes:
        print(f'This replaces the database with {args.file}. Stop the server first '
              '(docker compose stop storageforge), then rerun with --yes.', file=sys.stderr)
        return 2
    r = backup.restore(Database(args.db), args.file)
    if r['warning']:
        print(f'warning: {r["warning"]}', file=sys.stderr)
    print(f'restored {r["restored"]}: {r["keys"]} key(s), {r["files"]:,} indexed files. Previous database kept as {r["previous"]}')
    if not r['files']:
        print('an essentials backup: start the server and the next scans rebuild the file index', file=sys.stderr)
    return 0


def cmd_prune(args) -> int:
    db, conn = open_db(args)
    r = db.prune(conn, change_days=args.days, max_change_rows=args.max_rows)
    print(f'removed {r["changes"]:,} change rows, {r["denied"]:,} old unreadable-folder rows, {r["jobs"]:,} old jobs')
    if args.vacuum:
        print('vacuuming (rewrites the file; needs as much free space as the database)…', file=sys.stderr)
        db.vacuum(conn)
    return 0


def cmd_hosts(args) -> int:
    if getattr(args, 'hosts_cmd', None) == 'rekey':
        return _rekey_host(args)
    db, conn = open_db(args)
    if getattr(args, 'hosts_cmd', None) == 'remove':
        from .retire import retire
        from .vault import Vault, VaultError
        try:
            gone = retire(conn, args.name, args.keep_design)
        except (LookupError, ValueError) as exc:
            print(exc, file=sys.stderr)
            return 1
        try:
            with Vault(db, conn).unlock() as v:
                _audit(db, conn, v, 'hosts.retire', host=args.name, **gone)
        except VaultError:
            _audit(db, conn, None, 'hosts.retire', host=args.name, **gone)
        print(f'retired {args.name}: ' + ', '.join(f'{v} {k}' for k, v in gone.items()))
        return 0
    rows = conn.all("""SELECT h.hostname, h.ip_address, h.last_scanned_at,
                              (SELECT count(*) FROM mounts m WHERE m.host_id = h.host_id AND m.scan_state = 'indexed'),
                              (SELECT count(*) FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = h.host_id),
                              (SELECT coalesce(sum(f.file_size_bytes), 0) FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id
                               WHERE m.host_id = h.host_id)
                       FROM hosts h ORDER BY h.hostname""")
    if not rows:
        print('No hosts indexed yet. Run: storageforge-index scan --host <host> --user <user> --key <path>', file=sys.stderr)
        return 1
    for hn, ip, last, mounts, files, size in rows:
        print(f'{hn:<28} {ip or "—":<16} scanned {when(epoch(last))}  {mounts} mounts  {files:,} entries  {fmt_bin(size)}')
    return 0


def _rekey_host(args) -> int:
    """A host was reinstalled (new SSH host keys) or moved: forget its pinned identity and its known_hosts lines, so
    the next scan that claims the name pins it again. Until then a scan from anywhere may claim it: scan it now."""
    import subprocess
    from .db import Database
    from .remote import child_env
    from .runner import known_hosts_path
    from .vault import Vault, VaultError
    db, conn = open_db(args)
    try:
        name, addr = Database.rekey_host(conn, args.name)
    except LookupError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    if addr:
        for entry in (addr, f'[{addr}]:{args.port}'):
            subprocess.run(['ssh-keygen', '-R', entry, '-f', str(known_hosts_path())], capture_output=True, env=child_env())
    try:
        with Vault(db, conn).unlock() as v:
            _audit(db, conn, v, 'host.rekey', host=name, address=addr)
    except VaultError:
        _audit(db, conn, None, 'host.rekey', host=name, address=addr)
    print(f'forgot the pinned SSH host keys of {name}' + (f' (and {addr} in known_hosts)' if addr else '')
          + f'. Scan it now: storageforge-index scan --host <its address>; that scan pins it again.')
    return 0


def _write(text: str, output: str | None):
    if output:
        Path(output).write_text(text)
        print(f'wrote {output}', file=sys.stderr)
    else:
        sys.stdout.write(text)


def _report_kwargs(args):
    return {'title': args.title, 'as_of': dt.date.fromisoformat(args.as_of) if args.as_of else None,
            'kwh_price': args.kwh_price, 'currency': args.currency, 'idle_share': args.idle_share}


def cmd_export_markdown(args) -> int:
    from .payloads import load_structured, merge_blueprint, node_from_blueprint, node_from_index
    from .report import render_report
    _, conn = open_db(args)
    hosts = args.host or [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    if not hosts:
        print('No hosts indexed yet.', file=sys.stderr)
        return 1
    nodes = [node_from_index(conn, h) for h in hosts]
    for path in args.blueprint or []:
        bp = node_from_blueprint(load_structured(path))
        target = next((n for n in nodes if n['hostname'].split('.')[0] == bp['hostname'].split('.')[0]), None)
        if target:
            merge_blueprint(target, bp)
        else:
            print(f'{path}: blueprint host {bp["hostname"]} is not among the exported hosts; ignored', file=sys.stderr)
    from .protection import fill_node
    for n in nodes:
        fill_node(conn, n)
    from .reportextra import sections
    _write(render_report(nodes, extra=sections(conn, nodes), **_report_kwargs(args)), args.output)
    return 0


def cmd_report(args) -> int:
    from .report import render_report
    _write(render_report([node_from_payload_args(args)], **_report_kwargs(args)), args.output)
    return 0


def node_from_payload_args(args, bp: dict | None = None) -> dict:
    from .payloads import (apply_df, apply_fstab, apply_zpool_status, finalize_zfs_capacity, load_structured,
                           node_from_blueprint, node_from_lsblk, node_skeleton, parse_df, parse_fstab, parse_zpool_status)
    if args.blueprint:
        node = node_from_blueprint(bp if bp is not None else load_structured(args.blueprint))
        if args.lsblk:
            print('note: --lsblk is ignored when a blueprint describes the devices', file=sys.stderr)
    elif args.lsblk:
        node = node_from_lsblk(load_structured(args.lsblk), args.hostname or 'host')
    else:
        node = node_skeleton(args.hostname or 'host')
    if args.hostname:
        node['hostname'] = args.hostname
    if args.zpool_status:
        apply_zpool_status(node, parse_zpool_status(Path(args.zpool_status).read_text()))
        finalize_zfs_capacity(node)
    if args.fstab:
        apply_fstab(node, parse_fstab(Path(args.fstab).read_text()))
    if args.df:
        apply_df(node, parse_df(Path(args.df).read_text()))
    return node


# vault, audit, graph, server

def _vault(args, unlock=True):
    from .vault import Vault
    db, conn = open_db(args)
    v = Vault(db, conn)
    if unlock:
        v.unlock()
    return db, conn, v


def _audit(db, conn, v, action, outcome='ok', host=None, fp=None, **detail):
    from .vault import AuditLog, actor_name
    AuditLog(db, conn, v.audit_key if v else None).append(actor_name(), action, outcome, host, fp, detail)


def cmd_vault(args) -> int:
    from .vault import Vault, importable_keys, secret_from_env
    a = args.vault_cmd
    if a == 'init':
        db, conn = open_db(args)
        v = Vault(db, conn, secret_from_env())
        created = v.init()
        v.unlock()
        if created:
            _audit(db, conn, v, 'vault.init')
        print('vault initialised' if created else 'vault already initialised; secret verified')
        return 0
    if a == 'status':
        db, conn = open_db(args)
        v = Vault(db, conn)
        if not v.initialized:
            print('vault: not initialised (run: storageforge-index vault init)')
            return 1
        v.unlock()
        keys = v.list_keys()
        print(f'vault: unlocked · {len(keys)} key(s) · {len(v.bindings())} binding(s)')
        return 0
    db, conn, v = _vault(args)
    with v:
        if a in ('add', 'generate'):
            if a == 'add':
                data = sys.stdin.buffer.read() if args.key_file == '-' else Path(args.key_file).expanduser().read_bytes()
                pw = os.environ[args.passphrase_env].encode() if args.passphrase_env else None
                info = v.add_key(args.name, data, pw, args.comment)
                del data
            else:
                info = v.generate_key(args.name, args.type, args.comment)
            _audit(db, conn, v, f'vault.key.{a}', fp=info['fingerprint'], name=args.name, type=info['type'])
            print(f'{"added" if a == "add" else "generated"} {info["type"]} key "{args.name}"  {info["fingerprint"]}', file=sys.stderr)
            print(info['public_key'])
        elif a == 'list':
            for k in v.list_keys():
                state = ' (disabled)' if k['disabled_at'] else ''
                print(f'{k["name"]:<20} {k["type"]:<12} {k["fingerprint"]}  {k["bindings"]} binding(s)  {k["origin"]}{state}')
        elif a == 'pubkey':
            print(v.public_key(args.name))
        elif a == 'remove':
            fp = conn.scalar('SELECT fingerprint FROM ssh_keys WHERE name = :n', {'n': args.name})
            n = v.remove_key(args.name)
            _audit(db, conn, v, 'vault.key.remove', 'ok' if n else 'failed', fp=fp, name=args.name)
            print(f'removed {n} key(s) and their bindings')
        elif a == 'bind':
            bid = v.bind(args.key, args.host, args.user, args.port, args.actions, args.priority)
            _audit(db, conn, v, 'vault.bind', host=args.host, binding_id=bid, key=args.key, user=args.user,
                   port=args.port, actions=args.actions)
            print(f'binding #{bid}: {args.key} → {args.user}@{args.host}:{args.port} ({args.actions})')
        elif a == 'unbind':
            n = v.unbind(args.id)
            _audit(db, conn, v, 'vault.unbind', 'ok' if n else 'failed', binding_id=args.id)
            print(f'removed {n} binding(s)')
        elif a == 'bindings':
            for b in v.bindings():
                print(f'#{b["binding_id"]:<4} {b["pattern"]:<28} {b["kind"]:<5} {b["user"]}@:{b["port"]:<6} '
                      f'key={b["key"]:<16} actions={b["actions"]} priority={b["priority"]}')
        elif a == 'resolve':
            b = v.resolve(args.host, args.action)
            print(f'{args.host} → key "{b.key_name}" ({b.fingerprint}) as {b.user}@:{b.port} via binding #{b.binding_id} [{b.pattern}]')
        elif a == 'policy':
            if args.policy:
                from .alerts import set_setting
                from .vault import POLICY_KEY, actor_name
                set_setting(conn, POLICY_KEY, args.policy, actor_name())
                _audit(db, conn, v, 'vault.policy', policy=args.policy)
            print(v.key_policy())
            imported = [k['name'] for k in v.list_keys() if k['origin'] != 'generated']
            if imported and v.key_policy() == 'generate-only':
                print(f'not generated here, or not known to be: {", ".join(imported)}', file=sys.stderr)
        elif a == 'rotate-secret':
            new = os.environ.get('STORAGEFORGE_VAULT_NEW_SECRET', '')
            if len(new) < 32:
                raise SystemExit('Set STORAGEFORGE_VAULT_NEW_SECRET (≥ 32 characters) to the new secret')
            n = v.rotate_secret(new.encode())
            _audit(db, conn, v, 'vault.rotate-secret', rewrapped=n)
            print(f'rewrapped {n} key(s); switch STORAGEFORGE_VAULT_SECRET to the new value now')
        elif a == 'import-dir':
            if v.key_policy() == 'generate-only':
                print(f'this site only takes keys generated in its vault: nothing imported from {args.dir}', file=sys.stderr)
                return 0
            known = {r[0] for r in conn.all('SELECT name FROM ssh_keys')}
            for f in importable_keys(args.dir):
                name = f.stem
                if name in known:
                    continue
                try:
                    info = v.add_key(name, f.read_bytes())
                    _audit(db, conn, v, 'vault.key.add', fp=info['fingerprint'], name=name, source=str(f))
                    print(f'imported {name}  {info["fingerprint"]}')
                except Exception as exc:
                    print(f'skipped {f.name}: {exc}', file=sys.stderr)
    return 0


def cmd_log(args) -> int:
    from . import logbook
    db, conn = open_db(args)
    try:
        f = logbook.clean_filter(args.host, args.source, args.outcome, args.grep, args.since, args.until)
        text, n = logbook.export(conn, f, args.format, args.with_output, args.limit)
    except ValueError as exc:
        raise SystemExit(str(exc))
    if not args.output:
        print(text, end='')
        return 0
    with open(args.output, 'w', encoding='utf-8', newline='') as out:
        out.write(text)
    _audit(db, conn, None, 'log.export', host=f['host'], format=args.format, entries=n, file=args.output)
    print(f'{n} entries written to {args.output}')
    return 0


def cmd_audit(args) -> int:
    from .vault import AuditLog, Vault, VaultError
    db, conn = open_db(args)
    if args.audit_cmd == 'verify':
        try:
            with Vault(db, conn).unlock() as v:
                log = AuditLog(db, conn, v.audit_key)
                ok, n, bad = log.verify()
                weak = log.unkeyed()
        except VaultError as exc:
            raise SystemExit(f'cannot verify HMAC entries: {exc}')
        print(f'audit chain {"intact" if ok else "BROKEN at entry #" + str(bad)} · {n} entries verified')
        if weak['unkeyed_after_keyed']:
            print(f'note: {weak["unkeyed_after_keyed"]} entries from #{weak["first_unkeyed_after_keyed"]} on were written while the '
                  f'vault was locked (plain SHA-256): whoever can write the database could have rewritten them')
        return 0 if ok else 2
    entries = AuditLog(db, conn, None).tail(args.limit)
    for e in reversed(entries):
        if args.format == 'json':
            print(json.dumps(e))
            continue
        when_ = dt.datetime.fromtimestamp(e['ts'], dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        detail = ' '.join(f'{k}={v}' for k, v in e['detail'].items())
        print(f'{when_}  {e["outcome"]:<6} {e["action"]:<18} {e["host"] or "—":<22} {e["actor"]:<16} {detail}')
    return 0


def cmd_graph(args) -> int:
    from . import graph
    from .payloads import load_structured
    db, conn = open_db(args)
    if args.graph_cmd == 'build':
        hosts = args.host or [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
        for h in hosts:
            n, e = graph.rebuild_host(db, conn, h)
            print(f'{h}: {n} nodes, {e} edges')
    elif args.graph_cmd == 'import':
        bp = load_structured(args.blueprint) if args.blueprint else None   # read once: may be /dev/stdin
        node = node_from_payload_args(args, bp)
        if bp:
            graph.store_blueprint(conn, bp)
        nodes, edges = graph.build(node, dt.date.fromisoformat(args.as_of) if args.as_of else None)
        graph.save(db, conn, node['hostname'], nodes, edges)
        print(f'{node["hostname"]}: {len(nodes)} nodes, {len(edges)} edges')
    elif args.graph_cmd == 'stats':
        for kind, health, n in conn.all('SELECT kind, health, count(*) FROM graph_nodes GROUP BY kind, health ORDER BY kind, health'):
            print(f'{kind:<12} {health:<11} {n}')
    return 0


def cmd_canvas(args) -> int:
    from . import canvas, graph
    _, conn = open_db(args)
    _write(canvas.dumps(graph.load(conn, args.host)), args.output)
    return 0


def cmd_blueprint(args) -> int:
    from . import graph
    from .payloads import load_structured
    db, conn = open_db(args)
    host = graph.store_blueprint(conn, load_structured(args.file))
    print(f'stored blueprint for {host}; it is overlaid on the next scan or `graph build --host {host}`')
    return 0


def cmd_migrate(args) -> int:
    db = Database(args.db)
    applied = db.migrate(db.connect())
    print('applied ' + ', '.join(applied) if applied else 'schema up to date')
    return 0


def cmd_serve(args) -> int:
    from .server import serve
    db, conn = open_db(args)
    conn.close()
    interval = parse_age(args.scan_interval) if args.scan_interval else None
    serve(db, args.listen, args.port, interval, args.parallel)
    return 0


def _new_password(args) -> str:
    import getpass
    if args.password_env:
        pw = os.environ.get(args.password_env, '')
        if not pw:
            raise SystemExit(f'error: ${args.password_env} is empty')
        return pw
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip('\r\n')
    pw = getpass.getpass('Password: ')
    if pw != getpass.getpass('Repeat password: '):
        raise SystemExit('error: passwords do not match')
    return pw


def cmd_user(args) -> int:
    from . import users
    from .vault import Vault, VaultError
    db, conn = open_db(args)
    a = args.user_cmd
    try:
        if a == 'list':
            for name, created, last, disabled, role in users.listing(conn):
                print(f'{name:<24} {role:<9} created {when(created)}  last login {when(last)}{"  DISABLED" if disabled else ""}')
            return 0
        if a == 'add':
            users.create(conn, args.name, _new_password(args), args.role)
        elif a == 'role':
            users.set_role(conn, args.name, args.new_role)
        elif a == 'passwd':
            users.set_password(conn, args.name, _new_password(args))
        elif a in ('disable', 'enable'):
            users.set_disabled(conn, args.name, a == 'disable')
        elif a == 'remove':
            users.remove(conn, args.name)
        elif a == 'signout':
            users.end_all_sessions(conn, args.name)
    except users.UserError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    try:   # HMAC-chain the entry when the vault secret is available, plain SHA-256 otherwise
        with Vault(db, conn).unlock() as v:
            _audit(db, conn, v, f'user.{a}', username=args.name)
    except VaultError:
        _audit(db, conn, None, f'user.{a}', username=args.name)
    print({'add': 'created', 'role': f'role {getattr(args, "new_role", "")} for', 'passwd': 'password changed for', 'disable': 'disabled', 'enable': 'enabled',
           'remove': 'removed', 'signout': 'signed out every session of'}[a] + f' user {args.name}' + (' (existing sessions signed out)' if a in ('passwd', 'disable') else ''))
    return 0


def cmd_schedule(args) -> int:
    from . import scheduler
    db, conn = open_db(args)
    try:
        cmd = args.schedule_cmd
        if cmd == 'list':
            schedules = scheduler.list_schedules(conn, host=args.host, task_type=args.type,
                                                 paused=True if args.paused else None)
            if args.json:
                print(json.dumps(schedules, indent=2))
            else:
                if not schedules:
                    print("No schedules found.")
                    return 0
                print(f"{'ID':<6} {'NAME':<24} {'HOST':<16} {'CRON':<16} {'TYPE':<8} {'PAUSED':<8} {'NEXT RUN':<18} {'LAST STATUS'}")
                print("-" * 110)
                for s in schedules:
                    nxt = dt.datetime.fromtimestamp(s['next_run_at'], dt.timezone.utc).strftime('%Y-%m-%d %H:%M') if s['next_run_at'] else '—'
                    print(f"{s['schedule_id']:<6} {s['name'][:23]:<24} {s['host'][:15]:<16} {s['cron_expr']:<16} "
                          f"{s['task_type']:<8} {'yes' if s['paused'] else 'no':<8} {nxt:<18} {s['last_status'] or '—'}")
            return 0

        elif cmd == 'add':
            cfg = json.loads(args.config) if args.config else {}
            body = {
                'name': args.name,
                'host': args.host,
                'cron_expr': args.cron,
                'task_type': args.type,
                'task_ref': args.ref,
                'config': cfg,
                'paused': args.paused,
            }
            sched, token = scheduler.create_schedule(conn, body, 'cli')
            if args.json:
                print(json.dumps({'schedule': sched, 'token': token}, indent=2))
            else:
                print(f"Created schedule #{sched['schedule_id']} ({sched['name']}) on {sched['host']}")
                print(f"Auth token: {token}")
                print("Keep this token safe; it authenticates execution reports from the client.")
            return 0

        elif cmd == 'get':
            sched = scheduler.get_schedule(conn, args.id)
            print(json.dumps(sched, indent=2))
            return 0

        elif cmd == 'pause':
            sched = scheduler.pause_schedule(conn, args.id, True, 'cli')
            print(f"Paused schedule #{args.id} ({sched['name']})")
            return 0

        elif cmd == 'resume':
            sched = scheduler.pause_schedule(conn, args.id, False, 'cli')
            print(f"Resumed schedule #{args.id} ({sched['name']})")
            return 0

        elif cmd == 'remove':
            sched = scheduler.get_schedule(conn, args.id)
            scheduler.delete_schedule(conn, args.id, 'cli')
            print(f"Removed schedule #{args.id} ({sched['name']})")
            return 0

        elif cmd == 'token':
            token = scheduler.token_for_schedule(conn, args.id, 'cli')
            print(f"Generated new auth token for schedule #{args.id}:\n{token}")
            return 0

        elif cmd == 'runs':
            runs = scheduler.get_schedule_runs(conn, schedule_id=args.id, host=args.host, limit=args.limit)
            if args.json:
                print(json.dumps(runs, indent=2))
            else:
                if not runs:
                    print("No runs recorded.")
                    return 0
                print(f"{'RUN ID':<8} {'SCHED':<6} {'STATUS':<12} {'STARTED':<18} {'EXIT':<6} {'VERIFIED':<10} {'SUMMARY'}")
                print("-" * 90)
                for r in runs:
                    st = dt.datetime.fromtimestamp(r['started_at'], dt.timezone.utc).strftime('%Y-%m-%d %H:%M')
                    v = 'passed' if r['verified'] == 1 else 'failed' if r['verified'] == -1 else 'none'
                    summ = (r['verify_result'] or {}).get('summary', '')[:30]
                    print(f"{r['run_id']:<8} {r['schedule_id']:<6} {r['status']:<12} {st:<18} {str(r['exit_code']):<6} {v:<10} {summ}")
            return 0

        elif cmd == 'cron':
            sched = scheduler.get_schedule(conn, args.id)
            print(scheduler.generate_cron_entry(sched).strip())
            return 0

        elif cmd == 'install-script':
            sched = scheduler.get_schedule(conn, args.id)
            report_url = args.report_url or ''
            token = scheduler.token_for_schedule(conn, args.id, 'cli')
            print(scheduler.generate_install_script(conn, sched, report_url, token))
            return 0

        elif cmd == 'run':
            import subprocess
            import tempfile
            import time
            sched = scheduler.get_schedule(conn, args.id)
            script, sargs = scheduler.generate_task_script(conn, sched)
            started = int(time.time())
            with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as tf:
                tf.write(script)
                tmp_path = tf.name
            try:
                os.chmod(tmp_path, 0o750)
                env = {**os.environ, **(sched['config'].get('env') or {})}
                timeout = int(sched['config'].get('timeout_sec') or 3600) or None
                proc = subprocess.run(['/bin/bash', tmp_path, *sargs], capture_output=True, text=True,
                                      timeout=timeout, env=env)
                rc = proc.returncode
                out = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
            except subprocess.TimeoutExpired:
                rc, out = 124, 'Schedule execution timed out'
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            finished = int(time.time())
            res = scheduler.ingest_report(conn, {
                'schedule_id': args.id,
                'started_at': started,
                'finished_at': finished,
                'exit_code': rc,
                'output': out,
            }, 'cli:run')
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(f"Run #{res['run_id']} finished with status={res['status']} (exit={rc}): {res['verify_result']['summary']}")
            return 0 if res['status'] in ('verified', 'reported') else 1

        elif cmd == 'verify':
            if args.run_id:
                res = scheduler.reverify_run(conn, args.run_id)
            else:
                res = scheduler.verify_schedule(conn, args.id)
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(f"Schedule #{args.id} verification: {res['status']} — {res['verify_result']['summary']}")
                for chk in res['verify_result'].get('checks') or []:
                    print(f"  [{chk['status'].upper():<4}] {chk['name']}: {chk['message']}")
            return 0 if res['verified'] != -1 else 1

    finally:
        conn.close()
    return 0


def cmd_healthcheck(args) -> int:
    import urllib.request
    try:
        with urllib.request.urlopen(args.url, timeout=4) as r:
            body = json.loads(r.read())
            return 0 if body.get('status') == 'ok' else 1
    except Exception as exc:
        print(f'unhealthy: {exc}', file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='storageforge-index', description=__doc__)
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('--db', default=DEFAULT_DB, help='SQLite path or postgresql:// URL (env STORAGEFORGE_DB)')
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('scan', help='index one or more hosts over SSH')
    s.add_argument('--host', action='append', required=True, help='hostname or IP; repeat for several hosts')
    s.add_argument('--user', help='SSH user')
    s.add_argument('--key', help='SSH private key (key authentication only; never prompts)')
    s.add_argument('--port', type=int, default=22)
    s.add_argument('--ssh-option', action='append', metavar='OPT', help='extra ssh -o option, e.g. ProxyJump=bastion')
    s.add_argument('--local', action='store_true', help='scan this machine without SSH')
    s.add_argument('--path', action='append', help='index only this subtree (repeatable); default is every eligible mount')
    s.add_argument('--exclude-path', action='append', help='absolute path to skip (repeatable)')
    s.add_argument('--exclude-name', action='append', help='file or directory name glob to skip anywhere (repeatable)')
    s.add_argument('--no-default-excludes', action='store_true',
                   help=f'do not skip {", ".join(DEFAULT_EXCLUDE_PATHS + DEFAULT_EXCLUDE_NAMES)}')
    s.add_argument('--include-network', action='store_true', help='also walk NFS/SMB/rclone/sshfs mounts')
    s.add_argument('--include-tmpfs', action='store_true')
    s.add_argument('--include-fstype', action='append', metavar='FS', help='walk a normally skipped type, e.g. overlay')
    s.add_argument('--parallel', type=int, default=4, help='concurrent find streams per host (default 4)')
    s.add_argument('--batch-size', type=int, default=20_000)
    s.add_argument('--checksum', action='store_true', help='sha256 files whose size collides with another file')
    s.add_argument('--checksum-min-size', type=size_arg, default=1 << 20, metavar='SIZE')
    s.add_argument('--max-delete-ratio', type=float, default=0.5,
                   help='refuse a diff that deletes more than this share of a mount (default 0.5)')
    s.add_argument('--no-nice', action='store_true', help='do not run find under nice/ionice')
    s.add_argument('--dry-run', action='store_true', help='show the mount plan and find commands, write nothing')
    s.add_argument('--json', action='store_true', help='print a JSON summary per host')
    s.set_defaults(fn=cmd_scan)

    q = sub.add_parser('search', help='find files across every indexed host')
    q.add_argument('pattern', nargs='?', help='shell-style name pattern, e.g. "*.cr2" or "IMG_2019*"')
    q.add_argument('--name', help='same as the positional pattern')
    q.add_argument('--host', action='append', help='limit to host (repeatable)')
    q.add_argument('--size-gt', '--min-size', dest='size_gt', type=size_arg, metavar='SIZE')
    q.add_argument('--size-lt', '--max-size', dest='size_lt', type=size_arg, metavar='SIZE')
    q.add_argument('--type', choices=['f', 'd', 'l'], help='file, directory or symlink')
    q.add_argument('--ext', action='append', help='extension(s), comma separated')
    q.add_argument('--under', help='only below this directory')
    q.add_argument('--path-contains', help='substring of the directory path')
    q.add_argument('--newer-than', type=parse_age, metavar='AGE', help='modified within, e.g. 7d')
    q.add_argument('--older-than', type=parse_age, metavar='AGE', help='not modified for, e.g. 1y')
    q.add_argument('--sort', choices=['path', 'name', 'size', 'mtime', 'host'], default='path')
    q.add_argument('--desc', action='store_true')
    q.add_argument('--limit', type=int, default=100)
    q.add_argument('--format', choices=['table', 'json', 'paths'], default='table')
    q.set_defaults(fn=cmd_search)

    c = sub.add_parser('changes', help='files added, modified or deleted in a scan')
    c.add_argument('--host', required=True)
    c.add_argument('--scan', type=int, help='scan id (default: latest)')
    c.add_argument('--limit', type=int, default=200)
    c.add_argument('--format', choices=['table', 'json'], default='table')
    c.set_defaults(fn=cmd_changes)

    d = sub.add_parser('dupes', help='identical files found by --checksum scans')
    d.add_argument('--host')
    d.add_argument('--min-size', type=size_arg, default=1 << 20, metavar='SIZE')
    d.add_argument('--limit', type=int, default=50)
    d.add_argument('--format', choices=['table', 'json'], default='table')
    d.set_defaults(fn=cmd_dupes)

    fo = sub.add_parser('folders', help='duplicate folders by name and structure (no checksums needed)')
    fo.add_argument('--host')
    fo.add_argument('--min-files', type=int, default=3)
    fo.add_argument('--min-size', type=size_arg, default=1 << 20, metavar='SIZE')
    fo.add_argument('--limit', type=int, default=50)
    fo.add_argument('--include-system', action='store_true', help='also compare /usr, /var/lib, node_modules and similar')
    fo.add_argument('--format', choices=['table', 'json'], default='table')
    fo.set_defaults(fn=cmd_folders)

    ac = sub.add_parser('access', help='read-only scan access: status, and the setup script to run as root')
    acs = ac.add_subparsers(dest='access_cmd', required=True)
    a1 = acs.add_parser('status', help='folders the latest scans could not read')
    a1.add_argument('--host')
    a1.add_argument('--limit', type=int, default=50)
    a2 = acs.add_parser('script', help='print the setup script; pipe it to: ssh admin@host sudo sh')
    a2.add_argument('--host', help="use this host's bound scan user")
    a2.add_argument('--user', help='scan user name')
    a2.add_argument('--remove', action='store_true', help='print the removal script instead')
    ac.set_defaults(fn=cmd_access)

    mv = sub.add_parser('moves', help='data move plans: list, check against the index, write the rsync script')
    mvs = mv.add_subparsers(dest='moves_cmd', required=True)
    mvs.add_parser('list')
    m1 = mvs.add_parser('check'); m1.add_argument('id', type=int)
    m2 = mvs.add_parser('script', help='write the Bash script that runs the plan')
    m2.add_argument('id', type=int)
    m2.add_argument('-o', '--output', help='file to write (default stdout); made executable')
    m3 = mvs.add_parser('import', help='save a plan from a JSON file ({"name", "steps": [...]})')
    m3.add_argument('file'); m3.add_argument('--id', type=int, help='replace this plan')
    mv.set_defaults(fn=cmd_moves)

    ta = sub.add_parser('tasks', help='storage tasks: list, check against the index, write the Bash script')
    tas = ta.add_subparsers(dest='tasks_cmd', required=True)
    tas.add_parser('list')
    t1 = tas.add_parser('check'); t1.add_argument('id', type=int)
    t2 = tas.add_parser('script', help='write the Bash script that runs the task')
    t2.add_argument('id', type=int)
    t2.add_argument('-o', '--output', help='file to write (default stdout); made executable')
    t3 = tas.add_parser('import', help='save a task from a JSON file ({"name", "host", "blocks": [...]})')
    t3.add_argument('file'); t3.add_argument('--id', type=int, help='replace this task')
    ta.set_defaults(fn=cmd_tasks)

    gi = sub.add_parser('git', help='git repositories found by scans: state, copies and archives')
    gi.add_argument('--host')
    gi.add_argument('--format', choices=['table', 'json'], default='table')
    gi.set_defaults(fn=cmd_git)

    sh = sub.add_parser('shares', help="deploy the NFS/SMB shares in a host's design")
    shs = sh.add_subparsers(dest='shares_cmd', required=True)
    s1 = shs.add_parser('check'); s1.add_argument('host')
    s2 = shs.add_parser('script', help='write the deploy script (server + client mounts)')
    s2.add_argument('host'); s2.add_argument('-o', '--output')
    sh.set_defaults(fn=cmd_shares)

    ch = sub.add_parser('plan', help='staged change plans for folders, btrfs, mounts and drives (not "changes": that is file changes)')
    chs = ch.add_subparsers(dest='changes_cmd', required=True)
    chs.add_parser('list'); chs.add_parser('types', help='task types and their fields')
    c1 = chs.add_parser('check'); c1.add_argument('id', type=int)
    for kind in ('script', 'ansible'):
        c2 = chs.add_parser(kind, help=f'write the plan as {"a Bash script" if kind == "script" else "an Ansible playbook"}')
        c2.add_argument('id', type=int); c2.add_argument('-o', '--output')
    c3 = chs.add_parser('import', help='save a plan from a JSON file ({"name", "tasks": [...]})')
    c3.add_argument('file'); c3.add_argument('--id', type=int, help='replace this plan')
    ch.set_defaults(fn=cmd_plan)

    dp = sub.add_parser('deploy', help='deploy access, deployed jobs and their state, drift and alerts')
    dps = dp.add_subparsers(dest='deploy_cmd', required=True)
    dps.add_parser('status', help='hosts, jobs with their last runs, drift')
    d1 = dps.add_parser('setup-script', help='the deploy setup script, to run as root on a host')
    d1.add_argument('--remove', action='store_true', help='the script that removes it instead')
    dps.add_parser('alerts', help='evaluate alerts now (and notify); exit 1 while any are open')
    dp.set_defaults(fn=cmd_deploy)

    dk = sub.add_parser('docker', help='containers, compose stacks and the folders they use')
    dk.add_argument('--host')
    dk.add_argument('--path', help='which containers use this folder (needs --host)')
    dk.set_defaults(fn=cmd_docker)

    bk = sub.add_parser('backup', help='database backups (essentials by default: keys, bindings, users, designs, plans, audit)')
    bks = bk.add_subparsers(dest='backup_cmd')
    b1 = bks.add_parser('create', help='write a backup now (the default)')
    bks.add_parser('list', help='backups on disk').add_argument('--dir', help='backup folder')
    for x in (bk, b1):
        x.add_argument('--full', action='store_true', help='the whole database, file index included (large)')
        x.add_argument('--keep', type=int, help='then delete the oldest of that kind beyond this many')
        x.add_argument('--dir', help='backup folder (default $STORAGEFORGE_BACKUP_DIR or <data>/backups)')
    bk.set_defaults(fn=cmd_backup, backup_cmd='create')

    hc = sub.add_parser('config', help='host configuration history and the reinstall script (mounts, accounts, shares, symlinks)')
    hcs = hc.add_subparsers(dest='config_cmd', required=True)
    hcs.add_parser('list', help='saved versions: the newest of every host, or all of one').add_argument('host', nargs='?')
    h1 = hcs.add_parser('diff', help='what changed between two versions')
    h1.add_argument('old', type=int)
    h1.add_argument('new', type=int)
    h2 = hcs.add_parser('script', help='write the reinstall script of a host')
    h2.add_argument('host', nargs='?')
    h2.add_argument('--id', type=int, help='an older version (see config list)')
    h2.add_argument('-o', '--output', help='file to write (default: print it)')
    h3 = hcs.add_parser('export', help='a .tar.gz of reinstall scripts, records and config files, to keep somewhere else')
    h3.add_argument('host', nargs='?', help='one host (default: all)')
    h3.add_argument('--id', type=int, help='an older version')
    h3.add_argument('-o', '--output', required=True)
    hc.set_defaults(fn=cmd_config)

    rs = sub.add_parser('restore', help='replace the database with a backup (stop the server first)')
    rs.add_argument('file')
    rs.add_argument('--yes', action='store_true', help='really replace it')
    rs.set_defaults(fn=cmd_restore)

    st = sub.add_parser('site', help='which client this database belongs to')
    sts = st.add_subparsers(dest='site_cmd')
    sts.add_parser('show', help='its name and id (the default)')
    sts.add_parser('rename', help='change its name').add_argument('name')
    st.set_defaults(fn=cmd_site, site_cmd='show')

    rt = sub.add_parser('reset', help='archive this site and start a new one: new database, vault and vault secret (stop the server first)')
    rt.add_argument('--site-name', required=True, help='the new site, usually the client')
    rt.add_argument('--archive', help='folder for the old site, outside the data and backup folders (default $STORAGEFORGE_ARCHIVE_DIR)')
    rt.add_argument('--abandon-deployed', action='store_true', help='go ahead although jobs and schedules are still on the old machines')
    rt.add_argument('--yes', action='store_true', help='really do it')
    rt.set_defaults(fn=cmd_reset)

    pr = sub.add_parser('prune', help='drop old change history and job rows (also runs after every scan)')
    pr.add_argument('--days', type=int, help='keep file changes this many days (default $STORAGEFORGE_CHANGE_DAYS or 90)')
    pr.add_argument('--max-rows', type=int, help='and at most this many change rows, oldest scans dropped first '
                                                 '(default $STORAGEFORGE_CHANGE_MAX_ROWS or 2000000)')
    pr.add_argument('--vacuum', action='store_true', help='then shrink the file (slow, locks the database)')
    pr.set_defaults(fn=cmd_prune)

    h = sub.add_parser('hosts', help='list indexed hosts')
    hs = h.add_subparsers(dest='hosts_cmd')
    rk = hs.add_parser('rekey', help='a host was reinstalled or moved: forget its pinned SSH host keys (scan it right after)')
    rk.add_argument('name')
    rk.add_argument('--port', type=int, default=22, help='its SSH port, to drop that known_hosts line too')
    rm = hs.add_parser('remove', help='retire a host: drop its index, graph, scan jobs, bindings and design')
    rm.add_argument('name')
    rm.add_argument('--keep-design', action='store_true', help='keep its saved design')
    h.set_defaults(fn=cmd_hosts)

    def report_opts(x):
        x.add_argument('--title', help='system or network name for the report heading')
        x.add_argument('--as-of', metavar='YYYY-MM-DD', help='date used for backup-age checks (default today)')
        x.add_argument('--kwh-price', type=float, help='electricity price per kWh for the cost estimate')
        x.add_argument('--currency', default='', help='currency symbol for the cost estimate, e.g. $ or €')
        x.add_argument('--idle-share', type=float, default=0.75, help='share of time drives sit idle (default 0.75)')
        x.add_argument('--output', '-o', help='write to a file instead of stdout')

    e = sub.add_parser('export-markdown', help='architecture report for indexed host(s)')
    e.add_argument('--host', action='append', help='host to include (repeatable; default: all)')
    e.add_argument('--blueprint', action='append', help='StorageForge blueprint to overlay (tiers, links, protection)')
    report_opts(e)
    e.set_defaults(fn=cmd_export_markdown)

    r = sub.add_parser('report', help='architecture report from saved payloads, no index needed')
    r.add_argument('--blueprint', help='StorageForge blueprint JSON or YAML')
    r.add_argument('--lsblk', help='output of lsblk -J -b')
    r.add_argument('--fstab', help='/etc/fstab')
    r.add_argument('--df', help='output of df -h or df -B1 -P')
    r.add_argument('--zpool-status', help='output of zpool status')
    r.add_argument('--hostname', help='host name when the payload does not carry one')
    report_opts(r)
    r.set_defaults(fn=cmd_report)

    def payload_opts(x):
        x.add_argument('--blueprint', help='StorageForge blueprint JSON or YAML')
        x.add_argument('--lsblk', help='output of lsblk -J -b')
        x.add_argument('--fstab', help='/etc/fstab')
        x.add_argument('--df', help='output of df -h or df -B1 -P')
        x.add_argument('--zpool-status', help='output of zpool status')
        x.add_argument('--hostname', help='host name when the payload does not carry one')
        x.add_argument('--as-of', metavar='YYYY-MM-DD')

    v = sub.add_parser('vault', help='encrypted SSH key vault and host bindings')
    vs = v.add_subparsers(dest='vault_cmd', required=True)
    vs.add_parser('init', help='create the vault (needs STORAGEFORGE_VAULT_SECRET)')
    vs.add_parser('status', help='check the secret unlocks the vault')
    x = vs.add_parser('add', help='import a private key (file or - for stdin)')
    x.add_argument('--name', required=True)
    x.add_argument('--key-file', required=True)
    x.add_argument('--passphrase-env', metavar='VAR', help='environment variable holding the key passphrase')
    x.add_argument('--comment')
    x = vs.add_parser('generate', help='create a new key inside the vault and print its public key')
    x.add_argument('--name', required=True)
    x.add_argument('--type', choices=['ed25519', 'rsa'], default='ed25519')
    x.add_argument('--comment')
    vs.add_parser('list', help='list keys (fingerprints only)')
    x = vs.add_parser('pubkey', help='print a public key for authorized_keys')
    x.add_argument('--name', required=True)
    x = vs.add_parser('remove', help='delete a key and its bindings')
    x.add_argument('--name', required=True)
    x = vs.add_parser('bind', help='allow a key to reach a host, glob or CIDR')
    x.add_argument('--key', required=True)
    x.add_argument('--host', required=True, help='nas-02, *.tail4c2e.ts.net or 10.0.20.0/24')
    x.add_argument('--user', required=True)
    x.add_argument('--port', type=int, default=22)
    x.add_argument('--actions', default='scan', help='comma list: scan, checksum')
    x.add_argument('--priority', type=int, default=100, help='lower wins among equally specific bindings')
    x = vs.add_parser('unbind')
    x.add_argument('--id', type=int, required=True)
    vs.add_parser('bindings', help='list host bindings')
    x = vs.add_parser('resolve', help='show which key and user a host would use')
    x.add_argument('--host', required=True)
    x.add_argument('--action', default='scan')
    vs.add_parser('policy', help="show or set where this site's keys may come from").add_argument(
        'policy', nargs='?', choices=('generate-only', 'open'), help='generate-only: refuse imported keys')
    vs.add_parser('rotate-secret', help='rewrap all keys under STORAGEFORGE_VAULT_NEW_SECRET')
    x = vs.add_parser('import-dir', help='import every private key file in a directory (name = file stem)')
    x.add_argument('dir')
    v.set_defaults(fn=cmd_vault)

    lg = sub.add_parser('log', help='what has been done: audit log, deploys, scans and task runs in one list')
    lg.add_argument('--host', help='only this host')
    lg.add_argument('--source', help='comma-separated: audit, deploy, scan, task, schedule, hostlog')
    lg.add_argument('--outcome', help='comma-separated: ok, warn, failed, denied, info, running')
    lg.add_argument('--grep', help='only entries holding this text')
    lg.add_argument('--since', help='unix seconds or a date like 2026-10-30')
    lg.add_argument('--until', help='unix seconds or a date like 2026-10-30 (the whole day)')
    lg.add_argument('--limit', type=int, default=100)
    lg.add_argument('--format', choices=['text', 'csv', 'json'], default='text')
    lg.add_argument('--with-output', action='store_true', help='include the full output of deploy runs and fetched logs')
    lg.add_argument('-o', '--output', help='write to this file instead of the terminal')
    lg.set_defaults(fn=cmd_log)

    a = sub.add_parser('audit', help='append-only audit log')
    asub = a.add_subparsers(dest='audit_cmd', required=True)
    x = asub.add_parser('tail')
    x.add_argument('--limit', type=int, default=50)
    x.add_argument('--format', choices=['table', 'json'], default='table')
    asub.add_parser('verify', help='check the HMAC hash chain')
    a.set_defaults(fn=cmd_audit)

    g = sub.add_parser('graph', help='storage topology graph')
    gs = g.add_subparsers(dest='graph_cmd', required=True)
    x = gs.add_parser('build', help='rebuild the graph for indexed host(s)')
    x.add_argument('--host', action='append')
    x = gs.add_parser('import', help='build a host graph from payload files (no scan)')
    payload_opts(x)
    gs.add_parser('stats')
    g.set_defaults(fn=cmd_graph)

    c = sub.add_parser('canvas', help='export the graph as an Obsidian .canvas file')
    c.add_argument('--host', help='one host and its direct neighbours (default: everything)')
    c.add_argument('--output', '-o')
    c.set_defaults(fn=cmd_canvas)

    b = sub.add_parser('blueprint', help='store a StorageForge blueprint to overlay on scans')
    b.add_argument('file')
    b.set_defaults(fn=cmd_blueprint)

    m = sub.add_parser('migrate', help='apply database migrations')
    m.set_defaults(fn=cmd_migrate)

    sv = sub.add_parser('serve', help='HTTP API and graph UI')
    sv.add_argument('--listen', default=os.environ.get('STORAGEFORGE_LISTEN', '127.0.0.1'))
    sv.add_argument('--port', type=int, default=int(os.environ.get('STORAGEFORGE_PORT', '8080')))
    sv.add_argument('--scan-interval', default=os.environ.get('STORAGEFORGE_SCAN_INTERVAL'),
                    metavar='AGE', help='rescan every host bound in the vault, e.g. 6h')
    sv.add_argument('--parallel', type=int, default=4)
    sv.set_defaults(fn=cmd_serve)

    u = sub.add_parser('user', help='web UI accounts')
    us = u.add_subparsers(dest='user_cmd', required=True)
    us.add_parser('list', help='list accounts')
    for name, text in (('add', 'create an account (prompts for a password, or reads one line from stdin)'),
                       ('passwd', 'change a password and sign out its sessions')):
        x = us.add_parser(name, help=text)
        x.add_argument('name')
        x.add_argument('--password-env', metavar='VAR', help='read the password from this environment variable')
        if name == 'add':
            x.add_argument('--role', default='admin', help='a built-in or custom role')
    ro = us.add_parser('role', help='set what an account may do')
    ro.add_argument('name'); ro.add_argument('new_role', help='a built-in or custom role')
    for name, text in (('disable', 'block sign-in and sign out its sessions'), ('enable', 'allow sign-in again'),
                       ('remove', 'delete an account'), ('signout', 'end every web session of an account')):
        us.add_parser(name, help=text).add_argument('name')
    u.set_defaults(fn=cmd_user)

    sc = sub.add_parser('schedule', help='unified task scheduler across all storageforge operations')
    scs = sc.add_subparsers(dest='schedule_cmd', required=True)

    scl = scs.add_parser('list', help='list schedules')
    scl.add_argument('--host')
    scl.add_argument('--type', choices=['task', 'change', 'move', 'shares', 'scan', 'command'])
    scl.add_argument('--paused', action='store_true')
    scl.add_argument('--json', action='store_true')

    sca = scs.add_parser('add', help='create a new schedule')
    sca.add_argument('--name', required=True)
    sca.add_argument('--host', required=True)
    sca.add_argument('--cron', required=True, help='cron expression e.g. "0 2 * * *" or "*/15 * * * *"')
    sca.add_argument('--type', required=True, choices=['task', 'change', 'move', 'shares', 'scan', 'command'])
    sca.add_argument('--ref', required=True, help='task id/slug, plan id, host name, or command string')
    sca.add_argument('--config', help='JSON string with extra config options')
    sca.add_argument('--paused', action='store_true')
    sca.add_argument('--json', action='store_true')

    scg = scs.add_parser('get', help='get schedule details')
    scg.add_argument('id', type=int)

    scp = scs.add_parser('pause', help='pause a schedule')
    scp.add_argument('id', type=int)

    scr = scs.add_parser('resume', help='resume a schedule')
    scr.add_argument('id', type=int)

    scd = scs.add_parser('remove', help='delete a schedule')
    scd.add_argument('id', type=int)

    sct = scs.add_parser('token', help='generate/rotate auth token for schedule')
    sct.add_argument('id', type=int)

    scu = scs.add_parser('runs', help='view run history and verification results')
    scu.add_argument('--id', type=int)
    scu.add_argument('--host')
    scu.add_argument('--limit', type=int, default=50)
    scu.add_argument('--json', action='store_true')

    scc = scs.add_parser('cron', help='generate /etc/cron.d/ entry')
    scc.add_argument('id', type=int)

    sci = scs.add_parser('install-script', help='generate target host install script')
    sci.add_argument('id', type=int)
    sci.add_argument('--report-url', help='StorageForge report endpoint URL')

    scrun = scs.add_parser('run', help='execute a schedule immediately and verify the result')
    scrun.add_argument('id', type=int)
    scrun.add_argument('--json', action='store_true')

    scver = scs.add_parser('verify', help='re-verify a schedule or specific run against the index')
    scver.add_argument('id', type=int)
    scver.add_argument('--run-id', type=int, help='specific run_id to re-verify')
    scver.add_argument('--json', action='store_true')

    sc.set_defaults(fn=cmd_schedule)

    hc = sub.add_parser('healthcheck', help='probe /healthz (for Docker HEALTHCHECK)')
    hc.add_argument('--url', default=f"http://127.0.0.1:{os.environ.get('STORAGEFORGE_PORT', '8080')}/healthz")
    hc.set_defaults(fn=cmd_healthcheck)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:             # before Exception, which would catch it first
        return 0
    except Exception as exc:
        from .vault import VaultError
        if isinstance(exc, VaultError):
            print(f'error: {exc}', file=sys.stderr)
            return 2
        raise
