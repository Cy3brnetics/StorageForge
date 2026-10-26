"""storageforge-index: agentless file indexing over SSH, fast search, and architecture reports."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
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
        local = args.local or host in ('localhost', '127.0.0.1', '::1') and not args.user and not args.key
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


def cmd_hosts(args) -> int:
    _, conn = open_db(args)
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
    _write(render_report(nodes, **_report_kwargs(args)), args.output)
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
    from .vault import Vault, secret_from_env
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
                print(f'{k["name"]:<20} {k["type"]:<12} {k["fingerprint"]}  {k["bindings"]} binding(s){state}')
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
        elif a == 'rotate-secret':
            new = os.environ.get('STORAGEFORGE_VAULT_NEW_SECRET', '')
            if len(new) < 32:
                raise SystemExit('Set STORAGEFORGE_VAULT_NEW_SECRET (≥ 32 characters) to the new secret')
            n = v.rotate_secret(new.encode())
            _audit(db, conn, v, 'vault.rotate-secret', rewrapped=n)
            print(f'rewrapped {n} key(s); switch STORAGEFORGE_VAULT_SECRET to the new value now')
        elif a == 'import-dir':
            known = {r[0] for r in conn.all('SELECT name FROM ssh_keys')}
            for f in sorted(Path(args.dir).iterdir()):
                if f.suffix in ('.pub', '.md', '.txt') or not f.is_file() or f.name.startswith('.'):
                    continue
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


def cmd_audit(args) -> int:
    from .vault import AuditLog, Vault, VaultError
    db, conn = open_db(args)
    if args.audit_cmd == 'verify':
        try:
            with Vault(db, conn).unlock() as v:
                ok, n, bad = AuditLog(db, conn, v.audit_key).verify()
        except VaultError as exc:
            raise SystemExit(f'cannot verify HMAC entries: {exc}')
        print(f'audit chain {"intact" if ok else "BROKEN at entry #" + str(bad)} · {n} entries verified')
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
            for name, created, last, disabled in users.listing(conn):
                print(f'{name:<24} created {when(created)}  last login {when(last)}{"  DISABLED" if disabled else ""}')
            return 0
        if a == 'add':
            users.create(conn, args.name, _new_password(args))
        elif a == 'passwd':
            users.set_password(conn, args.name, _new_password(args))
        elif a in ('disable', 'enable'):
            users.set_disabled(conn, args.name, a == 'disable')
        elif a == 'remove':
            users.remove(conn, args.name)
    except users.UserError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    try:   # HMAC-chain the entry when the vault secret is available, plain SHA-256 otherwise
        with Vault(db, conn).unlock() as v:
            _audit(db, conn, v, f'user.{a}', username=args.name)
    except VaultError:
        _audit(db, conn, None, f'user.{a}', username=args.name)
    print({'add': 'created', 'passwd': 'password changed for', 'disable': 'disabled', 'enable': 'enabled',
           'remove': 'removed'}[a] + f' user {args.name}' + (' (existing sessions signed out)' if a in ('passwd', 'disable') else ''))
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

    h = sub.add_parser('hosts', help='list indexed hosts')
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
    vs.add_parser('rotate-secret', help='rewrap all keys under STORAGEFORGE_VAULT_NEW_SECRET')
    x = vs.add_parser('import-dir', help='import every private key file in a directory (name = file stem)')
    x.add_argument('dir')
    v.set_defaults(fn=cmd_vault)

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
    for name, text in (('disable', 'block sign-in and sign out its sessions'), ('enable', 'allow sign-in again'),
                       ('remove', 'delete an account')):
        us.add_parser(name, help=text).add_argument('name')
    u.set_defaults(fn=cmd_user)

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
    except Exception as exc:
        from .vault import VaultError
        if isinstance(exc, VaultError):
            print(f'error: {exc}', file=sys.stderr)
            return 2
        raise
    except BrokenPipeError:
        return 0
