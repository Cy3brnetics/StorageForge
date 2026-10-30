"""Deploy NFS and SMB servers from a host's design, and mount the shares on client hosts.

Exports added in the topology view (or the planner) live in the host's saved design. The scan reports the shares a
host already serves; the ones you add are what this deploys. script() writes one Bash script per server, in the
style of storage-setup.sh: a read-only report by default, --apply to make it so, --host to run it elsewhere.

Server side: installs the NFS server or Samba if missing, writes StorageForge's own files
(/etc/exports.d/storageforge.exports, /etc/samba/storageforge.conf, included once from smb.conf), labels SMB paths
for SELinux, opens the firewall (firewalld or ufw) for the clients, and starts the services.
Client side, for each "mount on" entry: installs the mount helper, appends an fstab line (automount, nofail,
_netdev) after a backup, keeps SMB credentials in a 0600 file, and mounts it. Nothing existing is edited: a
different fstab line for the same mount point is a conflict to fix by hand.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shlex

from .db import Conn
from .moves import _subtree_sql, find_host, host_slug, hosts, mount_of
from .payloads import is_designed
from .scriptkit import HELPERS, REMOTE, comments, host_name, one_line

SMB_NAME = re.compile(r'[A-Za-z0-9_.$-]{1,80}')
NFS_DEFAULT = 'rw,sync,no_subtree_check'
NFS_CLIENT = re.compile(r'[A-Za-z0-9.*?:/@_\[\]-]{1,255}')
NFS_OPTION = re.compile(r'rw|ro|sync|async|(no_)?subtree_check|(no_)?root_squash|(no_)?all_squash|anon(uid|gid)=\d{1,10}'
                        r'|secure|insecure|(no_)?wdelay|(no)?crossmnt|nohide|hide|fsid=[A-Za-z0-9-]{1,40}|sec=[a-z0-9:]{1,40}'
                        r'|mp|mountpoint(=/[^,\s()"]*)?|insecure_locks|no_auth_nlm|(no_)?pnfs|(no_)?acl')
# presets offered by the topology editor for one client rule
NFS_PRESETS = {'read-only': 'ro,sync,no_subtree_check', 'read-write': 'rw,sync,no_subtree_check',
               'read-write, root not squashed': 'rw,sync,no_subtree_check,no_root_squash',
               'all users as one owner': 'rw,sync,no_subtree_check,all_squash,anonuid=1000,anongid=1000'}


def proto(e: dict) -> str:
    p = str(e.get('protocol') or e.get('proto') or '').upper()
    return 'SMB' if p.startswith(('SMB', 'CIFS')) else 'NFS' if p.startswith('NFS') else p


def design_exports(conn: Conn, host: str) -> list[dict]:
    from .graph import stored_blueprint
    bp = stored_blueprint(conn, host)
    if not bp:
        raise LookupError(f'{host} has no saved design: add exports in the topology view and save it')
    out = []
    for e in bp.get('exports') or []:
        if not is_designed(e) or proto(e) not in ('NFS', 'SMB'):
            continue
        rules = [{'clients': str(r.get('clients') or '').strip(), 'options': str(r.get('options') or '').strip()}
                 for r in e.get('rules') or [] if str(r.get('clients') or '').strip()]
        if not rules and str(e.get('clients') or '').strip():          # one rule, as designs had before rules
            rules = [{'clients': str(e.get('clients')).strip(), 'options': str(e.get('options') or '').strip()}]
        out.append({'deployed': bool(e.get('fromScan')), 'proto': proto(e), 'name': str(e.get('name') or '').strip(), 'path': str(e.get('path') or '').rstrip('/') or '/',
                    'clients': ' '.join(r['clients'] for r in rules) or str(e.get('clients') or '').strip(),
                    'options': str(e.get('options') or '').strip(), 'rules': rules,
                    'mounts': [{'host': str(m.get('host') or '').strip(), 'path': str(m.get('path') or '').strip()}
                               for m in e.get('mounts') or [] if m.get('host') and m.get('path')]})
    return out


def nfs_options(opts: str) -> str:
    """Checked export options, with sync and no_subtree_check added unless the rule says otherwise."""
    parts = [o.strip() for o in (opts or 'rw').split(',') if o.strip()]
    bad = [o for o in parts if not NFS_OPTION.fullmatch(o)]
    if bad:
        raise ValueError(f'unknown NFS export option(s): {", ".join(bad)}')
    if not {'sync', 'async'} & set(parts):
        parts.append('sync')
    if not {'subtree_check', 'no_subtree_check'} & set(parts):
        parts.append('no_subtree_check')
    return ','.join(parts)


def nfs_rules(e: dict) -> str:
    """The client part of an /etc/exports line: client1(opts1) client2(opts2) ..."""
    out = []
    for r in e['rules']:
        opts = nfs_options(r['options'] or e['options'] or NFS_DEFAULT)
        for c in r['clients'].split():
            if not NFS_CLIENT.fullmatch(c):
                raise ValueError(f'{c!r} is not a host, subnet, wildcard or @netgroup')
            out.append(f'{c}({opts})')
    return ' '.join(out)


def _ids(inv: dict) -> tuple[dict, dict] | None:
    text = inv.get('ids')
    if not text:
        return None
    by_uid, by_name = {}, {}
    for line in text.splitlines():
        kind, _, rest = line.partition(' ')
        name, _, num = rest.partition(' ')
        if kind == 'u' and num.isdigit():
            by_uid[int(num)], by_name[name] = name, int(num)
    return by_uid, by_name


def id_check(conn: Conn, srv: dict, e: dict, clients: list[dict]) -> list[tuple[str, str]]:
    """NFS (sec=sys) trusts numeric UIDs: the owners of an export's files should have the same UID on each client."""
    if all('all_squash' in (r['options'] or '') for r in e['rules']) and e['rules']:
        return [('ok', 'all users are mapped to one owner (all_squash): user IDs do not need to match')]
    inv = lambda h: json.loads(conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']}) or '{}')   # noqa: E731
    mine = _ids(inv(srv))
    if mine is None:
        return [('note', f'rescan {srv["name"]} to check user IDs against the clients')]
    m = mount_of(srv, e['path'])
    if not m or m['state'] != 'indexed':
        return []
    where, params = _subtree_sql(e['path'], m['target'])
    owners = conn.all(f"""SELECT f.owner_uid, count(*) FROM file_records f WHERE {where} AND f.owner_uid >= 1000
                         GROUP BY f.owner_uid ORDER BY 2 DESC LIMIT 8""", {'m': m['id'], **params})
    out = []
    for c in clients:
        theirs = _ids(inv(c))
        if theirs is None:
            out.append(('note', f'rescan {c["name"]} to check its user IDs'))
            continue
        for uid, n in owners:
            name = mine[0].get(uid)
            if name is None:
                out.append(('note', f'{n:,} files are owned by UID {uid}, which has no user on {srv["name"]}'))
            elif name not in theirs[1]:
                out.append(('warn', f'{name} (UID {uid}, owns {n:,} files) has no account on {c["name"]}: they show up there as '
                                    f'{theirs[0].get(uid, "UID " + str(uid))}'))
            elif theirs[1][name] != uid:
                out.append(('warn', f'{name} is UID {uid} on {srv["name"]} but {theirs[1][name]} on {c["name"]}: files they '
                                    f'write from {c["name"]} belong to {mine[0].get(theirs[1][name], "UID " + str(theirs[1][name]))} '
                                    f'on the server (usermod -u, or all_squash)'))
        if owners and not any(x[0] == 'warn' and c['name'] in x[1] for x in out):
            out.append(('ok', f'user IDs of the file owners match on {c["name"]}'))
    return out


def check(conn: Conn, host: str) -> dict:
    hs = hosts(conn)
    srv = find_host(hs, host)
    if not srv:
        raise LookupError(f'{host} has not been scanned')
    exports = design_exports(conn, srv['name'])
    items = check_exports(conn, hs, srv, exports)
    return {'host': srv['name'], 'address': srv['ssh_host'], 'exports': exports, 'items': items,
            'crit': sum(1 for x in items if x['level'] == 'crit'), 'warn': sum(1 for x in items if x['level'] == 'warn')}


def check_exports(conn: Conn, hs: dict, srv: dict, exports: list[dict], only: int | None = None) -> list[dict]:
    """Check a server's exports against the index: the folder, the protocol settings, and each client mount point.
    only: check just that export (the others are still compared against it)."""
    from .fsmap import SYSTEM_DIRS, designed_mounts, mount_kind, path_info, remote_of, same_host
    items = []
    say = lambda i, level, text: items.append({'export': i, 'level': level, 'text': text})   # noqa: E731
    others = [d for d in designed_mounts(conn) if not same_host(d['server'], srv['name'])]
    for i, e in enumerate(exports):
        if only is not None and i != only:
            continue
        if not e['path'].startswith('/') or '\n' in e['path'] or '"' in e['path']:
            say(i, 'crit', f'{e["path"]!r} is not a usable absolute path')
            continue
        info = path_info(conn, srv, e['path'])
        m = info['mount']
        if e['path'] == '/' or any(e['path'] == d or e['path'].startswith(d + '/') for d in ('/proc', '/sys', '/dev', '/run')):
            say(i, 'crit', f'{e["path"]} is a system path: share a data folder instead')
        elif e['path'] in SYSTEM_DIRS:
            say(i, 'warn', f'{e["path"]} is a system folder: clients could change files the OS depends on')
        if not m:
            say(i, 'warn', f'{e["path"]} is not on a scanned mount')
        elif m['kind'] in ('nfs', 'smb', 'sshfs', 'rclone'):
            r = m['remote'] or {}
            say(i, 'crit', f'{e["path"]} is itself a {m["kind"].upper()} mount from {r.get("server", "another host")}: '
                           f'share it from that host instead of re-exporting it')
        elif m['kind'] == 'virtual':
            say(i, 'crit', f'{e["path"]} is on {m["fstype"]}, which is not stored on a disk')
        else:
            say(i, 'ok' if m['target'] != '/' else 'warn',
                f'{e["path"]} is on {m["target"]} ({m["fstype"]}{", " + m["source"] if m["source"] else ""})'
                + ('' if m['target'] != '/' else ': the system disk; a data disk is safer'))
            if info['exists'] is False:
                say(i, 'warn', f'{e["path"]} is not in the index: create it (or rescan) before deploying')
            elif info['entries'] == 0:
                say(i, 'note', f'{e["path"]} is empty in the index')
        for j, o in enumerate(exports):          # duplicates and nesting among this server's shares
            if j == i:
                continue
            if o['proto'] == e['proto'] == 'SMB' and o['name'].lower() == e['name'].lower() and e['name']:
                say(i, 'crit', f'another SMB share on {srv["name"]} is already called {e["name"]}')
            elif o['proto'] == e['proto'] and o['path'] == e['path']:
                say(i, 'crit', f'{e["path"]} is already shared over {e["proto"]} from this host')
            elif o['proto'] == e['proto'] == 'NFS' and (o['path'].startswith(e['path'].rstrip('/') + '/')
                                                        or e['path'].startswith(o['path'].rstrip('/') + '/')):
                say(i, 'warn', f'nested NFS exports ({e["path"]} and {o["path"]}): clients may see different options '
                               f'depending on the path they mount; one export is simpler')
        below = [x for x in info['mounts_below'] if x['kind'] == 'local']
        if below and e['proto'] == 'NFS':
            opts = ' '.join(r['options'] or e['options'] or '' for r in e['rules'])
            names = ', '.join(x['target'] for x in below[:4]) + (' …' if len(below) > 4 else '')
            if 'crossmnt' in opts or 'nohide' in opts:
                say(i, 'ok', f'filesystems mounted inside ({names}) are visible through crossmnt')
            else:
                say(i, 'warn', f'{names} {"is a separate filesystem" if len(below) == 1 else "are separate filesystems"} '
                               f'inside {e["path"]}: clients see empty folders there unless you add crossmnt to the options')
        elif below:
            say(i, 'note', f'{len(below)} filesystem(s) mounted inside are shared too (Samba follows mounts)')
        if e['proto'] == 'NFS':
            if not e['clients']:
                say(i, 'crit', 'NFS needs clients: a subnet like 10.42.0.0/24, or host names. "*" would export to everyone')
            elif '*' in e['clients'].split():
                say(i, 'warn', 'exported to every host that can reach it ("*")')
            try:
                for r in e['rules']:
                    o = nfs_options(r['options'] or e['options'] or NFS_DEFAULT)
                    say(i, 'note', f'{r["clients"]}: {o}')
                    if 'no_root_squash' in o.split(','):
                        say(i, 'warn', f'root on {r["clients"]} is root on this share (no_root_squash)')
                nfs_rules(e)
            except ValueError as exc:
                say(i, 'crit', str(exc))
            clients = [ch for ch in (find_host(hs, mt['host']) for mt in e['mounts']) if ch and ch['id'] != srv['id']]
            for level, text in id_check(conn, srv, e, clients):
                say(i, level, text)
        else:
            if not SMB_NAME.fullmatch(e['name'] or ''):
                say(i, 'crit', 'an SMB share needs a name of letters, digits, . _ - (e.g. media)')
            users = [u for u in e['clients'].split() if not re.match(r'^[\d.:/]+$', u)]
            say(i, 'note', f'Samba accounts needed: {", ".join(users)} (smbpasswd -a <user> on {srv["name"]})' if users
                else 'no valid users set: any Samba account can connect; set clients to user names or @groups to restrict')
        seen = set()
        for mt in e['mounts']:
            ch = find_host(hs, mt['host'])
            target = mt['path'].rstrip('/') or '/'
            if not ch:
                say(i, 'crit', f'client {mt["host"]} has not been scanned')
                continue
            if ch['id'] == srv['id']:
                say(i, 'warn', f'{mt["host"]} is the server itself: use a bind mount or a symlink instead')
                continue
            if not target.startswith('/'):
                say(i, 'crit', f'mount point {mt["path"]!r} on {ch["name"]} must be absolute')
                continue
            if (ch['id'], target) in seen:
                say(i, 'crit', f'{ch["name"]}:{target} is listed twice')
                continue
            seen.add((ch['id'], target))
            where = f'{ch["name"]}:{target}'
            if target in SYSTEM_DIRS:
                say(i, 'crit', f'{where} is a system folder: mounting over it hides what the OS keeps there')
                continue
            used = next((x for x in ch['mounts'] if x['target'] == target and x['state'] != 'gone'), None)
            info_c = path_info(conn, ch, target)
            parent = info_c['mount']
            clash = [d for d in others if same_host(d['host'], ch['name']) and d['target'] == target]
            if clash:
                d = clash[0]
                say(i, 'crit', f'{where} is already the mount point of {d["proto"]} {d["name"] or d["path"]} from {d["server"]}')
            if used:
                r = remote_of(used)
                if r and same_host(r['server'], srv['name']) or r and r['server'] in (srv['ssh_host'],):
                    say(i, 'ok', f'{where} already mounts this server ({used["source"]})')
                elif mount_kind(used) in ('nfs', 'smb'):
                    say(i, 'crit', f'{where} already mounts {used["source"]} ({used["fstype"]}): pick another folder')
                else:
                    say(i, 'crit', f'{where} is where {used["source"] or used["fstype"]} ({used["fstype"]}) is mounted: '
                                   f'mounting the share there would hide that disk')
                continue
            if parent and parent['kind'] in ('nfs', 'smb', 'sshfs', 'rclone'):
                say(i, 'crit', f'{where} is inside the network mount {parent["target"]} ({parent["source"]}): '
                               f'mount shares on a local folder')
                continue
            if info_c['entries']:
                say(i, 'warn', f'{where} holds {info_c["entries"]:,} entries in the index: they are hidden while the share '
                               f'is mounted there (pick an empty folder)')
            elif info_c['exists'] is False:
                say(i, 'ok', f'mounts on {where} (the folder is created)')
            else:
                say(i, 'ok', f'mounts on {where}' + (f' (on {parent["target"]})' if parent and parent['target'] != '/' else ''))
            already = [x for x in ch['mounts'] if x['target'] != target and (remote_of(x) or {}).get('server') in
                       (srv['name'], srv['ssh_host']) and ((remote_of(x) or {}).get('path') == e['path']
                                                           or (remote_of(x) or {}).get('share', '').lower() == e['name'].lower())]
            if already:
                say(i, 'note', f'{ch["name"]} already mounts this share at {already[0]["target"]}')
    return items


def normalize_export(body: dict) -> dict:
    """A share from the wizard, in the design's shape. Raises ValueError for what cannot be saved at all."""
    from .moves import _path
    p = proto(body)
    if p not in ('NFS', 'SMB'):
        raise ValueError('protocol is NFS or SMB')
    protocol = str(body.get('protocol') or ('NFSv4.2' if p == 'NFS' else 'SMB3'))
    path = _path(body.get('path'), 'the shared folder')
    name = str(body.get('name') or '').strip() or (path.rsplit('/', 1)[-1] or 'share')
    if len(name) > 80 or '\n' in name:
        raise ValueError('the share name is too long')
    rules = [{'clients': ' '.join(str(r.get('clients') or '').split()), 'options': str(r.get('options') or '').replace(' ', '')}
             for r in body.get('rules') or [] if str(r.get('clients') or '').strip()]
    mounts = []
    for m in body.get('mounts') or []:
        if not str(m.get('host') or '').strip():
            continue
        mounts.append({'host': host_name(m['host'], 'a client host'), 'path': _path(m.get('path'), f'the mount point on {m["host"]}')})
    out = {'protocol': protocol, 'name': name, 'path': path, 'mounts': mounts}
    if p == 'NFS':
        out.update(rules=rules, clients=' '.join(r['clients'] for r in rules), options='')
    else:
        out.update(clients=' '.join(str(body.get('clients') or '').split()), options=str(body.get('options') or '').strip())
    return out


def _as_checked(e: dict) -> dict:
    return {'deployed': False, 'proto': proto(e), 'name': e['name'], 'path': e['path'].rstrip('/') or '/',
            'clients': e.get('clients') or '', 'options': e.get('options') or '', 'rules': e.get('rules') or [],
            'mounts': e['mounts']}


def validate(conn: Conn, host: str, body: dict, index: int | None = None) -> dict:
    """Check one share before it is saved: the draft takes the place of export #index in the design (or is added)."""
    hs = hosts(conn)
    srv = find_host(hs, host)
    if not srv:
        raise LookupError(f'{host} has not been scanned')
    e = normalize_export(body)
    try:
        exports = design_exports(conn, srv['name'])
    except LookupError:
        exports = []
    from .graph import stored_blueprint
    raw = (stored_blueprint(conn, srv['name']) or {}).get('exports') or []
    if index is not None:                       # design_exports skips scanned/other shares: map the raw index to its slot
        target = raw[index] if 0 <= index < len(raw) else None
        pos = next((k for k, x in enumerate(exports) if target and x['path'] == (str(target.get('path') or '').rstrip('/') or '/')
                    and x['name'] == str(target.get('name') or '').strip()), None)
    else:
        pos = None
    if pos is None:
        exports.append(_as_checked(e))
        pos = len(exports) - 1
    else:
        exports[pos] = _as_checked(e)
    items = check_exports(conn, hs, srv, exports, only=pos)
    return {'host': srv['name'], 'export': e, 'items': [{'level': x['level'], 'text': x['text']} for x in items],
            'crit': sum(1 for x in items if x['level'] == 'crit'), 'warn': sum(1 for x in items if x['level'] == 'warn')}


def save_export(db, conn: Conn, host: str, body: dict, index: int | None, actor: str) -> dict:
    """Add the share to the host's saved design (starting one from the scan if there is none), or replace #index."""
    from . import blueprint, graph
    hs = hosts(conn)
    srv = find_host(hs, host)
    if not srv:
        raise LookupError(f'{host} has not been scanned')
    e = normalize_export(body)
    e['designed'] = True
    bp = graph.stored_blueprint(conn, srv['name']) or blueprint.from_index(conn, srv['name'])
    exports = bp.setdefault('exports', [])
    if index is not None:
        if not 0 <= index < len(exports):
            raise LookupError(f'{srv["name"]} has no share #{index}')
        old = exports[index]
        if old.get('fromScan'):                 # editing a share the scan found: keep it marked as deployed
            e['fromScan'] = True
        exports[index] = {**{k: v for k, v in old.items() if k not in ('rules', 'clients', 'options', 'mounts')}, **e}
    else:
        exports.append(e)
        index = len(exports) - 1
    bp.setdefault('metadata', {})['host'] = (bp.get('metadata') or {}).get('host') or srv['name']
    graph.store_blueprint(conn, bp)
    graph.rebuild_host(db, conn, srv['name'])
    return {'host': srv['name'], 'index': index, 'export': exports[index]}


def remove_export(db, conn: Conn, host: str, index: int) -> dict:
    from . import graph
    bp = graph.stored_blueprint(conn, host)
    exports = (bp or {}).get('exports') or []
    if not 0 <= index < len(exports):
        raise LookupError(f'{host} has no share #{index}')
    if exports[index].get('fromScan'):
        raise ValueError('this share was found by the scan: remove it on the host, the next scan drops it')
    gone = exports.pop(index)
    graph.store_blueprint(conn, bp)
    graph.rebuild_host(db, conn, bp['metadata']['host'])
    return {'removed': gone}


def script(conn: Conn, host: str, prev_clients: list[str] | None = None) -> str:
    """prev_clients: hosts the last deployment mounted shares on; they run the cleanup even when the design dropped them."""
    c = check(conn, host)
    hs = hosts(conn)
    q = shlex.quote
    e_arrays = {k: [] for k in ('E_PROTO', 'E_NAME', 'E_PATH', 'E_CLIENTS', 'E_OPTS', 'E_RULES')}
    c_arrays = {k: [] for k in ('C_HOST', 'C_TARGET', 'C_PROTO', 'C_SOURCE', 'C_NAME')}
    lines = []
    for e in c['exports']:
        for k, v in (('E_PROTO', e['proto']), ('E_NAME', e['name'] or e['path']), ('E_PATH', e['path']),
                     ('E_CLIENTS', e['clients']), ('E_OPTS', e['options'] or (NFS_DEFAULT if e['proto'] == 'NFS' else 'rw')),
                     ('E_RULES', nfs_rules(e) if e['proto'] == 'NFS' and e['clients'] else '')):
            e_arrays[k].append(v)
        lines.append(f'#   {e["proto"]} {e["name"] if e["proto"] == "SMB" else e["path"]}  ({e["path"]} → {e["clients"] or "anyone"})')
        for mt in e['mounts']:
            ch = find_host(hs, mt['host'])
            src = f'{c["address"]}:{e["path"]}' if e['proto'] == 'NFS' else f'//{c["address"]}/{e["name"]}'
            for k, v in (('C_HOST', host_slug(ch['name'] if ch else mt['host'])), ('C_TARGET', mt['path']),
                         ('C_PROTO', e['proto']), ('C_SOURCE', src), ('C_NAME', e['name'] or 'share')):
                c_arrays[k].append(v)
            lines.append(f'#       mounted on {mt["host"]}:{mt["path"]}')
    problems = [f'#   {x["level"].upper()}: {x["text"]}' for x in c['items'] if x['level'] in ('crit', 'warn')]
    decl = '\n'.join(f'{k}=({" ".join(q(v) for v in vs)})' for k, vs in {**e_arrays, **c_arrays}.items())
    return (SHARES_HEAD.format(host=one_line(c['host']), slug=host_slug(c['host']), date=dt.datetime.now().strftime('%Y-%m-%d %H:%M'),
                               shares=comments(lines, '#   (no exports in the design)'), problems=comments(problems, '#   none'))
            + f'SERVER={q(host_slug(c["host"]))}\nSERVER_ADDR={q(c["address"])}\n{decl}\n'
            + f'PREV_CLIENTS=({" ".join(q(host_slug(h)) for h in prev_clients or [])})\n'
            + SHARES_BODY_1 + HELPERS + SHARES_BODY_2 + REMOTE + SHARES_BODY_3)


def deploy_items(db, conn: Conn, host: str, mode: str, actor: str) -> list[dict]:
    """deploy.start_group items: the server, then every client it mounts on now or did at the last deployment."""
    from . import deploy
    c = check(conn, host)
    srv, hs = c['host'], hosts(conn)
    prev = next((d['detail'].get('clients') or [] for d in deploy.deployed(conn, host=srv, kind='shares') if d['ref'] == srv), [])
    clients = sorted({ch['name'] for ch in (find_host(hs, mt['host']) for e in c['exports'] for mt in e['mounts'])
                      if ch and ch['name'] != srv})
    text = script(conn, srv, prev)
    digest = design_hash(conn, srv)

    def done(_res):
        c2 = db.connect()
        try:
            deploy.mark_deployed(c2, srv, 'shares', srv, digest, {'clients': clients}, actor)
        finally:
            c2.close()
    args = ['--apply'] if mode == 'apply' else []
    items = [{'host': srv, 'script': text, 'args': args + ['--only', 'server'], 'kind': 'shares', 'ref': srv, 'mode': mode,
              **({'on_ok': done} if mode == 'apply' else {})}]
    for h in sorted(set(clients) | (set(prev) - {srv})):
        items.append({'host': h, 'script': text, 'args': args + ['--only', 'clients'], 'kind': 'shares', 'ref': srv, 'mode': mode})
    return items


def design_hash(conn: Conn, host: str) -> str | None:
    """A fingerprint of the host's designed shares: a deployment whose hash differs has changes not deployed yet."""
    try:
        return hashlib.sha256(json.dumps(design_exports(conn, host), sort_keys=True).encode()).hexdigest()[:16]
    except LookupError:
        return None


SHARES_HEAD = r"""#!/usr/bin/env bash
# shares-{slug}.sh — StorageForge share deployment for {host}, generated {date}.
#
# Shares from the saved design:
{shares}
#
# What StorageForge flagged when this was generated:
{problems}
#
#   ./shares-{slug}.sh            report: packages, config files, services, firewall, client mounts (read-only)
#   sudo ./shares-{slug}.sh --apply   install what is missing, write StorageForge's config files, start services,
#                                     open the firewall, add client fstab lines and mount
#   --only server|clients        one side only        --host [user@]host   run on that machine instead
#
# Run it on the server and on each client (or from here with --host). It writes only its own files
# (/etc/exports.d/storageforge.exports, /etc/samba/storageforge.conf, /etc/samba/credentials/*) and appends to
# smb.conf (one include line) and fstab (after a backup). It never edits or removes existing lines.
set -euo pipefail

"""

SHARES_BODY_1 = r"""
MODE=report; ONLY=; HOST=; ARGS=("$@")
while (($#)); do
  case $1 in
    --report) MODE=report ;; --apply) MODE=apply ;;
    --only) ONLY=${2:?--only server or clients}; shift ;;
    --host) HOST=${2:?--host needs [user@]host}; shift ;;
    --forward-agent) FWD_AGENT=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
"""

SHARES_BODY_2 = r"""
"""

SHARES_BODY_3 = r"""
set -f          # client lists hold "*" and @groups: split them on spaces, never glob them
ME=$(host_slug "$(uname -n)")
APPLY=0; [[ $MODE == apply ]] && APPLY=1
if ((APPLY)) && [[ $EUID -ne 0 ]]; then echo "--apply needs root: sudo $0 ${ARGS[*]}" >&2; exit 1; fi
STAMP=$(date +%Y%m%d-%H%M%S)

pm() { for m in apt-get dnf zypper pacman; do command -v $m >/dev/null && { echo $m; return; }; done; echo none; }
install_pkg() { # apt-name rpm-name arch-name
  local m; m=$(pm)
  case $m in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1" >/dev/null ;;
    dnf) dnf install -y -q "$2" >/dev/null ;; zypper) zypper -nq install "$2" >/dev/null ;; pacman) pacman -S --needed --noconfirm "$3" >/dev/null ;;
    *) conflict "no package manager I know: install $2 yourself"; return 1 ;;
  esac
}
need_cmd() { # command what apt rpm arch
  if command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  if ((APPLY)); then doing "install $2"; install_pkg "$3" "$4" "$5" && ok "$2 installed"; else missing "$2 (package $3 / $4)"; fi
}
backup() { [[ -e $1 ]] && cp -a -- "$1" "$1.storageforge-$STAMP"; }
own_file() { # path content -> StorageForge's own file: written whole (after a backup) when it differs
  if [[ -e $1 && $(cat "$1") == "$2" ]]; then ok "$1"; return 1; fi
  if ((APPLY)); then mkdir -p "$(dirname "$1")"; backup "$1"; printf '%s\n' "$2" >"$1"; doing "wrote $1"; return 0
  else missing "$1 $([[ -e $1 ]] && echo '(differs)')"; return 1; fi
}
service_on() { # unit...
  local u
  for u; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && break; done
  if systemctl is-active -q "$u" && systemctl is-enabled -q "$u" 2>/dev/null; then ok "$u running and enabled"; return; fi
  if ((APPLY)); then doing "systemctl enable --now $u"; systemctl enable --now "$u"; else missing "$u not running/enabled"; fi
}
cidrs() { tr ' ' '\n' <<<"$1" | grep -E '^[0-9.:]+(/[0-9]+)?$' || true; }
open_fw() { # label tcp-ports clients firewalld-services...
  local label=$1 ports=$2 clients=$3; shift 3
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    local s; for s; do
      if firewall-cmd --query-service="$s" >/dev/null 2>&1; then ok "firewalld allows $s"
      elif ((APPLY)); then doing "firewalld: allow $s"; firewall-cmd -q --permanent --add-service="$s"; firewall-cmd -q --reload
      else missing "firewalld does not allow $s"; fi
    done
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    local from p c; from=$(cidrs "$clients"); [[ -n $from ]] || from=any
    for c in $from; do for p in $ports; do
      if ufw status | grep -qE "^$p/tcp +ALLOW +(IN +)?$([[ $c == any ]] && echo Anywhere || echo "${c//./\\.}")"; then ok "ufw allows $p/tcp from $c"
      elif ((APPLY)); then doing "ufw allow from $c to any port $p proto tcp"; ufw allow from "$c" to any port "$p" proto tcp >/dev/null
      else missing "ufw does not allow $p/tcp from $c ($label)"; fi
    done; done
  else info "no active firewalld or ufw: nothing to open for $label"; fi
}

server_nfs() {
  local i body="# StorageForge NFS exports for $(uname -n). Written by shares-$SERVER.sh; edit the design, not this file."
  if [[ " ${E_PROTO[*]} " != *" NFS "* ]]; then      # no NFS shares left: empty StorageForge's exports, if there are any
    if [[ -s /etc/exports.d/storageforge.exports ]] && grep -qv '^#' /etc/exports.d/storageforge.exports; then
      section "NFS server"; own_file /etc/exports.d/storageforge.exports "$body" && ((APPLY)) && { doing "exportfs -ra"; exportfs -ra; }
    fi
    return 0
  fi
  section "NFS server"
  for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == NFS ]] || continue
    local line; line=$(printf '"%s"' "${E_PATH[$i]}")
    line+=" ${E_RULES[$i]}"
    body+=$'\n'"$line"
    if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi
  done
  need_cmd exportfs "NFS server" nfs-kernel-server nfs-utils nfs-utils || return 0
  own_file /etc/exports.d/storageforge.exports "$body" && ((APPLY)) && { doing "exportfs -ra"; exportfs -ra; }
  service_on nfs-server nfs-kernel-server
  open_fw NFS "2049 111" "$(printf '%s ' "${E_CLIENTS[@]}")" nfs mountd rpc-bind
  if command -v exportfs >/dev/null; then
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == NFS ]] || continue
      if exportfs -s 2>/dev/null | grep -qF "${E_PATH[$i]}"; then ok "exported: ${E_PATH[$i]}"; elif ((!APPLY)); then missing "not exported yet: ${E_PATH[$i]}"; else conflict "${E_PATH[$i]} is not exported after exportfs -ra"; fi
    done
  fi
}
server_smb() {
  local i body="# StorageForge Samba shares for $(uname -n). Written by shares-$SERVER.sh; edit the design, not this file."
  if [[ " ${E_PROTO[*]} " != *" SMB "* ]]; then
    if [[ -s /etc/samba/storageforge.conf ]] && grep -q '^\[' /etc/samba/storageforge.conf; then
      section "SMB server (Samba)"; own_file /etc/samba/storageforge.conf "$body" && ((APPLY)) && { systemctl reload smb smbd 2>/dev/null || true; }
    fi
    return 0
  fi
  section "SMB server (Samba)"
  for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
    local users=() hostsallow=() c
    for c in ${E_CLIENTS[$i]}; do if [[ $c =~ ^[0-9.:]+(/[0-9]+)?$ ]]; then hostsallow+=("$c"); else users+=("$c"); fi; done
    body+=$'\n'"[${E_NAME[$i]}]"$'\n'"   path = ${E_PATH[$i]}"$'\n'"   browseable = yes"
    body+=$'\n'"   read only = $([[ ${E_OPTS[$i]} == *ro* ]] && echo yes || echo no)"
    ((${#users[@]})) && body+=$'\n'"   valid users = ${users[*]}"
    ((${#hostsallow[@]})) && body+=$'\n'"   hosts allow = ${hostsallow[*]} 127.0.0.1"
    if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi
  done
  need_cmd smbd "Samba" samba samba samba || return 0
  local changed=0; own_file /etc/samba/storageforge.conf "$body" && changed=1
  local inc='include = /etc/samba/storageforge.conf'
  if [[ ! -e /etc/samba/smb.conf ]]; then
    if ((APPLY)); then printf '[global]\n   workgroup = WORKGROUP\n   server role = standalone server\n   map to guest = never\n\n%s\n' "$inc" >/etc/samba/smb.conf; doing "wrote a minimal /etc/samba/smb.conf"; changed=1
    else missing "/etc/samba/smb.conf"; fi
  elif grep -qF "$inc" /etc/samba/smb.conf; then ok "smb.conf includes storageforge.conf"
  elif ((APPLY)); then backup /etc/samba/smb.conf; printf '\n# added by StorageForge\n%s\n' "$inc" >>/etc/samba/smb.conf; doing "appended the include to smb.conf"; changed=1
  else missing "smb.conf does not include storageforge.conf yet"; fi
  if command -v testparm >/dev/null && [[ -e /etc/samba/smb.conf ]]; then
    if testparm -s >/dev/null 2>&1; then ok "testparm: config is valid"; else conflict "testparm rejects the config: testparm -s"; fi
  fi
  if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
      if ls -Zd "${E_PATH[$i]}" 2>/dev/null | grep -q samba_share_t; then ok "SELinux: ${E_PATH[$i]} is samba_share_t"
      elif ((APPLY)); then doing "SELinux: label ${E_PATH[$i]} samba_share_t"
        if command -v semanage >/dev/null; then semanage fcontext -a -t samba_share_t "${E_PATH[$i]}(/.*)?" 2>/dev/null || true; restorecon -R "${E_PATH[$i]}"
        else chcon -R -t samba_share_t "${E_PATH[$i]}"; fi
      else missing "SELinux would block Samba from ${E_PATH[$i]} (needs samba_share_t)"; fi
    done
  fi
  service_on smb smbd
  ((APPLY && changed)) && systemctl reload smb smbd 2>/dev/null || true
  open_fw SMB "445 139" "$(printf '%s ' "${E_CLIENTS[@]}")" samba
  if command -v pdbedit >/dev/null; then
    local known u; known=$(pdbedit -L 2>/dev/null | cut -d: -f1)
    for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == SMB ]] || continue
      for u in ${E_CLIENTS[$i]}; do [[ $u == @* || $u =~ ^[0-9.:/]+$ ]] && continue
        if grep -qx "$u" <<<"$known"; then ok "Samba account $u"; else missing "Samba account $u: sudo smbpasswd -a $u (sets its SMB password)"; fi
      done
    done
  fi
}

client_mount() { # index into C_*
  local i=$1 t=${C_TARGET[$1]} line opts
  section "mount ${C_SOURCE[$i]} at $t"
  if [[ ${C_PROTO[$i]} == NFS ]]; then
    need_cmd mount.nfs "NFS client" nfs-common nfs-utils nfs-utils || return 0
    line="${C_SOURCE[$i]// /\\040} ${t// /\\040} nfs4 _netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=30 0 0"
  else
    need_cmd mount.cifs "SMB client" cifs-utils cifs-utils cifs-utils || return 0
    local cred=/etc/samba/credentials/$SERVER-${C_NAME[$i]} who=${SUDO_USER:-root}
    if [[ -s $cred ]]; then ok "credentials $cred"
    elif ((APPLY)) && [[ -t 0 ]]; then
      local u p; read -r -p "  Samba user for ${C_SOURCE[$i]}: " u; read -r -s -p "  password: " p; echo
      mkdir -p /etc/samba/credentials; chmod 700 /etc/samba/credentials
      ( umask 077; printf 'username=%s\npassword=%s\n' "$u" "$p" >"$cred" ); unset p; doing "wrote $cred (0600)"
    else missing "credentials $cred (--apply asks for them; or write username=/password= lines, chmod 600)"; return 0; fi
    line="${C_SOURCE[$i]// /\\040} ${t// /\\040} cifs credentials=$cred,uid=$(id -u "$who"),gid=$(id -g "$who"),iocharset=utf8,_netdev,nofail,x-systemd.automount 0 0"
  fi
  local have; have=$(awk -v t="${t// /\\040}" '!/^[[:space:]]*#/ && $2 == t' /etc/fstab)
  if [[ $have == "$line" ]]; then ok "fstab line"
  elif [[ -n $have && $(awk '{print $1, $3}' <<<"$have") == "$(awk '{print $1, $3}' <<<"$line")" ]]; then ok "fstab line (its own options kept)"
  elif [[ -n $have ]]; then conflict "fstab already has a different line for $t: $have"
  elif ((APPLY)); then
    backup /etc/fstab; mkdir -p "$t"; printf '# storageforge share %s:%s\n%s\n' "$SERVER" "$t" "$line" >>/etc/fstab; doing "appended to /etc/fstab"
    if ! findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1; then conflict "findmnt --verify complains about /etc/fstab; the backup is /etc/fstab.storageforge-$STAMP"; return 1; fi
    systemctl daemon-reload
  else missing "fstab: $line"; fi
  if mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then doing "mount $t"; mount "$t" && ok "mounted" || conflict "mount $t failed"
  else missing "not mounted"; fi
  WANT_LINES+=("$line")
}
client_cleanup() { # StorageForge's fstab lines for this server that the design no longer has
  local keep=" " i t line marker removed=0
  for i in "${!C_HOST[@]}"; do [[ ${C_HOST[$i]} == "$ME" ]] && keep+="${C_TARGET[$i]} "; done
  section "shares from $SERVER no longer in the design"
  while IFS= read -r marker; do
    t=${marker#"# storageforge share $SERVER:"}
    [[ $keep == *" $t "* ]] && continue
    removed=1
    line=$(awk -v m="$marker" 'found { print; exit } $0 == m { found = 1 }' /etc/fstab)
    if ((!APPLY)); then missing "would unmount $t and remove its fstab line: $line"; continue; fi
    if mountpoint -q "$t"; then
      systemctl stop "$(systemd-escape -p --suffix=automount "$t")" 2>/dev/null || true
      umount "$t" 2>/dev/null || { conflict "$t is in use: not removed (close what uses it, then deploy again)"; continue; }
    fi
    systemctl stop "$(systemd-escape -p --suffix=automount "$t")" 2>/dev/null || true
    backup /etc/fstab
    awk -v m="$marker" 'skip { skip = 0; next } $0 == m { skip = 1; next } { print }' /etc/fstab >/etc/fstab.storageforge-new \
      && cat /etc/fstab.storageforge-new >/etc/fstab && rm -f /etc/fstab.storageforge-new
    systemctl daemon-reload
    rmdir -- "$t" 2>/dev/null || true
    doing "unmounted $t and removed its fstab line (backup: /etc/fstab.storageforge-$STAMP)"
  done < <(grep -F "# storageforge share $SERVER:" /etc/fstab 2>/dev/null || true)
  ((removed)) || ok "nothing to remove"
}
record_managed() { # what this run wrote, for drift checks in later scans
  ((APPLY)) || return 0
  local d=/var/lib/storageforge/managed f files=()
  mkdir -p "$d"; chmod 0755 "$d"
  if [[ $ME == "$SERVER" ]]; then
    for f in /etc/exports.d/storageforge.exports /etc/samba/storageforge.conf; do [[ -r $f ]] && files+=("$f"); done
    if ((${#files[@]})); then sha256sum "${files[@]}" >"$d/shares-$SERVER.sha256"; chmod 0644 "$d/shares-$SERVER.sha256"; fi
  fi
  if ((${#WANT_LINES[@]})); then printf '%s\n' "${WANT_LINES[@]}" >"$d/shares-$SERVER.lines"; chmod 0644 "$d/shares-$SERVER.lines"
  else rm -f "$d/shares-$SERVER.lines"; fi
}
WANT_LINES=()

echo "${H}shares for $SERVER${N0} · $MODE on $(uname -n)"
if [[ $ONLY != clients ]]; then
  if [[ $ME == "$SERVER" ]]; then server_nfs; server_smb
  else section "server"; skip "the shares are served by $SERVER: ./$(basename "$0") --host <user>@$SERVER_ADDR ${ARGS[*]}"; fi
fi
if [[ $ONLY != server ]]; then
  for i in "${!C_HOST[@]}"; do
    if [[ ${C_HOST[$i]} == "$ME" ]]; then client_mount "$i" || true
    else section "mount ${C_SOURCE[$i]} at ${C_TARGET[$i]}"; skip "client ${C_HOST[$i]}: run this script there (or --host)"; fi
  done
  if [[ " ${C_HOST[*]} ${PREV_CLIENTS[*]} " == *" $ME "* ]]; then client_cleanup || true; fi
fi
record_managed
echo
if ((PROBLEMS)); then echo "${R}$PROBLEMS problem(s)${N0}"; exit 1; fi
echo "${G}done${N0}"
"""
