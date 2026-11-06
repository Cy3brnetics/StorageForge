"""Saved versions of a planner design: named, timestamped copies of a host's storageforge/v1 blueprint (UX-38, roadmap 3g).

A version is the whole blueprint as it was, kept as JSON, so it can be shown, compared with the current design in plain words and put
back without the versions before it. Restoring first keeps the current design as an automatic version, so nothing is lost by it.
Nothing here changes what a design means: the blueprint a version holds went through the same checks as a saved design (blueprint.check_text,
protection.as_typed), and a restore writes it through the same two calls the planner's own save does (graph.store_blueprint and the graph
rebuild). Limits: MAX_VERSIONS per host, MAX_BYTES for one and MAX_HOST_BYTES for a host's all together.
"""
from __future__ import annotations

import json
import re
import time

from . import blueprint, graph, protection

MAX_VERSIONS = 50                # per host, automatic ones included
MAX_BYTES = 2 << 20              # one version: as large as the biggest design the planner saves
MAX_HOST_BYTES = 40 << 20        # a host's versions together
MAX_NAME, MAX_NOTE = 80, 500
MAX_CHANGES = 500                # what a comparison lists; the rest is counted


def _blueprint(bp) -> dict:
    if not isinstance(bp, dict) or bp.get('apiVersion') != 'storageforge/v1' or bp.get('kind') != 'StorageBlueprint':
        raise ValueError('expected a storageforge/v1 StorageBlueprint')
    bp = json.loads(json.dumps(bp))                  # a copy: the caller's dict stays as it was
    if bp.get('protection'):                         # a design as loaded carries job names, which hold arrows: never part of a save
        bp['protection'] = protection.as_typed(bp['protection'])
    blueprint.check_text(bp)
    name = str((bp.get('metadata') or {}).get('host') or '').strip()
    if not name or len(name) > 253 or any(c.isspace() for c in name):
        raise ValueError('metadata.host must be a hostname')
    return bp


def _text(value, what: str, limit: int) -> str:
    text = str(value or '').strip()
    if len(text) > limit:
        raise ValueError(f'{what} is longer than {limit} characters')
    if blueprint.UNSAFE_TEXT.search(text):
        raise ValueError(f'{what} has a line break, control character or one of < > " `')
    return text


def _host(host) -> str:
    host = str(host or '').strip()
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError('give host')
    return host


def canonical(bp: dict) -> str:
    """The design without what changes on every save (the date it was generated), for telling whether two are the same."""
    bp = json.loads(json.dumps(bp))
    (bp.get('metadata') or {}).pop('generated', None)
    return json.dumps(bp, sort_keys=True)


META = 'id, host, name, note, author, auto, size_bytes, created_at'


def _meta(row) -> dict:
    return {'id': row[0], 'host': row[1], 'name': row[2], 'note': row[3], 'author': row[4], 'auto': bool(row[5]),
            'size_bytes': row[6], 'created_at': row[7]}


def list_versions(conn, host: str) -> list[dict]:
    """Newest first, without the designs themselves."""
    return [_meta(r) for r in conn.all(f'SELECT {META} FROM design_versions WHERE host = :h ORDER BY id DESC', {'h': _host(host)})]


def get(conn, version_id: int) -> dict:
    rows = conn.all(f'SELECT {META}, body_json FROM design_versions WHERE id = :i', {'i': version_id})
    if not rows:
        raise LookupError(f'no saved version #{version_id}')
    return {**_meta(rows[0]), 'blueprint': json.loads(rows[0][8])}


def _make_room(conn, host: str, size: int) -> None:
    """Drops the oldest automatic versions until one more of this size fits; never a version someone saved by hand."""
    while True:
        count, total = conn.all('SELECT count(*), coalesce(sum(size_bytes), 0) FROM design_versions WHERE host = :h', {'h': host})[0]
        if count < MAX_VERSIONS and total + size <= MAX_HOST_BYTES:
            return
        oldest = conn.scalar('SELECT min(id) FROM design_versions WHERE host = :h AND auto = 1', {'h': host})
        if oldest is None:
            why = f'{count} saved versions' if count >= MAX_VERSIONS else 'saved versions that take too much room'
            raise ValueError(f'{host} already has {why} (at most {MAX_VERSIONS}, {MAX_HOST_BYTES >> 20} MiB). Delete one first.')
        conn.execute('DELETE FROM design_versions WHERE id = :i', {'i': oldest})


def save(conn, host: str, bp: dict, actor: str, name: str = '', note: str = '', auto: bool = False) -> dict:
    """Keeps bp as a version of host's design. Returns it as list() shows it."""
    host = _host(host)
    bp = _blueprint(bp)
    body = json.dumps(bp)
    if len(body) > MAX_BYTES:
        raise ValueError(f'that design is too large to keep as a version (over {MAX_BYTES >> 20} MiB)')
    name, note = _text(name, 'the name', MAX_NAME), _text(note, 'the note', MAX_NOTE)
    _make_room(conn, host, len(body))
    if not name:
        name = f'Version {conn.scalar("SELECT count(*) FROM design_versions WHERE host = :h AND auto = 0", {"h": host}) + 1}'
    vid = conn.scalar("""INSERT INTO design_versions (host, name, note, author, auto, body_json, size_bytes, created_at)
                         VALUES (:h, :n, :o, :a, :u, :b, :s, :t) RETURNING id""",
                      {'h': host, 'n': name, 'o': note, 'a': actor, 'u': int(auto), 'b': body, 's': len(body), 't': int(time.time())})
    return next(v for v in list_versions(conn, host) if v['id'] == vid)


def delete(conn, version_id: int) -> dict:
    v = get(conn, version_id)
    conn.execute('DELETE FROM design_versions WHERE id = :i', {'i': version_id})
    return {k: v[k] for k in ('id', 'host', 'name')}


def apply(db, conn, bp: dict) -> dict:
    """Makes bp the host's saved design, as the planner's own save does: stored, then overlaid on the host's graph (or the whole graph
    of a planned host). Returns what the graph came to."""
    host = bp['metadata']['host']
    if 'layout' not in bp:                          # a version from the planner page carries no topology layout: keep the saved one
        kept = (graph.stored_blueprint(conn, host) or {}).get('layout')
        if kept:
            bp['layout'] = kept
    graph.store_blueprint(conn, bp)
    if conn.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
        return dict(zip(('nodes', 'edges'), graph.rebuild_host(db, conn, host)))
    from .payloads import node_from_blueprint
    nodes, edges = graph.build(node_from_blueprint(bp))
    graph.save(db, conn, host, nodes, edges)
    return {'nodes': len(nodes), 'edges': len(edges)}


def restore(db, conn, version_id: int, actor: str, current: dict | None = None) -> dict:
    """Puts a version back as the host's saved design. The design it replaces, which is `current` (what the person has on screen, saved or
    not) or else the saved one, is kept first as an automatic version, unless a version already holds exactly that. If it cannot be kept
    the restore does not happen."""
    v = get(conn, version_id)
    host = v['host']
    bp = _blueprint(v['blueprint'])                 # checked again: this is what gets written
    now = _blueprint(current) if current is not None else graph.stored_blueprint(conn, host)
    kept = None
    if now is not None:
        newest = conn.all('SELECT body_json FROM design_versions WHERE host = :h ORDER BY id DESC LIMIT 1', {'h': host})
        if not newest or canonical(json.loads(newest[0][0])) != canonical(now):
            kept = save(conn, host, now, actor, name=f'Before restoring {v["name"]}'[:MAX_NAME], auto=True,
                        note=f'Kept automatically when {actor} restored “{v["name"]}”.'[:MAX_NOTE])
    return {'restored': {k: v[k] for k in ('id', 'host', 'name')}, 'kept': kept, 'saved_at': int(time.time()), 'graph': apply(db, conn, bp)}


# ── comparing a version with a design, in words ─────────────────────────────────────
# What the planner works out from the rest of a design, or only labels it with: a change in these is not a change somebody made.
IGNORE = {'status', 'health', 'fromScan', 'usableBytes', 'levelSource', 'id', 'uuid', 'startMiB', 'deployed', 'hand', 'capacity', 'raw',
          'partitions', 'datasets', 'subvolumes', 'startBytes'}
WORDS = {'sizeBytes': 'size', 'fs': 'filesystem', 'opts': 'options', 'table': 'partition table', 'level': 'RAID level', 'member': 'member of',
         'mount': 'mount point', 'dev': 'device', 'sector': 'sector sizes', 'ashift': 'ashift', 'protocol': 'protocol', 'via': 'reached through',
         'ephemeral': 'left out of backups as temporary', 'sync': 'sync', 'snapshots': 'snapshots', 'backup': 'backup', 'clients': 'allowed clients',
         'spec': 'device spec', 'source': 'source', 'target': 'points at', 'kind': 'kind', 'media': 'media', 'bus': 'bus', 'tier': 'tier'}


def _word(field: str) -> str:
    return WORDS.get(field) or re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', field).lower()


def _size(n: float) -> str:
    u, i = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'], 0
    while abs(n) >= 1024 and i < len(u) - 1:
        n /= 1024
        i += 1
    return f'{n:.0f} {u[i]}' if i < 2 else f'{n:.2f} {u[i]}'


def _show(field: str, value) -> str:
    if value is None or value == '' or value == [] or value == {}:
        return 'none'
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, (int, float)):
        return _size(value) if field.endswith('Bytes') else str(value)
    if isinstance(value, list):
        return ', '.join(_show(field, x) for x in value)
    if isinstance(value, dict):
        return ', '.join(f'{_word(k)} {_show(k, v)}' for k, v in sorted(value.items()) if v is not None) or 'none'
    return str(value)


def _fields(obj: dict, only: tuple | None = None) -> dict:
    return {k: v for k, v in obj.items() if k not in IGNORE and (only is None or k in only)}


def _sections(bp: dict) -> dict[str, dict[str, tuple[str, dict]]]:
    """Kind of thing, then a key that names it in both designs, then how to call it and what it holds."""
    out: dict[str, dict] = {k: {} for k in ('Drive', 'Partition', 'Subvolume', 'Pool', 'Dataset', 'Mount', 'Remote', 'Link', 'Share', 'Protection', 'Setting')}

    def put(kind, key, label, fields):
        key, n = str(key), 1
        while key in out[kind]:                        # two things with one name: keep both, in order
            n += 1
            key = f'{key}#{n}'
        out[kind][key] = (label, fields)
    for d in bp.get('devices') or []:
        dev = str(d.get('dev') or '')
        put('Drive', dev, f'{dev}', _fields(d))
        for p in d.get('partitions') or []:
            pid = str(p.get('id') or f'{dev}{p.get("num")}')
            put('Partition', pid, pid, _fields(p))
            for s in p.get('subvolumes') or []:
                put('Subvolume', f'{pid}/{s.get("name")}', f'{s.get("name")} on {pid}', _fields(s))
    for p in bp.get('pools') or []:
        name = str(p.get('name') or '')
        put('Pool', name, name, _fields(p))
        for ds in p.get('datasets') or []:
            put('Dataset', f'{name}/{ds.get("name")}', f'{name}/{ds.get("name")}', _fields(ds))
    for m in bp.get('mounts') or []:
        put('Mount', m.get('target'), str(m.get('target')), _fields(m))
    for r in bp.get('remotes') or []:
        put('Remote', f'{r.get("endpoint")} at {r.get("mount")}', f'{r.get("endpoint") or r.get("name")} at {r.get("mount")}', _fields(r))
    for ln in bp.get('links') or []:
        put('Link', ln.get('path'), str(ln.get('path')), _fields(ln))
    for e in bp.get('exports') or []:
        put('Share', f'{e.get("protocol")} {e.get("name")}', f'{e.get("name")} ({e.get("protocol")})', _fields(e))
    for r in bp.get('protection') or []:
        what = r.get('dataset') or r.get('node') or r.get('path')
        put('Protection', r.get('node') or what, f'of {what}', _fields(r))
    ident = (bp.get('metadata') or {}).get('identifiers')
    if ident is not None:
        put('Setting', 'identifiers', 'fstab identifiers', {'identifiers': ident})
    return out


def _brief(fields: dict) -> str:
    bits = [f'{_word(k)} {_show(k, v)}' for k, v in fields.items() if v not in (None, '', [], {})]
    return ', '.join(bits[:4])


def compare(version: dict, current: dict) -> dict:
    """What is different between a saved version's design and the current one, as sentences. `only_version` is what restoring would bring
    back, `only_current` what it would take away, and `different` what it would put as the version had it."""
    a, b = _sections(version), _sections(current)
    changes: list[dict] = []
    for kind in a:
        for key, (label, fields) in a[kind].items():
            if key not in b[kind]:
                brief = _brief(fields)
                changes.append({'change': 'only_version', 'kind': kind, 'name': label,
                                'text': f'{kind} {label} is in this version only' + (f' ({brief})' if brief else '')})
                continue
            other = b[kind][key][1]
            rows = [{'field': _word(f), 'version': _show(f, fields.get(f)), 'current': _show(f, other.get(f))}
                    for f in sorted(set(fields) | set(other)) if fields.get(f) != other.get(f)]
            if rows:
                changes.append({'change': 'different', 'kind': kind, 'name': label, 'fields': rows,
                                'text': f'{kind} {label}: ' + '; '.join(f'{r["field"]} is {r["version"]} in this version and {r["current"]} now' for r in rows)})
        for key, (label, fields) in b[kind].items():
            if key not in a[kind]:
                brief = _brief(fields)
                changes.append({'change': 'only_current', 'kind': kind, 'name': label,
                                'text': f'{kind} {label} is in the current design only' + (f' ({brief})' if brief else '')})
    n = {c: sum(1 for x in changes if x['change'] == c) for c in ('only_version', 'only_current', 'different')}
    same = not changes
    parts = [f'{n["only_version"]} in this version only' if n['only_version'] else '', f'{n["only_current"]} in the current design only' if n['only_current'] else '',
             f'{n["different"]} that differ' if n['different'] else '']
    return {'same': same, 'counts': n, 'summary': 'This version and the current design hold the same things.' if same else ', '.join(p for p in parts if p).capitalize() + '.',
            'changes': changes[:MAX_CHANGES], 'truncated': max(0, len(changes) - MAX_CHANGES)}


def compare_with(conn, version_id: int, current: dict | None = None) -> dict:
    """A version against the design given, or else the host's saved one."""
    v = get(conn, version_id)
    now = _blueprint(current) if current is not None else graph.stored_blueprint(conn, v['host'])
    if now is None:
        raise ValueError(f'{v["host"]} has no saved design to compare with: save it first, or send the design on screen')
    return {'version': {k: v[k] for k in ('id', 'host', 'name', 'note', 'author', 'auto', 'created_at')}, **compare(v['blueprint'], now)}
