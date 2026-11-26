"""One read of a platform connection: the token released, the read-back of what it can do, then what the platform's reader takes (apipve,
apipbs, apipdm), stored as platform_objects in place of the last read. A failure of any kind is recorded on the connection, cleaned of the
token, and the objects of the last good read stay until the next good one. A certificate that changes in the middle of a read fails the whole read,
whichever call met it and whatever the reader did with the error.

tick() reads each connection whose certificate a person accepted, once every INTERVAL, from the server's background thread."""
from __future__ import annotations

import importlib
import json
import time

from . import apiconn, apireadback
from .db import Conn, loads

INTERVAL = 3600
READERS = {'pve': 'apipve', 'pbs': 'apipbs', 'pdm': 'apipdm'}


def reader(kind: str):
    from . import apiguide
    name = READERS.get(kind) or apiguide.PLATFORMS.get(kind)
    if not name:
        return None
    try:
        return importlib.import_module(f'.{name}', __package__)
    except ModuleNotFoundError:
        return None


def store_objects(conn: Conn, conn_id: int, objects: list[tuple[str, str, dict]], now: int) -> dict:
    counts: dict[str, int] = {}
    seen = set()
    with conn.tx():
        conn.execute('DELETE FROM platform_objects WHERE conn_id = :i', {'i': conn_id})
        for kind, ref, data in objects:
            if (kind, ref) in seen:
                continue
            seen.add((kind, ref))
            conn.execute('INSERT INTO platform_objects (conn_id, kind, ref, data_json, read_at) VALUES (:i, :k, :r, :d, :t)',
                         {'i': conn_id, 'k': kind, 'r': str(ref)[:300], 'd': json.dumps(data, sort_keys=True, default=str), 't': now})
            counts[kind] = counts.get(kind, 0) + 1
    return counts


def objects(conn: Conn, conn_id: int | None = None, kind: str | None = None) -> list[dict]:
    where, args = [], {}
    if conn_id is not None:
        where.append('o.conn_id = :i')
        args['i'] = int(conn_id)
    if kind:
        where.append('o.kind = :k')
        args['k'] = kind
    rows = conn.all(f"""SELECT o.conn_id, c.name, c.kind, c.host, o.kind, o.ref, o.data_json, o.read_at FROM platform_objects o
                        JOIN platform_connections c ON c.conn_id = o.conn_id {'WHERE ' + ' AND '.join(where) if where else ''}
                        ORDER BY c.name, o.kind, o.ref""", args)
    return [{'conn_id': r[0], 'connection': r[1], 'platform': r[2], 'host': r[3], 'kind': r[4], 'ref': r[5], **(loads(r[6]) or {}), 'read_at': r[7]} for r in rows]


def read(db, conn: Conn, row: dict) -> dict:
    """{'readback': ..., 'counts': {kind: n}, 'skipped': [what was not read and why]}. Raises apiconn.ApiError (recorded) on failure."""
    now = int(time.time())
    try:
        with apiconn.open_client(db, conn, row) as client:
            rb = apireadback.readback(client, row)
            if client.fatal:             # a read-back forgives some errors, and a reader writes one down as a skipped line: not this one
                raise client.fatal
            apireadback.store(conn, row, rb)
            mod = reader(row['kind'])
            got, skipped = (mod.read(client, row, rb) if mod else ([], ['no reader for this platform yet']))
            if client.fatal:
                raise client.fatal
    except Exception as exc:
        if not isinstance(exc, apiconn.ApiError):
            exc = apiconn.ApiError(apiconn._clean(f'{type(exc).__name__}: {exc}'))
        apiconn.record_failure(conn, row, exc)
        raise exc from None
    counts = store_objects(conn, row['conn_id'], got, now)
    conn.execute("UPDATE platform_connections SET read_ok = 1, read_error = :e, read_at = :t WHERE conn_id = :i",
                 {'e': '; '.join(skipped)[:300], 't': now, 'i': row['conn_id']})
    return {'readback': rb, 'counts': counts, 'skipped': skipped}


def tick(db) -> int:
    conn = db.connect()
    done = 0
    try:
        for row in apiconn.listing(conn):
            if row['state'] in ('certificate-unaccepted', 'certificate-changed'):
                continue
            if row['read_at'] and time.time() - row['read_at'] < INTERVAL:
                continue
            try:
                read(db, conn, row)
            except apiconn.ApiError:
                pass                     # recorded on the connection, and a notification says so
            done += 1
    finally:
        conn.close()
    return done


def problems(conn: Conn) -> dict:
    """What the readers find worth a notification (a backup whose verification failed, a datastore nearly full)."""
    out = {}
    for row in apiconn.listing(conn):
        mod = reader(row['kind'])
        if mod and hasattr(mod, 'problems'):
            out.update(mod.problems(conn, row, objects(conn, row['conn_id'])))
    return out
