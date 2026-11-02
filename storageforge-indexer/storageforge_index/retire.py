"""Retire a host: it leaves search, the graph, the scheduler and the alerts. The audit log keeps what happened to it,
and deploy history stays. A remote node's tunnel is cut with it. Refused while anything is deployed there or a scan is running: remove those first."""
from __future__ import annotations

from . import remotes
from .db import Conn


def blockers(conn: Conn, name: str) -> list[str]:
    out = [f'{kind} {ref} is deployed there' for kind, ref in conn.all(
        'SELECT kind, ref FROM deployed WHERE lower(host) = lower(:h)', {'h': name})]
    out += [f'job {j} runs on it or reads from it' for (j,) in conn.all(
        """SELECT name FROM jobs WHERE removed_at IS NULL AND (lower(runner_host) = lower(:h) OR lower(source_host) = lower(:h))""", {'h': name})]
    out += [f'schedule {s} runs on it' for (s,) in conn.all('SELECT name FROM schedules WHERE lower(host) = lower(:h)', {'h': name})]
    if conn.scalar("SELECT 1 FROM scan_jobs WHERE host = :h AND status IN ('queued', 'running')", {'h': name}):
        out.append('a scan of it is queued or running')
    return out


def retire(conn: Conn, name: str, keep_design: bool = False) -> dict:
    """Returns what went. LookupError when no such host, ValueError (with the reasons) when something still needs it."""
    rows = conn.all('SELECT host_id, ssh_host FROM hosts WHERE lower(hostname) = lower(:h)', {'h': name})
    if not rows:
        raise LookupError(f'{name} is not an indexed host')
    host_id, ssh_host = rows[0]
    if why := blockers(conn, name):
        raise ValueError(f'{name} is still in use: ' + '; '.join(why))
    out = {}
    with conn.tx():
        if conn.dialect == 'sqlite':       # the search index is not tied to file_records by a foreign key
            conn.execute("""INSERT INTO file_fts (file_fts, rowid, filename)
                            SELECT 'delete', f.file_id, f.filename FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id
                            WHERE m.host_id = :i""", {'i': host_id})
        out['bindings'] = conn.execute("""DELETE FROM key_bindings WHERE pattern_kind = 'host'
                                          AND host_pattern IN (:h, :s)""", {'h': name, 's': ssh_host or name}).rowcount     # not the IP it reports: another host can have that address
        access = conn.all('SELECT state FROM deploy_access WHERE lower(host) = lower(:h)', {'h': name})
        if access and access[0][0] != 'removed':
            out['still_on_host'] = 'its storageforge-deploy account and runner stay on the machine, but nothing here can use them: remove them there'
        conn.execute('DELETE FROM deploy_access WHERE lower(host) = lower(:h)', {'h': name})
        out['graph_nodes'] = conn.execute('DELETE FROM graph_nodes WHERE lower(host) = lower(:h)', {'h': name}).rowcount
        out['clamav'] = conn.execute('DELETE FROM clamav_detections WHERE lower(host) = lower(:h)', {'h': name}).rowcount
        conn.execute('DELETE FROM clamav_runs WHERE lower(host) = lower(:h)', {'h': name})
        conn.execute('DELETE FROM settings WHERE key = :k', {'k': f'clamav.host:{name.lower()}'})
        out['scan_jobs'] = conn.execute('DELETE FROM scan_jobs WHERE lower(host) = lower(:h)', {'h': name}).rowcount
        if not keep_design:
            out['design'] = conn.execute('DELETE FROM blueprints WHERE lower(hostname) = lower(:h)', {'h': name}).rowcount
        node = remotes.retired(conn, ssh_host)
        if node:
            out['remote_node'] = node
        conn.execute('DELETE FROM hosts WHERE host_id = :i', {'i': host_id})
    if node:
        remotes.sync(conn, drop_sessions=True)
    return out
