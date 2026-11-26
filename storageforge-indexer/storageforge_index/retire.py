"""Retire a host: it leaves search, the graph and its history, the scheduler and the alerts, and its security readings, ban history,
waivers, retention policies and settings go with it (HOST_TABLES, HOST_SETTINGS). The audit log keeps what happened to it,
and deploy history stays (KEPT). A remote node's tunnel is cut with it. Refused while anything is deployed there or a scan is running: remove those first."""
from __future__ import annotations

from . import remotes
from .db import Conn


# What a host owns and retire removes: (table, the column naming the host, the key its count goes under in what retire returns).
# A waiver or a retention policy for every host has '*' there and stays. tests/test_audit_fixes.py reads the schema and fails
# when a table with a host column is neither here nor in KEPT, nor tied to the hosts row by a cascading foreign key.
HOST_TABLES = (
    ('deploy_access', 'host', None),
    ('graph_nodes', 'host', 'graph_nodes'),
    ('graph_snapshots', 'host', None),                  # the host leaves the map's history too
    ('clamav_detections', 'host', 'clamav'),
    ('clamav_runs', 'host', None),
    ('security_events', 'host', None),
    ('security_measurements', 'host', None),
    ('security_readings', 'host', None),
    ('security_canaries', 'host', None),
    ('security_quarantine', 'host', None),
    ('security_ban_history', 'host', None),
    ('security_retention_holds', 'host', None),
    ('security_retention_policies', 'host', 'retention_policies'),
    ('security_waivers', 'host', 'waivers'),
    ('security_timelock_queue', 'host', None),
    ('host_log_lines', 'host', 'log_lines'),
    ('host_log_status', 'host', None),
    ('scan_jobs', 'host', 'scan_jobs'),
    ('host_design_sections', 'hostname', 'design'),     # unless keep_design
)
# Settings kept per host: the key is the prefix and the host's name. Most are stored in lowercase, the last two as the name was
# given, so the key is compared without regard to case.
HOST_SETTINGS = ('clamav.host:', 'security.host:', 'security.clock:', 'security.profile:', 'security.persistence:', 'security.aide.last:',
                 'security.autoscan:', 'security.drift.', 'security.identity.')
# Tables that name a host and that retire leaves alone, each with why. 'Not decided' marks what is left behind because nobody
# has ruled on it yet, not because it should stay: retiring can't be undone, so each of those moves to HOST_TABLES by a decision.
_HANDLED, _AGENT, _HISTORY, _STATE = (
    'handled in retire() itself: ', 'not decided: part of the agent, which is kept apart from the rest (roadmap 11.2); ',
    'not decided: history that is left behind; ', 'not decided: state that is left behind; ')
KEPT = {
    'hosts': _HANDLED + 'the row itself, deleted last, and its mounts, scans and files go with it by foreign key',
    'key_bindings': _HANDLED + 'bindings whose pattern is the host name or its SSH address go, one for an IP it only reported stays',
    'deployed': _HANDLED + 'retire is refused while a row names the host',
    'jobs': _HANDLED + 'retire is refused while a job that is not removed runs on the host or reads from it',
    'schedules': _HANDLED + 'retire is refused while a schedule runs on the host',
    'schedule_runs': 'belongs to a schedule and goes with it by foreign key, and retire is refused while the host has a schedule',
    'audit_log': 'kept on purpose: the audit log keeps what happened to the host',
    'deploy_runs': 'kept on purpose: deploy history stays',
    'design_versions': 'kept on purpose: the versions of a design are its history, and a design can be kept past its host',
    'blueprint_archive_v1': 'kept on purpose: the archive of designs from before they were stored by section, which nothing writes',
    'ssh_certificates': 'kept on purpose: the revocation list is made from the certificates that were issued',
    'log_rules': 'a rule belongs to the operator: its host is a pattern, * by default, and may match other hosts',
    'notification_mutes': 'a mute belongs to the operator: its host is a shell pattern, * by default, and may match other hosts',
    'platform_connections': 'a connection is to a platform, which is not the host: the column says which scanned host it runs on',
    'alerts': _HISTORY + 'an open alert is resolved by the next pass, when what raised it is gone',
    'agents': _AGENT + 'the pinned key and the manifest counter, which must not start again from 1 if the host comes back',
    'agent_peers': _AGENT + 'the last batch counter taken from the agent, which guards against a replayed batch',
    'agent_deliveries': _AGENT + 'the manifest signed for the host, with its counter',
    'agent_actions': _AGENT + 'what the agent\'s reports caused, revocations among them',
    'agent_console_grants': _AGENT + 'each time a console was turned on for the host, and when it was turned off',
    'agent_records': _AGENT + 'what the agent said and has not been read yet',
    'agent_events': _AGENT + 'the receiver\'s notes, pruned by age',
    'agent_disks': _AGENT + 'disk readings made of what the agent said',
    'agent_file_events': _AGENT + 'file events made of what the agent said',
    'agent_file_reads': _AGENT + 'read counts made of what the agent said, pruned by age',
    'agent_inventory': _AGENT + 'the inventory made of what the agent said',
    'host_logs': _HISTORY + 'logs fetched from the host for a problem a scan found, and the output deploy history shows',
    'host_configs': _HISTORY + 'the versions of the host\'s configuration, kept to rebuild it after a reinstall',
    'task_runs': _HISTORY + 'when the host\'s tasks ran',
    'host_log_counts': _HISTORY + 'log line counts per interval, pruned by age only when the host sends lines',
    'host_log_kinds': _HISTORY + 'the kinds of log line the host has sent',
    'log_rule_hits': _HISTORY + 'matches per rule and host, pruned by age',
    'notification_events': _HISTORY + 'what was notified about the host',
    'security_playbook_runs': _HISTORY + 'what a playbook did on the host',
    'traffic_samples': _HISTORY + 'traffic readings, pruned by age only when the host is read',
    'scan_signatures': _STATE + 'the signature of the host\'s last scan',
    'host_checks': _STATE + 'the result of the last check before a deploy',
    'netconsole_sources': _STATE + 'the address and port the host\'s kernel messages come from',
    'secret_deliveries': _STATE + 'where a secret was delivered, which is where a rotation would send the new value',
    'ssh_ca_hosts': _STATE + 'the host\'s opt in to SSH certificates',
    'workload_captures': _STATE + 'the definitions of workloads adopted on the host',
    'toolbox_installs': _STATE + 'which tools were staged on the host',
    'toolbox_overrides': _STATE + 'the host\'s Toolbox overrides',
    'toolbox_host_roles': _STATE + 'the host\'s Toolbox roles and exclusions',
    'toolbox_status': _STATE + 'each tool\'s last status on the host',
}


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
        for table, column, counted in HOST_TABLES:
            if table == 'host_design_sections' and keep_design:
                continue
            n = conn.execute(f'DELETE FROM {table} WHERE lower({column}) = lower(:h)', {'h': name}).rowcount
            if counted:
                out[counted] = n
        for prefix in HOST_SETTINGS:
            conn.execute('DELETE FROM settings WHERE lower(key) = :k', {'k': (prefix + name).lower()})
        node = remotes.retired(conn, ssh_host)
        if node:
            out['remote_node'] = node
        conn.execute('DELETE FROM hosts WHERE host_id = :i', {'i': host_id})
    if node:
        remotes.sync(conn, drop_sessions=True)
    return out
