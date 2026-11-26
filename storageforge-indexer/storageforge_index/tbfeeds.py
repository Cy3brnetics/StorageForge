"""Detection & IDS feed integration (tbfeeds.py, roadmap section 4.2): turns Toolbox readings from Suricata, CrowdSec, fail2ban, Trivy and Grype into security events, alerts and reconciled firewall state."""
from __future__ import annotations

import ipaddress
import time
import uuid

from . import alerts, changes, security
from .db import Conn, loads

SURICATA_DEDUPE_SECS = 6 * 3600


def _vip_networks(conn: Conn) -> list:
    nets = []
    for raw in security.vip_list(conn):
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return nets


def _overlaps_vip(raw_ip: str, vips: list) -> bool:
    try:
        net = ipaddress.ip_network(str(raw_ip or '').strip(), strict=False)
    except ValueError:
        return False
    return any(v.version == net.version and v.overlaps(net) for v in vips)


def ingest(conn: Conn, host: str, reading: dict, at: int | None = None) -> dict:
    """Ingest Suricata alerts from an infrastructure reading into security_events without duplicating seen alerts."""
    now = at or int(time.time())
    tb = (reading or {}).get('toolbox') or {}
    suri = tb.get('suricata') or {}
    added = 0
    for a in (suri.get('alerts') or []):
        sig = str(a.get('signature') or '').strip()
        src = str(a.get('src_ip') or '').strip()
        if not sig or not src:
            continue
        dest = str(a.get('dest_ip') or '').strip()
        sev = a.get('severity')
        sig_id = a.get('signature_id') or ''
        ts = str(a.get('timestamp') or '')
        summary = f'Suricata: {sig} from {src}' + (f' to {dest}' if dest else '')
        said = sig.replace(';', ',').replace('=', ':')          # free text inside a k=v;k=v detail (secplus.event_fields)
        detail = f'client={src};dest={dest};sig={said};signature_id={sig_id};severity={sev if sev is not None else ""}'
        if ts:
            uid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'suricata:{host.lower()}:{sig_id or sig}:{src}:{dest}:{ts}'))
            added += bool(security.record_event(conn, host, 'suricata_alert', summary, detail, 'suricata', now, uid))
        else:
            seen = conn.scalar(
                """SELECT 1 FROM security_events
                   WHERE lower(host) = lower(:h) AND kind = 'suricata_alert' AND summary = :s AND occurred_at > :t LIMIT 1""",
                {'h': host, 's': security.clean_text(summary), 't': now - SURICATA_DEDUPE_SECS},
            )
            if not seen:
                added += bool(security.record_event(conn, host, 'suricata_alert', summary, detail, 'suricata', now))
    return {'suricata': added}


def bouncer_view(conn: Conn, host: str | None = None, reading: dict | None = None) -> dict:
    """Compare CrowdSec/fail2ban bans against StorageForge's quarantine and never-quarantine VIP list."""
    if not host:
        return {'crowdsec_present': False, 'fail2ban_present': False, 'bans': [], 'vip_conflicts': [], 'unsynced_quarantine': [], 'unsynced_bouncer': [], 'jails': []}
    data = reading if reading is not None else security.measurement(conn, host, 'infra')
    tb = (data or {}).get('toolbox') or {}
    cs = tb.get('crowdsec')
    f2b = tb.get('fail2ban')
    vips = _vip_networks(conn)
    now = int(time.time())
    quarantined = {
        r[0]
        for r in conn.all(
            'SELECT ip_address FROM security_quarantine WHERE lower(host) = lower(:h) AND (expires_at IS NULL OR expires_at > :t)',
            {'h': host, 't': now},
        )
    }
    bans = []
    for d in (cs or {}).get('decisions') or []:
        ip = str(d.get('value') or '').strip()
        if not ip:
            continue
        bans.append({
            'tool': 'crowdsec',
            'ip': ip,
            'jail': '',
            'scenario': d.get('scenario') or d.get('origin') or 'crowdsec',
            'duration': d.get('duration') or '',
            'vip_conflict': _overlaps_vip(ip, vips),
            'in_quarantine': ip in quarantined,
        })
    jails = sorted(((f2b or {}).get('jails') or {}).keys())
    for jail, info in sorted(((f2b or {}).get('jails') or {}).items()):
        for ip in info.get('banned') or []:
            ip = str(ip).strip()
            if not ip:
                continue
            bans.append({
                'tool': 'fail2ban',
                'ip': ip,
                'jail': jail,
                'scenario': f'jail:{jail}',
                'duration': '',
                'vip_conflict': _overlaps_vip(ip, vips),
                'in_quarantine': ip in quarantined,
            })
    banned_ips = {b['ip'] for b in bans}
    return {
        'crowdsec_present': cs is not None,
        'fail2ban_present': f2b is not None,
        'jails': jails,
        'bans': bans,
        'vip_conflicts': [b for b in bans if b['vip_conflict']],
        'unsynced_quarantine': sorted(ip for ip in quarantined if ip not in banned_ips),
        'unsynced_bouncer': sorted({b['ip'] for b in bans if not b['vip_conflict'] and b['ip'] not in quarantined}),
    }


def reconcile_bouncer(db, conn: Conn, body: dict, actor: str) -> dict:
    """Reconcile CrowdSec/fail2ban bans with StorageForge quarantine and VIP exemptions."""
    host = security.known_host(conn, body.get('host'))
    action = str(body.get('action') or '')
    if action not in ('unban_vips', 'push_quarantine', 'import_bans'):
        raise ValueError('action is unban_vips, push_quarantine or import_bans')
    view = bouncer_view(conn, host)
    if action == 'unban_vips':
        tasks = [
            {
                'host': host,
                'type': 'ips-decision',
                'params': {'tool': b['tool'], 'ip': b['ip'], 'state': 'lifted', 'jail': b.get('jail') or '', 'duration': '', 'reason': 'VIP exempt in StorageForge'},
                'note': 'Reconcile IPS bouncer against VIP list',
            }
            for b in view['vip_conflicts']
        ]
        if not tasks:
            return {'ok': True, 'host': host, 'action': action, 'plan_id': None, 'tasks': 0, 'message': 'no bouncer ban overlaps a never-quarantine VIP address'}
        pid = changes.save_plan(conn, {'name': f'Lift bouncer VIP bans on {host}'[:80], 'tasks': tasks}, actor)
        return {'ok': True, 'host': host, 'action': action, 'plan_id': pid, 'tasks': len(tasks)}
    if action == 'push_quarantine':
        if not view['unsynced_quarantine']:
            return {'ok': True, 'host': host, 'action': action, 'plan_id': None, 'tasks': 0, 'message': 'every quarantined address is already in the bouncer'}
        tool = 'crowdsec' if view['crowdsec_present'] else 'fail2ban' if view['fail2ban_present'] else None
        if not tool:
            raise ValueError(f'neither CrowdSec nor fail2ban was present in the last reading of {host}')
        jail = 'sshd' if 'sshd' in view['jails'] else (view['jails'][0] if view['jails'] else 'sshd')
        tasks = [
            {
                'host': host,
                'type': 'ips-decision',
                'params': {'tool': tool, 'ip': ip, 'state': 'banned', 'jail': jail if tool == 'fail2ban' else '', 'duration': '4h', 'reason': 'from StorageForge quarantine'},
                'note': 'Push StorageForge quarantine to IPS bouncer',
            }
            for ip in view['unsynced_quarantine']
        ]
        pid = changes.save_plan(conn, {'name': f'Push quarantine to {tool} on {host}'[:80], 'tasks': tasks}, actor)
        return {'ok': True, 'host': host, 'action': action, 'plan_id': pid, 'tasks': len(tasks)}
    # import_bans
    mode = str(body.get('mode') or 'report')
    if mode not in ('preview', 'report', 'apply'):
        raise ValueError('mode is preview, report or apply')
    targets = view['unsynced_bouncer'][:50]
    if not targets:
        return {'ok': True, 'mode': mode, 'host': host, 'action': action, 'imported': 0, 'message': 'every bouncer ban is already quarantined'}
    results, imported, err = [], 0, None
    for ip in targets:
        res = security.quarantine(db, conn, {'host': host, 'ip_address': ip, 'minutes': 60, 'reason': 'imported from IPS bouncer', 'mode': mode}, actor)
        results.append(res)
        if res.get('ok'):
            imported += 1
        elif not err:
            err = res.get('error')
    ok = imported == len(targets) and not err
    return {'ok': ok, 'mode': mode, 'host': host, 'action': action, 'imported': imported, 'results': results, **({'error': err} if err else {})}


def problems(conn: Conn) -> dict:
    """Open alerts from detection/scanning Toolbox feeds: VIP conflicts, critical image CVEs, high-severity Suricata alerts."""
    out: dict = {}
    for host, raw in conn.all("SELECT host, data_json FROM security_measurements WHERE kind = 'infra'"):
        data = loads(raw) or {}
        tb = data.get('toolbox') or {}
        bv = bouncer_view(conn, host, data)
        if bv['vip_conflicts']:
            where = '; '.join(f'{b["ip"]} ({b["tool"]})' for b in bv['vip_conflicts'][:5])
            out[f'toolbox-bouncer-vip:{host}'] = ('toolbox-bouncer-vip', host, f'IPS banned a protected address on {host}', where, 'crit')
        scans = tb.get('scans') or []
        crit_fixable = sum((r.get('fixable') or {}).get('CRITICAL', 0) for r in scans)
        if crit_fixable:
            imgs = [r['image'] for r in scans if (r.get('fixable') or {}).get('CRITICAL', 0)]
            out[f'toolbox-cve:{host}'] = ('toolbox-cve', host, f'{crit_fixable} fixable critical CVE(s) in images on {host}', ', '.join(imgs[:4]), 'warn')
        suri_alerts = [a for a in ((tb.get('suricata') or {}).get('alerts') or []) if a.get('severity') in (1, 2)]
        if suri_alerts:
            where = '; '.join(f'{a.get("signature")} ({a.get("src_ip", "?")})' for a in suri_alerts[:3])
            out[f'toolbox-suricata:{host}'] = ('toolbox-suricata', host, f'Suricata high-severity alert on {host}', where, 'crit')
    return out


_ = (alerts,)
