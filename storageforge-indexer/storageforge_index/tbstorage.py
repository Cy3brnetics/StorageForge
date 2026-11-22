"""Storage-aware placement of the Toolbox's storage-facing apps (roadmap section 4.2; docs/toolbox.md): Samba, the NFS server, Garage,
Nextcloud, Syncthing and Jellyfin, each placed on a dataset with its snapshot and WORM policy, its shares fenced and its decoys wired in.

An entry says what its data is under storage (all optional):
  use        data, media or database: what placement.py advises for the folder (a database off the bulk pool and off NFS)
  worm       none or recommended: whether a retention hold (WORM) should reach its data
  canaries   none, data (the entry's data folders) or shares (the host's designed shares, for Samba and NFS): the folders the sentinel
             places decoys in, added to the host's decoy folders when the install is staged. A decoy is placed by the next sentinel
             deploy (Security, Decoys); nothing on the host changes when the folder is added
  fence      smb, nfs or ports (the entry's own): a fw-fence step in the same plan drops everyone but the clients given (allow_from) on those
             ports. A rootless container is fenced by its install step instead, from the same allow_from

What it reads, all from the index: the mount and dataset under each data folder, the snapshots, holds and backups that reach it
(placement.advise, protection.py), the decoys armed under it (security_canaries), and the host's share design (shares.py). Every line is
advice in the report; only the fence is a step, and only the decoy folders are saved.
"""
from __future__ import annotations

from .db import Conn

USES = ('data', 'media', 'database')
CANARIES = ('none', 'data', 'shares')
FENCES = ('smb', 'nfs', 'ports')


def load_storage(raw, volumes: list[str], problems: list[str]) -> dict | None:
    """The storage block of an entry, checked: {use, worm, canaries, fence, volumes}."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        problems.append('storage is a mapping: use, worm, canaries, fence, volumes')
        return None
    for k in raw:
        if k not in ('use', 'worm', 'canaries', 'fence', 'volumes'):
            problems.append(f'storage.{k} is not a field (use, worm, canaries, fence, volumes)')
    out = {'use': raw.get('use') or 'data', 'worm': raw.get('worm') or 'none', 'canaries': raw.get('canaries') or 'none', 'fence': raw.get('fence') or None,
           'volumes': raw.get('volumes') if raw.get('volumes') is not None else list(volumes)}
    if out['use'] not in USES:
        problems.append(f'storage.use is one of {", ".join(USES)}')
    if out['worm'] not in ('none', 'recommended'):
        problems.append('storage.worm is none or recommended')
    if out['canaries'] not in CANARIES:
        problems.append(f'storage.canaries is one of {", ".join(CANARIES)}')
    if out['fence'] is not None and out['fence'] not in FENCES:
        problems.append(f'storage.fence is one of {", ".join(FENCES)}')
    if not isinstance(out['volumes'], list) or any(v not in volumes for v in out['volumes']):
        problems.append('storage.volumes are names from requires.volumes')
        out['volumes'] = []
    return out


def folders(e: dict, r: dict) -> list[str]:
    """The host folders of the entry's data, as resolved for this install (overrides win)."""
    st = e.get('storage') or {}
    return [r['volumes'][v] for v in st.get('volumes') or [] if v in r['volumes']]


def share_paths(conn: Conn, host: str) -> list[str]:
    from .shares import design_exports
    try:
        return sorted({str(x['path']) for x in design_exports(conn, host) if str(x.get('path') or '').startswith('/')})
    except Exception:               # a design that cannot be read: no shares to place decoys in, and the report says so
        return []


def canary_folders(conn: Conn, host: str, e: dict, r: dict) -> list[str]:
    st = e.get('storage') or {}
    if st.get('canaries') == 'data':
        return folders(e, r)
    if st.get('canaries') == 'shares':
        return share_paths(conn, host)
    return []


def armed_under(conn: Conn, host: str, folder: str) -> int:
    rows = conn.all("SELECT path FROM security_canaries WHERE lower(host) = lower(:h) AND status = 'armed'", {'h': host})
    return sum(1 for (p,) in rows if p == folder or p.startswith(folder.rstrip('/') + '/'))


def wire(conn: Conn, host: str, e: dict, m: dict, r: dict, allow_from: str | None, say) -> list[dict]:
    """The report lines of a storage-facing install, and the steps it adds (the fence). Called from toolbox.preview."""
    st = e.get('storage')
    if not st:
        return []
    from . import changes, placement, security
    from .moves import find_host, hosts
    tasks: list[dict] = []
    h = find_host(hosts(conn), host)
    use = 'database' if st['use'] == 'database' else 'data'
    for folder in folders(e, r):
        if h:
            for level, text in placement.advise(conn, changes.Host(conn, h), h, folder, use, f'the data of {e["name"]}'):
                say(level, f'placement: {text}')
        if st['worm'] == 'recommended':
            m_ = None
            if h:
                from .moves import mount_of
                m_ = mount_of(h, folder)
            dataset = (m_.get('source') or '').split('[')[0] if m_ and m_.get('fstype') == 'zfs' else None
            cov = placement._cover(conn, host, folder, dataset)
            if cov['holds']:
                say('ok', f'WORM: {cov["holds"]} retention hold(s) reach {folder}')
            else:
                say('warn', f'WORM: no retention hold reaches {folder}. Give it a dataset of its own (zfs create, or a btrfs subvolume), snapshot it, '
                            'and lock the snapshots under Security, WORM, so ransomware with root cannot take them')
    wanted = canary_folders(conn, host, e, r)
    if st['canaries'] != 'none':
        cfg = security.sentinel_config(conn, host)
        have = set(cfg['folders'])
        new = [f for f in wanted if f not in have]
        for f in wanted:
            n = armed_under(conn, host, f)
            if n:
                say('ok', f'decoys: {n} armed under {f}')
        if new:
            say('note', 'decoys: ' + ', '.join(new) + f' will be added to the decoy folders of {host} when this is staged; '
                        'the next sentinel deploy (Security, Decoys) places them, and a decoy touched freezes the shares')
        elif not wanted:
            say('note', f'decoys: no {"share" if st["canaries"] == "shares" else "data folder"} to place decoys in yet'
                        + (': design the shares first (Shares), then stage this again' if st['canaries'] == 'shares' else ''))
        if wanted and not cfg['armed']:
            say('note', f'the sentinel of {host} is not armed: decoys only alert until it is armed')
    own_fence = st.get('fence') == 'ports' and m['kind'] == 'container'      # a rootless container is fenced by its install step itself
    if st.get('fence') and not own_fence:
        ports = ','.join(sorted({str(p['host']) for p in r['ports']} | {str(p['port']) for p in e['requires']['ports']}, key=int)) if st['fence'] == 'ports' else ''
        what = f'ports {ports}' if st['fence'] == 'ports' else f'{st["fence"].upper()} ports'
        if allow_from:
            tasks.append({'host': host, 'type': 'fw-fence', 'params': {'name': e['id'][:60], 'service': 'custom' if st['fence'] == 'ports' else st['fence'], 'ports': ports,
                          'clients': allow_from, 'iface': '', 'state': 'present', 'rollback': ''}, 'note': f'the fence of {e["name"]}'})
            say('ok', f'fence: only {allow_from} may reach the {what} of {host}; everyone else is dropped ahead of any other rule')
        else:
            say('warn', f'fence: anyone on the networks {host} is on can reach its {what}. Give the clients (Only these may reach it) '
                        'and a fence is added to the plan')
    elif allow_from:
        say('ok', f'fence: only {allow_from} may reach its ports')
    elif r['exposure'] != 'loopback':
        say('warn', f'fence: its ports are open to every client on the {r["exposure"]} network: give the clients allowed')
    return tasks


def after_stage(conn: Conn, pv: dict, actor: str) -> list[str]:
    """When a storage-facing install is staged: its decoy folders added to the host's sentinel configuration, which nothing deploys
    until someone does. Returns the folders added."""
    from . import security, toolbox
    row = toolbox.find(conn, pv['tool'])
    e = (row or {}).get('entry') or {}
    if not e.get('storage') or e['storage']['canaries'] == 'none':
        return []
    wanted = canary_folders(conn, pv['host'], e, pv['resolved'])
    cfg = security.sentinel_config(conn, pv['host'])
    new = [f for f in wanted if f not in cfg['folders']]
    if new:
        body = {k: cfg[k] for k in ('names', 'armed', 'actions', 'minutes', 'spread')}
        security.save_sentinel_config(conn, pv['host'], {**body, 'folders': sorted(set(cfg['folders']) | set(new))}, actor)
    return new
