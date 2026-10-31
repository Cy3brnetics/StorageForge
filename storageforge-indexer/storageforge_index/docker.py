"""Docker and Podman: which containers and stacks use which folders, and which stacks are only stored on disk.

After the file walk, one SSH call asks the host's engine (docker, else podman; directly, else through sudo -n) for
every container's name, image, state, compose labels and mounts, every volume, and the engine's data directory. A
second call reads the compose files the index found (docker-compose.yml, compose.yaml, ...) and keeps only what
describes storage: services, images, container names and volumes. Environment sections, .env files and volume
passwords are never read into the database.

Stacks come from two directions and are matched up: compose projects of existing containers (their labels name
the project, its folder and its compose files), and compose files on disk. Managers that run in a container
(Dockhand, Portainer, Komodo periphery, Dockge) record folders as they see them inside their own container; those
are translated to host paths through that container's mounts. A compose file nothing was deployed from is a
stored stack.
"""
from __future__ import annotations

import json
import posixpath
import re
import threading
import time

from .db import Conn

COMPOSE_NAMES = ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')
NOT_STACKS = ('/overlay2/', '/containerd/', '/node_modules/', '/.cache/', '/fuse-overlayfs/', '/vfs/dir/',
              '/.local/share/Trash/', '/site-packages/', '/tests/', '/test/', '/examples/', '/docs/')
MAX_COMPOSE = 500
KEEP_LABELS = re.compile(r'^(com\.docker\.compose\.|io\.podman\.compose\.|komodo\.|org\.opencontainers\.image\.title$)')
SECRET_OPT = re.compile(r'((?:pass|password|pwd|secret|token)=)[^,]*', re.I)

FMT_C = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}},'
         '"started":{{json .State.StartedAt}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}},'
         '"restart":{{json .HostConfig.RestartPolicy.Name}}}')
FMT_V = '{"name":{{json .Name}},"driver":{{json .Driver}},"mountpoint":{{json .Mountpoint}},"options":{{json .Options}},"labels":{{json .Labels}}}'

ENGINE = r"""
D=; how=
for e in docker podman; do
  command -v $e >/dev/null 2>&1 || continue
  if $e ps -q >/dev/null 2>&1; then D=$e; how=direct; break; fi
  if sudo -n $e ps -q >/dev/null 2>&1; then D="sudo -n $e"; how=sudo; break; fi
  [ -z "$how" ] && how="no access to $e"
done
printf '@@engine\t%s\t%s\n' "${D##* }" "$how"
[ -n "$D" ] || exit 0
echo '@@root'; $D info --format '{{.DockerRootDir}}' 2>/dev/null || $D info --format '{{.Store.GraphRoot}}' 2>/dev/null
echo '@@containers'; ids=$($D ps -aq); [ -n "$ids" ] && $D inspect --format 'FMT_C' $ids
echo '@@volumes'; vs=$($D volume ls -q); [ -n "$vs" ] && $D volume inspect --format 'FMT_V' $vs
echo '@@sizes'; [ "${D##* }" = docker ] && timeout 90 $D system df -v --format '{{json .Volumes}}' 2>/dev/null
echo; echo '@@end'                               # df prints no trailing newline
""".replace('FMT_C', FMT_C).replace('FMT_V', FMT_V)

READ = r"""
while IFS= read -r -d '' f; do
  if [ -r "$f" ] && [ "$(wc -c < "$f")" -le 524288 ]; then printf '@@file\t%s\n' "$f"; cat -- "$f"; printf '\n@@eof\n'
  else printf '@@unreadable\t%s\n' "$f"; fi
done
"""


def _sections(text: str) -> dict:
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith('@@') and line[2:].split('\t')[0] in ('engine', 'root', 'containers', 'volumes', 'sizes', 'end'):
            if cur:
                out[cur] = '\n'.join(buf)
            head = line[2:].split('\t')
            cur, buf = head[0], ['\t'.join(head[1:])] if len(head) > 1 else []
        else:
            buf.append(line)
    if cur:
        out[cur] = '\n'.join(buf)
    return out


def _jsonl(text: str) -> list:
    out = []
    for line in (text or '').splitlines():
        line = line.strip()
        if line.startswith('{'):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


SIZE_RE = re.compile(r'([\d.]+)\s*([kKMGTP]?i?B)')
UNITS = {'B': 1, 'kB': 1e3, 'KB': 1e3, 'MB': 1e6, 'GB': 1e9, 'TB': 1e12, 'PB': 1e15,
         'KiB': 1024, 'MiB': 1024 ** 2, 'GiB': 1024 ** 3, 'TiB': 1024 ** 4}


def _size(text) -> int | None:
    m = SIZE_RE.search(str(text or ''))
    return int(float(m.group(1)) * UNITS.get(m.group(2), 1)) if m else None


def parse_engine(text: str) -> dict:
    sec = _sections(text)
    engine, _, how = (sec.get('engine') or '\t').partition('\t')
    containers = []
    for c in _jsonl(sec.get('containers', '')):
        containers.append({
            'id': (c.get('id') or '')[:12], 'name': (c.get('name') or '').lstrip('/'), 'image': c.get('image'),
            'state': c.get('state'), 'started': c.get('started'), 'restart': c.get('restart'),
            'labels': {k: v for k, v in (c.get('labels') or {}).items() if KEEP_LABELS.match(k)},
            'mounts': [{'type': m.get('Type'), 'source': m.get('Source'), 'dest': m.get('Destination'),
                        'name': m.get('Name') or None, 'rw': bool(m.get('RW'))} for m in c.get('mounts') or []]})
    sizes = {}
    for line in (sec.get('sizes') or '').splitlines():
        try:
            for v in json.loads(line) or []:
                sizes[v.get('Name')] = _size(v.get('Size'))
        except (ValueError, TypeError, AttributeError):
            continue
    volumes = [{'name': v.get('name'), 'driver': v.get('driver'), 'mountpoint': v.get('mountpoint'),
                'options': {k: SECRET_OPT.sub(r'\1***', str(o)) for k, o in (v.get('options') or {}).items()},
                'project': (v.get('labels') or {}).get('com.docker.compose.project'),
                'size': sizes.get(v.get('name'))} for v in _jsonl(sec.get('volumes', ''))]
    return {'engine': engine or None, 'access': how or None, 'root_dir': (sec.get('root') or '').strip() or None,
            'containers': containers, 'volumes': volumes}


def _interp(text: str) -> bool:
    return '$' in text


def parse_compose(path: str, text: str) -> dict:
    """Only storage facts: project name, services (image, container_name, volumes) and named volume definitions."""
    import yaml
    base = posixpath.dirname(path)
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return {'path': path, 'dir': base, 'error': f'not valid YAML: {str(exc).splitlines()[0]}'}
    if not isinstance(doc, dict) or not isinstance(doc.get('services'), dict):
        return {'path': path, 'dir': base, 'error': 'no services'}
    services = []
    for name, svc in doc['services'].items():
        svc = svc if isinstance(svc, dict) else {}
        vols = []
        for v in svc.get('volumes') or []:
            if isinstance(v, str):
                parts = v.split(':')
                if len(parts) == 1:
                    vols.append({'type': 'anonymous', 'dest': parts[0]})
                    continue
                src, dest = parts[0], parts[1]
                mode = parts[2] if len(parts) > 2 else 'rw'
                kind = 'bind' if src.startswith(('/', '.', '~', '$')) else 'volume'
            elif isinstance(v, dict):
                src, dest = str(v.get('source') or ''), str(v.get('target') or '')
                kind, mode = v.get('type') or ('bind' if src.startswith(('/', '.')) else 'volume'), 'ro' if v.get('read_only') else 'rw'
            else:
                continue
            if kind == 'bind' and src.startswith('.'):
                src = posixpath.normpath(posixpath.join(base, src))
            vols.append({'type': kind, 'source': src, 'dest': dest, 'rw': 'ro' not in str(mode).split(','),
                         'unresolved': _interp(src)})
        services.append({'name': str(name), 'image': svc.get('image'), 'container_name': svc.get('container_name'),
                         'volumes': vols})
    named = {}
    for vname, vdef in (doc.get('volumes') or {}).items():
        vdef = vdef if isinstance(vdef, dict) else {}
        opts = vdef.get('driver_opts') or {}
        named[str(vname)] = {'driver': vdef.get('driver') or 'local', 'external': bool(vdef.get('external')),
                             'options': {k: SECRET_OPT.sub(r'\1***', str(o)) for k, o in opts.items()}}
    project = doc.get('name') or re.sub(r'[^a-z0-9_-]', '', posixpath.basename(base).lower())
    return {'path': path, 'dir': base, 'project': str(project), 'services': services, 'volumes': named}


def compose_candidates(conn: Conn, host_id: int, extra: list[str]) -> list[str]:
    rows = conn.all(f"""SELECT d.path, f.filename FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                        WHERE m.host_id = :h AND NOT f.is_directory AND f.file_size_bytes <= 524288
                          AND f.filename IN ({', '.join(f"'{n}'" for n in COMPOSE_NAMES)})""", {'h': host_id})
    paths = {posixpath.join(p, n) for p, n in rows}
    paths |= {p for p in extra if p.startswith('/')}
    paths = {p for p in paths if not any(x in p for x in NOT_STACKS) and '\n' not in p}
    return sorted(paths)[:MAX_COMPOSE]


def to_host_path(path: str, containers: list[dict]) -> str:
    """A path as a manager container sees it (/app/data/stacks/x) → the host path, through that container's mounts."""
    best = None
    for c in containers:
        for m in c['mounts']:
            d, s = m.get('dest') or '', m.get('source') or ''
            if d and s and d != '/' and (path == d or path.startswith(d.rstrip('/') + '/')) and (not best or len(d) > len(best[0])):
                best = (d, s)
    return best[1].rstrip('/') + path[len(best[0]):] if best else path


def _stream(t, script: str, items: list[str] | None = None) -> str:
    proc = t.stream(script, stdin=items is not None)
    if items is not None:
        def feed():
            try:
                for p in items:
                    proc.stdin.write(p.encode('utf-8', 'surrogateescape') + b'\0')
            except BrokenPipeError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
        threading.Thread(target=feed, daemon=True).start()
    from .remote import StderrTail
    err = StderrTail(proc.stderr)
    from .remote import read_capped
    out = read_capped(proc, 'docker inventory').decode('utf-8', 'replace')
    proc.wait()
    err.join(5)
    proc.stdout.close()
    proc.stderr.close()
    return out


def parse_files(text: str) -> tuple[dict, list]:
    files, unreadable, cur, buf = {}, [], None, []
    for line in text.splitlines():
        if line.startswith('@@file\t'):
            cur, buf = line[7:], []
        elif line == '@@eof' and cur:
            files[cur] = '\n'.join(buf)
            cur = None
        elif line.startswith('@@unreadable\t'):
            unreadable.append(line[13:])
        elif cur is not None:
            buf.append(line)
    return files, unreadable


def survey(db, conn: Conn, t, host_id: int, scan_id: int) -> dict:
    data = parse_engine(_stream(t, ENGINE))
    labels = [p for c in data['containers'] for p in (c['labels'].get('com.docker.compose.project.config_files') or '').split(',')]
    extra = [to_host_path(p.strip(), data['containers']) for p in labels if p.strip()]
    paths = compose_candidates(conn, host_id, extra)
    compose = []
    if paths:
        files, unreadable = parse_files(_stream(t, READ, paths))
        compose = [parse_compose(p, text) for p, text in files.items()]
        compose += [{'path': p, 'dir': posixpath.dirname(p), 'error': 'not readable by the scan user'} for p in unreadable]
    if not data['engine'] and not compose:
        conn.execute('DELETE FROM docker_hosts WHERE host_id = :h', {'h': host_id})
        return {'engine': None}
    with conn.tx():
        conn.execute('DELETE FROM docker_hosts WHERE host_id = :h', {'h': host_id})
        conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json,
                            compose_json, scan_id, updated_at) VALUES (:h, :e, :a, :r, :c, :v, :cf, :s, :t)""",
                     {'h': host_id, 'e': data['engine'], 'a': data['access'], 'r': data['root_dir'],
                      'c': json.dumps(data['containers']), 'v': json.dumps(data['volumes']), 'cf': json.dumps(compose),
                      's': scan_id, 't': int(time.time())})
    return {'engine': data['engine'], 'access': data['access'], 'containers': len(data['containers']),
            'running': sum(1 for c in data['containers'] if c['state'] == 'running'),
            'volumes': len(data['volumes']), 'compose': len(compose)}


# ── what the UI and the other modules ask ───────────────────────────────
def _manager(path: str) -> str:
    p = (path or '').lower()
    for key, name in (('dockhand', 'Dockhand'), ('komodo', 'Komodo'), ('portainer', 'Portainer'), ('/data/compose/', 'Portainer'),
                      ('/opt/stacks', 'Dockge'), ('dockge', 'Dockge'), ('casaos', 'CasaOS'), ('coolify', 'Coolify')):
        if key in p:
            return name
    return 'compose'


def host_view(row) -> dict:
    hostname, engine, access, root, cj, vj, fj, updated = row
    containers, volumes, compose = json.loads(cj), json.loads(vj), json.loads(fj)
    stacks: dict[str, dict] = {}
    for f in compose:
        if f.get('error') and not f.get('project'):     # unreadable or broken: still a stack folder, keyed by it
            stacks.setdefault(f['dir'], {'project': re.sub(r'[^a-z0-9_-]', '', posixpath.basename(f['dir']).lower()),
                                         'dir': f['dir'], 'files': [f['path']], 'containers': [], 'services': [],
                                         'error': f['error']})
            continue
        key = f['dir']
        s = stacks.setdefault(key, {'project': f['project'], 'dir': f['dir'], 'files': [], 'containers': [], 'services': []})
        s['files'].append(f['path'])
        s['services'] = f['services']
        s['named_volumes'] = f.get('volumes') or {}
    used_vols = set()
    for c in containers:
        for m in c['mounts']:
            if m.get('type') == 'volume' and m.get('name'):
                used_vols.add(m['name'])
        proj = c['labels'].get('com.docker.compose.project')
        if not proj:
            stacks.setdefault('standalone', {'project': None, 'dir': None, 'files': [], 'containers': [], 'services': []})['containers'].append(c)
            continue
        wd = c['labels'].get('com.docker.compose.project.working_dir') or ''
        host_dir = to_host_path(wd, containers) if wd else ''
        # the folder the containers were deployed from wins; a project name only decides when no folder was recorded
        same_name = [k for k, s in stacks.items() if s['project'] == proj and k != 'standalone']
        key = host_dir if host_dir in stacks else (same_name[0] if not host_dir and len(same_name) == 1 else None)
        if key is None:
            key = host_dir or 'project:' + proj
            stacks[key] = {'project': proj, 'dir': host_dir or None, 'files': [], 'containers': [], 'services': [],
                           'recorded_dir': wd if wd != host_dir else None}
        stacks[key]['containers'].append(c)
    out = []
    for key, s in stacks.items():
        run = sum(1 for c in s['containers'] if c['state'] == 'running')
        if s['containers'] and s.get('error'):
            s['note'], s['error'] = s.pop('error'), None   # deployed: the containers say what we need
        s['state'] = ('standalone' if key == 'standalone' else 'unreadable' if s.get('error')
                      else 'stored' if not s['containers'] else 'running' if run == len(s['containers'])
                      else 'partly running' if run else 'stopped')
        s['running'], s['manager'] = run, _manager(f"{s.get('recorded_dir') or ''} {s['dir'] or ''}")
        s['socket'] = any(m.get('source') in ('/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock')
                          for c in s['containers'] for m in c['mounts'])
        out.append(s)
    order = {'running': 0, 'partly running': 1, 'stopped': 2, 'stored': 3, 'unreadable': 4, 'standalone': 5}
    out.sort(key=lambda s: (order[s['state']], (s['project'] or '').lower()))
    unused = [v for v in volumes if v['name'] not in used_vols]
    return {'host': hostname, 'engine': engine, 'access': access, 'root_dir': root, 'updated_at': updated,
            'stacks': out, 'volumes': volumes, 'unused_volumes': unused, 'containers': len(containers),
            'running': sum(1 for c in containers if c['state'] == 'running')}


def listing(conn: Conn, host: str | None = None) -> list[dict]:
    rows = conn.all(f"""SELECT h.hostname, d.engine, d.access, d.root_dir, d.containers_json, d.volumes_json, d.compose_json,
                               d.updated_at FROM docker_hosts d JOIN hosts h ON h.host_id = d.host_id
                        {'WHERE h.hostname = :h OR h.ip_address = :h' if host else ''} ORDER BY h.hostname""", {'h': host})
    return [host_view(r) for r in rows]


def _under(p: str, root: str) -> bool:
    return root == '/' or p == root or p.startswith(root.rstrip('/') + '/')


def usage(conn: Conn, host: str | None = None) -> list[dict]:
    """Every folder a container reads or writes on its host: bind sources and volume data folders."""
    out = []
    for h in listing(conn, host):
        vols = {v['name']: v for v in h['volumes']}
        for s in h['stacks']:
            for c in s['containers']:
                for m in c['mounts']:
                    src = m.get('source') or (vols.get(m.get('name') or '') or {}).get('mountpoint')
                    if not src or not src.startswith('/'):
                        continue
                    out.append({'host': h['host'], 'path': src.rstrip('/') or '/', 'container': c['name'], 'state': c['state'],
                                'stack': s['project'], 'type': m.get('type'), 'volume': m.get('name'), 'dest': m.get('dest'),
                                'rw': m.get('rw')})
    return out


def users_of(conn: Conn, host: str, path: str) -> list[dict]:
    """Containers using path: anything mounted at, inside or above it."""
    path = path.rstrip('/') or '/'
    return [u for u in usage(conn, host) if _under(u['path'], path) or (_under(path, u['path']) and u['path'] != '/')]
