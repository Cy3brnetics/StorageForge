"""Git archive tracking: find repositories in the index, ask the host's git about them, and match copies.

Scans keep pruning .git (its objects are noise) but record the .git entry itself, so a working copy is "a folder
holding .git". Bare repositories are folders holding HEAD, config, objects/ and refs/. After the file walk one SSH
call reads every repository through git, read-only, with a timeout each. Repositories that share their first
(root) commit hold the same history, wherever they live and whatever they are called: that is how copies and
archives are matched, and their heads say which copy is behind.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import re
import shlex
import threading
import time

from .db import Conn

MAX_REPOS = 3000
# Checkouts that tools make for themselves: package caches, AUR helpers, build trees, the trash, container layers.
# They are kept in the table but hidden unless asked for.
NOISE = ('/.cache/', '/.cargo/', '/.rustup/', '/.npm/', '/.nvm', '/go/pkg/mod/', '/node_modules/', '/cache/uv/',
         '/.local/share/Trash/', '/var/lib/containerd/', '/var/lib/docker/', '-prefix/src/', '/.vscode-server/')


def is_noise(path: str, ignore: list[str] | tuple = ()) -> bool:
    """ignore adds path fragments to hide; a fragment starting with ! shows what matches it, whatever else says."""
    p = path + '/'
    if any(x.startswith('!') and x[1:] in p for x in ignore):
        return False
    return any(n in p for n in (*NOISE, *(x for x in ignore if not x.startswith('!'))))


def ignore_lists(conn: Conn) -> dict[str, list[str]]:
    from .alerts import get_setting
    return get_setting(conn, 'git.ignore') or {}


def save_ignore(conn: Conn, host: str, paths: list[str], actor: str):
    from .alerts import set_setting
    cur = ignore_lists(conn)
    clean = sorted({x.strip() for x in paths if x.strip() and x.strip() != '!'})
    key = host or '*'
    if clean:
        cur[key] = clean
    else:
        cur.pop(key, None)
    set_setting(conn, 'git.ignore', cur, actor)

# What a repository's own config can make git run. Other repositories on a host belong to other people, and git would run
# their programs as the scan account. These cover what the read commands below can reach; a worktree's clean filters can't be
# named in advance, so `git status` runs only in a repository this account owns (repo_owned).
SAFE_GIT = "-c safe.directory='*' -c core.fsmonitor=false -c core.hooksPath=/dev/null -c log.showSignature=false -c core.pager=cat -c protocol.ext.allow=never"
OWNED = 'owned() { [ -O "$1" ]; }'

_SURVEY_BASH = r"""
@OWNED@
while IFS= read -r -d '' r; do
  g() { timeout 20 git @SAFE@ -C "$r" "$@" 2>/dev/null; }
  printf '@@repo\t%s\n' "$r"
  bare=$(g rev-parse --is-bare-repository) || { printf 'error\tnot readable as a git repository\n'; continue; }
  printf 'bare\t%s\n' "$bare"
  printf 'branch\t%s\n' "$(g symbolic-ref --short -q HEAD)"
  printf 'head\t%s\n' "$(g log -1 --format='%H %ct %s')"
  printf 'root\t%s\n' "$(g rev-list --max-parents=0 HEAD | tail -n 1)"
  printf 'refs\t%s\n' "$(g for-each-ref --format=x refs/heads refs/tags | wc -l)"
  g remote -v | awk '$3 == "(fetch)" { print "remote\t" $1 "\t" $2 }'
  if [ "$bare" = false ]; then
    if owned "$r" && owned "$(g rev-parse --absolute-git-dir)/config"; then printf 'dirty\t%s\n' "$(g status --porcelain --untracked-files=no | wc -l)"; fi
    up=$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}') && printf 'upstream\t%s\t%s\n' "$up" "$(g rev-list --left-right --count '@{u}...HEAD')"
  fi
  printf 'size\t%s\n' "$(timeout 20 du -sk "$(g rev-parse --absolute-git-dir)" 2>/dev/null | cut -f1)"
done
""".replace('@SAFE@', SAFE_GIT).replace('@OWNED@', OWNED)
# read -d is bash: a login shell or sh that is dash would stop at it and report no repositories at all
SURVEY = ("command -v git >/dev/null 2>&1 || { echo '@@nogit'; exit 0; }\n"
          f'exec bash -c {shlex.quote(_SURVEY_BASH)}\n')


def candidates(conn: Conn, host_id: int) -> tuple[list[str], set[str]]:
    work = conn.all("""SELECT DISTINCT d.path FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                       WHERE m.host_id = :h AND f.filename = '.git'""", {'h': host_id})
    bare = conn.all("""SELECT DISTINCT d.path FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                       WHERE m.host_id = :h AND f.filename = 'HEAD' AND NOT f.is_directory
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'objects' AND o.is_directory)
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'refs' AND o.is_directory)
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'config')""", {'h': host_id})
    existing = conn.all('SELECT path FROM git_repos WHERE host_id = :h', {'h': host_id})
    paths = sorted({r[0].rstrip('/') for r in work + bare + existing if r[0] and '\n' not in r[0] and '\t' not in r[0]})
    return paths[:MAX_REPOS], {r[0].rstrip('/') for r in work}


def parse_survey(text: str) -> tuple[list[dict], bool]:
    repos, cur = [], None
    for line in text.splitlines():
        if line == '@@nogit':
            return [], False
        k, _, v = line.partition('\t')
        if k == '@@repo':
            cur = {'path': v, 'bare': False, 'remotes': []}
            repos.append(cur)
        elif cur is None:
            continue
        elif k == 'bare':
            cur['bare'] = v == 'true'
        elif k == 'branch':
            cur['branch'] = v or None
        elif k == 'head' and v:
            h, _, rest = v.partition(' ')
            t, _, subject = rest.partition(' ')
            cur.update(head_commit=h, head_time=int(t) if t.isdigit() else None, head_subject=subject[:200])
        elif k == 'root':
            cur['root_commit'] = v or None
        elif k in ('refs', 'dirty', 'size'):
            cur[{'size': 'size_kb'}.get(k, k)] = int(v) if v.strip().isdigit() else None
        elif k == 'remote':
            name, _, url = v.partition('\t')
            cur['remotes'].append({'name': name, 'url': url})
        elif k == 'upstream':
            up, _, counts = v.partition('\t')
            b, _, a = counts.partition('\t')
            cur.update(upstream=up, behind=int(b) if b.isdigit() else None, ahead=int(a) if a.isdigit() else None)
        elif k == 'error':
            cur['error'] = v
    return repos, True


def survey(db, conn: Conn, t, host_id: int, scan_id: int) -> dict:
    """Ask the host's git about every repository the index knows on it, and replace this host's rows."""
    paths, working = candidates(conn, host_id)
    if not paths:
        conn.execute('DELETE FROM git_repos WHERE host_id = :h', {'h': host_id})
        return {'repos': 0}
    proc = t.stream(SURVEY, stdin=True)

    def feed():
        try:
            for p in paths:
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
    out = read_capped(proc, 'git survey').decode('utf-8', 'replace')
    proc.wait()
    err.join(5)
    proc.stdout.close()
    proc.stderr.close()
    repos, have_git = parse_survey(out)
    if not have_git:
        return {'repos': len(paths), 'error': 'git is not installed on the host'}
    # a folder that merely looks bare (HEAD, config, objects/, refs/) but git rejects is not a repository
    repos = [r for r in repos if not (r.get('error') and r['path'] not in working)]
    with conn.tx():
        conn.execute('DELETE FROM git_repos WHERE host_id = :h', {'h': host_id})
        for r in repos:
            conn.execute("""INSERT INTO git_repos (host_id, path, bare, branch, head_commit, head_time, head_subject,
                                root_commit, refs, dirty, upstream, ahead, behind, remotes_json, size_kb, error, scan_id)
                            VALUES (:h, :path, :bare, :branch, :hc, :ht, :hs, :root, :refs, :dirty, :up, :ahead, :behind,
                                    :remotes, :size, :err, :s)""",
                         {'h': host_id, 'path': r['path'], 'bare': int(r['bare']), 'branch': r.get('branch'),
                          'hc': r.get('head_commit'), 'ht': r.get('head_time'), 'hs': r.get('head_subject'),
                          'root': r.get('root_commit'), 'refs': r.get('refs'), 'dirty': r.get('dirty'),
                          'up': r.get('upstream'), 'ahead': r.get('ahead'), 'behind': r.get('behind'),
                          'remotes': json.dumps(r['remotes']), 'size': r.get('size_kb'), 'err': r.get('error'), 's': scan_id})
    return {'repos': len(repos), 'dirty': sum(1 for r in repos if r.get('dirty')),
            'bare': sum(1 for r in repos if r['bare'])}


def norm_url(url: str) -> str:
    """git@host:me/x.git, ssh://git@host/me/x, https://host/me/x.git → host/me/x"""
    u = re.sub(r'^[a-z+]+://', '', url or '')
    u = re.sub(r'^[^@/]+@', '', u)
    u = re.sub(r'^([^/:]+):(?!\d+/)', r'\1/', u)
    u = re.sub(r':\d+/', '/', u)
    return re.sub(r'(\.git)?/?$', '', u).lower()


def listing(conn: Conn, host: str | None = None, include_noise: bool = False) -> dict:
    rows = conn.all("""SELECT h.hostname, g.path, g.bare, g.branch, g.head_commit, g.head_time, g.head_subject,
                              g.root_commit, g.refs, g.dirty, g.upstream, g.ahead, g.behind, g.remotes_json, g.size_kb, g.error
                       FROM git_repos g JOIN hosts h ON h.host_id = g.host_id ORDER BY h.hostname, g.path""")
    keys = ('host', 'path', 'bare', 'branch', 'head_commit', 'head_time', 'head_subject', 'root_commit', 'refs',
            'dirty', 'upstream', 'ahead', 'behind', 'remotes', 'size_kb', 'error')
    repos = [dict(zip(keys, r)) for r in rows]
    for r in repos:
        r['bare'] = bool(r['bare'])
        r['remotes'] = json.loads(r['remotes'] or '[]')
        r['name'] = re.sub(r'\.git$', '', r['path'].rstrip('/').rsplit('/', 1)[-1]) or r['path']
    by_root: dict[str, list] = {}
    for r in repos:
        if r['root_commit']:
            by_root.setdefault(r['root_commit'], []).append(r)
    for r in repos:
        group = by_root.get(r['root_commit'] or '', [r])
        latest = max(group, key=lambda x: x['head_time'] or 0)
        r['copies'] = [{'host': x['host'], 'path': x['path'], 'bare': x['bare'], 'head_commit': x['head_commit'],
                        'head_time': x['head_time'], 'same_head': x['head_commit'] == r['head_commit']}
                       for x in group if x is not r]
        r['archived'] = any(c['bare'] and c['host'] != r['host'] for c in r['copies'])
        r['elsewhere'] = any(c['host'] != r['host'] for c in r['copies'])
        r['behind_copies'] = bool(r['head_time'] and latest['head_time'] and r['head_commit'] != latest['head_commit']
                                  and r['head_time'] < latest['head_time'])
        r['state'] = ('error' if r['error'] else 'uncommitted' if r['dirty'] else
                      'unpushed' if r['ahead'] else 'behind' if r['behind_copies'] else
                      'archived' if r['archived'] else 'copied' if r['elsewhere'] else 'single copy')
    ignore = ignore_lists(conn)
    noise = lambda r: is_noise(r['path'], ignore.get('*', []) + ignore.get(r['host'], []))   # noqa: E731
    hidden = sum(1 for r in repos if noise(r) and (not host or r['host'] == host))
    shown = [r for r in repos if (not host or r['host'] == host) and (include_noise or not noise(r))]
    return {'repos': shown, 'hidden': 0 if include_noise else hidden, 'ignore': ignore, 'summary': {s: sum(1 for r in shown if r['state'] == s)
                                        for s in ('uncommitted', 'unpushed', 'behind', 'single copy', 'copied', 'archived', 'error')}}


LOOPBACK = ('local', 'localhost', '127.0.0.1', '::1')


@contextmanager
def open_host_transport(db, conn: Conn, host_name: str, action: str = 'scan'):
    """Context manager providing an open Transport to host_name via vault credentials. Never the server itself: the
    routes take any name, and the server holds the vault. A loopback name needs a key bound to it, like any other host."""
    from .remote import Transport
    if host_name.lower() in LOOPBACK and not conn.scalar('SELECT 1 FROM key_bindings WHERE lower(host_pattern) = lower(:h)', {'h': host_name}):
        raise LookupError(f'{host_name} is not an enrolled host')

    from .runner import connect_address, ephemeral_agent, known_hosts_path
    from .vault import Vault
    addr = connect_address(conn, host_name)
    with Vault(db, conn).unlock() as vault:
        b = vault.resolve(addr, action)
        with ephemeral_agent(vault.decrypt_key(b.key_id)) as sock:
            t = Transport(host=addr, user=b.user, port=b.port, agent_sock=sock,
                          known_hosts=str(known_hosts_path()), isolated=True)
            try:
                yield t
            finally:
                t.close()


def _known_repo(conn: Conn, host: str, path: str):
    """Only repositories a scan found: these routes run git, and a path from a request could be anything."""
    if not conn.scalar("""SELECT 1 FROM git_repos g JOIN hosts h ON h.host_id = g.host_id
                          WHERE lower(h.hostname) = lower(:h) AND g.path = :p""", {'h': host, 'p': path}):
        raise LookupError(f'{path} is not a repository found on {host}: scan or survey it first')


def survey_host(db, host_name: str, actor: str | None = None) -> dict:
    """Trigger an on-demand git survey on a host, updating git_repos table."""
    conn = db.connect()
    try:
        row = conn.all('SELECT host_id, hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h)',
                       {'h': host_name})
        if not row:
            raise LookupError(f'Host "{host_name}" is not indexed')
        host_id, canonical_name = row[0][0], row[0][1]
        scan_id = conn.scalar('SELECT MAX(scan_id) FROM scans WHERE host_id = :h', {'h': host_id}) or 0
        with open_host_transport(db, conn, canonical_name, 'scan') as t:
            res = survey(db, conn, t, host_id, scan_id)
            res['host'] = canonical_name
            return res
    finally:
        conn.close()


_STATUS_BASH = r"""
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export SSH_ASKPASS=
command -v git >/dev/null 2>&1 || { printf 'error\tgit is not installed on this host\n'; exit 0; }
@OWNED@
g() { timeout 25 git @SAFE@ -C "$R" "$@"; }
if ! g rev-parse --git-dir >/dev/null 2>&1; then
  printf 'error\tnot a git repository\n'
  exit 0
fi
bare=$(g rev-parse --is-bare-repository 2>/dev/null)
printf 'bare\t%s\n' "$bare"
printf 'branch\t%s\n' "$(g symbolic-ref --short -q HEAD 2>/dev/null || g describe --tags --exact-match 2>/dev/null || g rev-parse --short HEAD 2>/dev/null)"
printf 'head\t%s\n' "$(g log -1 --format='%H%x09%ct%x09%an%x09%s' 2>/dev/null)"
printf 'root\t%s\n' "$(g rev-list --max-parents=0 HEAD 2>/dev/null | tail -n 1)"
printf 'refs\t%s\n' "$(g for-each-ref --format=x refs/heads refs/tags 2>/dev/null | wc -l)"
g remote -v 2>/dev/null | awk '$3 == "(fetch)" { print "remote_fetch\t" $1 "\t" $2 } $3 == "(push)" { print "remote_push\t" $1 "\t" $2 }'
if [ "$bare" = "false" ]; then
  up=$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) && printf 'upstream\t%s\t%s\n' "$up" "$(g rev-list --left-right --count '@{u}...HEAD' 2>/dev/null)"
  printf 'stash\t%s\n' "$(g stash list 2>/dev/null | wc -l)"
  gd=$(g rev-parse --absolute-git-dir 2>/dev/null)
  if owned "$R" && owned "$gd/config"; then
    printf '@@porcelain\n'
    g status --porcelain -uall 2>/dev/null
    printf '@@endporcelain\n'
  else
    printf 'foreign\t1\n'
  fi
fi
git_dir="$(g rev-parse --git-dir 2>/dev/null)"
if [ -n "$git_dir" ]; then
  case "$git_dir" in /*) ;; *) git_dir="$R/$git_dir" ;; esac
  printf 'size\t%s\n' "$(du -sk "$git_dir" 2>/dev/null | cut -f1)"
fi
""".replace('@SAFE@', SAFE_GIT).replace('@OWNED@', OWNED)


def repo_status(db, host_name: str, path: str, actor: str | None = None) -> dict:
    """Run an on-demand status check on a specific git repository."""
    path = path.rstrip('/')
    conn = db.connect()
    try:
        row = conn.all('SELECT host_id, hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h) OR ip_address = :h',
                       {'h': host_name})
        canonical_name = row[0][1] if row else host_name
        host_id = row[0][0] if row else None
        _known_repo(conn, canonical_name, path)

        script = f'R={shlex.quote(path)}\n' + _STATUS_BASH
        with open_host_transport(db, conn, canonical_name, 'scan') as t:
            out = t.run(script, timeout=30)

        res = {
            'host': canonical_name,
            'path': path,
            'name': re.sub(r'\.git$', '', path.rstrip('/').rsplit('/', 1)[-1]) or path,
            'bare': False,
            'branch': None,
            'head_commit': None,
            'head_time': None,
            'head_author': None,
            'head_subject': None,
            'root_commit': None,
            'refs': 0,
            'remotes': [],
            'upstream': None,
            'ahead': None,
            'behind': None,
            'dirty': 0,
            'dirty_files': [],
            'stashes': 0,
            'size_kb': None,
            'foreign': False,     # someone else's repository: not read for changes, see SAFE_GIT
            'error': None,
        }

        remotes_dict: dict[str, dict] = {}
        in_porcelain = False

        for line in out.splitlines():
            if line == '@@porcelain':
                in_porcelain = True
                continue
            if line == '@@endporcelain':
                in_porcelain = False
                continue
            if in_porcelain:
                line = line.strip('\r\n')
                if len(line) >= 3:
                    code = line[:2]
                    fpath = line[3:].strip()
                    res['dirty_files'].append({'code': code, 'path': fpath})
                continue

            k, _, v = line.partition('\t')
            if k == 'bare':
                res['bare'] = v == 'true'
            elif k == 'branch':
                res['branch'] = v or None
            elif k == 'head' and v:
                parts = v.split('\t')
                if parts and parts[0]:
                    res['head_commit'] = parts[0]
                if len(parts) > 1 and parts[1].strip().isdigit():
                    res['head_time'] = int(parts[1].strip())
                if len(parts) > 2:
                    res['head_author'] = parts[2]
                if len(parts) > 3:
                    res['head_subject'] = '\t'.join(parts[3:])
            elif k == 'root':
                res['root_commit'] = v or None
            elif k == 'refs':
                res['refs'] = int(v) if v.strip().isdigit() else 0
            elif k == 'stash':
                res['stashes'] = int(v) if v.strip().isdigit() else 0
            elif k == 'size':
                res['size_kb'] = int(v) if v.strip().isdigit() else None
            elif k == 'upstream':
                up, _, counts = v.partition('\t')
                b, _, a = counts.partition('\t')
                res['upstream'] = up
                res['behind'] = int(b) if b.strip().isdigit() else None
                res['ahead'] = int(a) if a.strip().isdigit() else None
            elif k == 'remote_fetch':
                name, _, url = v.partition('\t')
                remotes_dict.setdefault(name, {'name': name})['fetch_url'] = url
            elif k == 'remote_push':
                name, _, url = v.partition('\t')
                remotes_dict.setdefault(name, {'name': name})['push_url'] = url
            elif k == 'foreign':
                res['foreign'] = True
            elif k == 'error':
                res['error'] = v

        for r_info in remotes_dict.values():
            res['remotes'].append({
                'name': r_info['name'],
                'url': r_info.get('fetch_url') or r_info.get('push_url') or '',
                'fetch_url': r_info.get('fetch_url'),
                'push_url': r_info.get('push_url'),
            })

        res['dirty'] = None if res['foreign'] else len(res['dirty_files'])

        # Update or insert into database git_repos table if host is known
        if host_id:
            with conn.tx():
                if res['error']:
                    conn.execute('UPDATE git_repos SET error = :err WHERE host_id = :h AND path = :path',
                                 {'h': host_id, 'path': path, 'err': res['error']})
                else:
                    conn.execute("""UPDATE git_repos SET
                                    bare = :bare, branch = :branch, head_commit = :hc, head_time = :ht,
                                    head_subject = :hs, root_commit = :rc, refs = :refs, dirty = :dirty,
                                    upstream = :up, ahead = :ahead, behind = :behind, remotes_json = :remotes,
                                    size_kb = :size, error = NULL
                                    WHERE host_id = :h AND path = :path""",
                                 {'h': host_id, 'path': path, 'bare': int(res['bare']), 'branch': res['branch'],
                                  'hc': res['head_commit'], 'ht': res['head_time'], 'hs': res['head_subject'],
                                  'rc': res['root_commit'], 'refs': res['refs'], 'dirty': res['dirty'],
                                  'up': res['upstream'], 'ahead': res['ahead'], 'behind': res['behind'],
                                  'remotes': json.dumps(res['remotes']), 'size': res['size_kb']})

        # Match copies across the fleet
        if res['root_commit']:
            copies_rows = conn.all("""SELECT h.hostname, g.path, g.bare, g.head_commit, g.head_time
                                      FROM git_repos g JOIN hosts h ON h.host_id = g.host_id
                                      WHERE g.root_commit = :root AND NOT (h.hostname = :host AND g.path = :path)""",
                                   {'root': res['root_commit'], 'host': canonical_name, 'path': path})
            res['copies'] = [{
                'host': r[0], 'path': r[1], 'bare': bool(r[2]), 'head_commit': r[3], 'head_time': r[4],
                'same_head': r[3] == res['head_commit'],
                'newer': (r[3] != res['head_commit']) and ((r[4] or 0) > (res['head_time'] or 0)),
            } for r in copies_rows]
        else:
            res['copies'] = []

        res['archived'] = any(c['bare'] and c['host'] != canonical_name for c in res['copies'])
        res['elsewhere'] = any(c['host'] != canonical_name for c in res['copies'])
        res['behind_copies'] = any(c['newer'] for c in res['copies'])
        res['state'] = ('error' if res['error'] else 'uncommitted' if res['dirty'] else
                        'unpushed' if res['ahead'] else 'behind' if res['behind_copies'] else
                        'archived' if res['archived'] else 'copied' if res['elsewhere'] else 'single copy')

        return res
    finally:
        conn.close()


# Runs as root through the signed runner, so the work happens as whoever owns the repository's config: its hooks, filters
# and credentials can then do nothing that person could not do anyway, and new files keep their owner.
_SYNC_BASH = r"""set -e
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export SSH_ASKPASS=
cfg=$R/.git/config
[ -e "$cfg" ] || cfg=$R/.git
[ -e "$cfg" ] || cfg=$R/config
owner=$(stat -c %U "$cfg" 2>/dev/null) || owner=
if [ -z "$owner" ]; then
  echo "Error: not a git repository" >&2
  exit 1
fi
if [ "$(id -u)" = 0 ] && [ "$owner" != root ]; then
  command -v runuser >/dev/null 2>&1 || { echo "Error: runuser is needed to work as $owner" >&2; exit 4; }
  home=$(getent passwd "$owner" | cut -d: -f6)
  g() { runuser -u "$owner" -- env HOME="$home" GIT_TERMINAL_PROMPT=0 timeout 60 git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.ext.allow=never -C "$R" "$@"; }
else
  g() { timeout 60 git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.ext.allow=never -C "$R" "$@"; }
fi

if ! g rev-parse --git-dir >/dev/null 2>&1; then
  echo "Error: not a git repository" >&2
  exit 1
fi

bare=$(g rev-parse --is-bare-repository 2>/dev/null)
remotes=$(g remote 2>/dev/null | tr '\n' ' ')

if [ -z "$remotes" ]; then
  echo "Error: No remote configured for this repository" >&2
  exit 2
fi

case "$ACT" in
  fetch)
    echo "==> Fetching from all remotes..."
    g fetch --all --prune --tags
    ;;
  pull)
    if [ "$bare" = "true" ]; then
      echo "==> Updating bare mirror remotes..."
      g remote update --prune
    else
      dirty=$(g status --porcelain --untracked-files=no 2>/dev/null | wc -l)
      if [ "$dirty" -gt 0 ]; then
        echo "Error: Working tree has uncommitted changes ($dirty files). Stash or commit before pulling." >&2
        exit 3
      fi
      echo "==> Pulling changes (fast-forward only)..."
      g pull --ff-only
    fi
    ;;
  push)
    branch="$(g symbolic-ref --short -q HEAD 2>/dev/null || true)"
    up="$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    if [ -z "$up" ] && [ -n "$branch" ]; then
      echo "==> No upstream branch configured for $branch; pushing with -u origin $branch..."
      g push -u origin "$branch"
    else
      echo "==> Pushing commits to upstream..."
      g push
    fi
    ;;
  sync)
    if [ "$bare" = "true" ]; then
      echo "==> Updating bare mirror..."
      g remote update --prune
    else
      echo "==> Fetching latest changes..."
      g fetch --all --prune --tags
      up=$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
      if [ -n "$up" ]; then
        behind=$(g rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 0)
        dirty=$(g status --porcelain --untracked-files=no 2>/dev/null | wc -l)
        if [ "$behind" -gt 0 ]; then
          if [ "$dirty" -gt 0 ]; then
            echo "Notice: Fetched $behind new commits, but cannot fast-forward because working tree has uncommitted changes."
          else
            echo "==> Fast-forwarding $behind commit(s) from $up..."
            g merge --ff-only "$up"
          fi
        else
          echo "Already up to date with $up."
        fi
      else
        echo "Fetched remotes (no upstream branch configured to fast-forward)."
      fi
    fi
    ;;
esac
echo "Done."
"""


def repo_sync(db, host_name: str, path: str, action: str = 'sync', actor: str | None = None) -> dict:
    """Run git fetch, pull, push, or sync on a repository."""
    action = (action or 'sync').lower()
    if action not in ('fetch', 'pull', 'push', 'sync'):
        raise ValueError(f'Invalid sync action: {action}')

    path = path.rstrip('/')
    conn = db.connect()
    try:
        row = conn.all('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h) OR ip_address = :h',
                       {'h': host_name})
        canonical_name = row[0][0] if row else host_name

        from . import deploy
        _known_repo(conn, canonical_name, path)
        if not deploy.ready(conn, canonical_name):
            raise deploy.DeployError(f'{canonical_name} is not set up for deploys yet: syncing changes the host, so it needs deploy access')
        script = f'R={shlex.quote(path)}\nACT={shlex.quote(action)}\n' + _SYNC_BASH
        run = deploy.run(db, canonical_name, script, kind='git_sync', ref=path[:200], mode='apply', actor=actor, timeout=300)
        ok = run['status'] in deploy.FINISHED
        out = run['output']
        err = None if ok else (out.strip()[-300:] or run['status'])

        # Refresh repo status after sync
        updated_status = None
        try:
            updated_status = repo_status(db, canonical_name, path, actor=actor)
        except Exception:
            pass

        return {
            'ok': ok,
            'action': action,
            'output': out.strip(),
            'error': err,
            'status': updated_status,
        }
    finally:
        conn.close()


_HISTORY_BASH = r"""
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export SSH_ASKPASS=
command -v git >/dev/null 2>&1 || { printf 'error\tgit is not installed on this host\n'; exit 0; }
g() { timeout 25 git @SAFE@ -C "$R" "$@"; }
if ! g rev-parse --git-dir >/dev/null 2>&1; then
  printf 'error\tnot a git repository\n'
  exit 0
fi

printf '@@tags\n'
g tag -l --sort=-creatordate --format='%(refname:short)%09%(if)%(*objectname)%(then)%(*objectname)%(else)%(objectname)%(end)%09%(creatordate:unix)%09%(subject)' 2>/dev/null | head -n 30
printf '@@commits\n'
g log -n "$MAX" --format='%H%x09%h%x09%an%x09%ae%x09%at%x09%s%x09%d' 2>/dev/null
""".replace('@SAFE@', SAFE_GIT)


def repo_history(db, host_name: str, path: str, max_commits: int = 50) -> dict:
    """Fetch commit history, tags, and formatted changelog for a repository."""
    path = path.rstrip('/')
    conn = db.connect()
    try:
        row = conn.all('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h) OR ip_address = :h',
                       {'h': host_name})
        canonical_name = row[0][0] if row else host_name
        _known_repo(conn, canonical_name, path)

        script = f'R={shlex.quote(path)}\nMAX={int(max_commits)}\n' + _HISTORY_BASH
        with open_host_transport(db, conn, canonical_name, 'scan') as t:
            out = t.run(script, timeout=30)

        tags = []
        commits = []
        mode = None

        for line in out.splitlines():
            line = line.strip('\r\n')
            if line == '@@tags':
                mode = 'tags'
                continue
            if line == '@@commits':
                mode = 'commits'
                continue
            if line.startswith('error\t'):
                return {'error': line.partition('\t')[2], 'tags': [], 'commits': [], 'changelog': []}

            if mode == 'tags' and line:
                parts = line.split('\t')
                tags.append({
                    'name': parts[0],
                    'commit': parts[1] if len(parts) > 1 else '',
                    'time': int(parts[2].strip()) if len(parts) > 2 and parts[2].strip().isdigit() else None,
                    'subject': parts[3] if len(parts) > 3 else '',
                })
            elif mode == 'commits' and line:
                parts = line.split('\t', 6)
                if len(parts) >= 6:
                    commits.append({
                        'hash': parts[0],
                        'short_hash': parts[1],
                        'author': parts[2],
                        'email': parts[3],
                        'time': int(parts[4].strip()) if parts[4].strip().isdigit() else None,
                        'subject': parts[5],
                        'refs': parts[6].strip(' ()') if len(parts) > 6 else '',
                    })

        # Generate structured changelog from tags and commits
        changelog = build_changelog(commits, tags)

        return {
            'host': canonical_name,
            'path': path,
            'tags': tags,
            'commits': commits,
            'changelog': changelog,
            'total_commits': len(commits),
        }
    finally:
        conn.close()


def build_changelog(commits: list[dict], tags: list[dict]) -> list[dict]:
    """Group commits into releases / milestones and categorize them."""
    tag_commit_map = {t['commit']: t['name'] for t in tags if t.get('commit')}
    tag_name_map = {t['name']: t for t in tags}

    # Group commits by tag release
    releases = []
    current_release = {
        'version': 'Unreleased' if tags else 'Recent Changes',
        'tag': None,
        'date': commits[0].get('time') if commits and commits[0].get('time') else None,
        'categories': {
            'features': [],
            'fixes': [],
            'docs': [],
            'perf': [],
            'maintenance': [],
            'other': [],
        },
        'count': 0,
    }

    def categorize(subject: str) -> str:
        s = subject.lower()
        if re.match(r'^(feat|feature)(\(.*\))?:', s):
            return 'features'
        if re.match(r'^(fix|bug)(\(.*\))?:', s):
            return 'fixes'
        if re.match(r'^docs(\(.*\))?:', s):
            return 'docs'
        if re.match(r'^perf(\(.*\))?:', s):
            return 'perf'
        if re.match(r'^(refactor|chore|style|build|ci|test)(\(.*\))?:', s):
            return 'maintenance'
        return 'other'

    for c in commits:
        commit_tag = tag_commit_map.get(c['hash'])
        if commit_tag and current_release['count'] > 0:
            releases.append(current_release)
            t_info = tag_name_map.get(commit_tag, {})
            current_release = {
                'version': commit_tag,
                'tag': commit_tag,
                'date': t_info.get('time') or c.get('time'),
                'categories': {
                    'features': [],
                    'fixes': [],
                    'docs': [],
                    'perf': [],
                    'maintenance': [],
                    'other': [],
                },
                'count': 0,
            }
        elif commit_tag:
            current_release['version'] = commit_tag
            current_release['tag'] = commit_tag
            current_release['date'] = tag_name_map.get(commit_tag, {}).get('time') or c.get('time')

        cat = categorize(c['subject'])
        current_release['categories'][cat].append(c)
        current_release['count'] += 1

    if current_release['count'] > 0:
        releases.append(current_release)

    return releases


def repo_commit(db, host_name: str, path: str, sha: str) -> dict:
    """Get commit details and diffstat for a commit."""
    if not re.fullmatch(r'[a-fA-F0-9]{4,64}', sha):
        raise ValueError('Invalid commit hash')

    path = path.rstrip('/')
    conn = db.connect()
    try:
        row = conn.all('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h) OR ip_address = :h',
                       {'h': host_name})
        canonical_name = row[0][0] if row else host_name

        _known_repo(conn, canonical_name, path)
        script = f'timeout 25 git {SAFE_GIT} -C {shlex.quote(path)} show --stat --no-ext-diff --no-textconv --pretty=fuller {shlex.quote(sha)}'
        with open_host_transport(db, conn, canonical_name, 'scan') as t:
            out = t.run(script, timeout=30)

        return {'sha': sha, 'output': out.strip()}
    finally:
        conn.close()

