"""Git archive tracking: find repositories in the index, ask the host's git about them, and match copies.

Scans keep pruning .git (its objects are noise) but record the .git entry itself, so a working copy is "a folder
holding .git". Bare repositories are folders holding HEAD, config, objects/ and refs/. After the file walk one SSH
call reads every repository through git, read-only, with a timeout each. Repositories that share their first
(root) commit hold the same history, wherever they live and whatever they are called: that is how copies and
archives are matched, and their heads say which copy is behind.
"""
from __future__ import annotations

import json
import re
import threading

from .db import Conn

MAX_REPOS = 3000
# Checkouts that tools make for themselves: package caches, AUR helpers, build trees, the trash, container layers.
# They are kept in the table but hidden unless asked for.
NOISE = ('/.cache/', '/.cargo/', '/.rustup/', '/.npm/', '/.nvm', '/go/pkg/mod/', '/node_modules/', '/cache/uv/',
         '/.local/share/Trash/', '/var/lib/containerd/', '/var/lib/docker/', '-prefix/src/', '/.vscode-server/')


def is_noise(path: str) -> bool:
    p = path + '/'
    return any(n in p for n in NOISE)

SURVEY = r"""
command -v git >/dev/null 2>&1 || { echo '@@nogit'; exit 0; }
while IFS= read -r -d '' r; do
  g() { timeout 20 git -c safe.directory='*' -C "$r" "$@" 2>/dev/null; }
  printf '@@repo\t%s\n' "$r"
  bare=$(g rev-parse --is-bare-repository) || { printf 'error\tnot readable as a git repository\n'; continue; }
  printf 'bare\t%s\n' "$bare"
  printf 'branch\t%s\n' "$(g symbolic-ref --short -q HEAD)"
  printf 'head\t%s\n' "$(g log -1 --format='%H %ct %s')"
  printf 'root\t%s\n' "$(g rev-list --max-parents=0 HEAD | tail -n 1)"
  printf 'refs\t%s\n' "$(g for-each-ref --format=x refs/heads refs/tags | wc -l)"
  g remote -v | awk '$3 == "(fetch)" { print "remote\t" $1 "\t" $2 }'
  if [ "$bare" = false ]; then
    printf 'dirty\t%s\n' "$(g status --porcelain --untracked-files=no | wc -l)"
    up=$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}') && printf 'upstream\t%s\t%s\n' "$up" "$(g rev-list --left-right --count '@{u}...HEAD')"
  fi
  printf 'size\t%s\n' "$(timeout 20 du -sk "$(g rev-parse --absolute-git-dir)" 2>/dev/null | cut -f1)"
done
"""


def candidates(conn: Conn, host_id: int) -> list[str]:
    work = conn.all("""SELECT DISTINCT d.path FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                       WHERE m.host_id = :h AND f.filename = '.git'""", {'h': host_id})
    bare = conn.all("""SELECT DISTINCT d.path FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                       WHERE m.host_id = :h AND f.filename = 'HEAD' AND f.is_directory = 0
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'objects' AND o.is_directory = 1)
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'refs' AND o.is_directory = 1)
                         AND EXISTS (SELECT 1 FROM file_records o WHERE o.dir_id = f.dir_id
                                     AND o.filename = 'config')""", {'h': host_id})
    paths = sorted({r[0] for r in work + bare if r[0] and '\n' not in r[0] and '\t' not in r[0]})
    return paths[:MAX_REPOS], {r[0] for r in work}


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
    out = proc.stdout.read().decode('utf-8', 'replace')
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
    hidden = sum(1 for r in repos if is_noise(r['path']) and (not host or r['host'] == host))
    shown = [r for r in repos if (not host or r['host'] == host) and (include_noise or not is_noise(r['path']))]
    return {'repos': shown, 'hidden': 0 if include_noise else hidden, 'summary': {s: sum(1 for r in shown if r['state'] == s)
                                        for s in ('uncommitted', 'unpushed', 'behind', 'single copy', 'copied', 'archived', 'error')}}
