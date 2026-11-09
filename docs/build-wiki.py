#!/usr/bin/env python3
"""Build a Forgejo or GitHub wiki from docs/ (links to repository files take the form of the host in --repo-url). A wiki is its own flat git repository, so pages are renamed from their titles and
links rewritten to match. Links to files outside docs/ go to the repository. Any link that leads nowhere stops the build,
so a broken wiki never gets published. Edit docs/, never the wiki: each build replaces it."""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / 'docs'
DEFAULT_REMOTE = 'ssh://git@10.42.0.3:2222/Gabe/StorageForge.wiki.git'
DEFAULT_REPO = 'http://10.42.0.3:3000/Gabe/StorageForge'
LINK = re.compile(r'(!?\[[^\]]*\]\()([^)\s]+)(\))')
PREFIX = {'features': 'Feature'}


def file_url(repo_url, kind, rel):
    """A file in the repository, in the address form of whoever hosts it: GitHub has /blob/main and /raw/main, Forgejo /src/branch/main and
    /raw/branch/main. kind is 'src' for a page about the file, 'raw' for the file itself (an image)."""
    if urlsplit(repo_url).hostname == 'github.com':
        return f'{repo_url}/{"raw" if kind == "raw" else "blob"}/main/{rel}'
    return f'{repo_url}/{kind}/branch/main/{rel}'          # guide pages share short titles such as "Views"


def page_name(path):
    if path == DOCS / 'README.md':
        return 'Home'
    title = re.search(r'^# (.+)$', path.read_text(), re.M)
    if not title:
        sys.exit(f'{path}: no title')
    name = re.sub(r'[^\w-]+', '-', title.group(1)).strip('-')
    prefix = PREFIX.get(path.parent.name)
    return f'{prefix}-{name}' if prefix and path.name != 'README.md' else name


def anchor(heading):
    return re.sub(r'[^\w\- ]', '', heading.strip().lower()).replace(' ', '-')


def anchors(path):
    return {anchor(h) for h in re.findall(r'^#+ (.+)$', path.read_text(), re.M)}


def convert(path, names, repo_url, errors):
    def fix(match):
        before, url, after = match.groups()
        if re.match(r'[a-z]+:', url):
            return match.group(0)
        target, _, frag = url.partition('#')
        dest = (path.parent / target).resolve() if target else path
        if not dest.exists():
            errors.append(f'{path.relative_to(ROOT)}: no such file: {url}')
            return match.group(0)
        if dest in names:
            if frag and frag not in anchors(dest):
                errors.append(f'{path.relative_to(ROOT)}: no such heading: {url}')
            return f'{before}{names[dest]}{"#" + frag if frag else ""}{after}'
        if dest.is_relative_to(DOCS):
            return f'{before}{dest.relative_to(DOCS).as_posix()}{after}'
        kind = 'raw' if before.startswith('!') else 'src'
        return f'{before}{file_url(repo_url, kind, dest.relative_to(ROOT).as_posix())}{"#" + frag if frag else ""}{after}'

    out, fenced = [], False
    for line in path.read_text().splitlines():
        if line.lstrip().startswith('```'):
            fenced = not fenced
        out.append(line if fenced else LINK.sub(fix, line))
    return '\n'.join(out) + '\n'


def sidebar(home, names):
    """Home's own sections, plus the guide's pages under its entry."""
    lines = ['**[Home](Home)**', '']
    for line in home.splitlines():
        if line.startswith('## '):
            lines += ['', f'**{line[3:]}**', '']
        elif link := re.match(r'\| \[([^\]]+)\]\(([^)#\s]+)\)', line):
            lines.append(f'- [{link.group(1)}]({link.group(2)})')
    guide = [n for p, n in sorted(names.items()) if p.parent.name == 'features' and p.name != 'README.md']
    lines[lines.index('**Every feature**') + 1:lines.index('**Every feature**') + 2] = [
        '', '- [Feature guide](Feature-guide)', *(f'- [{n.split("-", 1)[1].replace("-", " ")}]({n})' for n in guide), '']
    return '\n'.join(lines) + '\n'


def build(out, repo_url):
    pages = sorted(p for p in DOCS.rglob('*.md'))
    names = {p.resolve(): page_name(p) for p in pages}
    if len(set(names.values())) != len(names):
        sys.exit(f'two pages would have the same name: {sorted(names.values())}')
    errors = []
    converted = {names[p.resolve()]: convert(p.resolve(), names, repo_url, errors) for p in pages}
    if errors:
        sys.exit('broken links:\n  ' + '\n  '.join(errors))
    for item in out.iterdir():
        if item.name != '.git':
            shutil.rmtree(item) if item.is_dir() else item.unlink()
    for name, text in converted.items():
        (out / f'{name}.md').write_text(text)
    shutil.copytree(DOCS / 'images', out / 'images')
    (out / '_Sidebar.md').write_text(sidebar(converted['Home'], names))
    (out / '_Footer.md').write_text('Built from [`docs/`](' + file_url(repo_url, 'src', 'docs') + '). Edit there: each build replaces this wiki.\n')
    return len(converted)


def push(out, remote):
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(out)], check=True)
    subprocess.run(['git', '-C', str(out), 'remote', 'add', 'origin', remote], check=True)
    if subprocess.run(['git', '-C', str(out), 'fetch', '-q', 'origin'], capture_output=True).returncode == 0:
        heads = subprocess.run(['git', '-C', str(out), 'for-each-ref', '--format=%(refname:short)', 'refs/remotes/origin/'],
                               capture_output=True, text=True).stdout.split()
        heads = [h for h in heads if h.split('/', 1)[-1] != 'HEAD' and h != 'origin']
        if heads:     # Forgejo's wiki branch can be main or master
            subprocess.run(['git', '-C', str(out), 'symbolic-ref', 'HEAD', f'refs/heads/{heads[0].split("/", 1)[1]}'], check=True)
            subprocess.run(['git', '-C', str(out), 'reset', '-q', '--mixed', heads[0]], check=True)
    subprocess.run(['git', '-C', str(out), 'add', '-A'], check=True)
    if subprocess.run(['git', '-C', str(out), 'diff', '--cached', '--quiet']).returncode == 0:
        print('wiki already up to date')
        return
    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
    subprocess.run(['git', '-C', str(out), 'commit', '-q', '-m', f'Build from docs at {commit}'], check=True)
    subprocess.run(['git', '-C', str(out), 'push', '-q', 'origin', 'HEAD'], check=True)
    print(f'pushed to {remote}')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, help='build into this folder (default: a temporary one, with --push)')
    ap.add_argument('--push', action='store_true', help='also commit and push to the wiki repository')
    ap.add_argument('--remote', default=os.environ.get('STORAGEFORGE_WIKI_REMOTE', DEFAULT_REMOTE))
    ap.add_argument('--repo-url', default=os.environ.get('STORAGEFORGE_REPO_URL', DEFAULT_REPO), help='web address of the repository')
    args = ap.parse_args()
    if args.push and args.out:
        ap.error('--push builds in its own temporary folder: leave out --out')
    if not args.push and not args.out:
        ap.error('give --out DIR, or --push')
    with tempfile.TemporaryDirectory() as tmp:
        out = args.out or Path(tmp)
        out.mkdir(parents=True, exist_ok=True)
        print(f'{build(out, args.repo_url.rstrip("/"))} pages built in {out}')
        if args.push:
            push(out, args.remote)


if __name__ == '__main__':
    main()
