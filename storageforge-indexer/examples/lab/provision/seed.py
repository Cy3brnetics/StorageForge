#!/usr/bin/env python3
"""Seed data for one folder on a lab VM: writes a tar to stdout and, beside it, a manifest of every entry.

The same input gives the same files, and the hashes come from here rather than from the VM, so tests can check
what a VM holds and what a scan reports against something the VM had no part in.
    seed.py <vm> <full|plain> <folder on the VM> <manifest path>
"""
import hashlib
import io
import json
import os
import random
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

TOP = 'lab-seed'
SPARSE = 'links/sparse.img'      # 1 GiB apparent, nothing allocated: lab.sh truncates it after unpacking
SPARSE_SIZE = 1 << 30
WEIRD = ['with space.txt', 'unicode-日本語-é.txt', 'new\nline.txt', '-leading-hyphen.txt', '--help', "quote'd.txt", '"double".txt',
         'star*.txt', '$dollar.txt', 'back\\slash.txt', 'semi;colon.txt', os.fsdecode(b'not-utf8-\xff.txt'), 'x' * 200 + '.txt']


def blob(name, size):
    """Bytes decided only by the name: the same name is a duplicate on every host, and different names never match."""
    return random.Random(name).randbytes(size)


def sample_repo():
    """A real repository with one commit, with its dates fixed."""
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_AUTHOR_DATE': '2024-01-01T00:00:00Z',
               'GIT_COMMITTER_DATE': '2024-01-01T00:00:00Z', 'GIT_AUTHOR_NAME': 'lab', 'GIT_AUTHOR_EMAIL': 'lab@lab.invalid',
               'GIT_COMMITTER_NAME': 'lab', 'GIT_COMMITTER_EMAIL': 'lab@lab.invalid'}
        git = lambda *a: subprocess.run(['git', '-C', tmp, *a], env=env, check=True, capture_output=True)   # noqa: E731
        git('init', '-q', '-b', 'main', '--template=')
        Path(tmp, 'README.md').write_text('Lab sample repository.\n')
        git('add', '.')
        git('commit', '-q', '-m', 'first')
        files = {}
        for path in sorted(Path(tmp).rglob('*')):
            if path.is_file():
                files[f'repos/sample/{path.relative_to(tmp)}'] = path.read_bytes()
        return files


def build(vm, profile):
    """(dirs with modes, files with modes, hardlinks, symlinks), paths relative to the seed folder."""
    files = {}
    for i in range(1, 6):
        files[f'shared/photos/IMG_000{i}.cr2'] = blob(f'photo{i}', (i % 3 + 1) << 20)
    files['shared/docs/handbook.txt'] = b'The same handbook on every host.\n' * 200
    files[f'unique/{vm}-notes.txt'] = f'Notes only {vm} has.\n'.encode()
    modes, hard, sym, dirmodes = {}, {}, {}, {}
    if profile == 'full':
        files[f'unique/{vm}.bin'] = blob(f'unique-{vm}', 32 << 20)
        report = blob('report', 1 << 20)
        files['dupes/report.pdf'] = report
        files['dupes/archive/report-copy.pdf'] = report
        for name in 'abc':
            album = blob(f'album-{name}', 256 << 10)
            files[f'dupes/album-2024/{name}.jpg'] = album
            files[f'dupes/album-2024-copy/{name}.jpg'] = album
        files['restricted/secret.txt'] = f'Scan users must not read this on {vm}.\n'.encode()
        modes['restricted/secret.txt'] = 0o600
        dirmodes['restricted'] = 0o700
        for i, name in enumerate(WEIRD):
            files[f'weird/{name}'] = f'odd name {i}\n'.encode()
        files['links/target.txt'] = b'link target\n'
        files['links/hard-a.txt'] = b'hardlinked\n'
        hard['links/hard-b.txt'] = 'links/hard-a.txt'
        sym['links/sym-file'] = 'target.txt'
        sym['links/dangling'] = 'no-such-file'
        sym['links/loop'] = '..'
        files.update(sample_repo())
    return files, modes, hard, sym, dirmodes


def main():
    vm, profile, root, manifest_path = sys.argv[1:5]
    files, modes, hard, sym, dirmodes = build(vm, profile)
    dirs = sorted({str(p) for path in [*files, *hard, *sym] for p in Path(path).parents if str(p) != '.'})
    entries = []
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.GNU_FORMAT, encoding='utf-8', errors='surrogateescape') as tar:
        def add(name, kind, mode, data=b'', link=''):
            info = tarfile.TarInfo(f'{TOP}/{name}' if name else TOP)
            info.mtime, info.uid, info.gid, info.mode, info.type = 1704067200, 0, 0, mode, kind
            info.linkname = link
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        add('', tarfile.DIRTYPE, 0o755)
        for d in dirs:
            mode = dirmodes.get(d, 0o755)
            add(d, tarfile.DIRTYPE, mode)
            entries.append({'path': d, 'type': 'd', 'mode': mode})
        for name, data in sorted(files.items()):
            mode = modes.get(name, 0o644)
            add(name, tarfile.REGTYPE, mode, data)
            entries.append({'path': name, 'type': 'f', 'mode': mode, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        for name, target in sorted(hard.items()):
            add(name, tarfile.LNKTYPE, 0o644, link=f'{TOP}/{target}')
            data = files[target]
            entries.append({'path': name, 'type': 'f', 'mode': 0o644, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'hardlink': target})
        for name, target in sorted(sym.items()):
            add(name, tarfile.SYMTYPE, 0o777, link=target)
            entries.append({'path': name, 'type': 'l', 'target': target})
    if profile == 'full':
        entries.append({'path': SPARSE, 'type': 'f', 'mode': 0o644, 'size': SPARSE_SIZE, 'sparse': True})
    Path(manifest_path).write_text(json.dumps({'vm': vm, 'profile': profile, 'root': f'{root}/{TOP}', 'entries': entries}, indent=1))


if __name__ == '__main__':
    main()
