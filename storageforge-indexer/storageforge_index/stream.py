"""Streaming parser for NUL-delimited `find -printf` output.

Every record is FIELDS NUL-terminated fields, so paths may contain spaces,
newlines or any byte except NUL. Memory use is bounded by one read chunk no
matter how many files the remote host has.
"""
from __future__ import annotations

from typing import BinaryIO, Iterator

# type, size, symbolic mode, uid, gid, mtime (epoch, fractional), symlink target, path
FIND_FORMAT = r'%y\0%s\0%M\0%U\0%G\0%T@\0%l\0%p\0'
FIELDS = 8
CHUNK = 1 << 20

# Row layout shared by the scanner, the staging tables and the COPY stream.
ROW_COLUMNS = ('parent_path', 'filename', 'extension', 'size', 'is_dir', 'is_link',
               'target', 'mode', 'uid', 'gid', 'mtime')


class TruncatedStream(RuntimeError):
    """The remote stream ended in the middle of a record (connection dropped)."""


def iter_fields(stream: BinaryIO, nfields: int = FIELDS, chunk: int = CHUNK) -> Iterator[list[bytes]]:
    read = getattr(stream, 'read1', stream.read)
    pending = b''
    record: list[bytes] = []
    while True:
        data = read(chunk)
        if not data:
            break
        parts = (pending + data).split(b'\0')
        pending = parts.pop()
        for part in parts:
            record.append(part)
            if len(record) == nfields:
                yield record
                record = []
    if pending or record:
        raise TruncatedStream(f'stream ended inside a record ({len(record)} of {nfields} fields read)')


def decode(raw: bytes) -> str:
    # Non-UTF-8 names stay searchable; the undecodable bytes become \xNN escapes.
    return raw.decode('utf-8', 'backslashreplace')


def split_path(path: str) -> tuple[str, str]:
    """'/' → ('', '/'), '/etc' → ('/', 'etc'), '/etc/fstab' → ('/etc', 'fstab')."""
    if path == '/':
        return '', '/'
    path = path.rstrip('/') or '/'
    i = path.rfind('/')
    return (path[:i] or '/'), path[i + 1:]


def join_path(parent: str, name: str) -> str:
    if not parent:
        return name
    return '/' + name if parent == '/' else f'{parent}/{name}'


def extension(name: str, is_dir: bool) -> str:
    if is_dir:
        return ''
    i = name.rfind('.')
    if i <= 0 or i == len(name) - 1:
        return ''
    ext = name[i + 1:].lower()
    return ext if len(ext) <= 16 and ' ' not in ext else ''


def to_row(rec: list[bytes]) -> tuple:
    ftype, size, mode, uid, gid, mtime, target, path = rec
    parent, name = split_path(decode(path))
    t = ftype.decode('ascii', 'replace')
    is_dir = t == 'd'
    is_link = t == 'l'
    return (parent, name, extension(name, is_dir), int(size), is_dir, is_link,
            decode(target) if is_link else None, mode.decode('ascii', 'replace'),
            int(uid), int(gid), int(float(mtime)))


def iter_rows(stream: BinaryIO) -> Iterator[tuple]:
    for rec in iter_fields(stream):
        yield to_row(rec)
