"""The folder analyses (the file map, twin folders, cold folders), made by one function that runs in a worker process under serve() and in the
caller's own process anywhere else (tests, an App without timers).

They are Python reading every file record, seconds of the one interpreter each at a few million files. In the web's process they shared that
interpreter with every request: at 64 clients the light routes waited 3 s behind them (tests/stress/hammer.py). In a process of their own they
run on another core, the folder index they keep (2 GiB at two million files) is not the web's memory, and if the worker dies, out of memory
say, the server stays up and starts another for the next request.
"""
from __future__ import annotations

import threading
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from multiprocessing import get_context

from . import copies, filemap, folders
from .db import Database

_kept: dict[str, dict] = {}        # database url → {mount id → (its mark, its folders)}, in whichever process makes the analyses
_build = threading.Lock()
_dbs: dict[str, Database] = {}


def _database(url: str) -> Database:
    if url not in _dbs:
        _dbs[url] = Database(url)
    return _dbs[url]


def dir_index(url: str, conn) -> dict:
    """The folder index, rebuilding only the mounts a scan changed since they were kept, one build at a time. A mount whose host is being
    scanned, or that changed while it was read, serves this call and is built again next time."""
    with _build:
        kept_all = _kept.get(url, {})
        marks = folders.mount_marks(conn)
        kept = {m: v for m, v in kept_all.items() if marks.get(m) == v[0]}
        _kept[url] = kept                    # what went stale goes first: two copies of a big mount is a lot of memory
        stale = [m for m in marks if m not in kept]
        built = folders.dir_index(conn, None, stale) if stale else {}
        if stale:
            after, busy = folders.mount_marks(conn), folders.scanning_mounts(conn)
            _kept[url] = {**kept, **{m: (marks[m], built.get(m)) for m in stale if after.get(m) == marks[m] and m not in busy}}
        index = {m: v[1] for m, v in kept.items() if v[1] is not None}
        index.update(built)
        return index


def compute(url: str, kind: str, args: tuple):
    """One analysis: ('cold', (host, years, min_size)), ('dupes', (host, min_files, min_size, include_system)),
    ('filemap', (host, min_size, system, with_folders)), or ('index', ()) to build the folder index ahead of the first request."""
    conn = _database(url).connect()
    try:
        if kind == 'cold':
            host, years, min_size = args
            return folders.cold_folders(conn, host, years, min_size, limit=200)
        if kind == 'dupes':           # a folder a deployed sync keeps is that sync's copy, not a duplicate (copies.py)
            host, min_files, min_size, include_system = args
            return folders.duplicate_folders(conn, host, min_files, min_size, limit=200, include_system=include_system, index=dir_index(url, conn),
                                             syncs=copies.syncs(conn))
        if kind == 'filemap':
            host, min_size, system, with_folders = args
            twins = (folders.duplicate_folders(conn, host, 3, min_size, limit=200, include_system=system, index=dir_index(url, conn),
                                               syncs=copies.syncs(conn))
                     if with_folders else None)
            return filemap.build(conn, host, min_size, system, twins)
        if kind == 'index':
            dir_index(url, conn)
            return None
        raise ValueError(f'no analysis {kind!r}')
    finally:
        conn.close()


class Worker:
    """One process for the analyses: started when first needed, started again if it dies."""

    def __init__(self):
        self.pool = None
        self.lock = threading.Lock()

    def run(self, url: str, kind: str, args: tuple):
        with self.lock:
            if self.pool is None:
                self.pool = ProcessPoolExecutor(max_workers=1, mp_context=get_context('spawn'))
            pool = self.pool
        try:
            return pool.submit(compute, url, kind, args).result()
        except BrokenProcessPool:
            with self.lock:
                if self.pool is pool:
                    self.pool = None
            raise RuntimeError('the folder analysis worker stopped (out of memory, or killed): another starts with the next request') from None

    def stop(self):
        with self.lock:
            pool, self.pool = self.pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
