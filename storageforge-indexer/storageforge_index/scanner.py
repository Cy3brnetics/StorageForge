"""Scan orchestration: mount planning, parallel `find` streams and the database writer pool.

    remote host                         this machine
    ───────────                         ────────────
    find mount A ──ssh stream──► reader thread A ─┐  batches   ┌─► writer 0 (stage → diff → apply)
    find mount B ──ssh stream──► reader thread B ─┼──────────► │
    find mount C ──ssh stream──► reader thread C ─┘  by mount  └─► writer N (PostgreSQL only)

Readers parse NUL-delimited records and push fixed-size batches into bounded
queues, so a slow database applies back-pressure instead of growing memory.
Each mount is routed to one writer, which loads it into a staging table and
diffs it against the previous index in a single transaction.
"""
from __future__ import annotations

import posixpath
import queue
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .capacity import fmt_bin
from .db import Database, DiffStats
from .remote import (DEFAULT_EXCLUDE_NAMES, DEFAULT_EXCLUDE_PATHS, NETWORK_FS, PSEUDO_FS, TMP_FS,
                     MountInfo, RemoteError, StderrTail, Transport, checksum_command, collect_inventory,
                     find_command, is_under)
from .stream import iter_fields, iter_rows, join_path


def log_err(msg: str):
    print(msg, file=sys.stderr, flush=True)


@dataclass
class ScanOptions:
    roots: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS))
    exclude_names: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_NAMES))
    include_network: bool = False
    include_tmpfs: bool = False
    include_fstypes: list[str] = field(default_factory=list)   # e.g. ['overlay'] to walk container root filesystems
    parallel: int = 4
    batch_size: int = 20_000
    checksum: bool = False
    git: bool = True                 # read every repository the walk found through the host's git
    docker: bool = True              # containers, volumes and compose stacks, and which folders they use
    checksum_min_size: int = 1 << 20
    nice: bool = True
    dry_run: bool = False
    max_delete_ratio: float = 0.5


@dataclass
class MountPlan:
    info: MountInfo
    action: str                      # scan | skip | alias
    reason: str = ''
    alias_of: 'MountPlan | None' = None
    mount_id: int | None = None


@dataclass
class ScanJob:
    id: int
    plan: MountPlan
    root: str
    prune: list[str]

    @property
    def full(self) -> bool:
        return self.root == self.plan.info.target


@dataclass
class JobResult:
    job: ScanJob
    entries: int = 0
    bytes: int = 0
    read_errors: int = 0
    denied: list = field(default_factory=list)
    seconds: float = 0.0
    error: Exception | None = None
    diff: DiffStats | None = None


def skip_reason(m: MountInfo, opts: ScanOptions) -> str | None:
    fs = m.fstype
    if fs in opts.include_fstypes:
        return None
    if fs in PSEUDO_FS or fs.startswith('cgroup') or (fs.startswith('fuse.') and fs not in NETWORK_FS and fs != 'fuse.mergerfs'):
        return f'pseudo or virtual filesystem ({fs}; use --include-fstype {fs} to walk it)'
    if fs in TMP_FS and not opts.include_tmpfs:
        return 'tmpfs is volatile (use --include-tmpfs)'
    if fs in NETWORK_FS and not opts.include_network:
        return 'network filesystem: index it on its source host (or use --include-network)'
    return None


def _subvolid(m: MountInfo) -> str | None:
    hit = re.search(r'(?:^|,)subvolid=(\d+)', m.options or '')
    return hit.group(1) if hit else None


def _walk_reaches(m: MountInfo, prior: MountInfo) -> bool:
    """Whether the walk of prior (same filesystem, fsroot above m's) sees m's files somewhere besides m's own mount
    point: only then is m a mere bind (alias). A btrfs subvolume nested in another (openSUSE's /@/home) is its own
    tree that the parent's -xdev walk never enters, and a mount over the very place its files would show up is pruned
    from that walk; either needs a scan of its own."""
    a, b = _subvolid(m), _subvolid(prior)
    if m.fstype == 'btrfs' and a and b and a != b:
        return False
    rel = posixpath.relpath(m.fsroot or '/', prior.fsroot or '/')
    return posixpath.normpath(posixpath.join(prior.target, rel)) != m.target


def plan_mounts(mounts: list[MountInfo], opts: ScanOptions) -> list[MountPlan]:
    plans: list[MountPlan] = []
    kept: dict[str, list[MountPlan]] = {}
    # Broadest filesystem root first, so a bind of a subdirectory is recognised as an alias.
    for m in sorted(mounts, key=lambda m: (len(m.fsroot or '/'), len(m.target))):
        why = skip_reason(m, opts)
        if why is None and any(is_under(m.target, p) for p in opts.exclude_paths):
            why = 'excluded path'
        if why:
            plans.append(MountPlan(m, 'skip', why))
            continue
        prior = next((p for p in kept.get(m.majmin, []) if is_under(m.fsroot or '/', p.info.fsroot or '/')
                      and _walk_reaches(m, p.info)), None) if m.majmin else None
        if prior:
            plans.append(MountPlan(m, 'alias', f'bind of {prior.info.target}', alias_of=prior))
        else:
            plan = MountPlan(m, 'scan')
            plans.append(plan)
            kept.setdefault(m.majmin, []).append(plan)
    return plans


def build_jobs(plans: list[MountPlan], opts: ScanOptions) -> list[ScanJob]:
    targets = [p.info.target for p in plans]
    scan = [p for p in plans if p.action == 'scan']
    pairs: dict[tuple[str, str], tuple[MountPlan, str]] = {}
    if opts.roots:
        roots = sorted({posixpath.normpath(r) for r in opts.roots}, key=len)
        roots = [r for i, r in enumerate(roots) if not any(is_under(r, o) for o in roots[:i])]
        for root in roots:
            owner = max((p for p in plans if is_under(root, p.info.target)), key=lambda p: len(p.info.target), default=None)
            if owner is None or owner.action != 'scan':
                why = owner.reason if owner else 'no mount contains it'
                raise ValueError(f'{root} cannot be indexed: {why}')
            pairs[(owner.info.target, root)] = (owner, root)
            for p in scan:
                if p is not owner and is_under(p.info.target, root):
                    pairs[(p.info.target, p.info.target)] = (p, p.info.target)
    else:
        for p in scan:
            pairs[(p.info.target, p.info.target)] = (p, p.info.target)
    jobs = []
    for i, (plan, root) in enumerate(pairs.values()):
        prune = sorted({t for t in targets if t != root and is_under(t, root)}
                       | {x for x in opts.exclude_paths if x != root and is_under(x, root)})
        jobs.append(ScanJob(i, plan, root, prune))
    return jobs


class WriterPool:
    """One thread per database connection; every mount is pinned to one writer."""

    def __init__(self, db: Database, scan_id: int, writers: int, max_delete_ratio: float):
        self.db, self.scan_id, self.ratio = db, scan_id, max_delete_ratio
        self.queues = [queue.Queue(maxsize=16) for _ in range(writers)]
        self.results: dict[int, DiffStats | Exception] = {}
        self.threads = [threading.Thread(target=self._run, args=(q,), daemon=True) for q in self.queues]
        for t in self.threads:
            t.start()

    def send(self, mount_id: int, msg: tuple):
        self.queues[mount_id % len(self.queues)].put(msg)

    def close(self) -> dict[int, DiffStats | Exception]:
        for q in self.queues:
            q.put(None)
        for t in self.threads:
            t.join()
        return self.results

    def _run(self, q: queue.Queue):
        conn = self.db.connect()
        failed: set[int] = set()
        try:
            while (msg := q.get()) is not None:
                kind, jid = msg[0], msg[1]
                if jid in failed and kind != 'abort':
                    continue
                try:
                    if kind == 'begin':
                        self.db.stage_create(conn, jid)
                    elif kind == 'rows':
                        self.db.stage_insert(conn, jid, msg[2])
                    elif kind == 'end':
                        _, _, mount_id, root, full = msg
                        self.results[jid] = self.db.apply_diff(conn, self.scan_id, jid, mount_id, root, full, self.ratio)
                        self.db.stage_drop(conn, jid)
                    elif kind == 'abort':
                        self.results.setdefault(jid, msg[2])
                        self.db.stage_drop(conn, jid)
                except Exception as exc:  # keep the writer alive for other mounts
                    failed.add(jid)
                    self.results[jid] = exc
                    try:
                        self.db.stage_drop(conn, jid)
                    except Exception:
                        pass
        finally:
            conn.close()


def stream_job(t: Transport, job: ScanJob, pool: WriterPool, opts: ScanOptions) -> JobResult:
    mid = job.plan.mount_id
    res = JobResult(job)
    started = time.time()
    pool.send(mid, ('begin', job.id))
    proc = t.stream(find_command(job.root, job.prune, opts.exclude_names, nice=opts.nice))
    err = StderrTail(proc.stderr)
    try:
        batch = []
        for row in iter_rows(proc.stdout):
            batch.append(row)
            res.entries += 1
            res.bytes += row[3]
            if len(batch) >= opts.batch_size:
                pool.send(mid, ('rows', job.id, batch))
                batch = []
        if batch:
            pool.send(mid, ('rows', job.id, batch))
        rc = proc.wait()
        err.join(5)
        # find exits 1 when some directories were unreadable; that is a partial but usable walk.
        # Exit 1 with no output, or anything else, means the walk did not happen and nothing may be deleted.
        if rc not in (0, 1) or (rc == 1 and res.entries == 0):
            raise RemoteError(f'find {job.root} exited {rc}: ' + ('; '.join(err.tail) or 'no output'))
        pool.send(mid, ('end', job.id, mid, job.root, job.full))
    except Exception as exc:
        proc.kill()
        proc.wait()
        res.error = exc
        pool.send(mid, ('abort', job.id, exc))
    err.join(5)
    for pipe in (proc.stdout, proc.stderr):
        pipe.close()
    res.read_errors = err.count
    res.denied = err.denied
    res.seconds = time.time() - started
    return res


def checksum_pass(db: Database, conn, t: Transport, host_id: int, min_size: int, nice: bool = True) -> int:
    """Hash only files whose size collides with another file: the only possible duplicates."""
    cands = db.checksum_candidates(conn, host_id, min_size)
    if not cands:
        return 0
    by_path = {join_path(parent, name): fid for fid, parent, name in cands}
    proc = t.stream(checksum_command(nice), stdin=True)

    def feed():
        try:
            for path in by_path:
                proc.stdin.write(path.encode('utf-8', 'surrogateescape') + b'\0')
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass

    threading.Thread(target=feed, daemon=True).start()
    err = StderrTail(proc.stderr)
    done, updates = 0, []
    for (rec,) in iter_fields(proc.stdout, nfields=1):
        line = rec.decode('utf-8', 'backslashreplace')
        fid = by_path.get(line[66:])
        if fid is not None:
            updates.append((line[:64], fid))
        if len(updates) >= 5000:
            done += db.set_checksums(conn, updates)
            updates = []
    proc.wait()
    err.join(5)
    proc.stdout.close()
    proc.stderr.close()
    return done + (db.set_checksums(conn, updates) if updates else 0)


def scan_host(db: Database, t: Transport, opts: ScanOptions, log=log_err) -> dict | None:
    conn = db.connect()
    try:
        inv = collect_inventory(t)
        plans = plan_mounts(inv.mounts, opts)
        jobs = build_jobs(plans, opts)
        log(f'{inv.hostname} ({inv.ip or t.host}) · {inv.os_info or "unknown OS"}')
        in_jobs = {j.plan.info.target for j in jobs}
        for p in sorted(plans, key=lambda p: p.info.target):
            if p.action != 'scan' and (p.info.fstype in PSEUDO_FS or any(is_under(p.info.target, x) for x in DEFAULT_EXCLUDE_PATHS)):
                continue
            if opts.roots and p.info.target not in in_jobs:
                continue
            mark = {'scan': 'index', 'skip': 'skip ', 'alias': 'alias'}[p.action]
            log(f'  {mark}  {p.info.target:<34} {p.info.fstype:<10} {p.reason}')
        if opts.dry_run:
            for j in jobs:
                log(f'  would run: {find_command(j.root, j.prune, opts.exclude_names, opts.nice)}')
            return None

        host_id = db.upsert_host(conn, inv, t, t.host_keys())   # refuses a machine claiming another host's name
        if inv.jobs:                                     # runs of deployed jobs that could not report themselves
            try:
                from .jobs import ingest_scan
                if n := ingest_scan(conn, inv.hostname, inv.jobs):
                    log(f'  picked up {n} job run(s) the jobs could not report')
            except Exception as exc:
                log(f'  job runs: {exc}')
        if getattr(inv, 'runs', None) or getattr(inv, 'tasks', None) or getattr(inv, 'schedules', None):
            try:
                from . import confirm
                summary = confirm.ingest_scan(db, conn, inv.hostname, getattr(inv, 'runs', ''),
                                              getattr(inv, 'tasks', ''), getattr(inv, 'schedules', ''), log=log)
                if summary.get('confirmed') or summary.get('tasks') or summary.get('schedules'):
                    log(f'  confirmed {summary.get("confirmed", 0)} deploy run(s), '
                        f'{summary.get("tasks", 0)} task run(s), {summary.get("schedules", 0)} schedule run(s)')
            except Exception as exc:
                log(f'  confirm runs: {exc}')
        scan_id = db.begin_scan(conn, host_id)          # refuses while another scan of this host runs
        db.sync_mounts(conn, host_id, plans)
        writers = max(1, min(db.max_writers, len(jobs)))
        log(f'scan #{scan_id}: {len(jobs)} job(s), {opts.parallel} parallel stream(s), {writers} writer(s)')
        pool = WriterPool(db, scan_id, writers, opts.max_delete_ratio)
        started = time.time()
        with ThreadPoolExecutor(max_workers=max(1, opts.parallel)) as ex:
            results = list(ex.map(lambda j: stream_job(t, j, pool, opts), jobs))
        diffs = pool.close()

        tot = {'entries': 0, 'bytes': 0, 'added': 0, 'modified': 0, 'deleted': 0, 'read_errors': 0, 'failed': 0}
        for r in results:
            d = diffs.get(r.job.id)
            if r.error is None and isinstance(d, Exception):
                r.error = d
            elif isinstance(d, DiffStats):
                r.diff = d
            tot['entries'] += r.entries
            tot['bytes'] += r.bytes
            tot['read_errors'] += r.read_errors
            if r.error:
                tot['failed'] += 1
                log(f'  ✗ {r.job.root}: {r.error}')
                continue
            tot['added'] += r.diff.added
            tot['modified'] += r.diff.modified
            tot['deleted'] += r.diff.deleted
            rate = r.entries / r.seconds if r.seconds else 0
            change = 'first index' if r.diff.first_scan else f'+{r.diff.added} ~{r.diff.modified} -{r.diff.deleted}'
            errs = f', {r.read_errors} unreadable' if r.read_errors else ''
            log(f'  ✓ {r.job.root:<34} {r.entries:>11,} entries {fmt_bin(r.bytes):>11}  {change}  '
                f'({r.seconds:.1f}s, {rate:,.0f}/s{errs})')
        denied = [(r.job.plan.info.target, p) for r in results for p in r.denied]
        if denied:
            db.save_denied(conn, scan_id, denied)
            log(f'  {sum(len(r.denied) for r in results):,} folder(s) unreadable as {inv.user or "the scan user"}; '
                'see Access in the web UI, or: storageforge-index access script')
        if opts.git:
            from .gitrepos import survey
            try:
                g = survey(db, conn, t, host_id, scan_id)
                if g.get('error'):
                    log(f'  git: {g["error"]}')
                elif g['repos']:
                    log(f'  git: {g["repos"]} repositories ({g["bare"]} bare, {g["dirty"]} with uncommitted changes)')
            except Exception as exc:                      # never fail a finished scan over the git pass
                log(f'  git survey failed: {exc}')
        if opts.docker:
            from .docker import survey as docker_survey
            try:
                d = docker_survey(db, conn, t, host_id, scan_id)
                if d.get('engine'):
                    log(f'  {d["engine"]} ({d["access"]}): {d["running"]}/{d["containers"]} containers running, '
                        f'{d["volumes"]} volumes, {d["compose"]} compose files')
                elif d.get('compose'):
                    log(f'  {d["compose"]} compose files (no container engine reachable)')
            except Exception as exc:                      # never fail a finished scan over the docker pass
                log(f'  docker survey failed: {exc}')
        if opts.checksum:
            hashed = checksum_pass(db, conn, t, host_id, opts.checksum_min_size, opts.nice)
            log(f'  checksummed {hashed:,} size-collision candidates')
        status = 'ok' if not tot['failed'] else ('failed' if tot['failed'] == len(results) else 'partial')
        db.finish_scan(conn, scan_id, host_id, tot, status, time.time() - started)
        if status != 'failed':
            try:
                from .scheduler import verify_pending
                if n := verify_pending(conn, inv.hostname):
                    log(f'  checked {n} schedule run(s) against this scan')
            except Exception as exc:
                log(f'  schedule runs: {exc}')
        if status != 'failed':
            from .hostconfig import capture
            try:
                if capture(conn, inv.hostname)['new']:
                    log('  host configuration changed: saved a new version')
            except Exception as exc:                      # never fail a finished scan over the config history
                log(f'  host configuration not saved: {exc}')
        log(f'scan #{scan_id} {status}: {tot["entries"]:,} entries, {fmt_bin(tot["bytes"])} in '
            f'{time.time() - started:.1f}s · +{tot["added"]:,} ~{tot["modified"]:,} -{tot["deleted"]:,}')
        return {'scan_id': scan_id, 'host': inv.hostname, 'status': status, **tot}
    finally:
        conn.close()
