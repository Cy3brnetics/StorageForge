"""The per-job file index storageforge-job keeps on hosts, and the pre-transfer dedup built on it. SYNC_PY is embedded in
JOB_SCRIPT and runs under python3 -I, so it uses the standard library only and needs no second file on the host. It keeps to Python 3.6, what
openSUSE Leap 15 and RHEL 8 ship.

  hashes <db> <root> <algo>          source side: hex paths on fd 3 -> one JSON line per file: its stat and hash
  clone <src> <dst> <want>           same-host jobs: reflink what rsync would copy straight from the source
  candidates <db> <dst> <want> <min> what rsync would copy that is big enough, with a same-sized file already here
  apply <db> <dst> <manifest> <algo> <min> <hardlink 0|1>   make those files from local data, where the hash matches
  metric <db> <kind> <json>          record block-sharing figures

Paths come from the other host, which may have been taken over, so they are data: nothing is resolved through a
symlink, every step down a tree is openat(O_NOFOLLOW) from the job's own root. The pool is only this job's destination:
letting a source claim a hash from another job's tree would hand it that file on the next restore.
"""

SYNC_PY = r"""
import errno, fcntl, hashlib, json, os, re, sqlite3, stat, subprocess, sys, time

FICLONE = 0x40049409
TEMP = b'.sf-dedup-'
SKIP = {b'.rsync-partial', b'.storageforge-snap', b'.storage.lock', b'.storageforge-stream'}
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def opendb(path):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    db = sqlite3.connect(path, timeout=60)
    db.executescript('''
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS files (path BLOB PRIMARY KEY, size INTEGER, mtime_ns INTEGER, inode INTEGER,
                                        algo TEXT, hash TEXT, seen INTEGER);
      CREATE INDEX IF NOT EXISTS files_size ON files (size);
      CREATE TABLE IF NOT EXISTS space_metrics (at INTEGER, kind TEXT, total INTEGER, exclusive INTEGER, shared INTEGER,
                                                saved INTEGER, message TEXT);
    ''')
    return db


def digest(fd, algo):
    os.lseek(fd, 0, 0)
    if algo == 'sha256':
        h = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, 1 << 20), b''):
            h.update(chunk)
        return h.hexdigest()
    if algo == 'blake3':
        return subprocess.run(['b3sum', '--no-names'], stdin=fd, stdout=subprocess.PIPE, check=True, universal_newlines=True).stdout.split()[0]
    raise SystemExit(f'unknown hash {algo}')


def parts_of(rel):
    parts = rel.split(b'/')
    if not rel or rel.startswith(b'/') or b'\0' in rel or any(p in (b'', b'.', b'..') for p in parts):
        raise ValueError('bad path')
    return parts


def open_parent(root, parts, create=False):
    # a directory fd for parts[:-1], below root, through no symlink
    fd = os.open(root, DIR)
    try:
        for p in parts[:-1]:
            try:
                nxt = os.open(p, DIR, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(p, 0o700, dir_fd=fd)      # rsync gives it its real owner and mode
                nxt = os.open(p, DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_file(root, rel):
    parts = parts_of(rel)
    d = open_parent(root, parts)
    try:
        fd = os.open(parts[-1], FILE, dir_fd=d)
    finally:
        os.close(d)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('not a regular file')
    return fd


def cached_hash(db, rel, st, fd, algo):
    row = db.execute('SELECT size, mtime_ns, inode, algo, hash FROM files WHERE path = ?', (rel,)).fetchone()
    if row and row[:4] == (st.st_size, st.st_mtime_ns, st.st_ino, algo) and row[4]:
        return row[4]
    value = digest(fd, algo)
    after = os.fstat(fd)
    if (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns):      # changed under us: no claim about it
        return None
    db.execute('INSERT OR REPLACE INTO files (path, size, mtime_ns, inode, algo, hash, seen) VALUES (?, ?, ?, ?, ?, ?, ?)',
               (rel, st.st_size, st.st_mtime_ns, st.st_ino, algo, value, int(time.time())))
    return value


def cmd_hashes(dbpath, root, algo):
    db, root = opendb(dbpath), os.fsencode(root)
    for line in os.fdopen(3, 'r'):
        try:
            rel = bytes.fromhex(line.strip())
            fd = open_file(root, rel)
        except (ValueError, OSError):
            continue
        try:
            st = os.fstat(fd)
            value = cached_hash(db, rel, st, fd, algo)
            if value:
                print(json.dumps({'p': rel.hex(), 'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'mode': st.st_mode,
                                  'uid': st.st_uid, 'gid': st.st_gid, 'algo': algo, 'hash': value}))
        except OSError:
            pass
        finally:
            os.close(fd)
    db.commit()


def wanted(path):
    # rsync -n -8 --out-format='%l %n': "<size> <name>", with odd bytes in a name as \#ooo; folders end in /
    with open(path, 'rb') as f:
        for line in f:
            m = re.fullmatch(rb'(\d+) (.+)\n?', line)
            if not m or m[2].endswith(b'/'):
                continue
            yield int(m[1]), re.sub(rb'\\#([0-7]{3})', lambda x: bytes([int(x[1], 8)]), m[2])


def refresh(db, root, minsize):
    # stat every file of the pool; a hash is only worked out when a file of its size is wanted
    token = int(time.time() * 1000)
    device = os.lstat(root).st_dev

    def walk(path, rel):
        with os.scandir(path) as it:
            for e in it:
                if e.name.startswith(TEMP):
                    try:
                        os.unlink(e.path)     # left by a killed run
                    except OSError:
                        pass
                    continue
                if e.name in SKIP:
                    continue
                st = e.stat(follow_symlinks=False)
                sub = rel + e.name
                if stat.S_ISDIR(st.st_mode) and st.st_dev == device:
                    walk(e.path, sub + b'/')
                elif stat.S_ISREG(st.st_mode) and st.st_size >= minsize:
                    row = db.execute('SELECT size, mtime_ns, inode FROM files WHERE path = ?', (sub,)).fetchone()
                    if row == (st.st_size, st.st_mtime_ns, st.st_ino):
                        db.execute('UPDATE files SET seen = ? WHERE path = ?', (token, sub))
                    else:
                        db.execute('INSERT OR REPLACE INTO files (path, size, mtime_ns, inode, seen) VALUES (?, ?, ?, ?, ?)',
                                   (sub, st.st_size, st.st_mtime_ns, st.st_ino, token))
    walk(root, b'')
    db.execute('DELETE FROM files WHERE seen <> ?', (token,))
    db.commit()


def cmd_candidates(dbpath, dst, want, minsize):
    db, root = opendb(dbpath), os.fsencode(dst)
    refresh(db, root, int(minsize))
    sizes = {r[0] for r in db.execute('SELECT DISTINCT size FROM files')}
    for size, rel in wanted(want):
        if size >= int(minsize) and size in sizes:
            print(rel.hex())


def replace_with(root, parts, make, mtime_ns):
    # make(dirfd, temp name) leaves the new file at temp; it only takes the target's name once it is whole
    d = open_parent(root, parts, create=True)
    tmp = TEMP + b'%d' % os.getpid()
    try:
        make(d, tmp)
        os.rename(tmp, parts[-1], src_dir_fd=d, dst_dir_fd=d)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=d)
        except OSError:
            pass
        raise
    finally:
        os.close(d)


def clone_into(src_fd, mtime_ns):
    def make(d, tmp):
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=d)
        try:
            fcntl.ioctl(fd, FICLONE, src_fd)
            os.utime(fd, ns=(mtime_ns, mtime_ns))
        finally:
            os.close(fd)
    return make


def copy_into(src_fd, mtime_ns):
    def make(d, tmp):
        os.lseek(src_fd, 0, 0)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=d)
        try:
            for chunk in iter(lambda: os.read(src_fd, 1 << 20), b''):
                os.write(fd, chunk)
            os.utime(fd, ns=(mtime_ns, mtime_ns))
        finally:
            os.close(fd)
    return make


NO_REFLINK = (errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL, errno.ENOTTY, errno.EPERM, errno.EBADF)


def cmd_clone(src, dst, want):
    root_s, root_d = os.fsencode(src), os.fsencode(dst)
    files = saved = 0
    for size, rel in wanted(want):
        try:
            fd = open_file(root_s, rel)
        except (ValueError, OSError):
            continue
        try:
            replace_with(root_d, parts_of(rel), clone_into(fd, os.fstat(fd).st_mtime_ns), 0)
            files, saved = files + 1, saved + size
        except OSError as e:
            if e.errno in NO_REFLINK:
                break                  # this filesystem or pair cannot: rsync copies them, as without dedup
        finally:
            os.close(fd)
    print(files, saved)


def cmd_apply(dbpath, dst, manifest, algo, minsize, hardlink):
    db, root = opendb(dbpath), os.fsencode(dst)
    files = saved = linked = copied = failed = 0
    reflink = True
    for line in open(manifest):
        try:
            m = json.loads(line)
            rel, size, mtime_ns, value = bytes.fromhex(m['p']), int(m['size']), int(m['mtime_ns']), str(m['hash'])
            parts = parts_of(rel)
        except (ValueError, KeyError, TypeError):
            failed += 1
            continue
        if m.get('algo') != algo or size < int(minsize):
            continue
        try:
            d = open_parent(root, parts)
            try:
                st = os.stat(parts[-1], dir_fd=d, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or (st.st_size == size and st.st_mtime_ns == mtime_ns):
                    continue               # a folder or link is rsync's to replace; a match needs nothing
            finally:
                os.close(d)
        except FileNotFoundError:
            pass
        except OSError:
            failed += 1                    # a link in the way, and the like: rsync decides
            continue
        for (cand,) in db.execute('SELECT path FROM files WHERE size = ? AND path <> ?', (size, rel)).fetchall():
            try:
                fd = open_file(root, cand)
            except (ValueError, OSError):
                continue
            try:
                st = os.fstat(fd)
                if st.st_size != size or digest(fd, algo) != value:   # read now: never trust the index for what gets linked
                    continue
                db.execute('UPDATE files SET algo = ?, hash = ?, mtime_ns = ?, inode = ? WHERE path = ?',
                           (algo, value, st.st_mtime_ns, st.st_ino, cand))
                done = False
                if reflink:
                    try:
                        replace_with(root, parts, clone_into(fd, mtime_ns), mtime_ns)
                        done = True
                    except OSError as e:
                        if e.errno not in NO_REFLINK:
                            raise
                        reflink = False
                # one inode has one owner, mode and time: rsync setting them for one name must not change the other
                if not done and hardlink == '1' and (st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid) == \
                        (mtime_ns, m.get('mode'), m.get('uid'), m.get('gid')):
                    cparts = parts_of(cand)
                    cd = open_parent(root, cparts)
                    try:
                        replace_with(root, parts, lambda d, tmp: os.link(cparts[-1], tmp, src_dir_fd=cd, dst_dir_fd=d,
                                                                         follow_symlinks=False), mtime_ns)
                    finally:
                        os.close(cd)
                    done, linked = True, linked + 1
                if not done:
                    vfs = os.statvfs(root)
                    if vfs.f_bavail * vfs.f_frsize <= size:
                        break              # no room: rsync reports it properly
                    replace_with(root, parts, copy_into(fd, mtime_ns), mtime_ns)
                    copied += 1
                files, saved = files + 1, saved + size
                break
            except OSError:
                failed += 1
                break
            finally:
                os.close(fd)
    db.commit()
    print(files, saved, linked, copied, failed)


def cmd_metric(dbpath, kind, text):
    m = json.loads(text)
    db = opendb(dbpath)
    db.execute('INSERT INTO space_metrics VALUES (?, ?, ?, ?, ?, ?, ?)',
               (int(time.time()), kind, m.get('total'), m.get('exclusive'), m.get('shared'), m.get('saved'), m.get('message')))
    db.execute('DELETE FROM space_metrics WHERE at < ?', (int(time.time()) - 400 * 86400,))
    db.commit()


{'hashes': cmd_hashes, 'clone': cmd_clone, 'candidates': cmd_candidates, 'apply': cmd_apply, 'metric': cmd_metric}[sys.argv[1]](*sys.argv[2:])
"""
