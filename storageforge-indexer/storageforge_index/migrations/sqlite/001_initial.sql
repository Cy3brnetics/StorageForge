-- StorageForge-Indexer schema v1 · SQLite ≥ 3.35 (FTS5 trigram tokenizer needs ≥ 3.34)
--
-- The CLI applies this automatically. To apply by hand:
--   sqlite3 ~/.local/share/storageforge/index.db < 001_initial.sql
--
-- Runtime pragmas (set per connection by the CLI, not persisted here except WAL):
--   journal_mode=WAL, synchronous=NORMAL, foreign_keys=ON, cache_size=-262144, mmap_size=1 GiB
--
-- Times are unix epoch seconds (UTC). Booleans are 0/1.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    applied_at  INTEGER NOT NULL
);

-- One row per scanned machine.
CREATE TABLE hosts (
    host_id          INTEGER PRIMARY KEY,
    hostname         TEXT    NOT NULL UNIQUE,      -- as reported by the host (hostname -f)
    ip_address       TEXT,
    os_info          TEXT,
    ssh_host         TEXT,                         -- --host value used to reach it
    ssh_user         TEXT,
    ssh_port         INTEGER,
    inventory_json   TEXT,                         -- lsblk -J, zpool status, findmnt, df from the last scan
    created_at       INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
    last_scanned_at  INTEGER
);

-- Every mount seen on a host, including the ones the scanner skipped and why.
CREATE TABLE mounts (
    mount_id          INTEGER PRIMARY KEY,
    host_id           INTEGER NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    mount_point       TEXT    NOT NULL,
    source            TEXT,
    filesystem_type   TEXT    NOT NULL,
    mount_options     TEXT,
    dev_majmin        TEXT,                        -- st_dev of the mount; equal values + nested fs_root = bind mount
    fs_root           TEXT,                        -- subtree of the filesystem exposed here (btrfs subvol, bind source)
    total_bytes       INTEGER,
    used_bytes        INTEGER,
    scan_state        TEXT    NOT NULL DEFAULT 'indexed'
                      CHECK (scan_state IN ('indexed', 'skipped', 'bind-alias', 'gone')),
    skip_reason       TEXT,
    bind_of_mount_id  INTEGER REFERENCES mounts (mount_id) ON DELETE SET NULL,
    last_scan_id      INTEGER,
    seen_at           INTEGER,
    UNIQUE (host_id, mount_point)
);

CREATE TABLE scans (
    scan_id       INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER,
    status        TEXT    NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running', 'ok', 'partial', 'failed')),
    entries_seen  INTEGER NOT NULL DEFAULT 0,
    bytes_seen    INTEGER NOT NULL DEFAULT 0,
    added         INTEGER NOT NULL DEFAULT 0,
    modified      INTEGER NOT NULL DEFAULT 0,
    deleted       INTEGER NOT NULL DEFAULT 0,
    read_errors   INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER
);

-- One row per file, directory or symlink. (mount_id, parent_path, filename) is the identity used by diffs.
CREATE TABLE file_records (
    file_id               INTEGER PRIMARY KEY,
    mount_id              INTEGER NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    parent_path           TEXT    NOT NULL,         -- absolute; '' only for the filesystem root entry '/'
    filename              TEXT    NOT NULL,
    extension             TEXT    NOT NULL DEFAULT '',   -- lower-cased, '' for directories and dotless names
    file_size_bytes       INTEGER NOT NULL DEFAULT 0,
    is_directory          INTEGER NOT NULL DEFAULT 0 CHECK (is_directory IN (0, 1)),
    is_symlink            INTEGER NOT NULL DEFAULT 0 CHECK (is_symlink IN (0, 1)),
    symlink_target        TEXT,
    mode_permissions      TEXT,                     -- symbolic, e.g. -rw-r--r--
    owner_uid             INTEGER,
    group_gid             INTEGER,
    modified_at           INTEGER NOT NULL,
    checksum_hash         TEXT,                     -- sha256, only for size-collision candidates
    first_seen_scan_id    INTEGER,
    last_changed_scan_id  INTEGER,
    UNIQUE (mount_id, parent_path, filename)
);

-- Exact and prefix name lookups (LIKE 'IMG_%' uses this because case_sensitive_like is off).
CREATE INDEX ix_file_filename  ON file_records (filename COLLATE NOCASE);
-- Directory browsing across mounts; per-mount browsing uses the UNIQUE index prefix.
CREATE INDEX ix_file_parent    ON file_records (parent_path);
CREATE INDEX ix_file_size      ON file_records (file_size_bytes);
-- "*.cr2 bigger than 100 MB" is answered from this index alone.
CREATE INDEX ix_file_ext_size  ON file_records (extension, file_size_bytes);
CREATE INDEX ix_file_mtime     ON file_records (modified_at);
CREATE INDEX ix_file_checksum  ON file_records (checksum_hash) WHERE checksum_hash IS NOT NULL;
CREATE INDEX ix_file_seen      ON file_records (mount_id, first_seen_scan_id);
CREATE INDEX ix_mounts_host    ON mounts (host_id);
CREATE INDEX ix_scans_host     ON scans (host_id, scan_id);

-- Substring and wildcard search on file names. External content: no second copy of the text.
-- The trigram tokenizer lets LIKE/GLOB with a 3+ character literal run against the index.
-- Only names are indexed: trigram-indexing full parent paths costs ~2x the ingest time for a
-- rarely used filter, and a substring scan of parent_path stays well under a second at 1M rows.
-- Kept in sync by the scanner inside the same transaction as each diff.
CREATE VIRTUAL TABLE file_fts USING fts5 (
    filename,
    content = 'file_records', content_rowid = 'file_id',
    tokenize = 'trigram'
);

-- What changed between scans (adds are only logged after a mount's first scan).
CREATE TABLE file_changes (
    change_id        INTEGER PRIMARY KEY,
    scan_id          INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    mount_id         INTEGER NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    change_type      TEXT    NOT NULL CHECK (change_type IN ('added', 'modified', 'deleted')),
    parent_path      TEXT    NOT NULL,
    filename         TEXT    NOT NULL,
    is_directory     INTEGER NOT NULL DEFAULT 0,
    old_size         INTEGER,
    new_size         INTEGER,
    old_modified_at  INTEGER,
    new_modified_at  INTEGER
);
CREATE INDEX ix_changes_scan ON file_changes (scan_id, change_type);

-- Convenience view for ad-hoc SQL.
CREATE VIEW v_files AS
SELECT h.hostname, m.mount_point, f.*,
       CASE f.parent_path WHEN '' THEN f.filename
                          WHEN '/' THEN '/' || f.filename
                          ELSE f.parent_path || '/' || f.filename END AS full_path
FROM file_records f
JOIN mounts m ON m.mount_id = f.mount_id
JOIN hosts  h ON h.host_id  = m.host_id;

INSERT INTO schema_version (version, name, applied_at)
VALUES (1, 'initial', CAST(strftime('%s', 'now') AS INTEGER));
