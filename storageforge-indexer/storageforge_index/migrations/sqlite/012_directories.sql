-- StorageForge schema v12 · sqlite: directories
-- Each folder path is stored once in `directories`; file_records points at it by dir_id instead of repeating the
-- path text in every row and in two indexes. file_ids are kept, so the FTS index stays valid.
-- On a large index this rewrites file_records (a few minutes, and temporarily as much free space as that table).
-- Run `storageforge-index prune --vacuum` afterwards to give the freed space back to the filesystem.
BEGIN;

CREATE TABLE directories (
    dir_id    INTEGER PRIMARY KEY,
    mount_id  INTEGER NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    path      TEXT    NOT NULL,             -- absolute; '' only for the parent of the filesystem root entry '/'
    UNIQUE (mount_id, path)
);
-- "under /mnt/x" across mounts; per-mount lookups use the UNIQUE index.
CREATE INDEX ix_dir_path ON directories (path);

INSERT INTO directories (mount_id, path)
SELECT DISTINCT mount_id, parent_path FROM file_records ORDER BY mount_id, parent_path;

DROP VIEW v_files;

CREATE TABLE file_records_new (
    file_id               INTEGER PRIMARY KEY,
    mount_id              INTEGER NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    dir_id                INTEGER NOT NULL REFERENCES directories (dir_id) ON DELETE CASCADE,
    filename              TEXT    NOT NULL,
    extension             TEXT    NOT NULL DEFAULT '',
    file_size_bytes       INTEGER NOT NULL DEFAULT 0,
    is_directory          INTEGER NOT NULL DEFAULT 0 CHECK (is_directory IN (0, 1)),
    is_symlink            INTEGER NOT NULL DEFAULT 0 CHECK (is_symlink IN (0, 1)),
    symlink_target        TEXT,
    mode_permissions      TEXT,
    owner_uid             INTEGER,
    group_gid             INTEGER,
    modified_at           INTEGER NOT NULL,
    checksum_hash         TEXT,
    first_seen_scan_id    INTEGER,
    last_changed_scan_id  INTEGER,
    UNIQUE (dir_id, filename)
);

INSERT INTO file_records_new
SELECT f.file_id, f.mount_id, d.dir_id, f.filename, f.extension, f.file_size_bytes, f.is_directory, f.is_symlink,
       f.symlink_target, f.mode_permissions, f.owner_uid, f.group_gid, f.modified_at, f.checksum_hash,
       f.first_seen_scan_id, f.last_changed_scan_id
FROM file_records f JOIN directories d ON d.mount_id = f.mount_id AND d.path = f.parent_path
ORDER BY f.file_id;

DROP TABLE file_records;
ALTER TABLE file_records_new RENAME TO file_records;

-- ix_file_parent is gone: folder lookups go through directories, then the UNIQUE (dir_id, filename) prefix.
CREATE INDEX ix_file_filename  ON file_records (filename COLLATE NOCASE);
CREATE INDEX ix_file_size      ON file_records (file_size_bytes);
CREATE INDEX ix_file_ext_size  ON file_records (extension, file_size_bytes);
CREATE INDEX ix_file_mtime     ON file_records (modified_at);
CREATE INDEX ix_file_checksum  ON file_records (checksum_hash) WHERE checksum_hash IS NOT NULL;
-- also the per-mount index (WHERE mount_id = :m)
CREATE INDEX ix_file_seen      ON file_records (mount_id, first_seen_scan_id);

CREATE VIEW v_files AS
SELECT h.hostname, m.mount_point, d.path AS parent_path, f.*,
       CASE d.path WHEN '' THEN f.filename
                   WHEN '/' THEN '/' || f.filename
                   ELSE d.path || '/' || f.filename END AS full_path
FROM file_records f
JOIN directories d ON d.dir_id = f.dir_id
JOIN mounts m ON m.mount_id = f.mount_id
JOIN hosts  h ON h.host_id  = m.host_id;

-- Bulk imports (a new disk or folder on a host that was already indexed) no longer list every added entry in the
-- change log; drop the ones logged before. The scan's added count is unaffected.
DELETE FROM file_changes WHERE change_type = 'added' AND (scan_id, mount_id) IN (
    SELECT scan_id, mount_id FROM file_changes WHERE change_type = 'added'
    GROUP BY scan_id, mount_id HAVING count(*) > 50000);

INSERT INTO schema_version (version, name, applied_at)
VALUES (12, 'directories', CAST(strftime('%s', 'now') AS INTEGER));

COMMIT;

-- Full statistics (seconds even at 10M+ rows): with sampled ones the planner reads all of a mount for a name prefix.
ANALYZE file_records;
ANALYZE directories;
