-- StorageForge-Indexer schema v1 · PostgreSQL ≥ 13 with pg_trgm
--
-- The CLI applies this automatically. To apply by hand:
--   psql "$STORAGEFORGE_DB" -v ON_ERROR_STOP=1 -f 001_initial.sql
--
-- Bulk loads go through COPY into per-connection TEMP staging tables, then one
-- set-based diff per mount. Wildcard and substring search use pg_trgm GIN indexes.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    applied_at  BIGINT  NOT NULL
);

CREATE TABLE hosts (
    host_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname         TEXT        NOT NULL UNIQUE,
    ip_address       TEXT,
    os_info          TEXT,
    ssh_host         TEXT,
    ssh_user         TEXT,
    ssh_port         INTEGER,
    inventory_json   JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scanned_at  TIMESTAMPTZ
);

CREATE TABLE mounts (
    mount_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id           BIGINT NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    mount_point       TEXT   NOT NULL,
    source            TEXT,
    filesystem_type   TEXT   NOT NULL,
    mount_options     TEXT,
    dev_majmin        TEXT,
    fs_root           TEXT,
    total_bytes       BIGINT,
    used_bytes        BIGINT,
    scan_state        TEXT   NOT NULL DEFAULT 'indexed'
                      CHECK (scan_state IN ('indexed', 'skipped', 'bind-alias', 'gone')),
    skip_reason       TEXT,
    bind_of_mount_id  BIGINT REFERENCES mounts (mount_id) ON DELETE SET NULL,
    last_scan_id      BIGINT,
    seen_at           TIMESTAMPTZ,
    UNIQUE (host_id, mount_point)
);

CREATE TABLE scans (
    scan_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id       BIGINT      NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ,
    status        TEXT        NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running', 'ok', 'partial', 'failed')),
    entries_seen  BIGINT      NOT NULL DEFAULT 0,
    bytes_seen    BIGINT      NOT NULL DEFAULT 0,
    added         BIGINT      NOT NULL DEFAULT 0,
    modified      BIGINT      NOT NULL DEFAULT 0,
    deleted       BIGINT      NOT NULL DEFAULT 0,
    read_errors   BIGINT      NOT NULL DEFAULT 0,
    duration_ms   BIGINT
);

-- fillfactor leaves room on each page so rescans update rows in place (HOT updates).
CREATE TABLE file_records (
    file_id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mount_id              BIGINT      NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    parent_path           TEXT        NOT NULL,
    filename              TEXT        NOT NULL,
    extension             TEXT        NOT NULL DEFAULT '',
    file_size_bytes       BIGINT      NOT NULL DEFAULT 0,
    is_directory          BOOLEAN     NOT NULL DEFAULT false,
    is_symlink            BOOLEAN     NOT NULL DEFAULT false,
    symlink_target        TEXT,
    mode_permissions      TEXT,
    owner_uid             BIGINT,
    group_gid             BIGINT,
    modified_at           TIMESTAMPTZ NOT NULL,
    checksum_hash         TEXT,
    first_seen_scan_id    BIGINT,
    last_changed_scan_id  BIGINT,
    UNIQUE (mount_id, parent_path, filename)
) WITH (fillfactor = 90);

CREATE INDEX ix_file_filename        ON file_records (filename);
CREATE INDEX ix_file_filename_lower  ON file_records (lower(filename));
CREATE INDEX ix_file_filename_trgm   ON file_records USING gin (filename gin_trgm_ops);
-- text_pattern_ops makes "under /mnt/x" prefix LIKE queries indexable under any collation.
CREATE INDEX ix_file_parent          ON file_records (parent_path text_pattern_ops);
CREATE INDEX ix_file_parent_trgm     ON file_records USING gin (parent_path gin_trgm_ops);
CREATE INDEX ix_file_size            ON file_records (file_size_bytes);
CREATE INDEX ix_file_ext_size        ON file_records (extension, file_size_bytes);
CREATE INDEX ix_file_mtime           ON file_records (modified_at);
CREATE INDEX ix_file_checksum        ON file_records (checksum_hash) WHERE checksum_hash IS NOT NULL;
CREATE INDEX ix_file_seen            ON file_records (mount_id, first_seen_scan_id);
CREATE INDEX ix_mounts_host          ON mounts (host_id);
CREATE INDEX ix_scans_host           ON scans (host_id, scan_id);

CREATE TABLE file_changes (
    change_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id          BIGINT  NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    mount_id         BIGINT  NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    change_type      TEXT    NOT NULL CHECK (change_type IN ('added', 'modified', 'deleted')),
    parent_path      TEXT    NOT NULL,
    filename         TEXT    NOT NULL,
    is_directory     BOOLEAN NOT NULL DEFAULT false,
    old_size         BIGINT,
    new_size         BIGINT,
    old_modified_at  TIMESTAMPTZ,
    new_modified_at  TIMESTAMPTZ
);
CREATE INDEX ix_changes_scan ON file_changes (scan_id, change_type);

CREATE VIEW v_files AS
SELECT h.hostname, m.mount_point, f.*,
       CASE f.parent_path WHEN '' THEN f.filename
                          WHEN '/' THEN '/' || f.filename
                          ELSE f.parent_path || '/' || f.filename END AS full_path
FROM file_records f
JOIN mounts m ON m.mount_id = f.mount_id
JOIN hosts  h ON h.host_id  = m.host_id;

INSERT INTO schema_version (version, name, applied_at)
VALUES (1, 'initial', extract(epoch FROM now())::bigint);
