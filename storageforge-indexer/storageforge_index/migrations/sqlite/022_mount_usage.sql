-- StorageForge schema v22 · sqlite: how full each mount was at each scan, for trends and "full in N days".
CREATE TABLE mount_usage (
    usage_id     INTEGER PRIMARY KEY,
    host_id      BIGINT NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    mount_point  TEXT   NOT NULL,
    at           BIGINT NOT NULL,
    used_bytes   BIGINT NOT NULL,
    total_bytes  BIGINT NOT NULL
);
CREATE INDEX ix_mount_usage ON mount_usage (host_id, mount_point, at);
INSERT INTO schema_version (version, name, applied_at)
VALUES (22, 'mount_usage', CAST(strftime('%s', 'now') AS INTEGER));
