-- StorageForge schema v18 · sqlite: host configuration history
-- What it takes to rebuild a host: its config files, mounts, accounts, shares and symlinks. A scan adds a version when
-- any of it changed. Kept by name, not host_id, so a host's history outlives its row.
CREATE TABLE host_configs (
    config_id   INTEGER PRIMARY KEY,
    hostname    TEXT    NOT NULL,
    captured_at INTEGER NOT NULL,
    digest      TEXT    NOT NULL,
    body_json   TEXT    NOT NULL
);
CREATE INDEX host_configs_host ON host_configs (hostname, config_id);

INSERT INTO schema_version (version, name, applied_at)
VALUES (18, 'host_configs', CAST(strftime('%s', 'now') AS INTEGER));
