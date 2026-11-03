-- StorageForge schema v33 · postgres: a host's network as its scan user reads it. Rebuilt by the next scan.
CREATE TABLE host_network (
    host_id     BIGINT PRIMARY KEY REFERENCES hosts (host_id) ON DELETE CASCADE,
    data_json   TEXT   NOT NULL DEFAULT '{}',
    scan_id     BIGINT,
    updated_at  BIGINT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (33, 'host_network', EXTRACT(EPOCH FROM now())::BIGINT);
