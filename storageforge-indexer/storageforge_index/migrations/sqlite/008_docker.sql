-- StorageForge schema v8 · sqlite: Docker and Podman as the last scan saw them
-- Per host: the engine and how the scan user reached it, containers (name, image, state, compose labels, mounts),
-- volumes, and the compose files the index found, parsed down to services, images and volume definitions.
-- Environment variables, .env files and volume passwords are never stored.
CREATE TABLE docker_hosts (
    host_id          INTEGER PRIMARY KEY REFERENCES hosts (host_id) ON DELETE CASCADE,
    engine           TEXT,
    access           TEXT,
    root_dir         TEXT,
    containers_json  TEXT NOT NULL DEFAULT '[]',
    volumes_json     TEXT NOT NULL DEFAULT '[]',
    compose_json     TEXT NOT NULL DEFAULT '[]',
    error            TEXT,
    scan_id          BIGINT,
    updated_at       BIGINT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (8, 'docker', CAST(strftime('%s', 'now') AS INTEGER));
