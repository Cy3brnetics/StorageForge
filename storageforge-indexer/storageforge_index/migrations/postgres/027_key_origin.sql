-- StorageForge schema v27 · postgres: where a vault key came from. Keys from before this are 'unknown': nothing recorded it.
ALTER TABLE ssh_keys ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown';
INSERT INTO schema_version (version, name, applied_at)
VALUES (27, 'key_origin', extract(epoch FROM now())::bigint);
