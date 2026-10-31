-- StorageForge schema v21 · postgres: per-host scan schedule. NULL means the global STORAGEFORGE_SCAN_INTERVAL and no quiet hours.
-- scan_interval in seconds; quiet_hours as "22-6", local hours in which no scheduled scan starts.
ALTER TABLE hosts ADD COLUMN scan_interval BIGINT;
ALTER TABLE hosts ADD COLUMN quiet_hours TEXT;
INSERT INTO schema_version (version, name, applied_at)
VALUES (21, 'host_schedule', extract(epoch FROM now())::bigint);
