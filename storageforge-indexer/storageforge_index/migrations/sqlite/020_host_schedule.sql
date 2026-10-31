-- StorageForge schema v20 · sqlite: per-host scan schedule. NULL means the global STORAGEFORGE_SCAN_INTERVAL and no quiet hours.
-- scan_interval in seconds; quiet_hours as "22-6", local hours in which no scheduled scan starts.
ALTER TABLE hosts ADD COLUMN scan_interval BIGINT;
ALTER TABLE hosts ADD COLUMN quiet_hours TEXT;
INSERT INTO schema_version (version, name, applied_at)
VALUES (20, 'host_schedule', CAST(strftime('%s', 'now') AS INTEGER));
