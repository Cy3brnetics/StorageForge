-- StorageForge schema v29 · sqlite: a report token sent to a host that may or may not have received it.
ALTER TABLE schedules ADD COLUMN pending_token_hash TEXT;
INSERT INTO schema_version (version, name, applied_at)
VALUES (29, 'schedule_pending_token', CAST(strftime('%s', 'now') AS INTEGER));
