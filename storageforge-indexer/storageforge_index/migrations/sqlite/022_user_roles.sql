-- StorageForge schema v22 · sqlite: what an account may do. Existing accounts stay admins, so nothing changes on upgrade.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('viewer', 'operator', 'admin'));
INSERT INTO schema_version (version, name, applied_at)
VALUES (22, 'user_roles', CAST(strftime('%s', 'now') AS INTEGER));
