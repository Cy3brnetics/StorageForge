-- StorageForge schema v21 · postgres: what an account may do. Existing accounts stay admins, so nothing changes on upgrade.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('viewer', 'operator', 'admin'));
INSERT INTO schema_version (version, name, applied_at)
VALUES (21, 'user_roles', extract(epoch FROM now())::bigint);
