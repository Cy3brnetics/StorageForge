-- When an account last became someone the dual-admin quorum may trust: promoted to admin, enabled again, or its password set
-- through a reset link. NULL is created_at. security.established_admins counts an admin only once this is older than the cool-off.
ALTER TABLE users ADD COLUMN trusted_since BIGINT;

INSERT INTO schema_version (version, name, applied_at) VALUES (75, 'user_trusted_since', CAST(strftime('%s','now') AS INTEGER));
