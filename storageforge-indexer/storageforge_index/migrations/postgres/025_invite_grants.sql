-- StorageForge schema v25 · postgres: what an invite or reset link was made for, so it dies when that changes
ALTER TABLE invites ADD COLUMN grants_json TEXT;
ALTER TABLE invites ADD COLUMN reset_user_id BIGINT;
ALTER TABLE invites ADD COLUMN reset_version BIGINT;
INSERT INTO schema_version (version, name, applied_at)
VALUES (25, 'invite_grants', extract(epoch FROM now())::bigint);
