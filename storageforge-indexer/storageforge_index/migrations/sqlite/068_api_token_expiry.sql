-- StorageForge schema v68 · sqlite: expiry and rotation of platform API tokens (roadmap section 13; apiconn.py, docs/api-connections.md).
-- token_expires_at: when the token lapses, as the platform said at the last read-back (token_expiry_source 'platform') or as the person
-- who gave it said (token_expiry_source 'given'); NULL when nobody knows, 0 when the platform says it never lapses. token_set_at: when
-- this token was given or last replaced. token_previous: the ID of the token this one replaced, which still works on the platform until
-- someone deletes it there; the connection says so until a person clears it. None of these is secret.
ALTER TABLE platform_connections ADD COLUMN token_expires_at INTEGER;
ALTER TABLE platform_connections ADD COLUMN token_expiry_source TEXT;
ALTER TABLE platform_connections ADD COLUMN token_set_at INTEGER;
ALTER TABLE platform_connections ADD COLUMN token_previous TEXT;

INSERT INTO schema_version (version, name, applied_at)
VALUES (68, 'api_token_expiry', CAST(strftime('%s', 'now') AS INTEGER));
