-- StorageForge schema v39 · sqlite: the sentinel has its own permission. Custom roles that could change its settings under
-- security.emergency keep that. Deploying and removing it, which deploy.apply alone used to allow, now takes it as well.
UPDATE roles SET permissions = replace(permissions, '"security.emergency"', '"security.emergency", "security.sentinel"')
 WHERE permissions LIKE '%"security.emergency"%' AND permissions NOT LIKE '%"security.sentinel"%';

INSERT INTO schema_version (version, name, applied_at)
VALUES (39, 'sentinel_permission', CAST(strftime('%s', 'now') AS INTEGER));
