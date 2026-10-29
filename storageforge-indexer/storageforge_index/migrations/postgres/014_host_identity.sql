-- StorageForge schema v14 · postgres: host identity
-- A host is the machine whose SSH host keys StorageForge verified at its address, not whatever name it reports.
-- host_keys: JSON list of SHA-256 fingerprints from StorageForge's known_hosts; a scan that claims an indexed name
-- with other keys is refused. machine_id: /etc/machine-id, signed into deploy requests so a request for one machine
-- runs nowhere else, even on a machine with the same short name.
ALTER TABLE hosts ADD COLUMN host_keys TEXT;
ALTER TABLE hosts ADD COLUMN machine_id TEXT;

INSERT INTO schema_version (version, name, applied_at)
VALUES (14, 'host_identity', extract(epoch FROM now())::bigint);
