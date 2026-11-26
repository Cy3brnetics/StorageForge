-- The engine's own settings as the last scan read them: storage, logging and cgroup drivers, live-restore, registry mirrors and the
-- known keys of daemon.json (docker.py keeps no others). NULL is a row stored before they were read.
ALTER TABLE docker_hosts ADD COLUMN settings_json TEXT;

INSERT INTO schema_version (version, name, applied_at) VALUES (77, 'docker_settings', CAST(strftime('%s','now') AS INTEGER));
