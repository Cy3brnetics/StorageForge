-- How long a deploy run was allowed to take, in seconds. confirm.py marks a run absent only well after this; NULL is the old
-- fixed 10 minutes.
ALTER TABLE deploy_runs ADD COLUMN timeout_s BIGINT;

INSERT INTO schema_version (version, name, applied_at) VALUES (76, 'deploy_run_timeout', CAST(strftime('%s','now') AS INTEGER));
