-- StorageForge schema v11 · sqlite: storage tasks
-- Small programs built from blocks (rsync copies, snapshots, guards, conditions, commands) that run on one host by
-- hand or on a systemd timer. StorageForge writes their Bash script; deploys install it as sf-task-<name>.
CREATE TABLE storage_tasks (
    task_id     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    body_json   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (11, 'storage_tasks', CAST(strftime('%s', 'now') AS INTEGER));
