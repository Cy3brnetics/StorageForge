-- StorageForge schema v20 · sqlite: unified scheduler for tasks, changes, moves, scans, and commands
CREATE TABLE schedules (
    schedule_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    host             TEXT    NOT NULL,
    cron_expr        TEXT    NOT NULL,
    task_type        TEXT    NOT NULL,
    task_ref         TEXT    NOT NULL,
    config_json      TEXT    NOT NULL DEFAULT '{}',
    paused           INTEGER NOT NULL DEFAULT 0,
    auth_token_hash  TEXT    NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    created_by       TEXT    NOT NULL,
    last_run_at      INTEGER,
    next_run_at      INTEGER,
    last_status      TEXT
);
CREATE INDEX schedules_host ON schedules (host, paused);
CREATE INDEX schedules_next ON schedules (next_run_at);

CREATE TABLE schedule_runs (
    run_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id         INTEGER NOT NULL REFERENCES schedules(schedule_id) ON DELETE CASCADE,
    host                TEXT    NOT NULL,
    status              TEXT    NOT NULL,
    started_at          INTEGER NOT NULL,
    finished_at         INTEGER,
    exit_code           INTEGER,
    output              TEXT    NOT NULL DEFAULT '',
    verified            INTEGER NOT NULL DEFAULT 0,
    verify_result_json  TEXT    NOT NULL DEFAULT '{}',
    verified_at         INTEGER,
    nonce               TEXT,
    report_source       TEXT
);
CREATE INDEX schedule_runs_sched ON schedule_runs (schedule_id, started_at);
CREATE INDEX schedule_runs_host ON schedule_runs (host, started_at);

INSERT INTO schema_version (version, name, applied_at)
VALUES (20, 'scheduler', CAST(strftime('%s', 'now') AS INTEGER));
