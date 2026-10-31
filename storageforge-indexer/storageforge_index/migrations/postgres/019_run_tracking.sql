-- StorageForge schema v19 · PostgreSQL: what scans confirm about deployed scripts (confirm.py)
-- nonce: the one-time id signed into a deploy run; the host's runner writes it to a ledger scans read, with how it ended.
-- host_state: what that ledger said as of the last scan: finished | unfinished (started, no end) | absent (never ran).
ALTER TABLE deploy_runs ADD COLUMN nonce TEXT;
ALTER TABLE deploy_runs ADD COLUMN host_state TEXT;
ALTER TABLE deploy_runs ADD COLUMN host_exit INTEGER;
ALTER TABLE deploy_runs ADD COLUMN confirmed_at BIGINT;
CREATE INDEX deploy_runs_nonce ON deploy_runs (nonce);
CREATE INDEX deploy_runs_host ON deploy_runs (host, started_at);

-- runs of installed storage tasks (sf-task-* timers), as scans read them from /var/lib/storageforge/tasks
CREATE TABLE task_runs (
    host         TEXT    NOT NULL,
    task         TEXT    NOT NULL,
    started_at   BIGINT  NOT NULL,
    finished_at  BIGINT,
    exit_code    INTEGER,
    via          TEXT    NOT NULL,
    received_at  BIGINT  NOT NULL,
    PRIMARY KEY (host, task, started_at)
);

-- logs fetched from a host because a scan found a problem: one row per problem, so each is fetched once
CREATE TABLE host_logs (
    log_key      TEXT    PRIMARY KEY,
    host         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    ref          TEXT,
    reason       TEXT    NOT NULL,
    detail_json  TEXT    NOT NULL DEFAULT '{}',
    state        TEXT    NOT NULL,
    output       TEXT    NOT NULL DEFAULT '',
    fetch_run    BIGINT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    found_at     BIGINT  NOT NULL,
    fetched_at   BIGINT
);
CREATE INDEX host_logs_host ON host_logs (host, state);

INSERT INTO schema_version (version, name, applied_at)
VALUES (19, 'run_tracking', extract(epoch FROM now())::bigint);
