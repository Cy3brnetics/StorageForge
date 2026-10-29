-- StorageForge schema v10 · sqlite: deployments from the web UI
-- Hosts set up for signed deploys, each deploy run and its output, what is deployed where, rsync/rsnapshot jobs and
-- their run history, open alerts and settings. Job tokens are stored as SHA-256 hashes; private keys never are.
CREATE TABLE deploy_access (
    host         TEXT    PRIMARY KEY,
    state        TEXT    NOT NULL,
    detail       TEXT,
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT
);

CREATE TABLE deploy_runs (
    run_id       INTEGER PRIMARY KEY,
    group_id     TEXT    NOT NULL,
    host         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    ref          TEXT,
    mode         TEXT    NOT NULL,
    status       TEXT    NOT NULL,
    exit_code    INTEGER,
    output       TEXT    NOT NULL DEFAULT '',
    script_sha   TEXT,
    actor        TEXT,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER
);
CREATE INDEX deploy_runs_group ON deploy_runs (group_id);
CREATE INDEX deploy_runs_started ON deploy_runs (started_at);

CREATE TABLE deployed (
    host         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    ref          TEXT    NOT NULL,
    deploy_hash  TEXT    NOT NULL,
    detail_json  TEXT    NOT NULL DEFAULT '{}',
    deployed_at  INTEGER NOT NULL,
    deployed_by  TEXT,
    PRIMARY KEY (host, kind, ref)
);

CREATE TABLE jobs (
    job_id       TEXT    PRIMARY KEY,
    plan_id      INTEGER,
    step_id      TEXT,
    name         TEXT    NOT NULL,
    method       TEXT    NOT NULL,
    runner_host  TEXT    NOT NULL,
    source_host  TEXT    NOT NULL,
    schedule     TEXT,
    spec_json    TEXT    NOT NULL DEFAULT '{}',
    token_hash   TEXT,
    paused       INTEGER NOT NULL DEFAULT 0,
    deployed_at  INTEGER,
    removed_at   INTEGER
);

CREATE TABLE job_runs (
    run_uuid     TEXT    PRIMARY KEY,
    job_id       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    level        TEXT,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    exit_code    INTEGER,
    bytes        INTEGER,
    files        INTEGER,
    message      TEXT,
    via          TEXT    NOT NULL,
    received_at  INTEGER NOT NULL
);
CREATE INDEX job_runs_job ON job_runs (job_id, started_at);

CREATE TABLE alerts (
    alert_key    TEXT    PRIMARY KEY,
    kind         TEXT    NOT NULL,
    ref          TEXT,
    title        TEXT    NOT NULL,
    message      TEXT,
    state        TEXT    NOT NULL,
    first_at     INTEGER NOT NULL,
    last_at      INTEGER NOT NULL,
    notified_at  INTEGER,
    resolved_at  INTEGER
);

CREATE TABLE settings (
    key          TEXT    PRIMARY KEY,
    value_json   TEXT    NOT NULL,
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (10, 'deployments', CAST(strftime('%s', 'now') AS INTEGER));
