-- StorageForge schema v17 · PostgreSQL: a deploy as one thing (engine.py), and what the last check of each host found
-- digest: the plan or design a group ran; an apply that names its dry run is refused if it has changed since.
CREATE TABLE deploy_groups (
    group_id     TEXT    PRIMARY KEY,
    kind         TEXT    NOT NULL,
    ref          TEXT,
    mode         TEXT    NOT NULL,
    title        TEXT,
    state        TEXT    NOT NULL,
    options_json TEXT    NOT NULL DEFAULT '{}',
    digest       TEXT,
    report_group TEXT,
    retry_of     TEXT,
    actor        TEXT,
    started_at   BIGINT  NOT NULL,
    finished_at  BIGINT
);
CREATE INDEX deploy_groups_started ON deploy_groups (started_at);

ALTER TABLE deploy_runs ADD COLUMN phase INTEGER NOT NULL DEFAULT 0;

CREATE TABLE host_checks (
    host         TEXT    PRIMARY KEY,
    source       TEXT    NOT NULL,
    facts_json   TEXT    NOT NULL DEFAULT '{}',
    items_json   TEXT    NOT NULL DEFAULT '[]',
    checked_at   BIGINT  NOT NULL,
    checked_by   TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (17, 'deploy_engine', extract(epoch FROM now())::bigint);
