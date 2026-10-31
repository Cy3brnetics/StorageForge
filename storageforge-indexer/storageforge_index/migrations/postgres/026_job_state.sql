-- StorageForge schema v26 · postgres: the latest state event of each running job (POST /api/jobs/state).
CREATE TABLE job_state (
    job_id       TEXT PRIMARY KEY,
    run_uuid     TEXT NOT NULL,
    state        TEXT NOT NULL,
    percent      INTEGER,
    speed        TEXT,
    dedup_ratio  DOUBLE PRECISION,
    route        TEXT,
    node         TEXT,
    at           BIGINT NOT NULL,
    received_at  BIGINT NOT NULL
);
INSERT INTO schema_version (version, name, applied_at)
VALUES (26, 'job_state', extract(epoch FROM now())::bigint);
