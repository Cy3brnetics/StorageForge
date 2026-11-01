-- StorageForge schema v28 · postgres: ClamAV results read from hosts, and what people decided about them.
CREATE TABLE clamav_runs (
    run_uuid       TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    started_at     BIGINT NOT NULL,
    finished_at    BIGINT NOT NULL,
    exit_code      INTEGER NOT NULL,
    scanned        BIGINT NOT NULL,
    found          INTEGER NOT NULL,
    version        TEXT,
    signatures_at  BIGINT,
    via            TEXT NOT NULL,
    received_at    BIGINT NOT NULL
);
CREATE INDEX ix_clamav_runs_host ON clamav_runs (host, finished_at);
CREATE TABLE clamav_detections (
    detection_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host           TEXT NOT NULL,
    path_b64       TEXT NOT NULL,
    path           TEXT NOT NULL,
    signature      TEXT NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('open', 'gone', 'quarantined')),
    ignored        INTEGER NOT NULL DEFAULT 0,
    ignore_reason  TEXT,
    quarantine_id  TEXT,
    sha256         TEXT,
    first_seen     BIGINT NOT NULL,
    last_seen      BIGINT NOT NULL,
    handled_by     TEXT,
    handled_at     BIGINT
);
CREATE INDEX ix_clamav_detections_host ON clamav_detections (host, state);
INSERT INTO schema_version (version, name, applied_at)
VALUES (28, 'clamav', extract(epoch FROM now())::bigint);
