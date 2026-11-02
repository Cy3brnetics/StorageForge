-- StorageForge schema v32 · postgres: security state is what hosts report and what signed runs did.
-- Nothing in the v31 tables ever reached a host: holds, quarantines, canaries and scores were written without running
-- anything. They are dropped, not migrated, so no invented row can pass for a real one.
DROP TABLE security_playbooks;
DROP TABLE security_compliance_profiles;
DROP TABLE security_avc_events;
DROP TABLE security_aide_checks;
DROP TABLE security_lynis_audits;
DROP TABLE security_compliance_status;
DROP TABLE security_canaries;
DROP TABLE security_quarantine;
DROP TABLE security_retention_holds;
DROP TABLE security_timelock_queue;
DELETE FROM settings WHERE key LIKE 'security.%';

-- The last reading of each kind from a host. kind: host (the measure script), entropy (a sample of changed files).
CREATE TABLE security_measurements (
    host        TEXT   NOT NULL,
    kind        TEXT   NOT NULL,
    measured_at BIGINT NOT NULL,
    via         TEXT   NOT NULL,
    data_json   TEXT   NOT NULL,
    PRIMARY KEY (host, kind)
);

-- What the sentinel on a host saw, and what its brake did. Comes from the host it describes, so it can only raise alarms.
CREATE TABLE security_events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid            TEXT   NOT NULL UNIQUE,
    host            TEXT   NOT NULL,
    kind            TEXT   NOT NULL,
    severity        TEXT   NOT NULL CHECK (severity IN ('info', 'warn', 'crit')),
    occurred_at     BIGINT NOT NULL,
    received_at     BIGINT NOT NULL,
    via             TEXT   NOT NULL,
    summary         TEXT   NOT NULL,
    detail          TEXT   NOT NULL DEFAULT '',
    acknowledged_by TEXT,
    acknowledged_at BIGINT
);
CREATE INDEX ix_security_events_host ON security_events (host, occurred_at);

-- A row exists only once a signed run confirmed the hold on the host. verified_at: when a measurement last saw it there.
CREATE TABLE security_retention_holds (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host        TEXT   NOT NULL,
    snapshot    TEXT   NOT NULL,
    hold_tag    TEXT   NOT NULL,
    filesystem  TEXT   NOT NULL CHECK (filesystem IN ('zfs', 'btrfs')),
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT,
    legal_hold  INTEGER NOT NULL DEFAULT 0,
    status      TEXT   NOT NULL DEFAULT 'locked' CHECK (status IN ('locked', 'release_pending', 'released')),
    applied_by  TEXT   NOT NULL,
    verified_at BIGINT,
    missing_at  BIGINT,
    UNIQUE (host, snapshot, hold_tag)
);
CREATE INDEX ix_security_holds_host ON security_retention_holds (host, status);

CREATE TABLE security_timelock_queue (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action           TEXT   NOT NULL,
    target_ref       TEXT   NOT NULL,
    host             TEXT   NOT NULL DEFAULT '',
    actor            TEXT   NOT NULL,
    mode             TEXT   NOT NULL CHECK (mode IN ('dual_admin', 'cool_off')),
    requested_at     BIGINT NOT NULL,
    executes_at      BIGINT NOT NULL,
    status           TEXT   NOT NULL CHECK (status IN ('pending', 'aborted', 'executed', 'failed')),
    decided_by       TEXT,
    decided_at       BIGINT,
    break_glass_used INTEGER NOT NULL DEFAULT 0,
    detail_json      TEXT   NOT NULL DEFAULT '{}',
    output           TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX ix_security_timelock_status ON security_timelock_queue (status, executes_at);

-- sha256 and size are of the decoy the deploy really wrote, as it reported them.
CREATE TABLE security_canaries (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host        TEXT   NOT NULL,
    path        TEXT   NOT NULL,
    sha256      TEXT   NOT NULL,
    size        BIGINT NOT NULL,
    deployed_at BIGINT NOT NULL,
    status      TEXT   NOT NULL CHECK (status IN ('armed', 'tripped')),
    tripped_at  BIGINT,
    verified_at BIGINT,
    UNIQUE (host, path)
);
CREATE INDEX ix_security_canaries_host ON security_canaries (host, status);

-- A row exists only once a signed run confirmed the address in the host's firewall.
CREATE TABLE security_quarantine (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host       TEXT   NOT NULL,
    ip_address TEXT   NOT NULL,
    reason     TEXT   NOT NULL,
    added_at   BIGINT NOT NULL,
    expires_at BIGINT,
    actor      TEXT   NOT NULL,
    UNIQUE (host, ip_address)
);
CREATE INDEX ix_security_quarantine_host ON security_quarantine (host);

INSERT INTO schema_version (version, name, applied_at)
VALUES (32, 'security_measured', EXTRACT(EPOCH FROM now())::BIGINT);
