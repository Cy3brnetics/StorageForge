-- StorageForge schema v31 · postgres: Ransomware defense, WORM holds, adaptive quorum, canaries, MAC, firewall quarantine, FIM/Lynis, compliance, and playbooks.
CREATE TABLE security_timelock_queue (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_type      TEXT NOT NULL,
    target_ref       TEXT NOT NULL,
    host_name        TEXT NOT NULL DEFAULT '',
    actor            TEXT NOT NULL,
    approved_by      TEXT,
    requested_at     BIGINT NOT NULL,
    executes_at      BIGINT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'aborted', 'executed')),
    break_glass_used INTEGER NOT NULL DEFAULT 0,
    detail_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_security_timelock_status ON security_timelock_queue (status, executes_at);

CREATE TABLE security_compliance_profiles (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    standard    TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '1.0',
    config_yaml TEXT NOT NULL,
    created_at  BIGINT NOT NULL
);

CREATE TABLE security_compliance_status (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name    TEXT NOT NULL,
    profile_id   TEXT NOT NULL,
    score        INTEGER NOT NULL DEFAULT 100,
    drift_count  INTEGER NOT NULL DEFAULT 0,
    last_checked BIGINT NOT NULL,
    drift_json   TEXT NOT NULL DEFAULT '[]',
    UNIQUE (host_name, profile_id)
);
CREATE INDEX ix_security_compliance_host ON security_compliance_status (host_name);

CREATE TABLE security_canaries (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name       TEXT NOT NULL,
    share_path      TEXT NOT NULL,
    file_name       TEXT NOT NULL,
    trap_type       TEXT NOT NULL DEFAULT 'file_canary',
    baseline_sha256 TEXT NOT NULL,
    deployed_at     BIGINT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('armed', 'tripped', 'degraded')),
    UNIQUE (host_name, share_path, file_name)
);
CREATE INDEX ix_security_canaries_host ON security_canaries (host_name, status);

CREATE TABLE security_quarantine (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name   TEXT NOT NULL,
    ip_address  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    tripped_at  BIGINT NOT NULL,
    expires_at  BIGINT,
    permanent   INTEGER NOT NULL DEFAULT 0,
    actor       TEXT NOT NULL,
    UNIQUE (host_name, ip_address)
);
CREATE INDEX ix_security_quarantine_host ON security_quarantine (host_name);

CREATE TABLE security_retention_holds (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name     TEXT NOT NULL,
    dataset_name  TEXT NOT NULL,
    snapshot_name TEXT NOT NULL,
    hold_tag      TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    expires_at    BIGINT,
    legal_hold    INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'locked' CHECK (status IN ('locked', 'pending_release', 'released', 'expired')),
    UNIQUE (host_name, snapshot_name, hold_tag)
);
CREATE INDEX ix_security_holds_host ON security_retention_holds (host_name, status);

CREATE TABLE security_avc_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name   TEXT NOT NULL,
    timestamp   BIGINT NOT NULL,
    daemon      TEXT NOT NULL,
    syscall     TEXT NOT NULL,
    target_path TEXT NOT NULL,
    scontext    TEXT NOT NULL,
    tcontext    TEXT NOT NULL,
    remediated  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_security_avc_host ON security_avc_events (host_name, timestamp);

CREATE TABLE security_aide_checks (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name      TEXT NOT NULL,
    checked_at     BIGINT NOT NULL,
    status         TEXT NOT NULL,
    modified_count INTEGER NOT NULL DEFAULT 0,
    added_count    INTEGER NOT NULL DEFAULT 0,
    removed_count  INTEGER NOT NULL DEFAULT 0,
    details_json   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX ix_security_aide_host ON security_aide_checks (host_name, checked_at);

CREATE TABLE security_lynis_audits (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name            TEXT NOT NULL,
    audited_at           BIGINT NOT NULL,
    hardening_index      INTEGER NOT NULL,
    findings_json        TEXT NOT NULL DEFAULT '[]',
    recommendations_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX ix_security_lynis_host ON security_lynis_audits (host_name, audited_at);

CREATE TABLE security_playbooks (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    trigger_event   TEXT NOT NULL,
    conditions_json TEXT NOT NULL DEFAULT '{}',
    actions_json    TEXT NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (31, 'ransomware_defense', extract(epoch FROM now())::bigint);
