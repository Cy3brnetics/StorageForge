-- StorageForge schema v2 · PostgreSQL: credential vault, append-only audit log, graph entities, scan jobs
-- Applies on top of 001_initial.sql. Times in the vault and audit tables are unix epochs so the
-- hash chain is computed identically on SQLite and PostgreSQL.

-- ── Credential vault ───────────────────────────────────────────────────────────
CREATE TABLE vault_meta (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    kdf                TEXT    NOT NULL DEFAULT 'argon2id' CHECK (kdf = 'argon2id'),
    kdf_salt           BYTEA   NOT NULL,
    kdf_time_cost      INTEGER NOT NULL,
    kdf_memory_kib     INTEGER NOT NULL,
    kdf_lanes          INTEGER NOT NULL,
    verifier_nonce     BYTEA   NOT NULL,
    verifier           BYTEA   NOT NULL,
    audit_key_nonce    BYTEA   NOT NULL,
    audit_key_wrapped  BYTEA   NOT NULL,
    created_at         BIGINT  NOT NULL,
    rotated_at         BIGINT
);

CREATE TABLE ssh_keys (
    key_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_uuid     TEXT   NOT NULL UNIQUE,
    name         TEXT   NOT NULL UNIQUE,
    key_type     TEXT   NOT NULL CHECK (key_type IN ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                                                     'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521')),
    public_key   TEXT   NOT NULL,
    fingerprint  TEXT   NOT NULL UNIQUE,
    comment      TEXT,
    dek_nonce    BYTEA  NOT NULL,
    wrapped_dek  BYTEA  NOT NULL,
    key_nonce    BYTEA  NOT NULL,
    ciphertext   BYTEA  NOT NULL,
    created_at   BIGINT NOT NULL,
    rotated_at   BIGINT,
    disabled_at  BIGINT
);

CREATE TABLE key_bindings (
    binding_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id           BIGINT  NOT NULL REFERENCES ssh_keys (key_id) ON DELETE CASCADE,
    host_pattern     TEXT    NOT NULL,
    pattern_kind     TEXT    NOT NULL CHECK (pattern_kind IN ('host', 'glob', 'cidr')),
    ssh_user         TEXT    NOT NULL,
    ssh_port         INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    allowed_actions  TEXT    NOT NULL DEFAULT 'scan',
    priority         INTEGER NOT NULL DEFAULT 100,
    created_at       BIGINT  NOT NULL,
    UNIQUE (key_id, host_pattern, ssh_user)
);
CREATE INDEX ix_bindings_key ON key_bindings (key_id);

-- ── Audit log ──────────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    audit_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts_us            BIGINT NOT NULL,
    actor            TEXT   NOT NULL,
    action           TEXT   NOT NULL,
    target_host      TEXT,
    key_fingerprint  TEXT,
    outcome          TEXT   NOT NULL CHECK (outcome IN ('ok', 'denied', 'failed', 'info')),
    detail_json      TEXT   NOT NULL DEFAULT '{}',
    hash_alg         TEXT   NOT NULL CHECK (hash_alg IN ('hmac-sha256', 'sha256')),
    prev_hash        TEXT   NOT NULL,
    entry_hash       TEXT   NOT NULL UNIQUE
);
CREATE INDEX ix_audit_host ON audit_log (target_host, audit_id);

CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
-- Defence in depth for deployments that run the app as a non-owner role:
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;

-- ── Graph ──────────────────────────────────────────────────────────────────────
CREATE TABLE graph_nodes (
    node_id     TEXT   PRIMARY KEY,
    kind        TEXT   NOT NULL CHECK (kind IN ('Host', 'StoragePool', 'Filesystem', 'MountPoint', 'Symlink')),
    label       TEXT   NOT NULL,
    host        TEXT,
    health      TEXT   NOT NULL DEFAULT 'unknown' CHECK (health IN ('protected', 'local-only', 'broken', 'unknown')),
    props_json  TEXT   NOT NULL DEFAULT '{}',
    updated_at  BIGINT NOT NULL
);
CREATE INDEX ix_graph_nodes_host ON graph_nodes (host, kind);

CREATE TABLE graph_edges (
    src         TEXT NOT NULL REFERENCES graph_nodes (node_id) ON DELETE CASCADE,
    dst         TEXT NOT NULL REFERENCES graph_nodes (node_id) ON DELETE CASCADE,
    rel         TEXT NOT NULL CHECK (rel IN ('CONTAINS', 'MOUNTED_AT', 'SYMLINK_TO', 'REPLICATES_TO')),
    props_json  TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (src, dst, rel)
);
CREATE INDEX ix_graph_edges_dst ON graph_edges (dst);

CREATE TABLE blueprints (
    hostname     TEXT   PRIMARY KEY,
    body_json    TEXT   NOT NULL,
    imported_at  BIGINT NOT NULL
);

CREATE TABLE scan_jobs (
    job_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host          TEXT   NOT NULL,
    requested_by  TEXT   NOT NULL,
    status        TEXT   NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ok', 'partial', 'failed')),
    queued_at     BIGINT NOT NULL,
    started_at    BIGINT,
    finished_at   BIGINT,
    result_json   TEXT
);
CREATE INDEX ix_jobs_status ON scan_jobs (status, job_id);

INSERT INTO schema_version (version, name, applied_at)
VALUES (2, 'vault_audit_graph', extract(epoch FROM now())::bigint);
