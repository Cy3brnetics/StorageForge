-- StorageForge schema v2 · SQLite: credential vault, append-only audit log, graph entities, scan jobs
-- Applies on top of 001_initial.sql.

-- ── Credential vault ───────────────────────────────────────────────────────────
-- One row. The KEK is derived from STORAGEFORGE_VAULT_SECRET with Argon2id and never stored.
CREATE TABLE vault_meta (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    kdf                TEXT    NOT NULL DEFAULT 'argon2id' CHECK (kdf = 'argon2id'),
    kdf_salt           BLOB    NOT NULL,                 -- 16 random bytes
    kdf_time_cost      INTEGER NOT NULL,
    kdf_memory_kib     INTEGER NOT NULL,
    kdf_lanes          INTEGER NOT NULL,
    verifier_nonce     BLOB    NOT NULL,                 -- AES-GCM(KEK, constant): detects a wrong secret
    verifier           BLOB    NOT NULL,
    audit_key_nonce    BLOB    NOT NULL,                 -- AES-GCM(KEK, random audit MAC key)
    audit_key_wrapped  BLOB    NOT NULL,
    created_at         INTEGER NOT NULL,
    rotated_at         INTEGER
);

-- Private keys: AES-256-GCM under a per-key DEK, the DEK wrapped by the KEK.
-- Associated data binds both ciphertexts to key_uuid, so rows cannot be swapped.
CREATE TABLE ssh_keys (
    key_id       INTEGER PRIMARY KEY,
    key_uuid     TEXT    NOT NULL UNIQUE,
    name         TEXT    NOT NULL UNIQUE,
    key_type     TEXT    NOT NULL CHECK (key_type IN ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                                                      'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521')),
    public_key   TEXT    NOT NULL,
    fingerprint  TEXT    NOT NULL UNIQUE,                -- SHA256:… as printed by ssh-keygen -lf
    comment      TEXT,
    dek_nonce    BLOB    NOT NULL,
    wrapped_dek  BLOB    NOT NULL,                       -- 32-byte DEK + 16-byte GCM tag
    key_nonce    BLOB    NOT NULL,
    ciphertext   BLOB    NOT NULL,                       -- OpenSSH private key + GCM tag
    created_at   INTEGER NOT NULL,
    rotated_at   INTEGER,
    disabled_at  INTEGER
);

-- Which key may reach which hosts, as which user, for which actions.
-- host_pattern: exact name, glob (*.tailnet.ts.net) or CIDR (10.0.20.0/24).
CREATE TABLE key_bindings (
    binding_id       INTEGER PRIMARY KEY,
    key_id           INTEGER NOT NULL REFERENCES ssh_keys (key_id) ON DELETE CASCADE,
    host_pattern     TEXT    NOT NULL,
    pattern_kind     TEXT    NOT NULL CHECK (pattern_kind IN ('host', 'glob', 'cidr')),
    ssh_user         TEXT    NOT NULL,
    ssh_port         INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    allowed_actions  TEXT    NOT NULL DEFAULT 'scan',    -- comma list of: scan, checksum
    priority         INTEGER NOT NULL DEFAULT 100,
    created_at       INTEGER NOT NULL,
    UNIQUE (key_id, host_pattern, ssh_user)
);
CREATE INDEX ix_bindings_key ON key_bindings (key_id);

-- ── Audit log ──────────────────────────────────────────────────────────────────
-- Append-only and hash-chained: entry_hash = HMAC-SHA256(audit key, prev_hash ‖ payload).
-- Triggers reject UPDATE and DELETE; `storageforge-index audit verify` checks the chain.
CREATE TABLE audit_log (
    audit_id         INTEGER PRIMARY KEY,
    ts_us            INTEGER NOT NULL,                   -- unix epoch microseconds
    actor            TEXT    NOT NULL,                   -- cli:<user>, api:<address>, scheduler
    action           TEXT    NOT NULL,                   -- ssh.connect, ssh.scan, vault.key.add, …
    target_host      TEXT,
    key_fingerprint  TEXT,
    outcome          TEXT    NOT NULL CHECK (outcome IN ('ok', 'denied', 'failed', 'info')),
    detail_json      TEXT    NOT NULL DEFAULT '{}',
    hash_alg         TEXT    NOT NULL CHECK (hash_alg IN ('hmac-sha256', 'sha256')),
    prev_hash        TEXT    NOT NULL,
    entry_hash       TEXT    NOT NULL UNIQUE
);
CREATE INDEX ix_audit_host ON audit_log (target_host, audit_id);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- ── Graph ──────────────────────────────────────────────────────────────────────
-- Rebuilt per host after every scan (and from imported blueprints).
-- External replication/backup targets have host IS NULL.
CREATE TABLE graph_nodes (
    node_id     TEXT    PRIMARY KEY,                     -- host:atlas, pool:atlas:tank, fs:atlas:tank/media, mnt:atlas:/x, link:atlas:/y
    kind        TEXT    NOT NULL CHECK (kind IN ('Host', 'StoragePool', 'Filesystem', 'MountPoint', 'Symlink')),
    label       TEXT    NOT NULL,
    host        TEXT,
    health      TEXT    NOT NULL DEFAULT 'unknown' CHECK (health IN ('protected', 'local-only', 'broken', 'unknown')),
    props_json  TEXT    NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL
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

-- Design intent per host (tiers, links, protection) overlaid on scan results.
CREATE TABLE blueprints (
    hostname     TEXT    PRIMARY KEY,
    body_json    TEXT    NOT NULL,
    imported_at  INTEGER NOT NULL
);

-- ── Scan jobs (API and scheduler) ─────────────────────────────────────────────
CREATE TABLE scan_jobs (
    job_id        INTEGER PRIMARY KEY,
    host          TEXT    NOT NULL,
    requested_by  TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ok', 'partial', 'failed')),
    queued_at     INTEGER NOT NULL,
    started_at    INTEGER,
    finished_at   INTEGER,
    result_json   TEXT
);
CREATE INDEX ix_jobs_status ON scan_jobs (status, job_id);

INSERT INTO schema_version (version, name, applied_at)
VALUES (2, 'vault_audit_graph', CAST(strftime('%s', 'now') AS INTEGER));
