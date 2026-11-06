-- StorageForge schema v41 · postgres: signed scan payloads (scansign.py)
-- scan_signers: the scan signing key pinned for an address (host, or host:port), when StorageForge ran the read-only scan access setup
-- over a connection that accepted only the confirmed host key, or on the first signed scan. A host's SSH host keys are in known_hosts.
CREATE TABLE scan_signers (
    address      TEXT    PRIMARY KEY,
    public_key   TEXT    NOT NULL,
    fingerprint  TEXT    NOT NULL,
    pinned_at    BIGINT NOT NULL,
    how          TEXT    NOT NULL
);

-- what the last scan of each host found: every payload signed, some, or none, by which keys, and why not
CREATE TABLE scan_signatures (
    host         TEXT    PRIMARY KEY,
    state        TEXT    NOT NULL,
    signed       INTEGER NOT NULL DEFAULT 0,
    unsigned     INTEGER NOT NULL DEFAULT 0,
    keys         TEXT    NOT NULL DEFAULT '',
    reason       TEXT    NOT NULL DEFAULT '',
    checked_at   BIGINT NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (41, 'scan_signing', EXTRACT(EPOCH FROM now())::BIGINT);
