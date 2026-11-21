-- StorageForge schema v67 · postgres: API connections to platforms (roadmap section 13; apiconn.py, docs/api-connections.md).
-- platform_connections: one row per platform instance StorageForge reads through its own API (Proxmox VE, Backup Server, Datacenter
-- Manager). The token's secret is not here: it is a row of device_credentials named secret_name, sealed in the vault (inside the key
-- enclave when it is configured) with a policy that releases it for this platform instance only. token_id is the token's name
-- (user@realm!token), which is not secret. host: the StorageForge host this platform runs on, when one is known.
-- cert_sha256: the server certificate's SHA-256 fingerprint a person accepted; NULL until then, and nothing is sent with the token
-- before it is set. cert_offered: what the server presented when it differed from cert_sha256 (or before one was accepted).
-- actions_json: the actions a person turned on, beyond reading; empty means read-only. readback_json: what the token was found able
-- to do the last time it was read back, compared with the permission guide.
CREATE TABLE platform_connections (
    conn_id        BIGSERIAL PRIMARY KEY,
    kind           TEXT    NOT NULL,
    name           TEXT    NOT NULL UNIQUE,
    base_url       TEXT    NOT NULL,
    host           TEXT,
    token_id       TEXT    NOT NULL,
    secret_name    TEXT    NOT NULL UNIQUE,
    cert_sha256    TEXT,
    cert_offered   TEXT,
    cert_pinned_by TEXT,
    cert_pinned_at BIGINT,
    actions_json   TEXT    NOT NULL DEFAULT '[]',
    created_by     TEXT,
    created_at     BIGINT  NOT NULL,
    read_at        BIGINT,
    read_ok        INTEGER NOT NULL DEFAULT 0,
    read_error     TEXT    NOT NULL DEFAULT '',
    readback_json  TEXT,
    readback_at    BIGINT
);

-- platform_objects: what the last read of a connection found (nodes, guests, storage, backups, datastores, remotes...), one row per
-- object, replaced by the next read. Rebuilt by reading again.
CREATE TABLE platform_objects (
    conn_id    BIGINT  NOT NULL,
    kind       TEXT    NOT NULL,
    ref        TEXT    NOT NULL,
    data_json  TEXT    NOT NULL,
    read_at    BIGINT  NOT NULL,
    PRIMARY KEY (conn_id, kind, ref)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (67, 'api_connections', EXTRACT(EPOCH FROM now())::BIGINT);
