-- StorageForge schema v15 · postgres: host keys a person confirmed
-- A password (key install, scan access, deploy access) is only sent to a host whose key fingerprint someone compared
-- with the host's own and confirmed in the UI; scans alone trust a key on first use.
CREATE TABLE host_key_confirmations (
    address       TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    fingerprint   TEXT    NOT NULL,
    confirmed_by  TEXT    NOT NULL,
    confirmed_at  BIGINT  NOT NULL,
    PRIMARY KEY (address, port, fingerprint)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (15, 'host_key_confirmations', extract(epoch FROM now())::bigint);
