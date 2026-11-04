-- StorageForge schema v37 · sqlite: passwords for network devices that take no SSH key, such as Telnet-only switches. Sealed as keys are.
CREATE TABLE device_credentials (
    credential_id  INTEGER PRIMARY KEY,
    cred_uuid      TEXT    NOT NULL UNIQUE,
    name           TEXT    NOT NULL UNIQUE,
    username       TEXT,
    dek_nonce      BLOB    NOT NULL,
    wrapped_dek    BLOB    NOT NULL,
    nonce          BLOB    NOT NULL,
    ciphertext     BLOB    NOT NULL,               -- JSON: the password and any enable password
    created_at     INTEGER NOT NULL,
    rotated_at     INTEGER
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (37, 'device_credentials', CAST(strftime('%s', 'now') AS INTEGER));
