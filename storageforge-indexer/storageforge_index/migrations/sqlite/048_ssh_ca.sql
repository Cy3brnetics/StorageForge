-- StorageForge schema v48 · sqlite: the SSH certificate authority (sshcerts.py). The CA key itself is a row of ssh_keys like any other vault key.
-- ssh_certificates: every certificate the CA signed, so one can be named in a revocation list. No private key is here, and no user
-- certificate either: a user certificate lasts minutes and is given to ssh once. A host certificate is kept, for the plan step that installs it.
CREATE TABLE ssh_certificates (
    serial         BIGINT  PRIMARY KEY,
    kind           TEXT    NOT NULL,
    purpose        TEXT    NOT NULL,
    host           TEXT    NOT NULL,
    key_id         TEXT    NOT NULL,
    principals     TEXT    NOT NULL,
    subject_fp     TEXT    NOT NULL,
    issued_at      BIGINT  NOT NULL,
    expires_at     BIGINT  NOT NULL,
    issued_by      TEXT    NOT NULL,
    certificate    TEXT,
    revoked_at     BIGINT,
    revoked_by     TEXT,
    revoked_reason TEXT
);
CREATE INDEX ssh_certificates_host ON ssh_certificates (host, issued_at);

-- which hosts StorageForge logs in to with a certificate, and for what. A host not here gets none: its keys work as before.
CREATE TABLE ssh_ca_hosts (
    host       TEXT    PRIMARY KEY,
    console    INTEGER NOT NULL DEFAULT 0,
    scan       INTEGER NOT NULL DEFAULT 0,
    updated_at BIGINT  NOT NULL,
    updated_by TEXT    NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (48, 'ssh_ca', CAST(strftime('%s', 'now') AS INTEGER));
