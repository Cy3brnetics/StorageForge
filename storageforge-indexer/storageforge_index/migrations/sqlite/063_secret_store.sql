-- StorageForge schema v63 · sqlite: the secret store (roadmap section 5; secretstore.py, docs/secrets.md). A step's secret is a row of
-- device_credentials with the username 'secret', sealed as before; these columns say how it was made, and the table below where it went.
-- secret_kind: password, token, hex, pin or wireguard for a secret StorageForge generated, NULL for one a person gave (vault secret-add).
-- secret_length: how many characters it was generated with. secret_origin: generated or given. value_rotated_at: when its value was last
-- changed by a rotation (rotated_at is when its key was last rewrapped, which a vault rotation does to every row).
ALTER TABLE device_credentials ADD COLUMN secret_kind TEXT;
ALTER TABLE device_credentials ADD COLUMN secret_length INTEGER;
ALTER TABLE device_credentials ADD COLUMN secret_origin TEXT;
ALTER TABLE device_credentials ADD COLUMN value_rotated_at INTEGER;

-- secret_deliveries: each host a secret was delivered to, by a plan run through the runner's stdin, by vault send-secret or by a
-- rotation. A rotation sends the new value to these hosts. Never the value itself.
CREATE TABLE secret_deliveries (
    name       TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    step       TEXT    NOT NULL DEFAULT '',
    how        TEXT    NOT NULL DEFAULT 'plan',
    first_at   INTEGER NOT NULL,
    last_at    INTEGER NOT NULL,
    PRIMARY KEY (name, host)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (63, 'secret_store', CAST(strftime('%s', 'now') AS INTEGER));
