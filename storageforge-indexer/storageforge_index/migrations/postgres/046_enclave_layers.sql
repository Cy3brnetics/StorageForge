-- StorageForge schema v46 · postgres: the key enclave's step-up records, a policy on a stored secret, and the second lock on the KEK (roadmap section 14)
-- Nothing already stored changes: both new columns are empty on every row there is, and an empty one means "as before".
-- The way back: re-seal every secret that was given a policy without one (vault secret-policy NAME --none), take the second lock off
-- (vault second-lock off), then DROP TABLE enclave_stepup; ALTER TABLE device_credentials DROP COLUMN policy_json;
-- ALTER TABLE vault_meta DROP COLUMN second_lock; DELETE FROM schema_version WHERE version = 46.

-- enclave_stepup: what the key enclave holds about one person, to check a step-up itself: the hash of a password and the public keys of
-- their FIDO2 tokens, sealed under the KEK as a device credential is. Only the enclave reads it. fido_ids lists the tokens in it, to compare
-- with security_webauthn.
CREATE TABLE enclave_stepup (
    username     TEXT    PRIMARY KEY,
    rec_uuid     TEXT    NOT NULL UNIQUE,
    dek_nonce    BYTEA   NOT NULL,
    wrapped_dek  BYTEA   NOT NULL,
    nonce        BYTEA   NOT NULL,
    ciphertext   BYTEA   NOT NULL,
    fido_ids     TEXT    NOT NULL DEFAULT '[]',
    created_at   BIGINT  NOT NULL,
    updated_at   BIGINT  NOT NULL
);

-- NULL: a secret anyone who may use the vault can ask for by name, as before. Otherwise JSON naming the steps, hosts and platforms it may
-- be released for and whether it is sensitive. The same text is in the ciphertext's associated data, so changing it here opens nothing.
ALTER TABLE device_credentials ADD COLUMN policy_json TEXT;

-- NULL: the KEK comes from the vault secret alone, as before. Otherwise JSON saying a second share, held on the enclave's host, is mixed in.
ALTER TABLE vault_meta ADD COLUMN second_lock TEXT;

INSERT INTO schema_version (version, name, applied_at)
VALUES (46, 'enclave_layers', EXTRACT(EPOCH FROM now())::BIGINT);
