-- StorageForge schema v24 · postgres: custom roles and invite links. The built-in roles live in permissions.py.
-- users.role may now name a custom role. Only the SHA-256 of an invite's token is stored.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

CREATE TABLE roles (
    name         TEXT   PRIMARY KEY,
    description  TEXT   NOT NULL DEFAULT '',
    permissions  TEXT   NOT NULL,
    created_at   BIGINT NOT NULL,
    created_by   TEXT   NOT NULL
);

CREATE TABLE invites (
    invite_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash  TEXT   NOT NULL UNIQUE,
    role        TEXT   NOT NULL,
    reset_user  TEXT,
    note        TEXT   NOT NULL DEFAULT '',
    created_by  TEXT   NOT NULL,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    used_at     BIGINT,
    used_by     TEXT,
    revoked_at  BIGINT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (24, 'roles_invites', extract(epoch FROM now())::bigint);
