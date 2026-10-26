-- StorageForge schema v3 · PostgreSQL: local web UI accounts
-- Applies on top of 002_vault_audit_graph.sql. Passwords are hashed by Werkzeug (scrypt); this table never
-- sees plaintext. session_version is bumped on password change or disable, which logs out every session.
CREATE TABLE users (
    user_id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username         TEXT    NOT NULL,
    password_hash    TEXT    NOT NULL,
    session_version  INTEGER NOT NULL DEFAULT 1,
    created_at       BIGINT  NOT NULL,
    last_login_at    BIGINT,
    disabled_at      BIGINT
);
CREATE UNIQUE INDEX ux_users_username ON users (lower(username));

INSERT INTO schema_version (version, name, applied_at)
VALUES (3, 'users', extract(epoch FROM now())::bigint);
