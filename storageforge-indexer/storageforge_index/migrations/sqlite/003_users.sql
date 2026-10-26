-- StorageForge schema v3 · SQLite: local web UI accounts
-- Applies on top of 002_vault_audit_graph.sql. Passwords are hashed by Werkzeug (scrypt); this table never
-- sees plaintext. session_version is bumped on password change or disable, which logs out every session.
CREATE TABLE users (
    user_id          INTEGER PRIMARY KEY,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT    NOT NULL,
    session_version  INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL,
    last_login_at    INTEGER,
    disabled_at      INTEGER
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (3, 'users', CAST(strftime('%s', 'now') AS INTEGER));
