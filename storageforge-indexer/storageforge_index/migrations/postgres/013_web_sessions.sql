-- StorageForge schema v13 · postgres: per-user session length and server-side sessions
-- A web session ends session_minutes after sign-in (30 by default, up to 480); each user picks it in the UI.
-- web_sessions holds one row per signed-in browser (the SHA-256 of a random id kept in the signed cookie): signing
-- out deletes the row, so a copy of the cookie stops working too.
ALTER TABLE users ADD COLUMN session_minutes INTEGER NOT NULL DEFAULT 30;

CREATE TABLE web_sessions (
    sid_hash    TEXT   PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    created_at  BIGINT NOT NULL,
    client      TEXT
);
CREATE INDEX ix_web_sessions_user ON web_sessions (user_id);

INSERT INTO schema_version (version, name, applied_at)
VALUES (13, 'web_sessions', extract(epoch FROM now())::bigint);
