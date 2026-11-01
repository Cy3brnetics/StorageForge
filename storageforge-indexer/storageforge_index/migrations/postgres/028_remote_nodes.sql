-- StorageForge schema v28 · postgres: hosts that dial in through the tunnel. The public half of each tunnel key only.
CREATE TABLE remote_nodes (
    node_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         TEXT   NOT NULL,
    public_key   TEXT   NOT NULL,
    created_at   BIGINT NOT NULL,
    created_by   TEXT,
    expires_at   BIGINT NOT NULL,
    adopted_at   BIGINT,
    revoked_at   BIGINT
);
INSERT INTO schema_version (version, name, applied_at)
VALUES (28, 'remote_nodes', extract(epoch FROM now())::bigint);
