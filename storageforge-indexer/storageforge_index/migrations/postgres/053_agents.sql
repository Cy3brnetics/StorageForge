-- StorageForge schema v53 · postgres: the optional agent (sfagent.py, docs/agent.md). One row for a host the agent was ever switched
-- on for. enabled is the per-host switch, and a host with no row has it off. public_key is the agent's own key, read back over the
-- pinned SSH connection at enrollment and pinned here: nothing else is the agent of that host. counter is the last manifest counter
-- signed for the host. It only goes up, and the row is kept when an agent is removed so that it never starts again from 1.
-- No private key is here: the agent's stays on its host, and the controller's two are rows of ssh_keys like any other vault key.
CREATE TABLE agents (
    host         TEXT    PRIMARY KEY,
    enabled      INTEGER NOT NULL DEFAULT 0,
    state        TEXT    NOT NULL DEFAULT 'off',
    public_key   TEXT,
    fingerprint  TEXT,
    runtime      TEXT,
    image        TEXT,
    counter      BIGINT  NOT NULL DEFAULT 0,
    manifest_sha TEXT,
    detail       TEXT,
    enrolled_at  BIGINT,
    updated_at   BIGINT  NOT NULL,
    updated_by   TEXT    NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (53, 'agents', EXTRACT(EPOCH FROM now())::BIGINT);
