-- StorageForge schema v55 · postgres: the agent's tunnel (sfagent.py, agenttunnel.py, docs/agent.md). receiver_key is the receiver's
-- X25519 key as the host pinned it for its agent's tunnel, and endpoint the address and port the tunnel dials: a key that changes is
-- given to a host only when a person accepts it. agent_deliveries holds, per host, what the receiver hands its agent at the start of
-- every session: the manifest the controller signed for it, and the signed descriptor of each plugin it names. Nothing in either is
-- secret: the controller signed the manifest, the release key or an operator signed the plugins, and the agent checks both.
ALTER TABLE agents ADD COLUMN receiver_key TEXT;
ALTER TABLE agents ADD COLUMN endpoint TEXT;

CREATE TABLE agent_deliveries (
    host         TEXT    PRIMARY KEY,
    fingerprint  TEXT    NOT NULL,
    counter      BIGINT  NOT NULL,
    manifest     TEXT    NOT NULL,
    signature    TEXT    NOT NULL,
    plugins_json TEXT    NOT NULL DEFAULT '[]',
    updated_at   BIGINT  NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (55, 'agent_tunnel', EXTRACT(EPOCH FROM now())::BIGINT);
