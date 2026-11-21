-- StorageForge schema v57 · postgres: wipe and stop, and what an agent's report may cause (agentguard.py, agentaction.py, docs/agent.md).
-- checked_at and check_json: the last check from outside, over SSH, of the agent's container against its manifest, and what it found.
-- wiped_at: when the controller revoked the agent's key because a check found something, or the agent said it wiped itself; the
-- state is then 'wiped' and only an admin enrolls an agent there again. agent_actions: every action an agent's report caused or asked
-- for, aimed at whom, and what came of it. A report acts by itself only on the agent that sent it (outcome 'done'); anything wider is
-- held for a person (outcome 'held') unless an independent witness agrees, and the witnesses are kept beside it. The receiver's role
-- is given nothing on this table: only the web app's side writes it.
ALTER TABLE agents ADD COLUMN checked_at BIGINT;
ALTER TABLE agents ADD COLUMN check_json TEXT;
ALTER TABLE agents ADD COLUMN wiped_at BIGINT;

CREATE TABLE agent_actions (
    action_id      BIGSERIAL PRIMARY KEY,
    at             BIGINT  NOT NULL,
    host           TEXT    NOT NULL,
    fingerprint    TEXT,
    action         TEXT    NOT NULL,
    target         TEXT    NOT NULL,
    named_json     TEXT,
    witnesses_json TEXT,
    outcome        TEXT    NOT NULL,
    detail         TEXT
);
CREATE INDEX ix_agent_actions_host ON agent_actions (host, at);

INSERT INTO schema_version (version, name, applied_at)
VALUES (57, 'agent_guard', EXTRACT(EPOCH FROM now())::BIGINT);
