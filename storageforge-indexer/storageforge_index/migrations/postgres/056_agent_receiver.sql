-- StorageForge schema v56 · postgres: what the agent receiver keeps (agentreceiver.py, docs/agent.md). It is the only writer of these
-- three tables and writes no other: run it as its own role (python -m storageforge_index.agentreceiver grant ROLE prints the grants),
-- which can read five columns of agents and the deliveries, and write these three tables only. agent_peers: per agent key, the
-- receiver's own count of what came, worked out here and never taken from a batch. agent_records: what agents reported, under the
-- host their pinned key belongs to; source is always 'agent', so a reading here is never taken for one a scan measured; received_at
-- is the receiver's clock, which pruning goes by. agent_events: gaps, repeats, refusals and pruning, for the notification center.
CREATE TABLE agent_peers (
    fingerprint  TEXT    PRIMARY KEY,
    host         TEXT    NOT NULL,
    last_counter BIGINT  NOT NULL DEFAULT 0,
    last_digest  TEXT,
    last_run     BIGINT,
    last_seq     BIGINT  NOT NULL DEFAULT 0,
    last_dropped BIGINT  NOT NULL DEFAULT 0,
    batches      BIGINT  NOT NULL DEFAULT 0,
    records      BIGINT  NOT NULL DEFAULT 0,
    bytes        BIGINT  NOT NULL DEFAULT 0,
    gaps         BIGINT  NOT NULL DEFAULT 0,
    lost         BIGINT  NOT NULL DEFAULT 0,
    repeats      BIGINT  NOT NULL DEFAULT 0,
    resent       BIGINT  NOT NULL DEFAULT 0,
    malformed    BIGINT  NOT NULL DEFAULT 0,
    over_quota   BIGINT  NOT NULL DEFAULT 0,
    pruned       BIGINT  NOT NULL DEFAULT 0,
    sessions     BIGINT  NOT NULL DEFAULT 0,
    first_seen   BIGINT,
    last_seen    BIGINT,
    last_address TEXT,
    version      TEXT,
    claims_json  TEXT
);

CREATE TABLE agent_records (
    record_id    BIGSERIAL PRIMARY KEY,
    host         TEXT    NOT NULL,
    fingerprint  TEXT    NOT NULL,
    source       TEXT    NOT NULL DEFAULT 'agent' CHECK (source = 'agent'),
    counter      BIGINT  NOT NULL,
    seq          BIGINT  NOT NULL,
    plugin       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    claimed_at   BIGINT,
    received_at  BIGINT  NOT NULL,
    body_json    TEXT    NOT NULL
);
CREATE INDEX ix_agent_records_host ON agent_records (host, received_at);

CREATE TABLE agent_events (
    event_id     BIGSERIAL PRIMARY KEY,
    host         TEXT,
    fingerprint  TEXT,
    at           BIGINT  NOT NULL,
    kind         TEXT    NOT NULL,
    count        BIGINT  NOT NULL DEFAULT 1,
    detail       TEXT
);
CREATE INDEX ix_agent_events_host ON agent_events (host, at);

INSERT INTO schema_version (version, name, applied_at)
VALUES (56, 'agent_receiver', EXTRACT(EPOCH FROM now())::BIGINT);
