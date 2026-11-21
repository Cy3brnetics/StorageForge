-- StorageForge schema v59 · sqlite: what the web app keeps of the agent's disks, files, scan and sentinel plugins, monitoring-only hosts,
-- and consoles turned on for a session through storageforge-agentctl (docs/agent.md). Everything an agent said is its claim: these
-- tables hold what agentingest made of it, under the host the receiver stored it under (from the key), never one a reading names.
-- agents.mode: 'ssh' (the controller has SSH access and the agent is an extra) or 'monitoring' (the agent's lifecycle through
-- storageforge-agentctl is the only SSH there is). host_key: the host key an admin pasted when a monitoring-only host was adopted.
-- agent_disks: each disk's last SMART reading and error counts from the disks plugin. agent_file_events: changes the files plugin
-- saw, with the process and account that made them, and what the index and the next scan made of each. agent_file_reads: reads per
-- account and minute, for off-hours reads. agent_inventory: the scan plugin's last output. agent_console_grants: each console session
-- SSH was turned on for through storageforge-agentctl, and when it was turned off again.
ALTER TABLE agents ADD COLUMN mode TEXT NOT NULL DEFAULT 'ssh';
ALTER TABLE agents ADD COLUMN host_key TEXT;

CREATE TABLE agent_disks (
    host         TEXT    NOT NULL,
    dev          TEXT    NOT NULL,
    at           BIGINT  NOT NULL,
    health_json  TEXT,
    raw_json     TEXT,
    lines_json   TEXT,
    ioerr        BIGINT,
    ioerr_at     BIGINT,
    error        TEXT,
    PRIMARY KEY (host, dev)
);

CREATE TABLE agent_file_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT    NOT NULL,
    at           BIGINT  NOT NULL,
    received_at  BIGINT  NOT NULL,
    path         TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    pid          BIGINT,
    process      TEXT,
    uid          BIGINT,
    user_name    TEXT,
    managed      INTEGER NOT NULL DEFAULT 0,
    indexed      TEXT,
    checked      TEXT
);
CREATE INDEX ix_agent_file_events_host ON agent_file_events (host, at);
CREATE INDEX ix_agent_file_events_path ON agent_file_events (host, path);

CREATE TABLE agent_file_reads (
    host         TEXT    NOT NULL,
    minute       BIGINT  NOT NULL,
    uid          BIGINT  NOT NULL,
    user_name    TEXT,
    reads        BIGINT  NOT NULL,
    folders_json TEXT,
    PRIMARY KEY (host, minute, uid)
);

CREATE TABLE agent_inventory (
    host          TEXT    PRIMARY KEY,
    at            BIGINT  NOT NULL,
    received_at   BIGINT  NOT NULL,
    script        TEXT    NOT NULL,
    sections_json TEXT    NOT NULL,
    compared_json TEXT
);

CREATE TABLE agent_console_grants (
    grant_id     TEXT    PRIMARY KEY,
    host         TEXT    NOT NULL,
    user_name    TEXT    NOT NULL,
    fingerprint  TEXT    NOT NULL,
    opened_by    TEXT    NOT NULL,
    opened_at    BIGINT  NOT NULL,
    expires_at   BIGINT  NOT NULL,
    closed_at    BIGINT,
    close_detail TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (59, 'agent_plugins', CAST(strftime('%s', 'now') AS INTEGER));
