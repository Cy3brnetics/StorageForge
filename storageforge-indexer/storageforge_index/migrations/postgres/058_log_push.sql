-- StorageForge schema v58 · postgres: host logs pushed by the agent's logs plugin (roadmap section 3, phase 2; agentingest.py, docs/agent.md).
-- agent_peers.resume_json: per plugin, the cursor of the last reading the receiver stored, handed back to the agent when a session opens,
-- so a plugin that resumes (logs) starts after the last line the controller has, after a reboot too. Written by the receiver only, in a
-- table its role already writes.
-- host_log_lines.via: 'agent' for a line pushed in a batch the agent signed, NULL for one a scan collected over SSH.
-- host_log_status: how the host's lines came last (via), when pushed lines last arrived and with what delay, how many came pushed, the
-- journal's numbering last seen (seq_id, seq_last) and the numbers missing from it (seq_gaps, when last: seq_gap_at): lines deleted on
-- the host, or never sent. Debug lines the plugin leaves out are said by it and not counted as missing.
ALTER TABLE agent_peers ADD COLUMN resume_json TEXT;
ALTER TABLE host_log_lines ADD COLUMN via TEXT;
ALTER TABLE host_log_status ADD COLUMN via TEXT;
ALTER TABLE host_log_status ADD COLUMN pushed_at BIGINT;
ALTER TABLE host_log_status ADD COLUMN push_delay_ms BIGINT;
ALTER TABLE host_log_status ADD COLUMN push_lines BIGINT NOT NULL DEFAULT 0;
ALTER TABLE host_log_status ADD COLUMN seq_id TEXT;
ALTER TABLE host_log_status ADD COLUMN seq_last BIGINT;
ALTER TABLE host_log_status ADD COLUMN seq_gaps BIGINT NOT NULL DEFAULT 0;
ALTER TABLE host_log_status ADD COLUMN seq_gap_at BIGINT;

INSERT INTO schema_version (version, name, applied_at)
VALUES (58, 'log_push', EXTRACT(EPOCH FROM now())::BIGINT);
