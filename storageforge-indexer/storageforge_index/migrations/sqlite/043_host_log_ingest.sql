-- StorageForge schema v43 · sqlite: what journald itself says of a line, its place in the journal, a rate per host, and counts that outlive the lines (hostlogs.py)
-- uid, comm, exe: journald's own fields (_UID, _COMM, _EXE). ident is whatever the writer chose to call itself.
-- seqnum, seqnum_id: the journal's own numbering (__SEQNUM, __SEQNUM_ID), so lines deleted on the host can be seen as a gap once lines are pushed.
ALTER TABLE host_log_lines ADD COLUMN uid INTEGER;
ALTER TABLE host_log_lines ADD COLUMN comm TEXT;
ALTER TABLE host_log_lines ADD COLUMN exe TEXT;
ALTER TABLE host_log_lines ADD COLUMN seqnum INTEGER;
ALTER TABLE host_log_lines ADD COLUMN seqnum_id TEXT;
-- lines are pruned by when they arrived, not by the time the host stamped on them
CREATE INDEX host_log_lines_arrived ON host_log_lines (host, collected_at, line_id);

-- rate_tokens, rate_at: how many more lines this host may store, and when that was worked out. over_rate: lines the last pickup did not keep
-- for being over the rate; over_total: all of them so far.
ALTER TABLE host_log_status ADD COLUMN rate_tokens REAL;
ALTER TABLE host_log_status ADD COLUMN rate_at INTEGER;
ALTER TABLE host_log_status ADD COLUMN over_rate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_log_status ADD COLUMN over_total INTEGER NOT NULL DEFAULT 0;

-- how many lines a host logged per unit and level in each 5 minutes, by the host's clock held to the controller's. Kept much longer than
-- the lines, because a baseline needs weeks of them. unit is '' for a line with none. A line over the rate is counted here though not stored.
CREATE TABLE host_log_counts (
    host     TEXT    NOT NULL,
    unit     TEXT    NOT NULL,
    priority INTEGER NOT NULL,
    bucket   INTEGER NOT NULL,
    lines    INTEGER NOT NULL,
    PRIMARY KEY (host, unit, priority, bucket)
);
CREATE INDEX host_log_counts_bucket ON host_log_counts (bucket);

INSERT INTO schema_version (version, name, applied_at)
VALUES (43, 'host_log_ingest', CAST(strftime('%s', 'now') AS INTEGER));
