-- StorageForge schema v61 · sqlite: anomalies on host logs (roadmap section 3, phase 3; loganomaly.py, docs/scanning-and-search.md).
-- host_log_counts_host: the baselines read one host's counts over a few hours of each of the last four weeks, by host and bucket.
CREATE INDEX host_log_counts_host ON host_log_counts (host, bucket);

-- host_log_kinds: each kind of line a host has logged: the message with its numbers, hex, addresses and paths blanked (shape), and a
-- hash of that and the program. first_at and last_at are when lines of it arrived here, never the time the host stamped on them.
-- sample: the first line of the kind, scrubbed of secrets as every stored line is. priority: the worst level a line of it had.
CREATE TABLE host_log_kinds (
    host      TEXT    NOT NULL,
    kind_hash TEXT    NOT NULL,
    program   TEXT,
    shape     TEXT    NOT NULL,
    sample    TEXT    NOT NULL,
    priority  INTEGER NOT NULL,
    first_at  INTEGER NOT NULL,
    last_at   INTEGER NOT NULL,
    lines     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (host, kind_hash)
);
CREATE INDEX host_log_kinds_first ON host_log_kinds (host, first_at);

-- fresh_at: when a pickup or a push last brought a line not seen before, stored or over the rate: silence is measured from it, by
-- the controller's clock, so a host with a wrong clock does not look silent.
ALTER TABLE host_log_status ADD COLUMN fresh_at INTEGER;
-- kinds_over: new kinds a host logged after it had as many as one host may keep, so not kept and not said one by one.
ALTER TABLE host_log_status ADD COLUMN kinds_over INTEGER NOT NULL DEFAULT 0;

INSERT INTO schema_version (version, name, applied_at)
VALUES (61, 'log_anomalies', CAST(strftime('%s', 'now') AS INTEGER));
