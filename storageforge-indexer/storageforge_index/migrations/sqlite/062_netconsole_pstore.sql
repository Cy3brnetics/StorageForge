-- StorageForge schema v62 · sqlite: kernel messages over netconsole, and the last panic from pstore (roadmap section 3, phase 5;
-- netconsole.py, pstore.py, docs/scanning-and-search.md).
-- netconsole_sources: which host a netconsole packet is from. A packet is taken only when its source address and port are exactly one
-- row's, and is never trusted beyond that: UDP carries no signature, and anyone who can send from that address can write here.
-- packets, dropped, last_at: what the receiver took and refused from it, and when it last heard from it.
CREATE TABLE netconsole_sources (
    host       TEXT    PRIMARY KEY,
    address    TEXT    NOT NULL,
    port       INTEGER NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    note       TEXT    NOT NULL DEFAULT '',
    created_by TEXT,
    created_at INTEGER NOT NULL,
    last_at    INTEGER,
    packets    INTEGER NOT NULL DEFAULT 0,
    dropped    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (address, port)
);

-- pstore_at: when the newest crash record a scan found in pstore was written; pstore_records: how many there were; pstore_read: 1 when
-- the scan could read them; pstore_note: what to do when it could not; pstore_checked_at: the scan that looked.
ALTER TABLE host_log_status ADD COLUMN pstore_at INTEGER;
ALTER TABLE host_log_status ADD COLUMN pstore_records INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_log_status ADD COLUMN pstore_read INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_log_status ADD COLUMN pstore_note TEXT NOT NULL DEFAULT '';
ALTER TABLE host_log_status ADD COLUMN pstore_checked_at INTEGER;

INSERT INTO schema_version (version, name, applied_at)
VALUES (62, 'netconsole_pstore', CAST(strftime('%s', 'now') AS INTEGER));
