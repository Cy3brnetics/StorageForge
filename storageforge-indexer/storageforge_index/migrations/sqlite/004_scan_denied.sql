-- StorageForge schema v4 · SQLite: folders a scan could not read
-- find reports "Permission denied" for each directory it cannot list; the scan keeps the first few hundred per
-- scan so the UI can show what is missing and offer read-only scan access. Older scans' rows go with the scan.
CREATE TABLE scan_denied (
    scan_id      INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    mount_point  TEXT    NOT NULL,
    path         TEXT    NOT NULL,
    PRIMARY KEY (scan_id, path)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (4, 'scan_denied', CAST(strftime('%s', 'now') AS INTEGER));
