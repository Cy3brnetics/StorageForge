-- StorageForge schema v69 · sqlite: workloads adopted by capturing them (roadmap section 6; wlcapture.py, docs/workloads.md). A capture is
-- the definition of a running workload as StorageForge read it (compose, a Quadlet unit, libvirt XML or Incus YAML), kept so later readings
-- can be compared with it. facts_json: the fields drift is measured on (image, ports, mounts, networks, disks, NICs). Never an environment value.
CREATE TABLE workload_captures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT    NOT NULL,
    runtime      TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    format       TEXT    NOT NULL,
    definition   TEXT    NOT NULL,
    facts_json   TEXT    NOT NULL,
    note         TEXT    NOT NULL DEFAULT '',
    captured_at  INTEGER NOT NULL,
    captured_by  TEXT    NOT NULL,
    UNIQUE (host, runtime, name)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (69, 'workload_captures', CAST(strftime('%s', 'now') AS INTEGER));
