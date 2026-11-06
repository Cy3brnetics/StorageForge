-- StorageForge schema v42 · sqlite: saved versions of a planner design (design_versions.py)
-- One row is the whole blueprint as it was, so a version can be shown, compared and put back without the ones before it.
-- auto = 1 for the version the server makes by itself before a restore. Kept per host, with a count and a size limit in the module.
CREATE TABLE design_versions (
    id          INTEGER PRIMARY KEY,
    host        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    note        TEXT    NOT NULL DEFAULT '',
    author      TEXT    NOT NULL,
    auto        INTEGER NOT NULL DEFAULT 0,
    body_json   TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX ix_design_versions_host ON design_versions (host, id);

INSERT INTO schema_version (version, name, applied_at)
VALUES (42, 'design_versions', CAST(strftime('%s', 'now') AS INTEGER));
