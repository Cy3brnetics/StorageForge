-- StorageForge schema v35 · sqlite: what the map needs to go back in time, and what is the operator's own on it.
-- graph_json: a host's layers above storage as they stood at that reading, so the timeline can draw them. Rebuildable history.
ALTER TABLE graph_snapshots ADD COLUMN graph_json TEXT NOT NULL DEFAULT '{}';

-- Gear with no access: a switch, a modem. Placed by hand and always marked so. Theirs, so kept across every rescan.
CREATE TABLE map_manual (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,
    label       TEXT    NOT NULL,
    attrs_json  TEXT    NOT NULL DEFAULT '{}',
    links_json  TEXT    NOT NULL DEFAULT '[]',
    created_by  TEXT,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE map_annotations (
    id          INTEGER PRIMARY KEY,
    view_id     INTEGER,
    target      TEXT    NOT NULL,
    text        TEXT    NOT NULL,
    style_json  TEXT    NOT NULL DEFAULT '{}',
    created_by  TEXT,
    updated_at  INTEGER NOT NULL
);

-- An intended topology: hosts, networks, workloads and rules that may not exist yet. Compared with what scans find.
CREATE TABLE map_designs (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    owner       TEXT,
    graph_json  TEXT    NOT NULL DEFAULT '{}',
    compared_at INTEGER,
    updated_at  INTEGER NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (35, 'map_more', CAST(strftime('%s', 'now') AS INTEGER));
