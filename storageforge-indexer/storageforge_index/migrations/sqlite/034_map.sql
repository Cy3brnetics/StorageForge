-- StorageForge schema v34 · sqlite: the graph holds more than storage. Each node says which layer it is in and how sure we are of
-- it, and the kinds are no longer a fixed list here: graph.py and infragraph.py name them. All of this is rebuilt by a scan.
PRAGMA foreign_keys = OFF;
CREATE TABLE graph_nodes_new (
    node_id     TEXT    PRIMARY KEY,
    kind        TEXT    NOT NULL,
    label       TEXT    NOT NULL,
    host        TEXT,
    health      TEXT    NOT NULL DEFAULT 'unknown' CHECK (health IN ('protected', 'local-only', 'broken', 'unknown')),
    props_json  TEXT    NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL,
    layer       TEXT    NOT NULL DEFAULT 'storage',
    confidence  TEXT    NOT NULL DEFAULT 'certain',
    first_seen  INTEGER
);
INSERT INTO graph_nodes_new (node_id, kind, label, host, health, props_json, updated_at)
    SELECT node_id, kind, label, host, health, props_json, updated_at FROM graph_nodes;
CREATE TABLE graph_edges_new (
    src         TEXT NOT NULL REFERENCES graph_nodes (node_id) ON DELETE CASCADE,
    dst         TEXT NOT NULL REFERENCES graph_nodes (node_id) ON DELETE CASCADE,
    rel         TEXT NOT NULL,
    props_json  TEXT NOT NULL DEFAULT '{}',
    built_by    TEXT,
    PRIMARY KEY (src, dst, rel)
);
INSERT INTO graph_edges_new (src, dst, rel, props_json, built_by) SELECT src, dst, rel, props_json, built_by FROM graph_edges;
DROP TABLE graph_edges;
DROP TABLE graph_nodes;
ALTER TABLE graph_nodes_new RENAME TO graph_nodes;
ALTER TABLE graph_edges_new RENAME TO graph_edges;
CREATE INDEX ix_graph_nodes_host ON graph_nodes (host, kind);
CREATE INDEX ix_graph_nodes_layer ON graph_nodes (layer);
CREATE INDEX ix_graph_edges_dst ON graph_edges (dst);
CREATE INDEX ix_graph_edges_built_by ON graph_edges (built_by);
PRAGMA foreign_keys = ON;

-- What changed on a host between readings, kept only when something did.
CREATE TABLE graph_snapshots (
    id          INTEGER PRIMARY KEY,
    host        TEXT    NOT NULL,
    taken_at    INTEGER NOT NULL,
    graph_hash  TEXT    NOT NULL,
    keys_json   TEXT    NOT NULL DEFAULT '{}',
    diff_json   TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_graph_snapshots_host ON graph_snapshots (host, taken_at);

-- An operator's saved views: layers, filters and pinned positions. Theirs, so kept across every rescan.
CREATE TABLE map_views (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    owner       TEXT,
    body_json   TEXT    NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (34, 'map', CAST(strftime('%s', 'now') AS INTEGER));
