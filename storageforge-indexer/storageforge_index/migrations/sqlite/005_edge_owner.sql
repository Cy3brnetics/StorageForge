-- StorageForge schema v5 · SQLite: which host's build made each graph edge
-- A client's NFS/SMB mount draws an edge from the server's mount point. Rebuilding the server must not drop it, so
-- a rebuild deletes only the edges it made itself. NULL marks edges from before this column (the old rule applies).
ALTER TABLE graph_edges ADD COLUMN built_by TEXT;
CREATE INDEX ix_graph_edges_built_by ON graph_edges (built_by);

INSERT INTO schema_version (version, name, applied_at)
VALUES (5, 'edge_owner', CAST(strftime('%s', 'now') AS INTEGER));
