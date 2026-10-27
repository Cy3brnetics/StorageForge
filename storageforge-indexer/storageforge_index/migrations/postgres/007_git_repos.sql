-- StorageForge schema v7 · postgres: git repositories found by scans
-- Scans index the .git entry of every working copy (its contents stay pruned) and bare repositories, then ask the
-- host's git for branch, head, first commit, remotes and local changes. Repositories with the same first commit
-- are copies of one history; the UI shows which have an archive copy on another machine and which lag behind.
CREATE TABLE git_repos (
    host_id       BIGINT NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
    path          TEXT    NOT NULL,
    bare          INTEGER NOT NULL DEFAULT 0,
    branch        TEXT,
    head_commit   TEXT,
    head_time     BIGINT,
    head_subject  TEXT,
    root_commit   TEXT,
    refs          INTEGER,
    dirty         INTEGER,
    upstream      TEXT,
    ahead         INTEGER,
    behind        INTEGER,
    remotes_json  TEXT    NOT NULL DEFAULT '[]',
    size_kb       BIGINT,
    error         TEXT,
    scan_id       BIGINT,
    PRIMARY KEY (host_id, path)
);
CREATE INDEX ix_git_root ON git_repos (root_commit);

INSERT INTO schema_version (version, name, applied_at)
VALUES (7, 'git_repos', extract(epoch FROM now())::bigint);
