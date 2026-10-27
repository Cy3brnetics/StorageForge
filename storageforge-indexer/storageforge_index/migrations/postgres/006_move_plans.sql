-- StorageForge schema v6 · PostgreSQL: data move plans
-- A plan is a list of rsync steps (copy, move, mirror, rsnapshot) between folders on scanned hosts. StorageForge
-- checks plans against the index and generates the script that runs them; it never moves data itself.
CREATE TABLE move_plans (
    plan_id     BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    body_json   TEXT    NOT NULL,
    created_at  BIGINT  NOT NULL,
    updated_at  BIGINT  NOT NULL,
    updated_by  TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (6, 'move_plans', extract(epoch FROM now())::bigint);
