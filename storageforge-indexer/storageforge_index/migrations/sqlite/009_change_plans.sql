-- StorageForge schema v9 · sqlite: staged filesystem change plans
-- An ordered list of tasks (folders, renames, trash, links, permissions, btrfs subvolumes and snapshots, mounts,
-- partitions, formats, labels) staged in the topology view. StorageForge checks plans against the index and writes
-- the Bash script or Ansible playbook that applies them; it never changes a host itself.
CREATE TABLE change_plans (
    plan_id     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    body_json   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (9, 'change_plans', CAST(strftime('%s', 'now') AS INTEGER));
