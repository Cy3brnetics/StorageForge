-- StorageForge schema v72 · sqlite: Toolbox bundles, role profiles and per-host exclusions (roadmap section 4.1 & 4.3; tbbundles.py).
CREATE TABLE toolbox_bundles (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    summary     TEXT    NOT NULL DEFAULT '',
    entries_json TEXT   NOT NULL,
    params_json TEXT    NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL,
    created_by  TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE toolbox_profiles (
    role        TEXT    PRIMARY KEY,
    tools_json  TEXT    NOT NULL,
    params_json TEXT    NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);

CREATE TABLE toolbox_host_roles (
    host          TEXT    PRIMARY KEY,
    role          TEXT    NOT NULL,
    excluded_json TEXT    NOT NULL DEFAULT '[]',
    updated_at    INTEGER NOT NULL,
    updated_by    TEXT    NOT NULL
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (72, 'toolbox_bundles', CAST(strftime('%s', 'now') AS INTEGER));
