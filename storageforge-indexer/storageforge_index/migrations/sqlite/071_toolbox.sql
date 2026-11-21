-- StorageForge schema v71 · sqlite: the Toolbox catalog engine (roadmap section 4.1; toolbox.py, docs/toolbox.md).
-- toolbox_catalog: catalog entries that did not come in the package. source 'official': an update of the official catalog, taken only
-- when the release key signed its manifest (manifest_json, signature) and its serial is above the one in use. source 'custom': an
-- operator's own entry, with the SSH signature made on the operator's machine (signature, signed_by) or none. spec_yaml is kept byte
-- for byte, since that is what was signed; every read checks the signature again, so a row changed in the database is refused.
CREATE TABLE toolbox_catalog (
    source        TEXT    NOT NULL,
    id            TEXT    NOT NULL,
    revision      INTEGER NOT NULL,
    category      TEXT    NOT NULL,
    spec_yaml     TEXT    NOT NULL,
    sha256        TEXT    NOT NULL,
    signature     TEXT,
    signed_by     TEXT,
    manifest_json TEXT,
    serial        INTEGER,
    added_at      INTEGER NOT NULL,
    added_by      TEXT    NOT NULL,
    PRIMARY KEY (source, id)
);

-- toolbox_signers: the public keys whose signature makes a custom entry signed. The private half stays on the operator's machine.
CREATE TABLE toolbox_signers (
    name          TEXT    PRIMARY KEY,
    public_key    TEXT    NOT NULL,
    fingerprint   TEXT    NOT NULL,
    added_at      INTEGER NOT NULL,
    added_by      TEXT    NOT NULL
);

-- toolbox_installs: each tool staged, installed or removed on a host, with the entry (sha256) and method it was staged from.
-- params_json: what the install made (account, unit, packages, data folders), which removal reads. unsigned_by: who accepted an
-- unsigned custom entry for this host and entry, behind a fresh password: without it the step refuses to run.
CREATE TABLE toolbox_installs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    tool_id       TEXT    NOT NULL,
    revision      INTEGER NOT NULL,
    sha256        TEXT    NOT NULL,
    method        TEXT    NOT NULL,
    params_json   TEXT    NOT NULL DEFAULT '{}',
    status        TEXT    NOT NULL,
    plan_id       INTEGER,
    managed_by    TEXT    NOT NULL DEFAULT 'storageforge',
    unsigned_by   TEXT,
    staged_at     INTEGER NOT NULL,
    staged_by     TEXT    NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE (host, tool_id)
);

-- toolbox_status: what each tool's adapter made of the last infrastructure reading of its host. error: why the status is unavailable.
CREATE TABLE toolbox_status (
    host            TEXT    NOT NULL,
    tool_id         TEXT    NOT NULL,
    checked_at      INTEGER NOT NULL,
    detected        INTEGER NOT NULL DEFAULT 0,
    health          TEXT    NOT NULL,
    version_running TEXT,
    tiles_json      TEXT    NOT NULL DEFAULT '[]',
    metrics_json    TEXT    NOT NULL DEFAULT '{}',
    error           TEXT,
    PRIMARY KEY (host, tool_id)
);

-- toolbox_overrides: ports, bind address, exposure, volumes, method or image of one tool on one host, kept apart from the entry so a
-- catalog update does not undo them.
CREATE TABLE toolbox_overrides (
    host          TEXT    NOT NULL,
    tool_id       TEXT    NOT NULL,
    override_yaml TEXT    NOT NULL,
    sha256        TEXT    NOT NULL,
    updated_at    INTEGER NOT NULL,
    updated_by    TEXT    NOT NULL,
    PRIMARY KEY (host, tool_id)
);

INSERT INTO schema_version (version, name, applied_at)
VALUES (71, 'toolbox', CAST(strftime('%s', 'now') AS INTEGER));
