-- Preserve the v1 inputs at cutover. All new storage saves address a single host section.
ALTER TABLE blueprints RENAME TO blueprint_archive_v1;
CREATE VIEW blueprints AS SELECT hostname, body_json, imported_at FROM blueprint_archive_v1 OFFSET 0;

CREATE TABLE host_design_sections (
    hostname TEXT NOT NULL,
    section TEXT NOT NULL,
    body_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (hostname, section)
);
INSERT INTO host_design_sections (hostname, section, body_json, updated_at)
SELECT hostname, 'storage', body_json, imported_at FROM blueprint_archive_v1;
CREATE VIEW host_storage_designs AS
SELECT hostname, body_json, updated_at AS imported_at FROM host_design_sections WHERE section = 'storage';

DROP VIEW host_design_inputs;
CREATE VIEW host_design_inputs AS
WITH members AS (
    SELECT m.value ->> 'name' AS hostname, d.id AS design_id, d.name, d.owner, d.updated_at,
           coalesce(d.graph_json::jsonb ->> 'notes', '') AS notes, m.value AS member,
           row_number() OVER (PARTITION BY m.value ->> 'name' ORDER BY d.updated_at DESC, d.id DESC, m.ord) AS position
    FROM map_designs AS d CROSS JOIN jsonb_array_elements(d.graph_json::jsonb -> 'hosts') WITH ORDINALITY AS m(value, ord)
)
SELECT m.hostname, b.body_json, m.design_id, m.name, m.owner, m.updated_at, m.notes, m.member, m.position
FROM members AS m LEFT JOIN host_storage_designs AS b ON b.hostname = m.hostname
UNION ALL
SELECT b.hostname, b.body_json, NULL, NULL, NULL, NULL, NULL, NULL, 1
FROM host_storage_designs AS b WHERE NOT EXISTS (SELECT 1 FROM members AS m WHERE m.hostname = b.hostname);

INSERT INTO schema_version (version, name, applied_at) VALUES (74, 'host_design_sections', EXTRACT(EPOCH FROM now())::BIGINT);
