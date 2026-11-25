-- A row for each saved host alternative, including hosts known only to the planner.
CREATE VIEW host_design_inputs AS
WITH members AS (
    SELECT m.value ->> 'name' AS hostname, d.id AS design_id, d.name, d.owner, d.updated_at,
           coalesce(d.graph_json::jsonb ->> 'notes', '') AS notes, m.value AS member,
           row_number() OVER (PARTITION BY m.value ->> 'name' ORDER BY d.updated_at DESC, d.id DESC, m.ord) AS position
    FROM map_designs AS d CROSS JOIN jsonb_array_elements(d.graph_json::jsonb -> 'hosts') WITH ORDINALITY AS m(value, ord)
)
SELECT m.hostname, b.body_json, m.design_id, m.name, m.owner, m.updated_at, m.notes, m.member, m.position
FROM members AS m LEFT JOIN blueprints AS b ON b.hostname = m.hostname
UNION ALL
SELECT b.hostname, b.body_json, NULL, NULL, NULL, NULL, NULL, NULL, 1
FROM blueprints AS b WHERE NOT EXISTS (SELECT 1 FROM members AS m WHERE m.hostname = b.hostname);

INSERT INTO schema_version (version, name, applied_at) VALUES (73, 'host_design_inputs', EXTRACT(EPOCH FROM now())::BIGINT);
