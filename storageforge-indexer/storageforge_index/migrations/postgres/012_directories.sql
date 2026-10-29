-- StorageForge schema v12 · postgres: directories
-- Each folder path is stored once in `directories`; file_records points at it by dir_id instead of repeating the
-- path text in every row and in three indexes. Run `storageforge-index prune --vacuum` afterwards.
CREATE TABLE directories (
    dir_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mount_id  BIGINT NOT NULL REFERENCES mounts (mount_id) ON DELETE CASCADE,
    path      TEXT   NOT NULL,              -- absolute; '' only for the parent of the filesystem root entry '/'
    UNIQUE (mount_id, path)
);
-- text_pattern_ops makes "under /mnt/x" prefix LIKE queries indexable under any collation.
CREATE INDEX ix_dir_path      ON directories (path text_pattern_ops);
CREATE INDEX ix_dir_path_trgm ON directories USING gin (path gin_trgm_ops);

INSERT INTO directories (mount_id, path)
SELECT DISTINCT mount_id, parent_path FROM file_records ORDER BY mount_id, parent_path;

DROP VIEW v_files;

ALTER TABLE file_records ADD COLUMN dir_id BIGINT;
UPDATE file_records f SET dir_id = d.dir_id FROM directories d WHERE d.mount_id = f.mount_id AND d.path = f.parent_path;
ALTER TABLE file_records ALTER COLUMN dir_id SET NOT NULL,
    ADD CONSTRAINT file_records_dir_fk FOREIGN KEY (dir_id) REFERENCES directories (dir_id) ON DELETE CASCADE;
-- also drops UNIQUE (mount_id, parent_path, filename), ix_file_parent and ix_file_parent_trgm
ALTER TABLE file_records DROP COLUMN parent_path;
ALTER TABLE file_records ADD CONSTRAINT file_records_dir_filename_key UNIQUE (dir_id, filename);

CREATE VIEW v_files AS
SELECT h.hostname, m.mount_point, d.path AS parent_path, f.*,
       CASE d.path WHEN '' THEN f.filename
                   WHEN '/' THEN '/' || f.filename
                   ELSE d.path || '/' || f.filename END AS full_path
FROM file_records f
JOIN directories d ON d.dir_id = f.dir_id
JOIN mounts m ON m.mount_id = f.mount_id
JOIN hosts  h ON h.host_id  = m.host_id;

-- Bulk imports no longer list every added entry in the change log; drop the ones logged before.
DELETE FROM file_changes WHERE change_type = 'added' AND (scan_id, mount_id) IN (
    SELECT scan_id, mount_id FROM file_changes WHERE change_type = 'added'
    GROUP BY scan_id, mount_id HAVING count(*) > 50000);

INSERT INTO schema_version (version, name, applied_at)
VALUES (12, 'directories', extract(epoch FROM now())::bigint);
