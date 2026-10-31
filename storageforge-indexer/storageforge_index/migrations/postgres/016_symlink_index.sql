-- StorageForge schema v16 · PostgreSQL: find a host's symlinks without reading all of its files
-- Designs and the graph list them each time they are built, and symlinks are a small part of file_records.
CREATE INDEX ix_file_symlink ON file_records (mount_id) WHERE is_symlink;

INSERT INTO schema_version (version, name, applied_at)
VALUES (16, 'symlink_index', extract(epoch FROM now())::bigint);
