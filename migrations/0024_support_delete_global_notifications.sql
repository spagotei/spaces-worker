-- Spaces v54 - permanent report deletion cleanup.
-- Reports/cases are only deleted from the archive. The report payload/evidence
-- is removed immediately; the normal moderation audit log remains authoritative.
DROP TABLE IF EXISTS support_deleted_items;
