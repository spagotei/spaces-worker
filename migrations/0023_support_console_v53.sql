-- Spaces v53 - complete Support operations lifecycle.
-- Archives keep reports viewable. Permanent deletes remove report payload/evidence
-- and leave only a tiny tombstone proving that a deletion occurred.

ALTER TABLE reports ADD COLUMN archived_at INTEGER;
ALTER TABLE reports ADD COLUMN archived_by TEXT;

ALTER TABLE support_cases ADD COLUMN archived_at INTEGER;
ALTER TABLE support_cases ADD COLUMN archived_by TEXT;
ALTER TABLE support_cases ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE support_messages ADD COLUMN message_kind TEXT NOT NULL DEFAULT 'official';
ALTER TABLE support_messages ADD COLUMN reply_to_message_id TEXT;

CREATE INDEX IF NOT EXISTS idx_reports_archive_created
  ON reports(archived_at, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_archive_created
  ON support_cases(archived_at, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_messages_sender_created
  ON support_messages(sender_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS support_deleted_items (
  id TEXT PRIMARY KEY,
  source_kind TEXT NOT NULL CHECK(source_kind IN ('player','space','bug')),
  source_id TEXT NOT NULL,
  label TEXT NOT NULL,
  deleted_by TEXT NOT NULL,
  deleted_at INTEGER NOT NULL,
  FOREIGN KEY(deleted_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_support_deleted_items_deleted
  ON support_deleted_items(deleted_at DESC);
