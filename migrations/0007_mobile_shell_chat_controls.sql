PRAGMA foreign_keys = ON;

ALTER TABLE spaces
  ADD COLUMN background_preset TEXT NOT NULL DEFAULT 'graphite';

ALTER TABLE messages
  ADD COLUMN deleted_at INTEGER;

ALTER TABLE messages
  ADD COLUMN deleted_by TEXT;

ALTER TABLE messages
  ADD COLUMN attachment_name TEXT;

ALTER TABLE messages
  ADD COLUMN attachment_type TEXT;

ALTER TABLE messages
  ADD COLUMN attachment_size INTEGER;

ALTER TABLE messages
  ADD COLUMN attachment_data TEXT;

CREATE INDEX IF NOT EXISTS idx_messages_space_changed
  ON messages(space_id, created_at, edited_at, deleted_at);

INSERT OR IGNORE INTO platform_updates (
  version,
  published_at,
  title,
  changes_json,
  created_by,
  updated_at
)
VALUES (
  '0.53',
  CAST(strftime('%s','now') AS INTEGER) * 1000,
  'Mobile Glass Overhaul',
  '["New mobile app shell with Home, Spaces, and Settings.","Swipe-up glass Spaces drawer with recent destinations.","Readable mobile typography and smoother sync transitions.","Space backgrounds now persist with each Space.","Chat messages can be edited or removed with moderator controls.","Small protected chat attachments are supported up to 180 KB."]',
  NULL,
  CAST(strftime('%s','now') AS INTEGER) * 1000
);
