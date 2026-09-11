-- Spaces clean-install compatibility for the historical 0009 repair.
-- 0007_mobile_shell_chat_controls.sql now contains the required ALTER TABLE
-- statements, so they MUST NOT be repeated here on a fresh database.

PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS idx_channels_space_permissions
  ON channels(space_id, post_min_role, note_min_role);

CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated
  ON api_rate_limits(updated_at);

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
