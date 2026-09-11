CREATE TABLE IF NOT EXISTS channel_permission_overwrites (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('everyone','role','member')),
  target_id TEXT NOT NULL,
  allow_json TEXT NOT NULL DEFAULT '[]',
  deny_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(channel_id, target_type, target_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_permission_overwrites_space_channel
  ON channel_permission_overwrites(space_id, channel_id);

CREATE INDEX IF NOT EXISTS idx_channel_permission_overwrites_target
  ON channel_permission_overwrites(space_id, target_type, target_id);
