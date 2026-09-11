CREATE TABLE IF NOT EXISTS direct_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_direct_groups_owner ON direct_groups(owner_user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS direct_group_members (
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  added_by TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_direct_group_members_user ON direct_group_members(user_id, joined_at DESC);

CREATE TABLE IF NOT EXISTS direct_group_messages (
  id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_direct_group_messages_group ON direct_group_messages(group_id, created_at ASC);
