-- Spaces v62: account presence + user blocking.
-- Presence is user-owned and no longer shared through device-local preferences.

ALTER TABLE users ADD COLUMN presence_status TEXT NOT NULL DEFAULT 'online';
ALTER TABLE users ADD COLUMN custom_status TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS user_blocks (
  blocker_user_id TEXT NOT NULL,
  blocked_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (blocker_user_id, blocked_user_id),
  FOREIGN KEY(blocker_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(blocked_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_blocks_blocked
ON user_blocks(blocked_user_id, created_at DESC);
