PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS notification_read_cursors (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope_kind TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  read_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, scope_kind, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_notification_read_cursors_user
  ON notification_read_cursors(user_id, read_at DESC);

CREATE TABLE IF NOT EXISTS typing_presence (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope_kind TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, scope_kind, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_typing_presence_scope
  ON typing_presence(scope_kind, scope_id, updated_at DESC);
