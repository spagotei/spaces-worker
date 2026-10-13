-- Spaces V83: additive cross-platform broadcasts. No existing tables modified.
CREATE TABLE IF NOT EXISTS platform_broadcasts_v83 (
  id TEXT PRIMARY KEY NOT NULL,
  format TEXT NOT NULL CHECK(format IN ('banner','modal')),
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  image_url TEXT,
  action_label TEXT,
  action_url TEXT,
  published INTEGER NOT NULL DEFAULT 1 CHECK(published IN (0,1)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER NOT NULL,
  expires_at INTEGER,
  FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_platform_broadcasts_v83_active
  ON platform_broadcasts_v83(published, format, published_at DESC);
CREATE TABLE IF NOT EXISTS platform_broadcast_receipts_v83 (
  user_id TEXT NOT NULL,
  broadcast_id TEXT NOT NULL,
  dismissed_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, broadcast_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(broadcast_id) REFERENCES platform_broadcasts_v83(id) ON DELETE CASCADE
);
