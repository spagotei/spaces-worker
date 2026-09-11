-- Spaces v58 - repair/guarantee Beta Access storage.
-- Safe when migration 0020 already created the table.

CREATE TABLE IF NOT EXISTS beta_access (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  status TEXT NOT NULL
    CHECK (status IN ('invited', 'claimed', 'revoked')),
  invited_by TEXT NOT NULL
    REFERENCES users(id),
  user_id TEXT
    REFERENCES users(id),
  created_at INTEGER NOT NULL,
  claimed_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_beta_access_status_created
ON beta_access(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_beta_access_user
ON beta_access(user_id);
