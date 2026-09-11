-- Spaces v45 - private beta invite console
-- Adds auditable email invitations and first-sign-in profile setup.

ALTER TABLE users
ADD COLUMN beta_profile_pending INTEGER NOT NULL DEFAULT 0
CHECK (beta_profile_pending IN (0, 1));

CREATE TABLE beta_access (
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

CREATE INDEX idx_beta_access_status_created
ON beta_access(status, created_at DESC);

CREATE INDEX idx_beta_access_user
ON beta_access(user_id);
