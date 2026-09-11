PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  reporter_id TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  reported_user_id TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  workspace_id TEXT
    REFERENCES spaces(id)
    ON DELETE SET NULL,
  reason TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  snapshot_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (
      status IN (
        'open',
        'reviewed',
        'actioned',
        'dismissed'
      )
    ),
  created_at INTEGER NOT NULL,
  reviewed_by TEXT
    REFERENCES users(id)
    ON DELETE SET NULL,
  reviewed_at INTEGER
);

CREATE TABLE IF NOT EXISTS platform_bans (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  banned_by TEXT NOT NULL
    REFERENCES users(id),
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  active INTEGER NOT NULL DEFAULT 1
    CHECK (active IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_reports_status_created
  ON reports(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_reported_user
  ON reports(reported_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_bans_user_active
  ON platform_bans(user_id, active, created_at DESC);
