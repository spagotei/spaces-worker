PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS space_invites (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL
    REFERENCES spaces(id)
    ON DELETE CASCADE,
  code TEXT NOT NULL COLLATE NOCASE UNIQUE,
  created_by TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
    CHECK (revoked IN (0, 1))
);

CREATE TABLE IF NOT EXISTS platform_moderation_actions (
  id TEXT PRIMARY KEY,
  moderator_id TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  target_user_id TEXT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  action TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_space_invites_space_created
  ON space_invites(space_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_space_invites_code
  ON space_invites(code);

CREATE INDEX IF NOT EXISTS idx_moderation_actions_target
  ON platform_moderation_actions(target_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_moderation_actions_moderator
  ON platform_moderation_actions(moderator_id, created_at DESC);


-- Backfill the current snapshot for notes that existed before version history.
INSERT OR IGNORE INTO note_versions (
  id,
  note_id,
  version,
  title,
  body,
  reason,
  edited_by,
  created_at
)
SELECT
  'backfill-' || id || '-v' || version,
  id,
  version,
  title,
  body,
  'Backfilled current note version',
  updated_by,
  updated_at
FROM notes;
