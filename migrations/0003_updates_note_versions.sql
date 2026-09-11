PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS platform_updates (
  version TEXT PRIMARY KEY,
  published_at INTEGER NOT NULL,
  title TEXT NOT NULL,
  changes_json TEXT NOT NULL DEFAULT '[]',
  created_by TEXT
    REFERENCES users(id)
    ON DELETE SET NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS note_versions (
  id TEXT PRIMARY KEY,
  note_id TEXT NOT NULL
    REFERENCES notes(id)
    ON DELETE CASCADE,
  version INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  edited_by TEXT
    REFERENCES users(id)
    ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(note_id, version)
);

CREATE INDEX IF NOT EXISTS idx_platform_updates_published
  ON platform_updates(published_at DESC);

CREATE INDEX IF NOT EXISTS idx_note_versions_note_version
  ON note_versions(note_id, version DESC);
