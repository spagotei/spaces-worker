PRAGMA foreign_keys = ON;

ALTER TABLE spaces
  ADD COLUMN accent_color TEXT NOT NULL DEFAULT '#8b6ca8';

ALTER TABLE spaces
  ADD COLUMN banner_url TEXT;

CREATE TABLE IF NOT EXISTS space_roles (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#8b6ca8',
  permissions_json TEXT NOT NULL DEFAULT '[]',
  position INTEGER NOT NULL DEFAULT 0,
  hoist INTEGER NOT NULL DEFAULT 0 CHECK (hoist IN (0, 1)),
  mentionable INTEGER NOT NULL DEFAULT 0 CHECK (mentionable IN (0, 1)),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(space_id, name)
);

CREATE TABLE IF NOT EXISTS space_member_roles (
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  member_id TEXT NOT NULL REFERENCES space_members(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES space_roles(id) ON DELETE CASCADE,
  assigned_by TEXT NOT NULL REFERENCES users(id),
  assigned_at INTEGER NOT NULL,
  PRIMARY KEY(member_id, role_id)
);

CREATE TABLE IF NOT EXISTS space_emojis (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE,
  image_type TEXT NOT NULL,
  image_data TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(space_id, name)
);

CREATE TABLE IF NOT EXISTS note_comments (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  edited_at INTEGER,
  deleted_at INTEGER,
  deleted_by TEXT REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_space_roles_space_position
  ON space_roles(space_id, position DESC, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_space_member_roles_space_member
  ON space_member_roles(space_id, member_id);

CREATE INDEX IF NOT EXISTS idx_space_emojis_space
  ON space_emojis(space_id, name);

CREATE INDEX IF NOT EXISTS idx_note_comments_note_created
  ON note_comments(note_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_note_comments_space_changed
  ON note_comments(space_id, created_at, edited_at, deleted_at);

INSERT OR IGNORE INTO platform_updates (
  version,
  published_at,
  title,
  changes_json,
  created_by,
  updated_at
)
VALUES (
  '0.54',
  CAST(strftime('%s','now') AS INTEGER) * 1000,
  'Community Core',
  '["Responsive desktop/tablet community workspace with a richer phone shell.","Stackable custom roles with granular Space capabilities.","Post comments can be edited by their author and removed by the post owner or moderators.","Custom Space emoji library and chat emoji picker.","Chat-only file attachments remain protected and size-limited.","Expanded Space identity customization with accent and banner support."]',
  NULL,
  CAST(strftime('%s','now') AS INTEGER) * 1000
);
