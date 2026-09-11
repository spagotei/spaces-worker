PRAGMA foreign_keys = ON;

ALTER TABLE spaces
  ADD COLUMN avatar_url TEXT;

ALTER TABLE spaces
  ADD COLUMN description TEXT NOT NULL DEFAULT '';

ALTER TABLE channels
  ADD COLUMN post_min_role TEXT NOT NULL DEFAULT 'contributor';

ALTER TABLE channels
  ADD COLUMN note_min_role TEXT NOT NULL DEFAULT 'contributor';

UPDATE channels
SET
  post_min_role = CASE
    WHEN kind = 'announcement' THEN 'admin'
    WHEN kind = 'notes' THEN 'disabled'
    ELSE 'contributor'
  END,
  note_min_role = CASE
    WHEN kind IN ('notes', 'mixed') THEN 'contributor'
    ELSE 'disabled'
  END;

UPDATE channels
SET post_min_role = 'viewer'
WHERE space_id = 'spaces-hub' AND name = 'general';

UPDATE channels
SET note_min_role = 'admin'
WHERE space_id = 'spaces-hub' AND name = 'notes';

CREATE INDEX IF NOT EXISTS idx_channels_space_permissions
  ON channels(space_id, post_min_role, note_min_role);
