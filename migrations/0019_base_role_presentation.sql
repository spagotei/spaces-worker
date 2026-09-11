-- Spaces v44: persisted presentation settings for fixed Owner/Member base roles.
CREATE TABLE IF NOT EXISTS space_base_role_settings (
  space_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner', 'member')),
  color TEXT NOT NULL,
  hoist INTEGER NOT NULL DEFAULT 0,
  mentionable INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (space_id, role)
);

CREATE INDEX IF NOT EXISTS idx_space_base_role_settings_space
  ON space_base_role_settings(space_id);
