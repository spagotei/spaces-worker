-- Spaces v48 - Support Console / security operations
-- Granular staff permissions, reserved-ID history, and timed account restrictions.

CREATE TABLE IF NOT EXISTS support_staff_permissions (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  permissions_json TEXT NOT NULL DEFAULT '[]',
  updated_by TEXT REFERENCES users(id),
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS public_user_id_history (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  old_public_user_id TEXT NOT NULL,
  new_public_user_id TEXT NOT NULL,
  changed_by TEXT NOT NULL REFERENCES users(id),
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_public_user_id_history_user
ON public_user_id_history(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS platform_restrictions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('chat','space_create','space_join')),
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  revoked_at INTEGER,
  revoked_by TEXT REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_platform_restrictions_user_active
ON platform_restrictions(user_id, kind, active, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_restrictions_active_expires
ON platform_restrictions(active, expires_at);
