-- Spaces 0.0.17: support cases, support DMs, and platform Space restrictions.

CREATE TABLE IF NOT EXISTS support_cases (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('bug','space')),
  reporter_id TEXT NOT NULL,
  target_workspace_id TEXT,
  subject TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','reviewed','actioned','resolved','dismissed')),
  priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
  assigned_to TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resolved_at INTEGER,
  FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(target_workspace_id) REFERENCES spaces(id) ON DELETE SET NULL,
  FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_support_cases_status_created
  ON support_cases(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_kind_created
  ON support_cases(kind, created_at DESC);

CREATE TABLE IF NOT EXISTS support_messages (
  id TEXT PRIMARY KEY,
  recipient_user_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL,
  case_id TEXT,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  FOREIGN KEY(recipient_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(case_id) REFERENCES support_cases(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_support_messages_recipient_created
  ON support_messages(recipient_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_messages_case_created
  ON support_messages(case_id, created_at DESC);

CREATE TABLE IF NOT EXISTS space_restrictions (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL,
  restricted_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(space_id) REFERENCES spaces(id) ON DELETE CASCADE,
  FOREIGN KEY(restricted_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_space_restrictions_active
  ON space_restrictions(space_id, active, created_at DESC);
