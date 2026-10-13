-- Spaces V77 — unified Support Operations / Trust & Safety.
-- Additive rollout: no legacy Support/report tables are removed.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS support_cases_v77 (
  id TEXT PRIMARY KEY,
  case_number TEXT NOT NULL UNIQUE,
  case_type TEXT NOT NULL CHECK(case_type IN ('request','user_report','space_report','bug_report','appeal','other')),
  subtype TEXT NOT NULL DEFAULT '',
  reporter_id TEXT NOT NULL,
  target_user_id TEXT,
  target_space_id TEXT,
  target_channel_id TEXT,
  subject TEXT NOT NULL,
  answers_json TEXT NOT NULL DEFAULT '{}',
  details TEXT NOT NULL DEFAULT '',
  priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
  status TEXT NOT NULL DEFAULT 'waiting' CHECK(status IN ('waiting','reviewing','resolved','archived')),
  assigned_to TEXT,
  source TEXT NOT NULL DEFAULT 'support_bot',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  resolved_at INTEGER,
  resolved_by TEXT,
  archived_at INTEGER,
  archived_by TEXT,
  FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY(target_space_id) REFERENCES spaces(id) ON DELETE SET NULL,
  FOREIGN KEY(target_channel_id) REFERENCES channels(id) ON DELETE SET NULL,
  FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_support_cases_v77_status_activity ON support_cases_v77(status, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_v77_reporter_activity ON support_cases_v77(reporter_id, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_v77_target_user ON support_cases_v77(target_user_id, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_v77_target_space ON support_cases_v77(target_space_id, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_cases_v77_type_status ON support_cases_v77(case_type, status, last_activity_at DESC);

CREATE TABLE IF NOT EXISTS support_case_events_v77 (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  actor_user_id TEXT,
  event_type TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  FOREIGN KEY(case_id) REFERENCES support_cases_v77(id) ON DELETE CASCADE,
  FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_support_case_events_v77_case ON support_case_events_v77(case_id, created_at ASC);

CREATE TABLE IF NOT EXISTS support_case_collaborators_v77 (
  case_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  added_by TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  PRIMARY KEY(case_id, user_id),
  FOREIGN KEY(case_id) REFERENCES support_cases_v77(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(added_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS support_restrictions_v77 (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL CHECK(target_type IN ('user','space','channel')),
  target_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  reason_category TEXT NOT NULL DEFAULT 'Other',
  note TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  revoked_at INTEGER,
  revoked_by TEXT,
  case_id TEXT,
  FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY(revoked_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY(case_id) REFERENCES support_cases_v77(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_support_restrictions_v77_target ON support_restrictions_v77(target_type, target_id, capability, active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_restrictions_v77_active ON support_restrictions_v77(active, expires_at, created_at DESC);

CREATE TABLE IF NOT EXISTS support_audit_v77 (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  actor_role TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  case_id TEXT,
  reason_category TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  before_json TEXT NOT NULL DEFAULT '{}',
  after_json TEXT NOT NULL DEFAULT '{}',
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY(case_id) REFERENCES support_cases_v77(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_support_audit_v77_created ON support_audit_v77(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_audit_v77_target ON support_audit_v77(target_type, target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_audit_v77_case ON support_audit_v77(case_id, created_at ASC);
