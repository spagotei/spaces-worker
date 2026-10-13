-- Spaces V80.3: authoritative Partner decisions, approved Support email deliveries,
-- and per-member archive preferences. Additive only; existing ticket/report tables untouched.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS partner_program_applications_v80 (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL UNIQUE REFERENCES spaces(id) ON DELETE CASCADE,
  applicant_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','revoked')),
  message TEXT NOT NULL DEFAULT '',
  reviewer_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  review_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_partner_applications_v80_status
  ON partner_program_applications_v80(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS partner_space_status_v80 (
  space_id TEXT PRIMARY KEY REFERENCES spaces(id) ON DELETE CASCADE,
  classification TEXT NOT NULL DEFAULT 'community' CHECK(classification IN ('community','partner','official')),
  verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
  featured INTEGER NOT NULL DEFAULT 0 CHECK(featured IN (0,1)),
  beta INTEGER NOT NULL DEFAULT 0 CHECK(beta IN (0,1)),
  staff_owned INTEGER NOT NULL DEFAULT 0 CHECK(staff_owned IN (0,1)),
  approved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  approved_at INTEGER,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_partner_space_status_v80_classification
  ON partner_space_status_v80(classification, updated_at DESC);

CREATE TABLE IF NOT EXISTS partner_program_events_v80 (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  actor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK(event_type IN ('applied','approved','denied','revoked')),
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_partner_events_v80_space
  ON partner_program_events_v80(space_id, created_at DESC);

CREATE TABLE IF NOT EXISTS support_email_deliveries_v80 (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  ticket_id TEXT,
  template_id TEXT NOT NULL,
  sender_address TEXT NOT NULL,
  dedupe_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('sending','sent','failed')),
  provider_message_id TEXT,
  error_code TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_support_email_v80_actor
  ON support_email_deliveries_v80(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_email_v80_recipient
  ON support_email_deliveries_v80(recipient_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS support_member_case_archives_v80 (
  case_id TEXT NOT NULL REFERENCES support_cases_v77(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  archived_at INTEGER NOT NULL,
  PRIMARY KEY(case_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_member_case_archives_v80_user
  ON support_member_case_archives_v80(user_id, archived_at DESC);
