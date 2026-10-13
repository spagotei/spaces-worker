-- V90 applications. Reviewers cannot obtain owner emails from this table;
-- email is resolved only through an authenticated, permission-gated endpoint.
CREATE TABLE IF NOT EXISTS space_program_applications_v90 (
 id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
 owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 program TEXT NOT NULL CHECK(program IN ('verified','partner')),
 statement TEXT NOT NULL,
 public_link TEXT NOT NULL DEFAULT '',
 contact_consent INTEGER NOT NULL CHECK(contact_consent IN (0,1)),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','withdrawn')),
 reviewer_user_id TEXT REFERENCES users(id),
 reviewer_note TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 reviewed_at INTEGER,
 updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_program_apps_v90_queue ON space_program_applications_v90(status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_program_apps_v90_space ON space_program_applications_v90(space_id,program,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_pending_program_v90 ON space_program_applications_v90(space_id,program) WHERE status='pending';
CREATE TABLE IF NOT EXISTS space_program_badges_v90 (
 space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
 program TEXT NOT NULL CHECK(program IN ('verified','partner')),
 approved_by TEXT NOT NULL REFERENCES users(id),
 approved_at INTEGER NOT NULL,
 PRIMARY KEY(space_id,program)
);
