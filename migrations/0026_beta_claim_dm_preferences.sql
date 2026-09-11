-- Spaces v59: email-code beta claiming + per-user DM/support thread controls.

CREATE TABLE IF NOT EXISTS beta_claim_challenges (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE,
  code_hash TEXT NOT NULL,
  claim_token_hash TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  verified_at INTEGER,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_beta_claim_email_created
ON beta_claim_challenges(email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_beta_claim_expiry
ON beta_claim_challenges(expires_at);

CREATE TABLE IF NOT EXISTS direct_thread_preferences (
  user_id TEXT NOT NULL,
  thread_kind TEXT NOT NULL
    CHECK (thread_kind IN ('dm', 'group', 'support')),
  thread_id TEXT NOT NULL,
  pinned_at INTEGER,
  muted_until INTEGER,
  closed_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, thread_kind, thread_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_direct_thread_preferences_user
ON direct_thread_preferences(user_id, pinned_at DESC, updated_at DESC);
