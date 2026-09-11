CREATE TABLE IF NOT EXISTS account_space_dm_preferences (
  user_id TEXT NOT NULL,
  space_id TEXT NOT NULL,
  allow_dms INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, space_id)
);

CREATE TABLE IF NOT EXISTS direct_conversations (
  id TEXT PRIMARY KEY,
  user_low_id TEXT NOT NULL,
  user_high_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  source_space_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (user_low_id, user_high_id)
);

CREATE INDEX IF NOT EXISTS idx_direct_conversations_low ON direct_conversations(user_low_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_direct_conversations_high ON direct_conversations(user_high_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_direct_conversations_status ON direct_conversations(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS direct_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_direct_messages_conversation ON direct_messages(conversation_id, created_at ASC);
