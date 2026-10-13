-- Spaces V81.2: authenticated 1:1 DM call signaling. No media is stored here.
CREATE TABLE IF NOT EXISTS voice_dm_calls_v81 (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  caller_user_id TEXT NOT NULL,
  callee_user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ringing','active','ended')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(conversation_id) REFERENCES direct_conversations(id) ON DELETE CASCADE,
  FOREIGN KEY(caller_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(callee_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_voice_dm_expires_v81 ON voice_dm_calls_v81(expires_at);
CREATE INDEX IF NOT EXISTS idx_voice_dm_caller_v81 ON voice_dm_calls_v81(caller_user_id,status,expires_at);
CREATE INDEX IF NOT EXISTS idx_voice_dm_callee_v81 ON voice_dm_calls_v81(callee_user_id,status,expires_at);
CREATE TABLE IF NOT EXISTS voice_dm_signals_v81 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  call_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL,
  target_user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('offer','answer','ice','decline','hangup')),
  payload TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(call_id) REFERENCES voice_dm_calls_v81(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_voice_dm_signals_target_v81 ON voice_dm_signals_v81(call_id,target_user_id,id);
