-- V85: call completion history and exact answer timestamp. No media or SDP is stored here.
ALTER TABLE voice_dm_calls_v81 ADD COLUMN connected_at INTEGER;
CREATE TABLE IF NOT EXISTS voice_dm_events_v85 (
 call_id TEXT PRIMARY KEY,
 conversation_id TEXT NOT NULL,
 caller_user_id TEXT NOT NULL,
 callee_user_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('missed','declined','ended')),
 duration_seconds INTEGER NOT NULL DEFAULT 0 CHECK(duration_seconds>=0 AND duration_seconds<=7200),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(conversation_id) REFERENCES direct_conversations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_voice_dm_events_conversation_v85 ON voice_dm_events_v85(conversation_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_voice_dm_events_callee_v85 ON voice_dm_events_v85(callee_user_id,kind,created_at DESC);
