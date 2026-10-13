-- V91.3: staff outgoing one-to-one email delivery audit, no message body storage.
CREATE TABLE IF NOT EXISTS platform_email_external_v913 (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT NOT NULL,
 recipient_email TEXT NOT NULL,
 sender_address TEXT NOT NULL,
 subject TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('sending','sent','failed')),
 send_id TEXT NOT NULL UNIQUE,
 provider_message_id TEXT,
 error_code TEXT,
 created_at INTEGER NOT NULL,
 completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_email_external_v913_actor_time
 ON platform_email_external_v913(actor_user_id,created_at DESC);
