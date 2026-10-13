-- Spaces V84 Email Studio: bulk-send audit, opt-out and idempotent campaigns.
-- Never store email body; audit metadata only.
CREATE TABLE IF NOT EXISTS platform_email_campaigns_v84 (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT NOT NULL,
 audience TEXT NOT NULL CHECK (audience IN ('self','selected','platform_staff','beta_members')),
 recipient_count INTEGER NOT NULL CHECK (recipient_count BETWEEN 1 AND 20),
 subject TEXT NOT NULL,
 send_id TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_platform_email_campaigns_actor_v84 ON platform_email_campaigns_v84(actor_user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS platform_email_deliveries_v84 (
 id TEXT PRIMARY KEY,
 campaign_id TEXT NOT NULL REFERENCES platform_email_campaigns_v84(id),
 actor_user_id TEXT NOT NULL,
 recipient_user_id TEXT NOT NULL,
 recipient_email TEXT NOT NULL,
 sender_address TEXT NOT NULL,
 subject TEXT NOT NULL,
 send_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('sending','sent','failed')),
 provider_message_id TEXT,
 error_code TEXT,
 created_at INTEGER NOT NULL,
 completed_at INTEGER,
 UNIQUE(campaign_id,recipient_user_id)
);
CREATE INDEX IF NOT EXISTS idx_platform_email_deliveries_actor_v84 ON platform_email_deliveries_v84(actor_user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS platform_email_preferences_v84 (
 user_id TEXT PRIMARY KEY,
 token TEXT NOT NULL UNIQUE,
 opted_out INTEGER NOT NULL DEFAULT 0 CHECK(opted_out IN (0,1)),
 updated_at INTEGER NOT NULL
);
