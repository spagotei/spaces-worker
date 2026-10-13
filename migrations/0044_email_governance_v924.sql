-- Spaces V92.4 Founder-controlled email permissions, subscription choices and resumable delivery.
-- Updates are OPT-IN. Critical notices must be genuinely account/service-impacting.
CREATE TABLE IF NOT EXISTS platform_email_grants_v924 (
 user_id TEXT PRIMARY KEY,
 can_view INTEGER NOT NULL DEFAULT 0 CHECK(can_view IN (0,1)),
 can_compose INTEGER NOT NULL DEFAULT 0 CHECK(can_compose IN (0,1)),
 can_send INTEGER NOT NULL DEFAULT 0 CHECK(can_send IN (0,1)),
 can_global_updates INTEGER NOT NULL DEFAULT 0 CHECK(can_global_updates IN (0,1)),
 updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_email_subscriptions_v924 (
 user_id TEXT PRIMARY KEY,
 updates_opt_in INTEGER NOT NULL DEFAULT 0 CHECK(updates_opt_in IN (0,1)),
 unsubscribe_token TEXT NOT NULL UNIQUE,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_email_campaigns_v924 (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('updates','service','critical')),
 sender_key TEXT NOT NULL,
 subject TEXT NOT NULL,
 heading TEXT NOT NULL,
 body TEXT NOT NULL,
 reason TEXT NOT NULL,
 send_id TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL CHECK(status IN ('queued','running','completed')),
 recipient_count INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,
 completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS platform_email_campaign_recipients_v924 (
 campaign_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 recipient_email TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','sending','sent','failed','skipped')),
 provider_message_id TEXT,
 error_code TEXT,
 completed_at INTEGER,
 PRIMARY KEY(campaign_id,user_id),
 UNIQUE(campaign_id,recipient_email)
);
CREATE INDEX IF NOT EXISTS idx_v924_batch ON platform_email_campaign_recipients_v924(campaign_id,status);
CREATE TABLE IF NOT EXISTS platform_email_actions_v924 (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT NOT NULL,
 action TEXT NOT NULL,
 target_user_id TEXT,
 campaign_id TEXT,
 detail TEXT,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_v924_audit_time ON platform_email_actions_v924(created_at DESC);
