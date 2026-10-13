-- Incoming mail and expanded access audit. Existing V84 delivery history and audit table are preserved.
CREATE TABLE IF NOT EXISTS platform_staff_inbox_v84_3 (
 id TEXT PRIMARY KEY,
 dedupe_key TEXT NOT NULL UNIQUE,
 from_email TEXT NOT NULL,
 from_name TEXT NOT NULL,
 header_from_email TEXT NOT NULL,
 to_email TEXT NOT NULL,
 subject TEXT NOT NULL,
 text_body TEXT NOT NULL,
 received_at INTEGER NOT NULL,
 attachment_count INTEGER NOT NULL DEFAULT 0,
 truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1))
);
CREATE INDEX IF NOT EXISTS idx_staff_inbox_received_v84_3 ON platform_staff_inbox_v84_3(received_at DESC,id DESC);

-- V84.2 limits actions with CHECK. Preserve that table and its records unchanged.
CREATE TABLE IF NOT EXISTS platform_staff_access_audit_v84_3 (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('member_email_lookup','outbound_delivery_history','inbound_email_list','inbound_email_read')),
 row_count INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staff_access_audit_v84_3 ON platform_staff_access_audit_v84_3(created_at DESC);
