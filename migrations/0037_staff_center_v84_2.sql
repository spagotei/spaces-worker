-- SPACES_V84_2 STAFF CENTER: read audit. No changes to accounts or previous emails.
CREATE TABLE IF NOT EXISTS platform_staff_access_audit_v84_2 (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('member_email_lookup','outbound_delivery_history')),
  row_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_platform_staff_access_v84_2 ON platform_staff_access_audit_v84_2(actor_user_id,created_at DESC);
