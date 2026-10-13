-- Aggregated security attempts; no email, IP, password, token, or request body stored.
CREATE TABLE IF NOT EXISTS security_event_counters_v85 (
 event_key TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('login_failed','staff_center_denied')),
 status INTEGER NOT NULL,
 principal_fingerprint TEXT NOT NULL,
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 event_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_security_event_counters_v85_last ON security_event_counters_v85(last_seen DESC);
-- Retention SQL: DELETE FROM security_event_counters_v85 WHERE last_seen < (unixepoch()*1000 - 30*86400000);
