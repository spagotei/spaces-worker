-- Spaces v5.4.1 — private beta access gate
-- Access is deliberately NOT a role. Space roles remain independent.

ALTER TABLE users
ADD COLUMN spaces_access INTEGER NOT NULL DEFAULT 0
CHECK (spaces_access IN (0, 1));

-- Preserve access for the existing platform owner/founder and staff.
UPDATE users
SET spaces_access = 1
WHERE platform_role IN ('creator', 'staff');

INSERT OR REPLACE INTO platform_updates
  (version, published_at, title, changes_json, created_by, updated_at)
SELECT
  '0.5.4.1',
  CAST(strftime('%s','now') AS INTEGER) * 1000,
  'Private Spaces development',
  '["Closed public account registration","Added private access gate","Platform Creator is now presented as Founder"]',
  id,
  CAST(strftime('%s','now') AS INTEGER) * 1000
FROM users
WHERE platform_role = 'creator'
ORDER BY created_at ASC
LIMIT 1;
