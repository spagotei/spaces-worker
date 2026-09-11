ALTER TABLE users ADD COLUMN public_user_id TEXT;

-- Founder keeps the reserved, memorable ID. Existing non-Founder users are backfilled from 00020.
UPDATE users
SET public_user_id = '00001'
WHERE platform_role = 'creator';

WITH ranked AS (
  SELECT
    id,
    19 + ROW_NUMBER() OVER (ORDER BY created_at ASC, id ASC) AS public_number
  FROM users
  WHERE platform_role IS NULL OR platform_role <> 'creator'
)
UPDATE users
SET public_user_id = (
  SELECT printf('%05d', ranked.public_number)
  FROM ranked
  WHERE ranked.id = users.id
)
WHERE id IN (SELECT id FROM ranked);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_user_id
  ON users(public_user_id)
  WHERE public_user_id IS NOT NULL;

-- Atomic counter avoids duplicate public IDs if two registrations happen together.
CREATE TABLE IF NOT EXISTS platform_counters (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);

INSERT OR REPLACE INTO platform_counters (key, value)
SELECT
  'public_user_id',
  MAX(
    20,
    COALESCE(
      (SELECT MAX(CAST(public_user_id AS INTEGER)) + 1
       FROM users
       WHERE public_user_id IS NOT NULL
         AND public_user_id GLOB '[0-9]*'),
      20
    )
  );

CREATE TABLE IF NOT EXISTS support_staff_messages (
  id TEXT PRIMARY KEY,
  sender_user_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_support_staff_messages_created
  ON support_staff_messages(created_at DESC);
