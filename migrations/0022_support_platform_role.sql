-- Spaces v48 compatibility:
-- Replace the historical platform_role column without rebuilding users.
-- Keeps all user rows and all foreign-key relationships intact.

ALTER TABLE users
RENAME COLUMN platform_role TO platform_role_legacy;

ALTER TABLE users
ADD COLUMN platform_role TEXT
CHECK (
  platform_role IN ('creator', 'staff', 'support')
  OR platform_role IS NULL
);

UPDATE users
SET platform_role = platform_role_legacy;
