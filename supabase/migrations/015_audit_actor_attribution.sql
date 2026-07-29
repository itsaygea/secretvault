-- SV-017 / SV-044: complete audit actor attribution and queryable filters.
--
-- Add immutable actor display snapshot + structured source metadata so audit
-- rows remain interpretable after the referenced user/client is deleted, and
-- add the composite indexes that cursor pagination + filtered reads require.

ALTER TABLE secretvault.access_logs
  ADD COLUMN IF NOT EXISTS actor_username TEXT,
  ADD COLUMN IF NOT EXISTS source_ip TEXT,
  ADD COLUMN IF NOT EXISTS source_user_agent TEXT;

-- Backfill immutable actor snapshots from the users table where the link still
-- exists. Rows whose user_id was already nullified on user delete stay null,
-- which is the desired "no surviving identity" signal for historical rows.
UPDATE secretvault.access_logs AS a
SET actor_username = u.username
FROM secretvault.users AS u
WHERE a.user_id = u.id AND a.actor_username IS NULL;

-- Cursor pagination reads are always (user_id, created_at DESC) or
-- (client_id, created_at DESC) ordered. These composites cover both the filter
-- and the ordering in a single index scan.
CREATE INDEX IF NOT EXISTS idx_access_logs_user_created_at
  ON secretvault.access_logs (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_access_logs_access_type_created_at
  ON secretvault.access_logs (access_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_access_logs_secret_name_created_at
  ON secretvault.access_logs (secret_name, created_at DESC);
