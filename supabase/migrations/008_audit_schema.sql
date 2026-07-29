-- Phase 1: normalize access-log timestamps and make the event contract
-- compatible with both the current application and existing installations.

ALTER TABLE secretvault.access_logs
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;

UPDATE secretvault.access_logs
SET created_at = COALESCE(created_at, timestamp, now())
WHERE created_at IS NULL;

ALTER TABLE secretvault.access_logs
  ALTER COLUMN created_at SET DEFAULT now(),
  ALTER COLUMN created_at SET NOT NULL;

-- Authentication and account events have no secret target. Keep the target
-- column required while giving those events an explicit non-secret value.
ALTER TABLE secretvault.access_logs
  ALTER COLUMN secret_name SET DEFAULT 'system';

CREATE INDEX IF NOT EXISTS idx_access_logs_created_at
  ON secretvault.access_logs(created_at);

