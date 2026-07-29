-- Complete the access-log contract used by the application and admin viewer.

ALTER TABLE secretvault.access_logs
  ADD COLUMN IF NOT EXISTS outcome TEXT,
  ADD COLUMN IF NOT EXISTS request_id TEXT,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE secretvault.access_logs
SET outcome = COALESCE(outcome, 'succeeded'),
    secret_name = COALESCE(NULLIF(secret_name, ''), 'system');

ALTER TABLE secretvault.access_logs
  ALTER COLUMN outcome SET DEFAULT 'succeeded',
  ALTER COLUMN outcome SET NOT NULL,
  ALTER COLUMN secret_name SET DEFAULT 'system',
  ALTER COLUMN secret_name SET NOT NULL,
  ALTER COLUMN created_at SET NOT NULL;

ALTER TABLE secretvault.access_logs
  ADD CONSTRAINT access_logs_outcome_check
    CHECK (outcome IN ('succeeded', 'failed', 'denied', 'unknown')),
  ADD CONSTRAINT access_logs_secret_name_check
    CHECK (length(trim(secret_name)) > 0);

-- created_at is the canonical event timestamp. The original timestamp column
-- was the source of schema drift and is no longer part of the contract.
DROP INDEX IF EXISTS secretvault.idx_access_logs_timestamp;
ALTER TABLE secretvault.access_logs DROP COLUMN IF EXISTS timestamp;

CREATE INDEX IF NOT EXISTS idx_access_logs_outcome
  ON secretvault.access_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_created_at
  ON secretvault.access_logs(client_id, created_at DESC);
