-- Phase 013: Fix per-user secret uniqueness index, legacy ownership backfill, and user deletion foreign keys

-- 1. Drop the legacy global standalone unique index if it exists
DROP INDEX IF EXISTS secretvault.secrets_name_key;

-- 2. Backfill unowned legacy secrets (user_id IS NULL) to the primary administrator
DO $$
DECLARE
  primary_admin_id UUID;
BEGIN
  SELECT id INTO primary_admin_id FROM secretvault.users WHERE is_admin = true ORDER BY created_at ASC LIMIT 1;
  IF primary_admin_id IS NOT NULL THEN
    UPDATE secretvault.secrets SET user_id = primary_admin_id WHERE user_id IS NULL;
  END IF;
END $$;

-- 3. Re-create per-user unique index on (user_id, name)
CREATE UNIQUE INDEX IF NOT EXISTS secrets_user_id_name_idx ON secretvault.secrets (user_id, name);

-- 4. Update foreign key constraints on secrets and access_logs for clean lifecycle cascades
ALTER TABLE secretvault.secrets DROP CONSTRAINT IF EXISTS secrets_user_id_fkey;
ALTER TABLE secretvault.secrets ADD CONSTRAINT secrets_user_id_fkey FOREIGN KEY (user_id) REFERENCES secretvault.users(id) ON DELETE CASCADE;

ALTER TABLE secretvault.access_logs DROP CONSTRAINT IF EXISTS access_logs_user_id_fkey;
ALTER TABLE secretvault.access_logs ADD CONSTRAINT access_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES secretvault.users(id) ON DELETE SET NULL;
