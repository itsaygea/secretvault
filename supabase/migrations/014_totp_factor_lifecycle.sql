-- SV-013/014/015: Safe TOTP replacement, backup-code rows, pending enrollment

-- 1. Short-lived pending enrollment (does not touch verified factor)
CREATE TABLE IF NOT EXISTS secretvault.totp_pending_enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  secret_encrypted TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS totp_pending_enrollments_expires_at_idx
  ON secretvault.totp_pending_enrollments(expires_at);

ALTER TABLE secretvault.totp_pending_enrollments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access totp_pending" ON secretvault.totp_pending_enrollments;
CREATE POLICY "Service role full access totp_pending"
  ON secretvault.totp_pending_enrollments FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.totp_pending_enrollments TO service_role;

-- 2. One row per backup code for atomic compare-and-delete consumption
CREATE TABLE IF NOT EXISTS secretvault.totp_backup_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS totp_backup_codes_user_id_idx
  ON secretvault.totp_backup_codes(user_id);

ALTER TABLE secretvault.totp_backup_codes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access totp_backup" ON secretvault.totp_backup_codes;
CREATE POLICY "Service role full access totp_backup"
  ON secretvault.totp_backup_codes FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.totp_backup_codes TO service_role;

-- 3. Migrate legacy array hashes into rows (best-effort; hashes remain valid)
INSERT INTO secretvault.totp_backup_codes (user_id, code_hash)
SELECT t.user_id, unnest(t.backup_codes)
FROM secretvault.totp_secrets t
WHERE t.backup_codes IS NOT NULL
  AND cardinality(t.backup_codes) > 0
  AND NOT EXISTS (
    SELECT 1 FROM secretvault.totp_backup_codes b WHERE b.user_id = t.user_id
  );

-- 4. Drop legacy array column after migration
ALTER TABLE secretvault.totp_secrets DROP COLUMN IF EXISTS backup_codes;
