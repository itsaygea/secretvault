-- SV-055: Master key rotation checkpoint state table

CREATE TABLE IF NOT EXISTS secretvault.master_key_rotations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status TEXT NOT NULL DEFAULT 'in_progress',
  processed_secrets INTEGER NOT NULL DEFAULT 0,
  processed_clients INTEGER NOT NULL DEFAULT 0,
  processed_totp INTEGER NOT NULL DEFAULT 0,
  processed_pending_totp INTEGER NOT NULL DEFAULT 0,
  old_key_id TEXT,
  new_key_id TEXT,
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

ALTER TABLE secretvault.master_key_rotations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access master_key_rotations" ON secretvault.master_key_rotations;
CREATE POLICY "Service role full access master_key_rotations"
  ON secretvault.master_key_rotations FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.master_key_rotations TO service_role;
