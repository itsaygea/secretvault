-- Phase D: Per-Client Identity & Scoped Linking Keys

-- 1. Client Applications Table
CREATE TABLE IF NOT EXISTS secretvault.client_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  app_name TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL,
  key_prefix TEXT NOT NULL,
  scopes TEXT[] DEFAULT '{proxy:*}',
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS client_applications_user_id_idx ON secretvault.client_applications(user_id);
CREATE INDEX IF NOT EXISTS client_applications_key_hash_idx ON secretvault.client_applications(key_hash);

-- 2. Add client_id to access_logs
ALTER TABLE secretvault.access_logs ADD COLUMN IF NOT EXISTS client_id UUID REFERENCES secretvault.client_applications(id) ON DELETE SET NULL;

-- 3. Data Migration: Convert existing user linking keys into initial default client app records
INSERT INTO secretvault.client_applications (user_id, app_name, key_hash, key_prefix)
SELECT id, 'Default Legacy Key', api_key_hash, api_key_prefix
FROM secretvault.users
WHERE api_key_hash IS NOT NULL
ON CONFLICT (key_hash) DO NOTHING;

-- RLS & Grants
ALTER TABLE secretvault.client_applications ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access client_apps" ON secretvault.client_applications FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.client_applications TO service_role;
