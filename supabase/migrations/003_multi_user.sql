-- Phase B: Multi-user system

-- Users table
CREATE TABLE IF NOT EXISTS secretvault.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL DEFAULT false,
  api_key_hash TEXT UNIQUE,
  api_key_prefix TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Add user_id to secrets
ALTER TABLE secretvault.secrets ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES secretvault.users(id);

-- Add user_id to access_logs
ALTER TABLE secretvault.access_logs ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES secretvault.users(id);

-- Secrets uniqueness becomes per-user (nullable user_id = global secrets for migration)
ALTER TABLE secretvault.secrets DROP CONSTRAINT IF EXISTS secrets_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_name_key ON secretvault.secrets (user_id, name);

-- Disable RLS on users table (service role key bypasses, but explicit is cleaner)
ALTER TABLE secretvault.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access" ON secretvault.users FOR ALL USING (true) WITH CHECK (true);

-- Grant service_role access (the role used by the app via Supabase service key)
GRANT ALL ON secretvault.users TO service_role;
