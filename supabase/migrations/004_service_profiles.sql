-- Phase C: Service profiles for HTTP reverse proxy

CREATE TABLE IF NOT EXISTS secretvault.service_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target_url TEXT NOT NULL,
  auth_method TEXT NOT NULL CHECK (auth_method IN ('basic', 'bearer', 'header', 'cookie')),
  user_secret_name TEXT,
  pass_secret_name TEXT,
  header_name TEXT,
  cookie_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, name)
);

GRANT ALL ON secretvault.service_profiles TO service_role;

ALTER TABLE secretvault.service_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access" ON secretvault.service_profiles FOR ALL USING (true) WITH CHECK (true);
