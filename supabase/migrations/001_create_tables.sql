-- Ensure schema exists
CREATE SCHEMA IF NOT EXISTS secretvault;

-- Secrets table
CREATE TABLE IF NOT EXISTS secretvault.secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL,
  environment TEXT NOT NULL DEFAULT 'development',
  encrypted_blob TEXT NOT NULL,
  masked_preview TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_suffix TEXT NOT NULL,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Access logs table
CREATE TABLE IF NOT EXISTS secretvault.access_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id UUID REFERENCES secretvault.secrets(id) ON DELETE SET NULL,
  secret_name TEXT NOT NULL,
  access_type TEXT NOT NULL,
  caller TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secretvault.secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_environment ON secretvault.secrets(environment);
CREATE INDEX IF NOT EXISTS idx_access_logs_secret_id ON secretvault.access_logs(secret_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON secretvault.access_logs(timestamp);

-- Enable RLS
ALTER TABLE secretvault.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secretvault.access_logs ENABLE ROW LEVEL SECURITY;

-- RLS policies: service role has full access
CREATE POLICY "Service role full access" ON secretvault.secrets
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON secretvault.access_logs
  FOR ALL USING (auth.role() = 'service_role');

-- Auto-update updated_at trigger (in the schema)
CREATE OR REPLACE FUNCTION secretvault.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER secrets_updated_at
  BEFORE UPDATE ON secretvault.secrets
  FOR EACH ROW
  EXECUTE FUNCTION secretvault.update_updated_at();
