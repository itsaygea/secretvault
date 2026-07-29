-- Phase E: System Settings & Registration Control

CREATE TABLE IF NOT EXISTS secretvault.system_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID REFERENCES secretvault.users(id) ON DELETE SET NULL
);

-- Seed default configuration
INSERT INTO secretvault.system_settings (key, value)
VALUES ('open_registration_enabled', 'false'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- RLS & Grants
ALTER TABLE secretvault.system_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access system_settings" ON secretvault.system_settings FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.system_settings TO service_role;
