-- Phase C: Step-Up Authentication (WebAuthn / Passkeys & TOTP)

-- 1. WebAuthn Passkey Credentials Table
CREATE TABLE IF NOT EXISTS secretvault.webauthn_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  transports TEXT[] DEFAULT '{}',
  device_name TEXT NOT NULL DEFAULT 'Passkey',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_user_id_idx ON secretvault.webauthn_credentials(user_id);

-- 2. TOTP Secrets Table
CREATE TABLE IF NOT EXISTS secretvault.totp_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  secret_encrypted TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  backup_codes TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS & Grants
ALTER TABLE secretvault.webauthn_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access webauthn" ON secretvault.webauthn_credentials FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.webauthn_credentials TO service_role;

ALTER TABLE secretvault.totp_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access totp" ON secretvault.totp_secrets FOR ALL USING (true) WITH CHECK (true);
GRANT ALL ON secretvault.totp_secrets TO service_role;
