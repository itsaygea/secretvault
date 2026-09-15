-- 026_proxy_access_tokens.sql
--
-- Short-lived, client-bound bearer credentials for proxy traffic. Only the
-- SHA-256 digest is stored; the raw svt_ credential is returned once by the
-- exchange endpoint and is never logged or persisted.

CREATE TABLE IF NOT EXISTS secretvault.proxy_access_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES secretvault.users(id) ON DELETE CASCADE,
  client_id     UUID NOT NULL REFERENCES secretvault.client_applications(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,
  scopes        TEXT[] NOT NULL DEFAULT '{}',
  key_version   INTEGER NOT NULL,
  session_epoch BIGINT NOT NULL DEFAULT 0,
  expires_at    TIMESTAMPTZ NOT NULL,
  last_used_at  TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS proxy_access_tokens_client_idx
  ON secretvault.proxy_access_tokens (client_id, expires_at);
CREATE INDEX IF NOT EXISTS proxy_access_tokens_expiry_idx
  ON secretvault.proxy_access_tokens (expires_at)
  WHERE revoked_at IS NULL;

ALTER TABLE secretvault.proxy_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE secretvault.proxy_access_tokens FORCE ROW LEVEL SECURITY;

-- Pre-authentication must be able to look up a token digest before the tenant
-- is known. This is an internal auth bootstrap table; the API never exposes a
-- table query and the stored value is a one-way digest.
GRANT SELECT, INSERT, UPDATE, DELETE ON secretvault.proxy_access_tokens TO service_role;
GRANT SELECT, INSERT, UPDATE ON secretvault.proxy_access_tokens TO sv_runtime;

DROP POLICY IF EXISTS proxy_access_tokens_service_role ON secretvault.proxy_access_tokens;
CREATE POLICY proxy_access_tokens_service_role ON secretvault.proxy_access_tokens
  TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS proxy_access_tokens_runtime_tenant ON secretvault.proxy_access_tokens;
CREATE POLICY proxy_access_tokens_runtime_tenant ON secretvault.proxy_access_tokens
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );

REVOKE ALL ON secretvault.proxy_access_tokens FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON secretvault.proxy_access_tokens FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON secretvault.proxy_access_tokens FROM authenticated;
  END IF;
END $$;
