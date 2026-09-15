-- 028_pre_auth_lookup_functions.sql
--
-- Authentication happens before a tenant JWT exists. Migration 024 therefore
-- cannot grant the global service_role SELECT access to tenant tables just so
-- the application can resolve a linking key or proxy token. These narrowly
-- scoped SECURITY DEFINER functions return only the authentication projection
-- and are executable only by the internal service_role.

CREATE OR REPLACE FUNCTION secretvault.authenticate_linking_key(p_key_hash TEXT)
RETURNS TABLE (
  client_id UUID,
  user_id UUID,
  scopes TEXT[],
  key_version INTEGER,
  username TEXT,
  is_admin BOOLEAN,
  session_epoch BIGINT
)
LANGUAGE SQL
SECURITY DEFINER
SET search_path = secretvault, pg_catalog
AS $$
  SELECT c.id,
         c.user_id,
         c.scopes,
         c.key_version,
         u.username,
         u.is_admin,
         u.session_epoch
    FROM secretvault.client_applications AS c
    JOIN secretvault.users AS u ON u.id = c.user_id
   WHERE c.key_hash = p_key_hash
   LIMIT 1
$$;

CREATE OR REPLACE FUNCTION secretvault.touch_client_application_last_used(
  p_client_id UUID,
  p_last_used_at TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE SQL
SECURITY DEFINER
SET search_path = secretvault, pg_catalog
AS $$
  UPDATE secretvault.client_applications
     SET last_used_at = p_last_used_at
   WHERE id = p_client_id;
$$;

CREATE OR REPLACE FUNCTION secretvault.authenticate_proxy_access_token(p_token_hash TEXT)
RETURNS TABLE (
  token_id UUID,
  user_id UUID,
  client_id UUID,
  token_scopes TEXT[],
  token_key_version INTEGER,
  token_session_epoch BIGINT,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  client_scopes TEXT[],
  client_key_version INTEGER,
  username TEXT,
  is_admin BOOLEAN,
  user_session_epoch BIGINT
)
LANGUAGE SQL
VOLATILE
SECURITY DEFINER
SET search_path = secretvault, pg_catalog
AS $$
  WITH touched AS (
    UPDATE secretvault.proxy_access_tokens AS t
       SET last_used_at = now()
     WHERE t.token_hash = p_token_hash
       AND t.revoked_at IS NULL
       AND t.expires_at > now()
  )
  SELECT t.id,
         t.user_id,
         t.client_id,
         t.scopes,
         t.key_version,
         t.session_epoch,
         t.expires_at,
         t.revoked_at,
         c.scopes,
         c.key_version,
         u.username,
         u.is_admin,
         u.session_epoch
    FROM secretvault.proxy_access_tokens AS t
    JOIN secretvault.client_applications AS c
      ON c.id = t.client_id AND c.user_id = t.user_id
    JOIN secretvault.users AS u ON u.id = t.user_id
   WHERE t.token_hash = p_token_hash
   LIMIT 1
$$;

GRANT EXECUTE ON FUNCTION secretvault.authenticate_linking_key(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION secretvault.touch_client_application_last_used(UUID, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION secretvault.authenticate_proxy_access_token(TEXT) TO service_role;

REVOKE EXECUTE ON FUNCTION secretvault.authenticate_linking_key(TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION secretvault.touch_client_application_last_used(UUID, TIMESTAMPTZ) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION secretvault.authenticate_proxy_access_token(TEXT) FROM PUBLIC;

-- The proxy-token lookup is now performed by the narrow RPC above rather than
-- a global table query. Runtime INSERT/UPDATE access from migration 026 remains
-- available to sv_runtime for token issuance and tenant-scoped operations.
REVOKE SELECT, INSERT, UPDATE, DELETE
  ON secretvault.proxy_access_tokens
  FROM service_role;
