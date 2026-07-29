-- CI database bootstrap for SecretVault integration tests.
--
-- Mirrors the role architecture real Supabase/PostgREST uses so the grants
-- and RLS policies the migrations define are exercised against a real API,
-- not a mock that returns empty arrays (SV-029).
--
--   authenticator  - the LOGIN role PostgREST connects as; it can switch into
--                    service_role or anon per request via SET LOCAL ROLE.
--   service_role   - NOLOGIN; the trusted backend role the app uses. Migrations
--                    grant it SELECT/INSERT/UPDATE/DELETE on every table and
--                    USAGE on the secretvault schema.
--   anon           - NOLOGIN; the untrusted role. Must NOT be able to read or
--                    write secretvault data.

CREATE ROLE service_role NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticator LOGIN PASSWORD 'ci-authenticator' IN ROLE service_role, anon;

-- PostgREST resolves request.jwt.claim.role through this function (the same
-- convention the 001 RLS policies rely on via auth.role()).
--
-- Supabase Cloud populates the legacy `request.jwt.claim.role` GUC; standalone
-- PostgREST v12 sets only the `request.jwt.claims` JSON GUC and performs
-- SET LOCAL ROLE directly. Fall back to the effective role so the same RLS
-- policies are exercised faithfully in CI. current_user reflects the role
-- PostgREST switched into for the request (service_role or anon).
CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.role()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user) $$;
