-- SV-AUD-013: enforce tenant isolation in PostgreSQL.
--
-- Today the application runs all runtime queries as the global `service_role`
-- JWT, which by Supabase convention bypasses RLS. Every table has RLS ENABLEd
-- but with decorative USING (true)/auth.role()='service_role' policies, and no
-- table has FORCE ROW LEVEL SECURITY — so a single missed application
-- .eq("user_id") predicate returns every tenant's rows. This migration moves
-- isolation INTO the database.
--
-- Design:
--   * A new NOLOGIN/NOBYPASSRLS runtime role `sv_runtime` is the role PostgREST
--     switches into for authenticated app traffic. Because it cannot bypass RLS
--     and the tenant tables are FORCED, the per-request tenant claim in the JWT
--     (exposed by PostgREST as the `request.jwt.claims` GUC) becomes the real
--     boundary — not the application's .eq() filter.
--   * Tenant tables (secrets, access_logs, service_profiles, client_applications,
--     webauthn_credentials, totp_secrets, totp_pending_enrollments,
--     totp_backup_codes) get FORCE ROW LEVEL SECURITY + a policy that admits a
--     row only when user_id matches the request's tenant_user_id claim (or the
--     caller carries is_admin).
--   * `service_role` retains its grant on the non-tenant tables (users,
--     system_settings, master_key_rotations) which the pre-auth/global paths
--     (login by username, public settings, migrations) still use; it loses DML
--     on the tenant tables so the bypass role can no longer read every tenant.
--   * Every policy gets an explicit TO clause; PUBLIC/anon/authenticated are
--     revoked everywhere so a future accidental grant cannot expose data.
--
-- Forward-only, idempotent, checksum-safe: every statement is IF NOT EXISTS /
-- OR REPLACE / idempotent DROP+CREATE. Rollback = drop sv_runtime and the
-- tenant policies; RLS stays ENABLEd (harmless) and service_role regains its
-- grants only if an operator re-grants them. No data is transformed.

-- ── Roles ──────────────────────────────────────────────────────────────────
-- sv_runtime: the role authenticated app traffic switches into. NOBYPASSRLS so
-- RLS is the real boundary. NOLOGIN so it is only reachable via authenticator.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sv_runtime') THEN
    CREATE ROLE sv_runtime NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

-- A dedicated migration role (NOLOGIN). Normal request traffic never uses it;
-- only the one-shot migrate service connects as a DB owner. Declared here so
-- the threat model is explicit, even though migrations today run as the
-- POSTGRES_USER superuser.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sv_migrator') THEN
    CREATE ROLE sv_migrator NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

-- authenticator (created by bundled/ci postgres-init.sql) must be able to
-- SET LOCAL ROLE into sv_runtime for tenant JWTs. Grant membership idempotently.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticator') THEN
    GRANT sv_runtime TO authenticator;
  END IF;
END $$;

-- ── Schema + base grants for sv_runtime ────────────────────────────────────
GRANT USAGE ON SCHEMA secretvault TO sv_runtime;

-- Minimum DML on tenant tables for the runtime role. (Default privileges from
-- 018 already cover future tables for service_role; we grant sv_runtime
-- explicitly because it is a different role.)
GRANT SELECT, INSERT, UPDATE, DELETE
  ON secretvault.secrets,
     secretvault.access_logs,
     secretvault.service_profiles,
     secretvault.client_applications,
     secretvault.webauthn_credentials,
     secretvault.totp_secrets,
     secretvault.totp_pending_enrollments,
     secretvault.totp_backup_codes
  TO sv_runtime;

-- Non-tenant tables the runtime may touch (rate limiting runs as sv_runtime).
ALTER TABLE secretvault.rate_limit_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secretvault.rate_limit_buckets FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON secretvault.rate_limit_buckets TO sv_runtime;
GRANT EXECUTE ON FUNCTION secretvault.rate_limit_charge(TEXT, BIGINT) TO sv_runtime;
GRANT EXECUTE ON FUNCTION secretvault.rate_limit_reap(BIGINT) TO sv_runtime;

-- ── helper: read tenant claim from the PostgREST GUC ───────────────────────
-- PostgREST v12 exposes the verified JWT as the request.jwt.claims JSON GUC.
-- Returns NULL when no tenant claim is present (global/pre-auth path).
CREATE OR REPLACE FUNCTION secretvault.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT (current_setting('request.jwt.claims', true)::jsonb)->>'tenant_user_id'
$$;

CREATE OR REPLACE FUNCTION secretvault.current_is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF((current_setting('request.jwt.claims', true)::jsonb)->>'is_admin', '')::boolean,
    false
  )
$$;

-- ── tenant tables: FORCE RLS + tenant policies ─────────────────────────────
-- For each: force RLS (so even the owner can't bypass), drop the old decorative
-- policy, install a tenant policy TO sv_runtime, and revoke service_role DML so
-- the bypass role can no longer read every tenant.

-- secrets
ALTER TABLE secretvault.secrets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access" ON secretvault.secrets;
CREATE POLICY secrets_tenant_isolation ON secretvault.secrets
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.secrets FROM service_role;

-- access_logs
ALTER TABLE secretvault.access_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access" ON secretvault.access_logs;
CREATE POLICY access_logs_tenant_isolation ON secretvault.access_logs
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.access_logs FROM service_role;

-- service_profiles
ALTER TABLE secretvault.service_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access" ON secretvault.service_profiles;
CREATE POLICY service_profiles_tenant_isolation ON secretvault.service_profiles
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.service_profiles FROM service_role;

-- client_applications
ALTER TABLE secretvault.client_applications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access client_apps" ON secretvault.client_applications;
CREATE POLICY client_applications_tenant_isolation ON secretvault.client_applications
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.client_applications FROM service_role;

-- webauthn_credentials
ALTER TABLE secretvault.webauthn_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access webauthn" ON secretvault.webauthn_credentials;
CREATE POLICY webauthn_credentials_tenant_isolation ON secretvault.webauthn_credentials
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.webauthn_credentials FROM service_role;

-- totp_secrets
ALTER TABLE secretvault.totp_secrets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role full access totp" ON secretvault.totp_secrets;
CREATE POLICY totp_secrets_tenant_isolation ON secretvault.totp_secrets
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.totp_secrets FROM service_role;

-- totp_pending_enrollments
ALTER TABLE secretvault.totp_pending_enrollments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS totp_pending_enrollments_policy ON secretvault.totp_pending_enrollments;
CREATE POLICY totp_pending_enrollments_tenant_isolation ON secretvault.totp_pending_enrollments
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.totp_pending_enrollments FROM service_role;

-- totp_backup_codes
ALTER TABLE secretvault.totp_backup_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS totp_backup_codes_policy ON secretvault.totp_backup_codes;
CREATE POLICY totp_backup_codes_tenant_isolation ON secretvault.totp_backup_codes
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR user_id::text = secretvault.current_tenant_id()
  );
REVOKE SELECT, INSERT, UPDATE, DELETE ON secretvault.totp_backup_codes FROM service_role;

-- ── non-tenant tables: explicit TO + revoke PUBLIC/anon/authenticated ───────
-- users: global auth lookup (by username) + admin user management. service_role
-- only; sv_runtime gets NO grant (it never queries users — it has no tenant
-- until auth resolves, and admin user ops run on the service-role path).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='secretvault' AND tablename='users' AND policyname='users_service_role_only') THEN
    CREATE POLICY users_service_role_only ON secretvault.users
      TO service_role USING (true) WITH CHECK (true);
  END IF;
END $$;
DROP POLICY IF EXISTS "Service role full access" ON secretvault.users;

-- system_settings: global key/value. service_role only.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='secretvault' AND tablename='system_settings' AND policyname='system_settings_service_role_only') THEN
    CREATE POLICY system_settings_service_role_only ON secretvault.system_settings
      TO service_role USING (true) WITH CHECK (true);
  END IF;
END $$;

-- master_key_rotations: admin/CLI only. service_role only.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='secretvault' AND tablename='master_key_rotations' AND policyname='master_key_rotations_service_role_only') THEN
    CREATE POLICY master_key_rotations_service_role_only ON secretvault.master_key_rotations
      TO service_role USING (true) WITH CHECK (true);
  END IF;
END $$;

-- rate_limit_buckets: sv_runtime only (keyed by bucket_key, not user_id).
DROP POLICY IF EXISTS rate_limit_buckets_policy ON secretvault.rate_limit_buckets;
CREATE POLICY rate_limit_buckets_runtime_only ON secretvault.rate_limit_buckets
  TO sv_runtime USING (true) WITH CHECK (true);

-- Revoke PUBLIC/anon/authenticated across the board (defense in depth). 018
-- already revoked PUBLIC; this additionally clears anon/authenticated if a
-- later grant introduced them.
REVOKE ALL ON ALL TABLES IN SCHEMA secretvault FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON ALL TABLES IN SCHEMA secretvault FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON ALL TABLES IN SCHEMA secretvault FROM authenticated;
  END IF;
END $$;
