-- 024_reinstate_tenant_isolation.sql
--
-- Migration 023 was a compatibility rollback that restored broad service_role
-- policies. That re-opened the exact cross-tenant failure mode addressed by
-- migration 022. Keep the historical migration immutable, then remove only
-- the broad policies and grants here so the sv_runtime tenant boundary is
-- active again.

DROP POLICY IF EXISTS "Service role full access access_logs" ON secretvault.access_logs;
DROP POLICY IF EXISTS "Service role full access secrets" ON secretvault.secrets;
DROP POLICY IF EXISTS "Service role full access service_profiles" ON secretvault.service_profiles;
DROP POLICY IF EXISTS "Service role full access client_apps" ON secretvault.client_applications;
DROP POLICY IF EXISTS "Service role full access webauthn" ON secretvault.webauthn_credentials;
DROP POLICY IF EXISTS "Service role full access totp" ON secretvault.totp_secrets;
DROP POLICY IF EXISTS "Service role full access totp_pending" ON secretvault.totp_pending_enrollments;
DROP POLICY IF EXISTS "Service role full access totp_backup" ON secretvault.totp_backup_codes;

REVOKE SELECT, INSERT, UPDATE, DELETE
  ON secretvault.secrets,
     secretvault.access_logs,
     secretvault.service_profiles,
     secretvault.client_applications,
     secretvault.webauthn_credentials,
     secretvault.totp_secrets,
     secretvault.totp_pending_enrollments,
     secretvault.totp_backup_codes
  FROM service_role;

-- Authenticated application routes still need to read and mutate the current
-- user's account row after the tenant JWT is installed. Keep the global
-- service_role policy for pre-auth username lookups, but give sv_runtime only
-- the current tenant (or all rows for an admin).
ALTER TABLE secretvault.users FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON secretvault.users TO sv_runtime;
DROP POLICY IF EXISTS users_runtime_tenant_access ON secretvault.users;
CREATE POLICY users_runtime_tenant_access ON secretvault.users
  TO sv_runtime
  USING (
    secretvault.current_is_admin()
    OR id::text = secretvault.current_tenant_id()
  )
  WITH CHECK (
    secretvault.current_is_admin()
    OR id::text = secretvault.current_tenant_id()
  );

-- Admin settings are also reached after tenant context is installed. They are
-- not tenant data, so sv_runtime may access them only when the signed internal
-- claim identifies an admin; public settings continue to use service_role on
-- the pre-auth path.
ALTER TABLE secretvault.system_settings FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE ON secretvault.system_settings TO sv_runtime;
DROP POLICY IF EXISTS system_settings_admin_runtime ON secretvault.system_settings;
CREATE POLICY system_settings_admin_runtime ON secretvault.system_settings
  TO sv_runtime
  USING (secretvault.current_is_admin())
  WITH CHECK (secretvault.current_is_admin());
