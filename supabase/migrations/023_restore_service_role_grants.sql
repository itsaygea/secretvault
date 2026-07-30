-- 023_restore_service_role_grants.sql
-- Restore service_role grants and RLS policies for SecretVault application operations.

GRANT ALL ON ALL TABLES IN SCHEMA secretvault TO service_role;
GRANT USAGE ON SCHEMA secretvault TO service_role;

DROP POLICY IF EXISTS "Service role full access access_logs" ON secretvault.access_logs;
CREATE POLICY "Service role full access access_logs" ON secretvault.access_logs TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access secrets" ON secretvault.secrets;
CREATE POLICY "Service role full access secrets" ON secretvault.secrets TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access service_profiles" ON secretvault.service_profiles;
CREATE POLICY "Service role full access service_profiles" ON secretvault.service_profiles TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access client_apps" ON secretvault.client_applications;
CREATE POLICY "Service role full access client_apps" ON secretvault.client_applications TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access webauthn" ON secretvault.webauthn_credentials;
CREATE POLICY "Service role full access webauthn" ON secretvault.webauthn_credentials TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access totp" ON secretvault.totp_secrets;
CREATE POLICY "Service role full access totp" ON secretvault.totp_secrets TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access totp_pending" ON secretvault.totp_pending_enrollments;
CREATE POLICY "Service role full access totp_pending" ON secretvault.totp_pending_enrollments TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access totp_backup" ON secretvault.totp_backup_codes;
CREATE POLICY "Service role full access totp_backup" ON secretvault.totp_backup_codes TO service_role USING (true) WITH CHECK (true);
