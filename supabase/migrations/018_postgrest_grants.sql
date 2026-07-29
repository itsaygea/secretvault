-- SV-029: complete PostgREST exposure and least-privilege grants.
--
-- SecretVault queries every table through PostgREST as the `service_role`.
-- Earlier migrations granted service_role on tables they introduced but left
-- gaps that real PostgREST exposes and the CI mock hid:
--   - no USAGE on the `secretvault` schema (PostgREST cannot resolve any table),
--   - no grants on the original `secrets` and `access_logs` tables (001),
--   - no DEFAULT PRIVILEGES, so tables added by later migrations silently lost
--     access until someone remembered to add a GRANT.
--
-- This migration closes those gaps idempotently and pins least-privilege
-- defaults so the database enforces the contract the application assumes,
-- independent of PostgREST's own configuration.

-- 1. The application role must be able to resolve the schema at all.
GRANT USAGE ON SCHEMA secretvault TO service_role;

-- 2. Explicit table grants for every table created so far. Tables with grants
--    in their own migration are listed for completeness and idempotency; the
--    two from 001 (secrets, access_logs) are the actual fix.
GRANT SELECT, INSERT, UPDATE, DELETE
  ON secretvault.secrets,
     secretvault.access_logs,
     secretvault.users,
     secretvault.service_profiles,
     secretvault.webauthn_credentials,
     secretvault.totp_secrets,
     secretvault.client_applications,
     secretvault.system_settings,
     secretvault.totp_pending_enrollments,
     secretvault.totp_backup_codes,
     secretvault.master_key_rotations
  TO service_role;

-- 3. Default privileges: every table created in this schema by any role from
--    now on is automatically readable/writable by service_role without a
--    per-migration GRANT. This is the durable fix, not a one-time patch.
ALTER DEFAULT PRIVILEGES IN SCHEMA secretvault
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service_role;

-- 4. Least privilege: no sequence/foreign-data/object escapes. (Tables use
--    gen_random_uuid(), so there are no sequences today; default-privilege the
--    sequence class anyway so a future SERIAL/identity column is covered.)
ALTER DEFAULT PRIVILEGES IN SCHEMA secretvault
  GRANT USAGE, SELECT ON SEQUENCES TO service_role;

-- 5. Defense in depth. All tables have RLS enabled with a service_role-only
--    policy, so anonymous roles are already blocked at the row level. Revoke
--    the default PUBLIC privileges Postgres grants on new tables so the
--    database does not rely on RLS alone, and so a table that accidentally
--    ships without an RLS policy still cannot be read by untrusted roles.
REVOKE ALL ON SCHEMA secretvault FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA secretvault FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA secretvault
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA secretvault
  REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- 6. Record the schemas PostgREST must expose. There is no runtime setting
--    table for PostgREST's `db-schemas`; document the requirement here so an
--    operator following the migrations knows exactly what to configure. See
--    docs/install.md "PostgREST / Supabase schema exposure".
--    Exposed schemas: `secretvault` only. Never expose `auth`.

-- 7. Fix the two original 001 RLS policies so INSERTs are authorized. The
--    001 policies used `FOR ALL ... USING (...)` without `WITH CHECK`, so
--    Postgres applied no check to new rows for INSERT (USING is ignored on
--    INSERT without WITH CHECK), causing every service-role INSERT into
--    `secrets` and `access_logs` to be rejected by RLS over PostgREST. Every
--    table introduced by a later migration already uses WITH CHECK; this
--    brings the two originals in line. Discovered by the real-PostgREST CI
--    stack (SV-029) — the mock hid it by accepting all inserts.
--    (ALTER POLICY cannot change the command type; it re-applies the USING
--    expression and adds WITH CHECK to the existing FOR ALL policy.)
ALTER POLICY "Service role full access" ON secretvault.secrets
  TO service_role
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

ALTER POLICY "Service role full access" ON secretvault.access_logs
  TO service_role
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

