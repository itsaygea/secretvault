-- 029_revoke_residual_service_role_privileges.sql
--
-- Migrations 022/024 removed service_role data access from tenant tables by
-- revoking the four DML privileges. Earlier GRANT ALL statements can still
-- leave residual TRUNCATE, REFERENCES, or TRIGGER privileges behind. The
-- service_role must use the narrow pre-auth RPCs instead of having any direct
-- tenant-table privilege.

REVOKE ALL
  ON secretvault.secrets,
     secretvault.access_logs,
     secretvault.service_profiles,
     secretvault.client_applications,
     secretvault.webauthn_credentials,
     secretvault.totp_secrets,
     secretvault.totp_pending_enrollments,
     secretvault.totp_backup_codes,
     secretvault.proxy_access_tokens
  FROM service_role;
