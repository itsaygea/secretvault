-- 027_atomic_session_epoch_bump.sql
--
-- Make session revocation a single row-level UPDATE. The prior read-then-write
-- implementation could lose a concurrent bump and leave a stale token epoch.

CREATE OR REPLACE FUNCTION secretvault.bump_session_epoch(p_user_id UUID)
RETURNS BIGINT
LANGUAGE SQL
AS $$
  UPDATE secretvault.users
     SET session_epoch = session_epoch + 1
   WHERE id = p_user_id
  RETURNING session_epoch
$$;

GRANT EXECUTE ON FUNCTION secretvault.bump_session_epoch(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION secretvault.bump_session_epoch(UUID) TO sv_runtime;
REVOKE EXECUTE ON FUNCTION secretvault.bump_session_epoch(UUID) FROM PUBLIC;
