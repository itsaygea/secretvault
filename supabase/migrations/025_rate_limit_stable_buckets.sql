-- 025_rate_limit_stable_buckets.sql
--
-- Keep the bucket key stable across fixed windows. This prevents a denial
-- cooldown from disappearing merely because the clock crossed a window
-- boundary, while the counter itself resets for the new window.

CREATE OR REPLACE FUNCTION secretvault.rate_limit_charge(
  p_bucket_key   TEXT,
  p_window_start BIGINT
) RETURNS TABLE (current_count INTEGER, cooldown_until BIGINT)
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO secretvault.rate_limit_buckets (bucket_key, window_start, count, cooldown_until, updated_at)
  VALUES (p_bucket_key, p_window_start, 1, 0, now())
  ON CONFLICT (bucket_key) DO UPDATE
    SET count = CASE
                  WHEN secretvault.rate_limit_buckets.window_start < p_window_start THEN 1
                  ELSE secretvault.rate_limit_buckets.count + 1
                END,
        window_start = GREATEST(secretvault.rate_limit_buckets.window_start, p_window_start),
        updated_at = now()
  RETURNING rate_limit_buckets.count AS current_count,
            rate_limit_buckets.cooldown_until AS cooldown_until
  INTO current_count, cooldown_until;
  RETURN NEXT;
END;
$$;

GRANT EXECUTE ON FUNCTION secretvault.rate_limit_charge(TEXT, BIGINT) TO sv_runtime;
REVOKE EXECUTE ON FUNCTION secretvault.rate_limit_charge(TEXT, BIGINT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION secretvault.rate_limit_reap(BIGINT) FROM PUBLIC;
