-- SV-AUD-011: distributed authentication & step-up rate limits.
--
-- Login, self-registration, first-admin setup, TOTP verification and backup-code
-- consumption were previously unbounded: an attacker could perform unlimited
-- bcrypt work (login/register/setup) or unlimited six-digit / backup-code
-- guessing (TOTP/step-up) against any account. An in-memory limiter existed but
-- was never wired to a handler and was per-process, so it could not enforce
-- across more than one server replica.
--
-- This table is the shared atomic counter every replica increments through the
-- same database. Each limiter check performs an INSERT ... ON CONFLICT DO UPDATE
-- SET count = rate_limit_buckets.count + 1 inside one statement, so concurrent
-- requests from different replicas cannot lose an increment (Postgres row lock
-- serializes the upsert). This is the atomic pattern the session-epoch
-- read-then-write (migration 020) deliberately does NOT use, because an epoch
-- only needs to be monotonic while a counter must be exact.
--
-- Forward-only, idempotent, checksum-safe:
--   * IF NOT EXISTS on every object; re-running is a no-op.
--   * No data is migrated or transformed; dropping the table simply removes
--     rate limiting (every auth attempt is then allowed, as before this change).
--   * Stale buckets are cheaply reaped on each write (upsert resets the row for
--     the current window) and by a periodic cleanup; no background job is
--     required for correctness.
CREATE TABLE IF NOT EXISTS secretvault.rate_limit_buckets (
  -- Composite key in code: "<scope>:<identity>:<windowStartMs>". Stored as the
  -- primary key so the ON CONFLICT upsert has a single, indexed target.
  bucket_key      TEXT        PRIMARY KEY,
  -- Epoch-millis start of the fixed counting window this row belongs to. Kept
  -- denormalized from bucket_key so cooldown/reaping queries need not parse it.
  window_start    BIGINT      NOT NULL,
  -- Number of attempts charged against this bucket in its window.
  count           INTEGER     NOT NULL DEFAULT 1,
  -- Epoch-millis until which the bounded exponential cooldown blocks the
  -- identity at this scope, regardless of a fresh window. 0 = no cooldown.
  cooldown_until  BIGINT      NOT NULL DEFAULT 0,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index reaping: find rows whose window has aged out so a periodic sweep can
-- delete them without a full scan.
CREATE INDEX IF NOT EXISTS rate_limit_buckets_window_start_idx
  ON secretvault.rate_limit_buckets (window_start);

-- Least-privilege grant, mirroring migration 018. DEFAULT PRIVILEGES (set in
-- 018) already covers future tables; the explicit grant documents intent and
-- keeps this migration self-contained.
GRANT SELECT, INSERT, UPDATE, DELETE ON secretvault.rate_limit_buckets TO service_role;

-- Atomic charge primitive. PostgREST's upsert rewrites every column to the
-- supplied values, so it cannot express `count = count + 1`; without that, two
-- concurrent replicas could read the same count and each write count+1, losing
-- an increment and over-allowing. This RPC performs the increment inside one
-- statement: the INSERT ... ON CONFLICT DO UPDATE takes a per-row lock, so
-- concurrent callers (across replicas) are serialized and the returned count is
-- exact. The caller (TypeScript) owns all window/cooldown arithmetic with an
-- injectable clock; this function only does the part that must be atomic.
--
-- Returns (current_count, cooldown_until) for the bucket after charging.
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
    SET count          = secretvault.rate_limit_buckets.count + 1,
        window_start   = GREATEST(secretvault.rate_limit_buckets.window_start, p_window_start),
        updated_at     = now()
  RETURNING rate_limit_buckets.count AS current_count,
            rate_limit_buckets.cooldown_until AS cooldown_until
  INTO current_count, cooldown_until;
  RETURN NEXT;
END;
$$;

-- Reaping: remove buckets whose window has aged past a supplied horizon. Called
-- opportunistically by the server on a small fraction of charges so the table
-- stays bounded without a separate background job. Safe to call rarely or never.
CREATE OR REPLACE FUNCTION secretvault.rate_limit_reap(p_before_window_start BIGINT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  DELETE FROM secretvault.rate_limit_buckets WHERE window_start < p_before_window_start;
END;
$$;

-- Functions are callable through PostgREST by the service role (which has
-- EXECUTE by default on SECURITY INVOKER functions in the granted schema).
GRANT EXECUTE ON FUNCTION secretvault.rate_limit_charge(TEXT, BIGINT) TO service_role;
GRANT EXECUTE ON FUNCTION secretvault.rate_limit_reap(BIGINT) TO service_role;
