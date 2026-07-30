-- SV-AUD-002: session revocation epoch for stateless session tokens.
--
-- Session tokens are stateless HMAC-signed values (userId.epoch.ts.nonce.sig)
-- with no server-side session store. There is therefore no row to DELETE when a
-- user's authentication factors change. To make "revoke all older sessions after
-- factor replacement / removal" enforceable, every user carries a monotonically
-- increasing `session_epoch` that is folded into the token signature and checked
-- on validation. A factor change bumps the epoch; any token minted under a prior
-- epoch then fails signature validation and is rejected.
--
-- Forward-only, idempotent: existing tokens carry the implicit epoch 0 (handled
-- in code by treating a NULL/absent epoch as 0), and every existing row is
-- backfilled to 0 so the epoch check is uniform from cutover forward. No data is
-- lost and no rollback is required: if the epoch is removed the validator simply
-- stops checking it.
ALTER TABLE secretvault.users
  ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 0;

-- Backfill: make the implicit epoch-0 explicit for every existing user.
UPDATE secretvault.users SET session_epoch = 0 WHERE session_epoch IS NULL;

-- Index the epoch only where it is read: the auth path loads one user row by id
-- (already indexed by the primary key), so no additional index is required.
