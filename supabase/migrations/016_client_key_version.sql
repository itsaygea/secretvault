-- SV-016: make client-key regeneration atomic and concurrency-safe.
--
-- A monotonically increasing key_version lets the regenerate handler perform a
-- conditional UPDATE keyed on the version it read, so two concurrent
-- regenerations cannot both succeed: the second sees the version has moved and
-- its generated key is never persisted, which means at most one key is valid at
-- any time and a retry never leaves two live keys.

ALTER TABLE secretvault.client_applications
  ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;
