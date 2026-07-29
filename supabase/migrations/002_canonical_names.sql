-- Phase A: Case-insensitive canonical names
-- Adds display_name to preserve original casing, lowercases name for canonical form

-- Add display_name column (preserves original casing for UI)
ALTER TABLE secretvault.secrets ADD COLUMN IF NOT EXISTS display_name TEXT;

-- Backfill: copy current name to display_name, then lowercase name
UPDATE secretvault.secrets SET display_name = name WHERE display_name IS NULL;
UPDATE secretvault.secrets SET name = LOWER(name);

-- Rebuild unique index on canonical (lowercase) name
ALTER TABLE secretvault.secrets DROP CONSTRAINT IF EXISTS secrets_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_name_key ON secretvault.secrets (name);

-- Index for prefix-based lookups (everything before first underscore)
CREATE INDEX IF NOT EXISTS idx_secrets_prefix
  ON secretvault.secrets (split_part(name, '_', 1));
