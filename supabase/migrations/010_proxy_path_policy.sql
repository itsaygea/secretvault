-- Phase 1: constrain proxy operations per service profile.
ALTER TABLE secretvault.service_profiles
  ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] NOT NULL DEFAULT '{GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS}',
  ADD COLUMN IF NOT EXISTS allowed_path_prefixes TEXT[] NOT NULL DEFAULT '{/}';

