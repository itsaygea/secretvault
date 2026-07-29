-- Phase 1: explicit opt-in for private-network egress destinations.
ALTER TABLE secretvault.service_profiles
  ADD COLUMN IF NOT EXISTS allow_private_network BOOLEAN NOT NULL DEFAULT false;

