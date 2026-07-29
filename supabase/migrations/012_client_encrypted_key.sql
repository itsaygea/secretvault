-- Phase E: Client Application Encrypted Key Storage for Secure UI Reveal & Regeneration

ALTER TABLE secretvault.client_applications ADD COLUMN IF NOT EXISTS encrypted_key TEXT;
