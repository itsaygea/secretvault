export interface Secret {
  id: string;
  name: string;
  environment: string;
  encrypted_blob: string;
  masked_preview: string;
  key_prefix: string;
  key_suffix: string;
  created_at: Date;
  updated_at: Date;
  tags: string[];
}

export interface SecretReference {
  name: string;
  reference: string;
  masked: string;
  environment: string;
  tags: string[];
}

export interface AccessLog {
  id: string;
  secret_id: string | null;
  secret_name: string;
  access_type: string;
  caller: string;
  user_id: string | null;
  client_id: string | null;
  created_at: Date;
  outcome: "succeeded" | "failed" | "denied" | "unknown";
  request_id: string | null;
  metadata: Record<string, unknown>;
}

export interface CreateSecretInput {
  name: string;
  value: string;
  environment?: string;
  tags?: string[];
}

export interface SecretVaultConfig {
  supabaseUrl: string;
  supabaseKey: string;
  masterKey: string;
}

export interface User {
  id: string;
  username: string;
  is_admin: boolean;
  api_key_prefix: string | null;
  created_at: string;
}
