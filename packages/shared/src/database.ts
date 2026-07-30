export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export interface Database {
  secretvault: {
    Tables: {
      secrets: {
        Row: {
          id: string;
          name: string;
          display_name: string | null;
          user_id: string | null;
          environment: string;
          encrypted_blob: string;
          masked_preview: string;
          key_prefix: string;
          key_suffix: string;
          tags: string[];
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          display_name?: string | null;
          user_id?: string | null;
          environment?: string;
          encrypted_blob: string;
          masked_preview: string;
          key_prefix: string;
          key_suffix: string;
          tags?: string[];
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          name?: string;
          display_name?: string | null;
          user_id?: string | null;
          environment?: string;
          encrypted_blob?: string;
          masked_preview?: string;
          key_prefix?: string;
          key_suffix?: string;
          tags?: string[];
          created_at?: string;
          updated_at?: string;
        };
        Relationships: [];
      };
      access_logs: {
        Row: {
          id: string;
          secret_id: string | null;
          secret_name: string;
          access_type: string;
          caller: string;
          user_id: string | null;
          client_id: string | null;
          created_at: string;
          outcome: "succeeded" | "failed" | "denied" | "unknown";
          request_id: string | null;
          metadata: Json;
          actor_username: string | null;
          source_ip: string | null;
          source_user_agent: string | null;
        };
        Insert: {
          id?: string;
          secret_id?: string | null;
          secret_name: string;
          access_type: string;
          caller: string;
          user_id?: string | null;
          client_id?: string | null;
          created_at?: string;
          outcome?: "succeeded" | "failed" | "denied" | "unknown";
          request_id?: string | null;
          metadata?: Json;
          actor_username?: string | null;
          source_ip?: string | null;
          source_user_agent?: string | null;
        };
        Update: {
          id?: string;
          secret_id?: string | null;
          secret_name?: string;
          access_type?: string;
          caller?: string;
          user_id?: string | null;
          client_id?: string | null;
          created_at?: string;
          outcome?: "succeeded" | "failed" | "denied" | "unknown";
          request_id?: string | null;
          metadata?: Json;
          actor_username?: string | null;
          source_ip?: string | null;
          source_user_agent?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "access_logs_secret_id_fkey";
            columns: ["secret_id"];
            isOneToOne: false;
            referencedRelation: "secrets";
            referencedColumns: ["id"];
          },
        ];
      };
      users: {
        Row: {
          id: string;
          username: string;
          password_hash: string;
          is_admin: boolean;
          api_key_hash: string | null;
          api_key_prefix: string | null;
          session_epoch: number;
          created_at: string;
        };
        Insert: {
          id?: string;
          username: string;
          password_hash: string;
          is_admin?: boolean;
          api_key_hash?: string | null;
          api_key_prefix?: string | null;
          session_epoch?: number;
          created_at?: string;
        };
        Update: {
          id?: string;
          username?: string;
          password_hash?: string;
          is_admin?: boolean;
          api_key_hash?: string | null;
          api_key_prefix?: string | null;
          session_epoch?: number;
          created_at?: string;
        };
        Relationships: [];
      };
      service_profiles: {
        Row: {
          id: string;
          user_id: string;
          name: string;
          target_url: string;
          auth_method: string;
          user_secret_name: string | null;
          pass_secret_name: string | null;
          header_name: string | null;
          cookie_name: string | null;
          allow_private_network: boolean;
          allowed_methods: string[];
          allowed_path_prefixes: string[];
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          name: string;
          target_url: string;
          auth_method: string;
          user_secret_name?: string | null;
          pass_secret_name?: string | null;
          header_name?: string | null;
          cookie_name?: string | null;
          allow_private_network?: boolean;
          allowed_methods?: string[];
          allowed_path_prefixes?: string[];
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          name?: string;
          target_url?: string;
          auth_method?: string;
          user_secret_name?: string | null;
          pass_secret_name?: string | null;
          header_name?: string | null;
          cookie_name?: string | null;
          allow_private_network?: boolean;
          allowed_methods?: string[];
          allowed_path_prefixes?: string[];
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "service_profiles_user_id_fkey";
            columns: ["user_id"];
            isOneToOne: false;
            referencedRelation: "users";
            referencedColumns: ["id"];
          },
        ];
      };
      webauthn_credentials: {
        Row: {
          id: string;
          user_id: string;
          credential_id: string;
          public_key: string;
          counter: number;
          transports: string[];
          device_name: string;
          created_at: string;
          last_used_at: string | null;
        };
        Insert: {
          id?: string;
          user_id: string;
          credential_id: string;
          public_key: string;
          counter?: number;
          transports?: string[];
          device_name?: string;
          created_at?: string;
          last_used_at?: string | null;
        };
        Update: {
          id?: string;
          user_id?: string;
          credential_id?: string;
          public_key?: string;
          counter?: number;
          transports?: string[];
          device_name?: string;
          created_at?: string;
          last_used_at?: string | null;
        };
        Relationships: [];
      };
      totp_secrets: {
        Row: {
          id: string;
          user_id: string;
          secret_encrypted: string;
          verified: boolean;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          secret_encrypted: string;
          verified?: boolean;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          secret_encrypted?: string;
          verified?: boolean;
          created_at?: string;
        };
        Relationships: [];
      };
      totp_pending_enrollments: {
        Row: {
          id: string;
          user_id: string;
          secret_encrypted: string;
          expires_at: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          secret_encrypted: string;
          expires_at: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          secret_encrypted?: string;
          expires_at?: string;
          created_at?: string;
        };
        Relationships: [];
      };
      master_key_rotations: {
        Row: {
          id: string;
          status: string;
          processed_secrets: number;
          processed_clients: number;
          processed_totp: number;
          processed_pending_totp: number;
          old_key_id: string | null;
          new_key_id: string | null;
          error_message: string | null;
          started_at: string;
          completed_at: string | null;
        };
        Insert: {
          id?: string;
          status?: string;
          processed_secrets?: number;
          processed_clients?: number;
          processed_totp?: number;
          processed_pending_totp?: number;
          old_key_id?: string | null;
          new_key_id?: string | null;
          error_message?: string | null;
          started_at?: string;
          completed_at?: string | null;
        };
        Update: {
          id?: string;
          status?: string;
          processed_secrets?: number;
          processed_clients?: number;
          processed_totp?: number;
          processed_pending_totp?: number;
          old_key_id?: string | null;
          new_key_id?: string | null;
          error_message?: string | null;
          started_at?: string;
          completed_at?: string | null;
        };
        Relationships: [];
      };
      totp_backup_codes: {
        Row: {
          id: string;
          user_id: string;
          code_hash: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          code_hash: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          code_hash?: string;
          created_at?: string;
        };
        Relationships: [];
      };
      client_applications: {
        Row: {
          id: string;
          user_id: string;
          app_name: string;
          key_hash: string;
          key_prefix: string;
          encrypted_key: string | null;
          scopes: string[];
          last_used_at: string | null;
          created_at: string;
          key_version: number;
        };
        Insert: {
          id?: string;
          user_id: string;
          app_name: string;
          key_hash: string;
          key_prefix: string;
          encrypted_key?: string | null;
          scopes?: string[];
          last_used_at?: string | null;
          created_at?: string;
          key_version?: number;
        };
        Update: {
          id?: string;
          user_id?: string;
          app_name?: string;
          key_hash?: string;
          key_prefix?: string;
          encrypted_key?: string | null;
          scopes?: string[];
          last_used_at?: string | null;
          created_at?: string;
          key_version?: number;
        };
        Relationships: [];
      };
      rate_limit_buckets: {
        Row: {
          bucket_key: string;
          window_start: number;
          count: number;
          cooldown_until: number;
          updated_at: string;
        };
        Insert: {
          bucket_key: string;
          window_start: number;
          count?: number;
          cooldown_until?: number;
          updated_at?: string;
        };
        Update: {
          bucket_key?: string;
          window_start?: number;
          count?: number;
          cooldown_until?: number;
          updated_at?: string;
        };
        Relationships: [];
      };
      system_settings: {
        Row: {
          key: string;
          value: Json;
          updated_at: string;
          updated_by: string | null;
        };
        Insert: {
          key: string;
          value: Json;
          updated_at?: string;
          updated_by?: string | null;
        };
        Update: {
          key?: string;
          value?: Json;
          updated_at?: string;
          updated_by?: string | null;
        };
        Relationships: [];
      };
    };
    Views: {};
    Functions: {
      rate_limit_charge: {
        Args: { p_bucket_key: string; p_window_start: number };
        Returns: {
          current_count: number;
          cooldown_until: number;
        };
      };
      rate_limit_reap: {
        Args: { p_before_window_start: number };
        Returns: undefined;
      };
    };
  };
}
