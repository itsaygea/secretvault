import {
  SecretVaultTransport,
  type RequestOptions,
  type SecretVaultTransportOptions,
} from "@secretvault/client/internal";

export { SecretVaultError } from "@secretvault/client";
export type { FetchLike } from "@secretvault/client";

export interface SecretVaultAdminOptions extends SecretVaultTransportOptions {}

export interface SecretInfo {
  id?: string;
  name: string;
  display_name: string | null;
  masked_preview: string | null;
  environment: string | null;
  tags: string[] | null;
}

export interface ServiceProfile {
  id: string;
  name: string;
  target_url: string;
  auth_method: "basic" | "bearer" | "header" | "cookie" | string;
  user_secret_name: string | null;
  pass_secret_name: string | null;
  header_name: string | null;
  cookie_name: string | null;
  allow_private_network?: boolean;
  allowed_methods?: string[];
  allowed_path_prefixes?: string[];
}

export interface ClientApplication {
  id: string;
  app_name: string;
  key_prefix: string;
  scopes: string[];
  last_used_at?: string | null;
  created_at: string;
}

export interface UserInfo {
  id: string;
  username: string;
  is_admin: boolean;
  api_key_prefix?: string | null;
  created_at: string;
}

export interface CreateSecretOptions {
  environment?: string;
  tags?: string[];
}

export interface CreateProfileInput {
  name: string;
  target_url: string;
  auth_method: "basic" | "bearer" | "header" | "cookie";
  pass_secret_name: string;
  user_secret_name?: string;
  header_name?: string;
  cookie_name?: string;
  allow_private_network?: boolean;
  allowed_methods?: string[];
  allowed_path_prefixes?: string[];
}

export interface AdminUser {
  id: string;
  username: string;
  password: string;
  is_admin?: boolean;
}

/** Management-only client. It deliberately has no proxy execution method. */
export class SecretVaultAdmin {
  private readonly transport: SecretVaultTransport;

  constructor(options: SecretVaultAdminOptions) {
    this.transport = new SecretVaultTransport(options);
  }

  static async login(
    options: Omit<SecretVaultAdminOptions, "clientKey" | "sessionToken" | "token">,
    credentials: { username: string; password: string; totpCode?: string },
  ): Promise<SecretVaultAdmin> {
    const baseUrl = options.baseUrl.replace(/\/+$/, "");
    const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    let res = await fetcher(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    if (!res.ok) {
      res = await fetcher(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
      });
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as any;
      throw new Error(`Admin authentication failed: ${err?.error || res.statusText}`);
    }

    const data = await res.json() as { token: string };
    return new SecretVaultAdmin({ ...options, sessionToken: data.token });
  }

  private request<T>(path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<T> {
    return this.transport.requestJson<T>(`/v1${path.startsWith("/") ? path : `/${path}`}`, init, options);
  }

  async me(options: RequestOptions = {}): Promise<UserInfo> {
    return this.request<UserInfo>("/me", {}, options);
  }

  async listSecrets(options: RequestOptions = {}): Promise<SecretInfo[]> {
    return this.request<SecretInfo[]>("/secrets", {}, options);
  }

  async searchSecrets(query: { keyword?: string; tags?: string[] }, options: RequestOptions = {}): Promise<SecretInfo[]> {
    const all = await this.listSecrets(options);
    let results = all;
    if (query.keyword) {
      const keyword = query.keyword.toLowerCase();
      results = results.filter((secret) =>
        secret.name.toLowerCase().includes(keyword) ||
        (secret.display_name?.toLowerCase().includes(keyword) ?? false),
      );
    }
    if (query.tags?.length) {
      results = results.filter((secret) => secret.tags?.some((tag) => query.tags!.includes(tag)));
    }
    return results;
  }

  async createSecret(
    name: string,
    value: string,
    input: CreateSecretOptions = {},
    options: RequestOptions = {},
  ): Promise<{ created: boolean; name: string; display_name: string; masked_preview: string }> {
    return this.request("/secrets", {
      method: "POST",
      body: JSON.stringify({
        name,
        value,
        environment: input.environment ?? "development",
        tags: input.tags ?? [],
      }),
      headers: { "Content-Type": "application/json" },
    }, options);
  }

  async rotateSecret(
    name: string,
    newValue: string,
    options: RequestOptions = {},
  ): Promise<{ rotated: boolean; name: string; display_name: string; new_masked_preview: string }> {
    return this.request(`/secrets/${encodeURIComponent(name)}/rotate`, {
      method: "POST",
      body: JSON.stringify({ new_value: newValue }),
      headers: { "Content-Type": "application/json" },
    }, options);
  }

  async deleteSecret(name: string, options: RequestOptions = {}): Promise<{ deleted: boolean; name: string }> {
    return this.request(`/secrets/${encodeURIComponent(name)}`, { method: "DELETE" }, options);
  }

  async listProfiles(options: RequestOptions = {}): Promise<ServiceProfile[]> {
    return this.request<ServiceProfile[]>("/service-profiles", {}, options);
  }

  async createProfile(input: CreateProfileInput, options: RequestOptions = {}): Promise<ServiceProfile> {
    return this.request<ServiceProfile>("/service-profiles", {
      method: "POST",
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
    }, options);
  }

  async deleteProfile(profileId: string, options: RequestOptions = {}): Promise<{ deleted: boolean; name: string }> {
    return this.request(`/service-profiles/${encodeURIComponent(profileId)}`, { method: "DELETE" }, options);
  }

  async listClients(options: RequestOptions = {}): Promise<ClientApplication[]> {
    return this.request<ClientApplication[]>("/clients", {}, options);
  }

  async createClient(
    appName: string,
    scopes?: string[],
    options: RequestOptions = {},
  ): Promise<{ client: ClientApplication; linking_key: string; warning: string }> {
    return this.request("/clients", {
      method: "POST",
      body: JSON.stringify({ app_name: appName, ...(scopes ? { scopes } : {}) }),
      headers: { "Content-Type": "application/json" },
    }, options);
  }

  async deleteClient(clientId: string, options: RequestOptions = {}): Promise<{ revoked: boolean; id: string; app_name: string }> {
    return this.request(`/clients/${encodeURIComponent(clientId)}`, { method: "DELETE" }, options);
  }

  async getClientLogs(clientId: string, options: RequestOptions = {}): Promise<unknown[]> {
    return this.request<unknown[]>(`/clients/${encodeURIComponent(clientId)}/logs`, {}, options);
  }

  async listUsers(options: RequestOptions = {}): Promise<UserInfo[]> {
    return this.request<UserInfo[]>("/users", {}, options);
  }

  async createUser(input: Omit<AdminUser, "id">, options: RequestOptions = {}): Promise<{ created: boolean; username: string }> {
    return this.request("/users", {
      method: "POST",
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
    }, options);
  }

  async deleteUser(userId: string, options: RequestOptions = {}): Promise<{ deleted: boolean; username: string }> {
    return this.request(`/users/${encodeURIComponent(userId)}`, { method: "DELETE" }, options);
  }
}

export const SecretVaultManagement = SecretVaultAdmin;
