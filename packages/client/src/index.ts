import {
  SecretVaultTransport,
  validateProxyPath,
  validateServiceName,
  type FetchLike,
  type RequestOptions,
} from "./internal.js";

export { SecretVaultError } from "./errors.js";
export type { FetchLike, RequestOptions, SecretVaultTransportOptions } from "./internal.js";

export interface SecretVaultClientOptions {
  baseUrl: string;
  clientKey: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  userAgent?: string;
  allowInsecureHttp?: boolean;
}

export interface ProxyRequestInit extends RequestInit {
  timeoutMs?: number;
}

export interface SecretVaultCapabilities {
  name: string;
  version: string;
  api_version: string;
  supported_api_versions: string[];
  management_base_path: string;
  proxy_base_path: string;
  openapi: string;
}

export interface SecretVaultHealth {
  status: string;
  sse_connections: number;
  streamable_http_connections: number;
  total_connections: number;
}

/**
 * Proxy-only application client. Management operations belong to
 * @secretvault/admin so applications do not receive an accidental admin-shaped interface.
 */
export class SecretVaultClient {
  private readonly transport: SecretVaultTransport;

  constructor(options: SecretVaultClientOptions) {
    this.transport = new SecretVaultTransport(options);
  }

  proxyUrl(serviceName: string, path = "/"): string {
    validateServiceName(serviceName);
    validateProxyPath(path);
    return this.transport.url(`/proxy/${encodeURIComponent(serviceName)}${path}`);
  }

  async proxy(serviceName: string, path = "/", init: ProxyRequestInit = {}): Promise<Response> {
    const { timeoutMs, ...requestInit } = init;
    return this.transport.fetchResponse(this.proxyUrl(serviceName, path), requestInit, { timeoutMs });
  }

  async health(options: RequestOptions = {}): Promise<SecretVaultHealth> {
    return this.transport.requestJson<SecretVaultHealth>("/health", {}, options);
  }

  async capabilities(options: RequestOptions = {}): Promise<SecretVaultCapabilities> {
    return this.transport.requestJson<SecretVaultCapabilities>("/v1/version", {}, options);
  }
}

export const SecretVault = SecretVaultClient;
