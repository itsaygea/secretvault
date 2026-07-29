/**
 * @deprecated Use @secretvault/client for proxy access or @secretvault/admin
 * for management operations. This package remains a narrow proxy compatibility
 * adapter for existing applications.
 *
 * @deprecated Will be removed in v2.0. Migrate to @secretvault/client.
 */
console.warn(
  "[deprecation] @secretvault/bridge is deprecated. Use @secretvault/client directly. " +
  "See https://github.com/itsaygea/secretvault for migration guide."
);

import {
  SecretVaultClient,
  type ProxyRequestInit,
  type SecretVaultClientOptions,
} from "@secretvault/client";

export { SecretVaultError } from "@secretvault/client";
export type { ProxyRequestInit, SecretVaultClientOptions } from "@secretvault/client";

export interface BridgeConfig extends Omit<SecretVaultClientOptions, "baseUrl" | "clientKey" | "allowInsecureHttp"> {
  serverUrl: string;
  linkingKey: string;
  /** Local HTTP is retained only for legacy compatibility; new clients require HTTPS by default. */
  allowInsecureHttp?: boolean;
}

export class SecretBridge extends SecretVaultClient {
  private readonly linkingKey: string;

  constructor(config: BridgeConfig) {
    super({
      baseUrl: config.serverUrl,
      clientKey: config.linkingKey,
      fetch: config.fetch,
      timeoutMs: config.timeoutMs,
      userAgent: config.userAgent ?? "SecretVaultBridge/0.1.0",
      allowInsecureHttp: config.allowInsecureHttp ?? true,
    });
    this.linkingKey = config.linkingKey;
  }

  /** @deprecated Use proxy(). */
  async proxyFetch(serviceName: string, path: string, init?: ProxyRequestInit): Promise<Response> {
    return this.proxy(serviceName, path, init);
  }

  /** @deprecated Use proxy() so HeadersInit merging and auth ownership stay centralized. */
  proxyHeaders(): Record<string, string> {
    return { Authorization: `Bearer ${this.linkingKey}` };
  }
}

export const SecretVault = SecretBridge;
export const SecretVaultBridge = SecretBridge;
