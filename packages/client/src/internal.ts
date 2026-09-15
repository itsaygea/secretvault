import { SecretVaultError, isRecord } from "./errors.js";

export type FetchLike = typeof fetch;

export interface SecretVaultTransportOptions {
  baseUrl: string;
  clientKey?: string;
  sessionToken?: string;
  token?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  userAgent?: string;
  allowInsecureHttp?: boolean;
  /** Exchange the long-lived client key for short-lived proxy tokens (default true). */
  useProxyAccessTokens?: boolean;
}

export interface RequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface AbortContext {
  signal: AbortSignal;
  cleanup: () => void;
  timedOut: () => boolean;
}

const SERVICE_NAME_PATTERN = /^[A-Za-z0-9._~-]{1,64}$/;
const TOKEN_PATTERN = /^(sv_[A-Za-z0-9_-]{16,}|svt_[A-Za-z0-9_-]{16,}|session_[A-Za-z0-9_-]{16,}|[A-Za-z0-9._~+/-]{16,}=*)$/;
const PROXY_ACCESS_TOKEN_SAFETY_MS = 30_000;

export function validateBaseUrl(value: string, allowInsecureHttp = false): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TypeError("baseUrl must use http or https");
  }
  if (url.protocol === "http:" && !allowInsecureHttp) {
    throw new TypeError("baseUrl must use HTTPS unless allowInsecureHttp is enabled");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("baseUrl must not contain credentials, query parameters, or a fragment");
  }
  return value.replace(/\/+$/, "");
}

export function validateClientKey(value: string): string {
  const trimmed = value.trim();
  if (!TOKEN_PATTERN.test(trimmed)) {
    throw new TypeError("clientKey or sessionToken must be a valid SecretVault credential string");
  }
  return trimmed;
}

export function validateServiceName(value: string): string {
  if (!SERVICE_NAME_PATTERN.test(value)) {
    throw new TypeError("serviceName must be 1-64 characters and contain only letters, numbers, '.', '_', '-', or '~'");
  }
  return value;
}

export function validateProxyPath(value: string): string {
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\") || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError("proxy path must be an absolute path without authority or control characters");
  }
  const parsed = new URL(value, "https://secretvault.invalid");
  if (parsed.origin !== "https://secretvault.invalid" || parsed.hash || parsed.username || parsed.password) {
    throw new TypeError("proxy path must not change the upstream authority");
  }
  return value;
}

function composeAbortSignal(input: AbortSignal | undefined, timeoutMs: number | undefined): AbortContext {
  if (timeoutMs === undefined && input) {
    return { signal: input, cleanup: () => undefined, timedOut: () => false };
  }

  const controller = new AbortController();
  let didTimeout = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const abortFromCaller = () => controller.abort(input?.reason);

  if (input) {
    if (input.aborted) abortFromCaller();
    else input.addEventListener("abort", abortFromCaller, { once: true });
  }
  if (timeoutMs !== undefined) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive finite number");
    }
    timer = setTimeout(() => {
      didTimeout = true;
      controller.abort(new Error("SecretVault request timed out"));
    }, timeoutMs);
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      if (timer) clearTimeout(timer);
      input?.removeEventListener("abort", abortFromCaller);
    },
    timedOut: () => didTimeout,
  };
}

async function parseResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export class SecretVaultTransport {
  private readonly baseUrl: string;
  private readonly clientKey: string;
  private readonly useProxyAccessTokens: boolean;
  private readonly fetcher: FetchLike;
  private readonly timeoutMs: number | undefined;
  private readonly userAgent: string;
  private proxyAccessToken: { value: string; expiresAt: number } | null = null;
  private proxyAccessTokenPromise: Promise<string> | null = null;

  constructor(options: SecretVaultTransportOptions) {
    this.baseUrl = validateBaseUrl(options.baseUrl, options.allowInsecureHttp ?? false);
    const credential = options.sessionToken ?? options.token ?? options.clientKey;
    if (!credential) {
      throw new TypeError("SecretVaultTransport requires a clientKey, sessionToken, or token option");
    }
    this.clientKey = validateClientKey(credential);
    this.useProxyAccessTokens = options.useProxyAccessTokens
      ?? Boolean(options.clientKey?.startsWith("sv_") && !options.sessionToken && !options.token);
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = options.timeoutMs;
    this.userAgent = options.userAgent ?? "SecretVaultClient/0.1.0";
  }

  url(path: string): string {
    if (/^https?:\/\//.test(path)) return path;
    return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  }

  private isProxyRequest(path: string): boolean {
    try {
      return new URL(this.url(path)).pathname.startsWith("/proxy/");
    } catch {
      return false;
    }
  }

  private async exchangeProxyAccessToken(signal: AbortSignal): Promise<string> {
    const response = await this.fetcher(this.url("/v1/client/token"), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.clientKey}`,
        "Content-Type": "application/json",
        "User-Agent": this.userAgent,
      },
      body: "{}",
      signal,
    });
    const body = await parseResponse(response);
    if (!response.ok) throw SecretVaultError.fromResponse(response, body);
    if (!isRecord(body) || typeof body.access_token !== "string" || !/^(svt_[A-Za-z0-9_-]{16,})$/.test(body.access_token)) {
      throw new SecretVaultError("SecretVault returned an invalid proxy access token", {
        status: 502,
        code: "INVALID_PROXY_ACCESS_TOKEN",
        requestId: response.headers.get("X-Request-ID"),
        retryable: true,
      });
    }
    const expiresAt = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : NaN;
    const expiresIn = typeof body.expires_in === "number" && Number.isFinite(body.expires_in)
      ? body.expires_in * 1000
      : 0;
    const absoluteExpiry = Number.isFinite(expiresAt) ? expiresAt : Date.now() + expiresIn;
    if (!Number.isFinite(absoluteExpiry) || absoluteExpiry <= Date.now()) {
      throw new SecretVaultError("SecretVault returned an expired proxy access token", {
        status: 502,
        code: "INVALID_PROXY_ACCESS_TOKEN",
        requestId: response.headers.get("X-Request-ID"),
        retryable: true,
      });
    }
    this.proxyAccessToken = { value: body.access_token, expiresAt: absoluteExpiry };
    return body.access_token;
  }

  private async getProxyAccessToken(signal: AbortSignal): Promise<string> {
    const cached = this.proxyAccessToken;
    if (cached && cached.expiresAt - Date.now() > PROXY_ACCESS_TOKEN_SAFETY_MS) return cached.value;
    if (!this.proxyAccessTokenPromise) {
      this.proxyAccessTokenPromise = this.exchangeProxyAccessToken(signal).finally(() => {
        this.proxyAccessTokenPromise = null;
      });
    }
    return this.proxyAccessTokenPromise;
  }

  private invalidateProxyAccessToken(value: string): void {
    if (this.proxyAccessToken?.value === value) this.proxyAccessToken = null;
  }

  private static isReplayableBody(body: BodyInit | null | undefined): boolean {
    if (body === undefined || body === null || typeof body === "string") return true;
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return true;
    if (body instanceof URLSearchParams) return true;
    return typeof Blob !== "undefined" && body instanceof Blob;
  }

  /** Return a short-lived proxy Authorization header for manual integrations. */
  async proxyHeaders(requestOptions: RequestOptions = {}): Promise<Record<string, string>> {
    if (!this.useProxyAccessTokens) {
      throw new SecretVaultError("Short-lived proxy tokens are disabled for this transport", {
        status: 400,
        code: "PROXY_TOKENS_DISABLED",
        requestId: null,
        retryable: false,
      });
    }
    const abortContext = composeAbortSignal(requestOptions.signal, requestOptions.timeoutMs ?? this.timeoutMs);
    try {
      const token = await this.getProxyAccessToken(abortContext.signal);
      return {
        Authorization: `Bearer ${token}`,
        "User-Agent": this.userAgent,
      };
    } finally {
      abortContext.cleanup();
    }
  }

  async fetchResponse(path: string, init: RequestInit = {}, requestOptions: RequestOptions = {}): Promise<Response> {
    const timeoutMs = requestOptions.timeoutMs ?? this.timeoutMs;
    const callerSignal = requestOptions.signal ?? init.signal ?? undefined;
    const abortContext = composeAbortSignal(callerSignal, timeoutMs);
    try {
      const proxyRequest = this.useProxyAccessTokens && this.isProxyRequest(path);
      const credential = proxyRequest
        ? await this.getProxyAccessToken(abortContext.signal)
        : this.clientKey;
      const request = async (authCredential: string): Promise<Response> => {
        const headers = new Headers(init.headers);
        headers.set("Authorization", `Bearer ${authCredential}`);
        headers.set("User-Agent", this.userAgent);
        return this.fetcher(this.url(path), {
          ...init,
          headers,
          signal: abortContext.signal,
        });
      };
      let response = await request(credential);
      // Key rotation/session revocation can invalidate a cached token before
      // its TTL. Retry once for replayable requests with a fresh token; never
      // replay a streaming request body.
      if (proxyRequest && response.status === 401 && SecretVaultTransport.isReplayableBody(init.body)) {
        this.invalidateProxyAccessToken(credential);
        const refreshed = await this.getProxyAccessToken(abortContext.signal);
        response = await request(refreshed);
      }
      return response;
    } catch (cause) {
      if (cause instanceof SecretVaultError) throw cause;
      if (abortContext.timedOut()) {
        throw new SecretVaultError("SecretVault request timed out", {
          status: 408,
          code: "REQUEST_TIMEOUT",
          requestId: null,
          retryable: true,
          cause,
        });
      }
      if (callerSignal?.aborted) {
        throw new SecretVaultError("SecretVault request was aborted", {
          status: 0,
          code: "REQUEST_ABORTED",
          requestId: null,
          retryable: false,
          cause,
        });
      }
      throw new SecretVaultError(cause instanceof Error ? cause.message : "SecretVault request failed", {
        status: 0,
        code: "NETWORK_ERROR",
        requestId: null,
        retryable: true,
        cause,
      });
    } finally {
      abortContext.cleanup();
    }
  }

  async requestJson<T>(path: string, init: RequestInit = {}, requestOptions: RequestOptions = {}): Promise<T> {
    const response = await this.fetchResponse(path, init, requestOptions);
    const body = await parseResponse(response);
    if (!response.ok) throw SecretVaultError.fromResponse(response, body);
    return body as T;
  }
}

export function isClientResponseError(body: unknown): boolean {
  return isRecord(body) && isRecord(body.error) && typeof body.error.code === "string";
}
