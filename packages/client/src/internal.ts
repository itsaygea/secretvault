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
const TOKEN_PATTERN = /^(sv_[A-Za-z0-9_-]{16,}|session_[A-Za-z0-9_-]{16,}|[A-Za-z0-9._~+/-]{16,}=*)$/;

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
  private readonly fetcher: FetchLike;
  private readonly timeoutMs: number | undefined;
  private readonly userAgent: string;

  constructor(options: SecretVaultTransportOptions) {
    this.baseUrl = validateBaseUrl(options.baseUrl, options.allowInsecureHttp ?? false);
    const credential = options.sessionToken ?? options.token ?? options.clientKey;
    if (!credential) {
      throw new TypeError("SecretVaultTransport requires a clientKey, sessionToken, or token option");
    }
    this.clientKey = validateClientKey(credential);
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = options.timeoutMs;
    this.userAgent = options.userAgent ?? "SecretVaultClient/0.1.0";
  }

  url(path: string): string {
    if (/^https?:\/\//.test(path)) return path;
    return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  }

  async fetchResponse(path: string, init: RequestInit = {}, requestOptions: RequestOptions = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.clientKey}`);
    headers.set("User-Agent", this.userAgent);
    const timeoutMs = requestOptions.timeoutMs ?? this.timeoutMs;
    const callerSignal = requestOptions.signal ?? init.signal ?? undefined;
    const abortContext = composeAbortSignal(callerSignal, timeoutMs);
    try {
      return await this.fetcher(this.url(path), {
        ...init,
        headers,
        signal: abortContext.signal,
      });
    } catch (cause) {
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
