export interface SecretVaultErrorOptions {
  status: number;
  code: string;
  requestId: string | null;
  retryable: boolean;
  cause?: unknown;
}

export class SecretVaultError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly retryable: boolean;

  constructor(message: string, options: SecretVaultErrorOptions) {
    super(message, { cause: options.cause });
    this.name = "SecretVaultError";
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.retryable = options.retryable;
  }

  static fromResponse(response: Response, body: unknown): SecretVaultError {
    const nested = isRecord(body) && isRecord(body.error) ? body.error : null;
    const message = nested && typeof nested.message === "string"
      ? nested.message
      : isRecord(body) && typeof body.error === "string"
        ? body.error
        : typeof body === "string" && body.length > 0
          ? body.slice(0, 500)
          : `SecretVault request failed with status ${response.status}`;
    const code = nested && typeof nested.code === "string"
      ? nested.code
      : isRecord(body) && typeof body.code === "string"
        ? body.code
        : statusCode(response.status);
    const requestId = nested && typeof nested.requestId === "string"
      ? nested.requestId
      : response.headers.get("X-Request-ID");

    return new SecretVaultError(message, {
      status: response.status,
      code,
      requestId,
      retryable: isRetryableStatus(response.status),
    });
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function statusCode(status: number): string {
  const codes: Record<number, string> = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    429: "RATE_LIMITED",
    500: "INTERNAL_SERVER_ERROR",
    502: "UPSTREAM_ERROR",
    503: "SERVICE_UNAVAILABLE",
  };
  return codes[status] ?? `HTTP_${status}`;
}

export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}
