import crypto from "node:crypto";
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";

export const API_VERSION = "v1";
export const SERVER_VERSION = "0.1.0";

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

const STATUS_CODES: Record<number, string> = {
  400: "BAD_REQUEST",
  401: "UNAUTHORIZED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  405: "METHOD_NOT_ALLOWED",
  409: "CONFLICT",
  413: "PAYLOAD_TOO_LARGE",
  415: "UNSUPPORTED_MEDIA_TYPE",
  422: "UNPROCESSABLE_ENTITY",
  429: "RATE_LIMITED",
  500: "INTERNAL_SERVER_ERROR",
  502: "UPSTREAM_ERROR",
  503: "SERVICE_UNAVAILABLE",
};

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    requestId: string;
    status: number;
  };
}

export function getRequestId(req: IncomingMessage): string {
  const raw = req.headers["x-request-id"];
  const candidate = Array.isArray(raw) ? raw[0] : raw;
  return typeof candidate === "string" && REQUEST_ID_PATTERN.test(candidate)
    ? candidate
    : crypto.randomUUID();
}

export function initializeRequestContext(req: IncomingMessage, res: ServerResponse): string {
  const requestId = getRequestId(req);
  // Keep the generated ID available to audit/proxy modules without expanding
  // every handler interface.
  req.headers["x-request-id"] = requestId;
  res.setHeader("X-Request-ID", requestId);
  return requestId;
}

export function versionedApiPath(pathname: string): string | null {
  if (pathname === `/${API_VERSION}`) return "/api";
  if (pathname.startsWith(`/${API_VERSION}/`)) return `/api${pathname.slice(API_VERSION.length + 1)}`;
  return null;
}

export function legacyApiSuccessor(pathname: string): string | null {
  if (pathname === "/api") return `/${API_VERSION}`;
  if (pathname.startsWith("/api/")) return `/${API_VERSION}${pathname.slice(4)}`;
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function statusCode(status: number): string {
  return STATUS_CODES[status] ?? `HTTP_${status}`;
}

// SV-047: defense-in-depth. If a handler leaks a raw PostgreSQL/PostgREST
// message into an error body, redact it rather than forward it. Matches
// fingerprints that only appear in internal diagnostics, never in our own
// public messages (which are plain English).
const INTERNAL_DETAIL_FINGERPRINT =
  /(?:relation "|column "|schema "|column "[^"]*" of relation|PG::|PostgREST|pq:|syntax error at|unterminated quoted|permission denied for|violates foreign key|violates not-null|duplicate key|DETAIL:|Hint:|CONTEXT:|sql=|SQLSTATE|0x[0-9a-f]{8})/i;

function redactMessage(status: number, raw: string): string {
  if (INTERNAL_DETAIL_FINGERPRINT.test(raw)) return statusCode(status);
  return raw;
}

export function toErrorEnvelope(status: number, body: unknown, requestId: string): ErrorEnvelope {
  const source = isRecord(body) ? body : {};
  const nestedError = isRecord(source.error) ? source.error : {};
  const rawMessage = typeof nestedError.message === "string"
    ? nestedError.message
    : typeof source.error === "string"
      ? source.error
      : typeof source.message === "string"
        ? source.message
        : statusCode(status);
  const message = redactMessage(status, rawMessage);
  const code = typeof nestedError.code === "string"
    ? nestedError.code
    : typeof source.code === "string"
      ? source.code
      : statusCode(status);

  return {
    error: {
      code,
      message,
      requestId,
      status,
    },
  };
}

export function writeJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  requestId: string,
  headers: OutgoingHttpHeaders = {},
): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "X-Request-ID": requestId,
    ...headers,
  });
  res.end(JSON.stringify(body));
}

export function writeApiResponse(
  res: ServerResponse,
  status: number,
  body: unknown,
  requestId: string,
  headers: OutgoingHttpHeaders = {},
): void {
  writeJson(res, status, status >= 400 ? toErrorEnvelope(status, body, requestId) : body, requestId, headers);
}

/**
 * SV-AUD-003: stable body the proxy substitutes for an upstream error (4xx/5xx)
 * so an attacker-controlled upstream can never echo an injected credential back
 * through an error body. The upstream status code is preserved; the body is a
 * fixed SecretVault envelope with no upstream-derived content. Streamed bytes
 * from a failing upstream are discarded entirely.
 */
export function buildUpstreamErrorEnvelope(status: number, requestId: string): string {
  return JSON.stringify({
    error: {
      code: statusCode(status),
      message: "Upstream returned an error response",
      requestId,
      status,
    },
  });
}

export function writeErrorResponse(
  res: ServerResponse,
  status: number,
  message: string,
  requestId: string,
  code?: string,
  headers: OutgoingHttpHeaders = {},
): void {
  writeApiResponse(res, status, { error: message, ...(code ? { code } : {}) }, requestId, headers);
}
