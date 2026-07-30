import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 200;

export interface PaginationParams {
  cursor?: string | null;
  pageSize?: number;
}

export interface PageResult<T> {
  data: T[];
  next_cursor: string | null;
}

export function clampPageSize(pageSize: number | undefined | null): number {
  return Math.min(Math.max(pageSize ?? DEFAULT_PAGE_SIZE, 1), MAX_PAGE_SIZE);
}

/**
 * Cursor integrity / grammar-injection hardening (SV-AUD-014).
 *
 * Previously the cursor was an unsigned base64 string whose decoded contents
 * were interpolated verbatim into a PostgREST `.or()` filter. A client could
 * mint a cursor carrying arbitrary PostgREST grammar and alter the query.
 *
 * Cursors are now HMAC-authenticated opaque tokens: the payload is a compact
 * JSON `{a, t}` (after value, tiebreaker), base64url-encoded, and the whole
 * thing is wrapped as `v1.<payload>.<sig>` where `<sig>` is an HMAC-SHA256 of
 * the payload under a server key. Decode verifies the signature (constant-time)
 * AND validates that each field matches its exact type / maximum length before
 * the value is ever allowed to reach a query builder. Any failure — bad
 * signature, wrong version, malformed JSON, oversize or mistyped fields —
 * yields `null`, which callers translate into a 400 (REST) / first page (MCP).
 *
 * The server key is derived once at boot from the master key via HKDF with a
 * fixed purpose, the same pattern the token HMAC uses (`initAuth`). Cursors are
 * ephemeral pagination tokens; a master-key rotation invalidates outstanding
 * cursors, which is the correct behavior.
 */

const CURSOR_VERSION = "v1";
/** Maximum byte length of any single decoded field (name / id). Generous but bounded. */
const MAX_FIELD_LEN = 256;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let CURSOR_HMAC_KEY: Buffer | null = null;

/**
 * Initialize the cursor signing key from the master key. Called once at boot
 * (alongside `initAuth`). Idempotent — safe to call again on test re-init.
 */
export function initCursorKey(masterKey: Buffer): void {
  // Derive a purpose-bound 32-byte subkey via HKDF-SHA256. The salt/purpose
  // string binds this key to cursor signing only — it cannot be confused with
  // the token HMAC key or any per-secret encryption key.
  CURSOR_HMAC_KEY = Buffer.from(
    hkdfSync("sha256", masterKey, "secretvault/pagination", "cursor-v1", 32),
  );
}

function cursorKey(): Buffer {
  if (!CURSOR_HMAC_KEY) {
    throw new Error(
      "Cursor signing key not initialized. Call initCursorKey() at boot.",
    );
  }
  return CURSOR_HMAC_KEY;
}

function sign(payloadB64: string): string {
  return createHmac("sha256", cursorKey()).update(payloadB64).digest("base64url");
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Validate a decoded `after`/`before` field: non-empty string, bounded length. */
function isValidNameField(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_FIELD_LEN
  );
}

/** The tiebreaker is always a row id (UUID). Validate the exact shape. */
function isValidUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

/**
 * Escape a PostgREST filter value so it cannot inject grammar (`.`, `,`, `(`,
 * `)`). Defense-in-depth on top of HMAC validation: even a server-signed name
 * that legitimately contains PostgREST-significant characters is rendered safe.
 * PostgREST accepts double-quoted string literals with embedded quotes doubled.
 */
export function escapePostgrestValue(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

export function encodeCursor(after: string, tiebreaker: string): string {
  const payload = JSON.stringify({ a: after, t: tiebreaker });
  const payloadB64 = Buffer.from(payload, "utf8").toString("base64url");
  return `${CURSOR_VERSION}.${payloadB64}.${sign(payloadB64)}`;
}

export function decodeCursor(cursor: string): { after: string; tiebreaker: string } | null {
  try {
    const parts = cursor.split(".");
    if (parts.length !== 3 || parts[0] !== CURSOR_VERSION) return null;
    const [, payloadB64, sig] = parts;
    if (!payloadB64 || !sig) return null;
    // Verify signature first (constant-time). A tampered payload never reaches
    // JSON.parse or the field validators, so grammar cannot be injected.
    if (!constantTimeEqual(sign(payloadB64), sig)) return null;
    const payload = Buffer.from(payloadB64, "base64url").toString("utf8");
    const parsed = JSON.parse(payload) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as { a?: unknown; t?: unknown };
    // Exact type + length validation before any field is returned.
    if (!isValidNameField(obj.a) || !isValidUuid(obj.t)) return null;
    return { after: obj.a, tiebreaker: obj.t };
  } catch {
    return null;
  }
}

/**
 * Decode a *before* cursor (used for reverse pagination). Same integrity rules
 * as {@link decodeCursor}; payload field is `b` instead of `a`.
 */
export function decodeBeforeCursor(cursor: string): { before: string; tiebreaker: string } | null {
  try {
    const parts = cursor.split(".");
    if (parts.length !== 3 || parts[0] !== CURSOR_VERSION) return null;
    const [, payloadB64, sig] = parts;
    if (!payloadB64 || !sig) return null;
    if (!constantTimeEqual(sign(payloadB64), sig)) return null;
    const payload = Buffer.from(payloadB64, "base64url").toString("utf8");
    const parsed = JSON.parse(payload) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as { b?: unknown; t?: unknown };
    if (!isValidNameField(obj.b) || !isValidUuid(obj.t)) return null;
    return { before: obj.b, tiebreaker: obj.t };
  } catch {
    return null;
  }
}

export function encodeBeforeCursor(before: string, tiebreaker: string): string {
  const payload = JSON.stringify({ b: before, t: tiebreaker });
  const payloadB64 = Buffer.from(payload, "utf8").toString("base64url");
  return `${CURSOR_VERSION}.${payloadB64}.${sign(payloadB64)}`;
}

export async function paginateQuery<T extends Record<string, any>>(
  rows: T[],
  pageSize: number,
  encodeFn: (row: T) => string,
): Promise<PageResult<T>> {
  const hasMore = rows.length > pageSize;
  const page = hasMore ? rows.slice(0, pageSize) : rows;
  const next_cursor = hasMore && page.length > 0 ? encodeFn(page[page.length - 1]) : null;
  return { data: page, next_cursor };
}
