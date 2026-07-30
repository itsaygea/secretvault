/**
 * Database / internal-error → public-error mapping (SV-047).
 *
 * Handlers must never return raw PostgreSQL / PostgREST text to a remote
 * client — it leaks schema, column, and role details. This module is the
 * single funnel: every database failure is classified into one stable public
 * code and a generic message, while the redacted diagnostic is logged with the
 * request id for operators.
 *
 * Classification is driven by the error shape Supabase/PostgREST returns:
 *   - `code` is a PostgreSQL SQLSTATE (e.g. "23505" unique_violation) or a
 *     PostgREST code ("PGRST116" not-found, "PGRST204" no-body).
 *   - `message` may contain "JWT", "permission denied", "schema", etc.
 */

export interface PublicError {
  status: number;
  code: string;
  message: string;
}

/** A coarse, loggable public code for an error — never the raw DB text. */
export function publicDbCode(error: unknown): string {
  return classify(error).code;
}

/**
 * The handler-facing result for an unexpected database/internal failure.
 * Returns a 500 with a stable code; the request id is attached by the envelope
 * writer. Callers that can detect a specific not-found / conflict should do so
 * before falling back to this.
 */
export function internalError(): PublicError {
  return { status: 500, code: "INTERNAL_SERVER_ERROR", message: "Internal server error" };
}

/**
 * The safe public message for an otherwise-unhandled DB/internal failure —
 * for MCP tool handlers, which cannot set HTTP status. Returns the classified
 * {@link PublicError.message} (a generic string), never the raw DB text. The
 * raw diagnostic is already logged by the request envelope for operators; this
 * only keeps the message itself out of the tool response. (SV-AUD-014 / SV-047)
 */
export function safeErrorMessage(error: unknown): string {
  return classify(error).message;
}

/**
 * Classify a Supabase/PostgREST error into a stable PublicError. Used directly
 * when a handler wants to surface a precise code (conflict, validation) for a
 * known failure class; otherwise {@link internalError} is the safe default.
 */
export function classify(error: unknown): PublicError {
  if (!error || typeof error !== "object") return internalError();
  const err = error as { code?: string; message?: string };
  const code = (err.code ?? "").toString();
  const message = (err.message ?? "").toString();

  // PostgreSQL SQLSTATEs.
  if (code === "23505") return { status: 409, code: "CONFLICT", message: "Resource already exists" };
  if (code === "23503") return { status: 409, code: "DEPENDENCY_VIOLATION", message: "Referenced resource does not exist" };
  if (code === "23502") return { status: 400, code: "MISSING_REQUIRED_FIELD", message: "A required field is missing" };
  if (code === "42703") return { status: 500, code: "INTERNAL_SERVER_ERROR", message: "Internal server error" };
  // PostgREST not-found (single() on zero rows, PGRST116) → callers usually
  // map to 404 explicitly; here we keep it generic.
  if (code === "PGRST116") return { status: 404, code: "NOT_FOUND", message: "Resource not found" };

  const lower = message.toLowerCase();
  if (lower.includes("jwt") || lower.includes("auth") && lower.includes("denied")) {
    return { status: 401, code: "UNAUTHORIZED", message: "Authentication failed" };
  }
  if (lower.includes("permission denied") || lower.includes("rls")) {
    return { status: 403, code: "FORBIDDEN", message: "Access denied" };
  }
  return internalError();
}

/**
 * Returns true when a `.single()` result indicates the row was simply absent
 * (PostgREST PGRST116 / a "JSON object requested, multiple (or no) rows
 * returned" message) versus a genuine infrastructure failure.
 */
export function isNotFound(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as { code?: string; message?: string };
  if (err.code === "PGRST116") return true;
  const msg = (err.message ?? "").toLowerCase();
  return msg.includes("multiple (or no) rows returned") || msg.includes("json object requested");
}
