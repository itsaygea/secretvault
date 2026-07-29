/**
 * Centralized runtime validation with explicit limits (SV-048).
 *
 * Every route that accepts user input validates here, not by TypeScript casts.
 * Limits are explicit and shared so a single source defines the contract that
 * OpenAPI schemas and clients mirror. Unknown-field rejection is opt-in per
 * route (record vs. whitelist) because several endpoints accept open-shaped
 * proxy configuration.
 *
 * `validate*` functions throw `ValidationError`; handlers catch and map to a
 * 400 with a stable code via {@link validationErrorResponse}.
 */

export class ValidationError extends Error {
  readonly code = "VALIDATION_ERROR";
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export interface FieldLimits {
  SECRET_NAME_MAX: number;
  SECRET_VALUE_MAX: number;
  USERNAME_MIN: number;
  USERNAME_MAX: number;
  PASSWORD_MIN: number;
  PASSWORD_MAX: number; // bcrypt truncates at 72 bytes; reject longer to avoid silent truncation
  TAG_MAX_COUNT: number;
  TAG_MAX_LENGTH: number;
  ENVIRONMENT_MAX: number;
  APP_NAME_MAX: number;
  DEVICE_NAME_MAX: number;
  URL_MAX: number;
  SCOPES_MAX: number;
}

export const LIMITS: FieldLimits = {
  SECRET_NAME_MAX: 128,
  SECRET_VALUE_MAX: 64 * 1024, // 64 KiB; secrets are credentials, not blobs
  USERNAME_MIN: 3,
  USERNAME_MAX: 64,
  PASSWORD_MIN: 6,
  PASSWORD_MAX: 72, // bcrypt boundary
  TAG_MAX_COUNT: 32,
  TAG_MAX_LENGTH: 64,
  ENVIRONMENT_MAX: 64,
  APP_NAME_MAX: 128,
  DEVICE_NAME_MAX: 128,
  URL_MAX: 2048,
  SCOPES_MAX: 64,
};

const USERNAME_RE = /^[a-zA-Z0-9_-]+$/;
const ENVIRONMENT_RE = /^[a-zA-Z0-9_.-]+$/;

function assert(condition: boolean, message: string): void {
  if (!condition) throw new ValidationError(message);
}

/** Bounded, non-empty string. */
export function validateBoundedString(value: unknown, field: string, max: number, min = 1): string {
  if (typeof value !== "string") throw new ValidationError(`${field} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length < min) throw new ValidationError(`${field} must be at least ${min} character${min === 1 ? "" : "s"}`);
  if (trimmed.length > max) throw new ValidationError(`${field} must be at most ${max} characters`);
  return trimmed;
}

export function validateUsername(username: unknown): string {
  const u = validateBoundedString(username, "username", LIMITS.USERNAME_MAX, LIMITS.USERNAME_MIN);
  if (!USERNAME_RE.test(u)) throw new ValidationError("username must be alphanumeric/dash/underscore only");
  return u;
}

export function validatePassword(password: unknown): string {
  if (typeof password !== "string") throw new ValidationError("password must be a string");
  // bcrypt silently truncates inputs longer than 72 bytes; reject explicitly
  // so a longer password cannot be confused with its truncation.
  if (Buffer.byteLength(password, "utf8") > LIMITS.PASSWORD_MAX) {
    throw new ValidationError(`password must be at most ${LIMITS.PASSWORD_MAX} bytes`);
  }
  if (password.length < LIMITS.PASSWORD_MIN) {
    throw new ValidationError(`password must be at least ${LIMITS.PASSWORD_MIN} characters`);
  }
  return password;
}

export function validateTags(tags: unknown): string[] {
  if (tags === undefined || tags === null) return [];
  if (!Array.isArray(tags)) throw new ValidationError("tags must be an array");
  if (tags.length > LIMITS.TAG_MAX_COUNT) throw new ValidationError(`at most ${LIMITS.TAG_MAX_COUNT} tags allowed`);
  return tags.map((t, i) => validateBoundedString(t, `tags[${i}]`, LIMITS.TAG_MAX_LENGTH));
}

export function validateEnvironment(env: unknown): string {
  const e = validateBoundedString(env, "environment", LIMITS.ENVIRONMENT_MAX);
  if (!ENVIRONMENT_RE.test(e)) throw new ValidationError("environment must be alphanumeric/dot/dash/underscore only");
  return e;
}

export function validateScopes(scopes: unknown): string[] {
  if (scopes === undefined || scopes === null) return [];
  if (!Array.isArray(scopes)) throw new ValidationError("scopes must be an array");
  if (scopes.length > LIMITS.SCOPES_MAX) throw new ValidationError(`at most ${LIMITS.SCOPES_MAX} scopes allowed`);
  return scopes.map((s, i) => validateBoundedString(s, `scopes[${i}]`, 128));
}

/** Strip unknown top-level keys when `allowed` is provided; throw otherwise. */
export function rejectUnknownKeys(body: unknown, allowed: string[], context: string): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ValidationError(`${context} must be a JSON object`);
  }
  const rec = body as Record<string, unknown>;
  const allow = new Set(allowed);
  for (const key of Object.keys(rec)) {
    if (!allow.has(key)) throw new ValidationError(`${context}: unknown field '${key}'`);
  }
  return rec;
}

/** A handler-ready 400 body for a thrown ValidationError. */
export function validationErrorResponse(err: unknown): { status: number; body: { error: string; code: string } } {
  return err instanceof ValidationError
    ? { status: 400, body: { error: err.message, code: err.code } }
    : { status: 400, body: { error: "Invalid request body", code: "VALIDATION_ERROR" } };
}
