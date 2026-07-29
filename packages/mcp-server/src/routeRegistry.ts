/**
 * Authoritative route registry (SV-037).
 *
 * Every management API route is declared here exactly once. Two independent
 * checks consume this table so the runtime and the OpenAPI contract cannot
 * silently diverge in either direction:
 *
 *   - `handleApiRoute` matches incoming requests against {@link ROUTES} so an
 *     undocumented route is impossible to reach. Every entry that matches is
 *     a route the server actually serves.
 *   - `scripts/check-openapi-drift.mjs` imports {@link ROUTES} and asserts the
 *     OpenAPI document documents exactly the same (method, path) pairs, so a
 *     runtime route missing from the contract fails CI.
 *
 * Path parameters use OpenAPI `{name}` syntax. The registry is the single
 * source of truth; the OpenAPI document and the request router must both
 * agree with it.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";

/**
 * The authentication/authorization class a route belongs to. The drift check
 * asserts the OpenAPI `x-sv-auth` extension matches, so a route that changes
 * from public to admin (or vice versa) is caught.
 */
export type AuthClass =
  | "public" // no auth required
  | "session" // any authenticated session token
  | "admin_session" // session token + is_admin
  | "scope" // linking-key or session, gated by `scope`
  | "self_or_admin_session"; // session: own resource or admin

export interface RouteSpec {
  /** HTTP method, uppercased. */
  method: HttpMethod;
  /**
   * OpenAPI-style path with `{param}` segments, e.g. `/v1/secrets/{name}/rotate`.
   * Every management route uses the `/v1` prefix documented in OpenAPI.
   */
  path: string;
  /** Auth/authorization class required to reach the handler. */
  auth: AuthClass;
  /** For `scope`-class routes, the scope a principal must carry. */
  scope?: string;
  /**
   * Free-text OpenAPI-style description of who may call this. The drift check
   * cross-references this with the documented security requirement.
   */
}

/**
 * Compile a `/v1`-prefixed OpenAPI path into a matcher for an internal `/api`
 * pathname. Returns the captured params, or `null` if the pathname does not
 * match. `:id`-style params are not used; only `{name}`.
 */
export function matchRoute(spec: { path: string }, apiPathname: string): Record<string, string> | null {
  // Strip the leading "/v1" → "/api"-rooted segment set. The runtime serves
  // both /v1/... and /api/... ; both normalize to the same internal pathname
  // before this matcher runs.
  const segments = spec.path.split("/").filter(Boolean); // ["v1","secrets","{name}"]
  if (segments[0] !== "v1") return null;
  const pathSegments = apiPathname.split("/").filter(Boolean); // ["api","secrets","x"]
  if (pathSegments[0] !== "api") return null;
  const rest = segments.slice(1);
  const apiRest = pathSegments.slice(1);
  if (rest.length !== apiRest.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < rest.length; i += 1) {
    const seg = rest[i];
    const actual = apiRest[i];
    if (seg.startsWith("{") && seg.endsWith("}")) {
      params[seg.slice(1, -1)] = decodeURIComponent(actual);
    } else if (seg !== actual) {
      return null;
    }
  }
  return params;
}

export const ROUTES: readonly RouteSpec[] = [
  // ── Public (no auth) ────────────────────────────────────────────────
  { method: "POST", path: "/v1/auth/login", auth: "public" },
  { method: "GET", path: "/v1/auth/status", auth: "public" },
  { method: "GET", path: "/v1/version", auth: "public" },
  { method: "POST", path: "/v1/auth/setup", auth: "public" },
  { method: "GET", path: "/v1/settings/public", auth: "public" },
  { method: "POST", path: "/v1/auth/register", auth: "public" },

  // ── Session (any authenticated user) ────────────────────────────────
  { method: "GET", path: "/v1/me", auth: "session" },
  { method: "POST", path: "/v1/auth/change-password", auth: "session" },
  { method: "GET", path: "/v1/clients", auth: "session" },
  { method: "POST", path: "/v1/clients", auth: "session" },
  { method: "POST", path: "/v1/clients/{id}/reveal", auth: "session" },
  { method: "POST", path: "/v1/clients/{id}/regenerate", auth: "session" },
  { method: "PATCH", path: "/v1/clients/{id}", auth: "session" },
  { method: "DELETE", path: "/v1/clients/{id}", auth: "session" },
  { method: "GET", path: "/v1/clients/{id}/logs", auth: "session" },
  { method: "GET", path: "/v1/auth/webauthn/credentials", auth: "session" },
  { method: "DELETE", path: "/v1/auth/webauthn/credentials/{id}", auth: "session" },
  { method: "POST", path: "/v1/auth/webauthn/register-options", auth: "session" },
  { method: "POST", path: "/v1/auth/webauthn/register-verify", auth: "session" },
  { method: "POST", path: "/v1/auth/webauthn/authenticate-options", auth: "session" },
  { method: "POST", path: "/v1/auth/webauthn/authenticate-verify", auth: "session" },
  { method: "POST", path: "/v1/auth/totp/setup", auth: "session" },
  { method: "POST", path: "/v1/auth/totp/cancel-setup", auth: "session" },
  { method: "POST", path: "/v1/auth/totp/verify-setup", auth: "session" },
  { method: "POST", path: "/v1/auth/totp/authenticate", auth: "session" },
  { method: "POST", path: "/v1/auth/totp/regenerate-backup-codes", auth: "session" },
  { method: "DELETE", path: "/v1/auth/totp", auth: "session" },
  { method: "POST", path: "/v1/secrets/{name}/reveal", auth: "session" },

  // ── self_or_admin_session ───────────────────────────────────────────
  { method: "POST", path: "/v1/users/{id}/linking-key", auth: "self_or_admin_session" },

  // ── admin_session ───────────────────────────────────────────────────
  { method: "GET", path: "/v1/settings", auth: "admin_session" },
  { method: "PATCH", path: "/v1/settings", auth: "admin_session" },
  { method: "GET", path: "/v1/settings/audit-retention", auth: "admin_session" },
  { method: "PATCH", path: "/v1/settings/audit-retention", auth: "admin_session" },
  { method: "GET", path: "/v1/admin/stats", auth: "admin_session" },
  { method: "GET", path: "/v1/users", auth: "admin_session" },
  { method: "POST", path: "/v1/users", auth: "admin_session" },
  { method: "DELETE", path: "/v1/users/{id}", auth: "admin_session" },
  { method: "POST", path: "/v1/users/{id}/reset-password", auth: "admin_session" },
  { method: "POST", path: "/v1/users/{id}/reset-2fa", auth: "admin_session" },

  // ── scope (linking-key or session carrying the scope) ───────────────
  { method: "GET", path: "/v1/secrets", auth: "scope", scope: "secrets:metadata:read" },
  { method: "POST", path: "/v1/secrets", auth: "scope", scope: "secrets:write" },
  { method: "POST", path: "/v1/secrets/{name}/rotate", auth: "scope", scope: "secrets:write" },
  { method: "DELETE", path: "/v1/secrets/{name}", auth: "scope", scope: "secrets:write" },
  { method: "GET", path: "/v1/service-profiles", auth: "scope", scope: "profiles:read" },
  { method: "POST", path: "/v1/service-profiles", auth: "scope", scope: "profiles:write" },
  { method: "DELETE", path: "/v1/service-profiles/{id}", auth: "scope", scope: "profiles:write" },
  { method: "GET", path: "/v1/user/logs", auth: "scope", scope: "secrets:metadata:read" },
  { method: "GET", path: "/v1/user/logs/export", auth: "scope", scope: "secrets:metadata:read" },

  // ── runner (client plaintext read — capability-scoped per secret) ───
  // Documented in OpenAPI as the client secret-resolution route.
  { method: "GET", path: "/v1/client/secrets/{name}", auth: "scope", scope: "runner:secret:{name}" },
];

/**
 * Build the canonical OpenAPI `(METHOD path)` key set from the registry. Used
 * by the drift checker and by tests.
 */
export function routeKeys(): string[] {
  return ROUTES.map((r) => `${r.method} ${r.path}`).sort();
}
