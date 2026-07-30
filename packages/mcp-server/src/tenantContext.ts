/**
 * SV-AUD-013: per-request tenant context for database-enforced isolation.
 *
 * The application talks to Postgres through PostgREST using a single global
 * service-role key. PostgREST exposes the request's verified JWT as the
 * `request.jwt.claims` GUC, and the tenant RLS policies (migration 022) compare
 * `user_id` against the `tenant_user_id` claim in that GUC. This module mints a
 * short-lived, INTERNAL-ONLY tenant JWT per authenticated request and makes it
 * ambient via AsyncLocalStorage, so a custom `fetch` on the shared supabase
 * client can stamp it onto each database request without threading it through
 * every handler signature.
 *
 * The tenant JWT is never returned to any client. It is distinct from the
 * session HMAC token handed to users (api.ts) — it is a server-internal
 * credential scoped to a single request, with a short TTL, carrying only
 * { role, tenant_user_id, client_id, is_admin }.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createHmac, timingSafeEqual } from "node:crypto";

export interface TenantIdentity {
  userId: string;
  clientId: string | null;
  isAdmin: boolean;
}

const TENANT_TTL_SECONDS = 60;

/** Ambient store for the current request's tenant identity + its minted JWT. */
const tenantStorage = new AsyncLocalStorage<{ identity: TenantIdentity; token: string }>();

let jwtSecret = "";
let jwtIssuer = "secretvault-runtime";

/** Initialize with the PostgREST JWT secret (the same one install-server.sh generates). */
export function initTenantAuth(secret: string, issuer = "secretvault-runtime"): void {
  jwtSecret = secret;
  jwtIssuer = issuer;
}

export function isTenantAuthInitialized(): boolean {
  return jwtSecret.length > 0;
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Mint a short-lived HS256 JWT switching into `sv_runtime` with the given tenant
 * claims. PostgREST verifies it against PGRST_JWT_SECRET and exposes the claims
 * as request.jwt.claims, which the tenant RLS policies read.
 */
export function mintTenantJwt(identity: TenantIdentity, nowSeconds: number = Math.floor(Date.now() / 1000)): string {
  if (!jwtSecret) throw new Error("tenant auth not initialized: JWT secret missing");
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    role: "sv_runtime",
    tenant_user_id: identity.userId,
    client_id: identity.clientId ?? null,
    is_admin: identity.isAdmin,
    iss: jwtIssuer,
    iat: nowSeconds,
    exp: nowSeconds + TENANT_TTL_SECONDS,
    ref: "runtime",
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createHmac("sha256", jwtSecret).update(signingInput).digest();
  // Self-check so a misconfigured secret fails loudly at mint time.
  const verify = createHmac("sha256", jwtSecret).update(signingInput).digest();
  if (verify.length !== sig.length || !timingSafeEqual(verify, sig)) {
    throw new Error("tenant JWT self-verification failed");
  }
  return `${signingInput}.${b64url(sig)}`;
}

/** The tenant JWT for the current async context, or null outside one. */
export function currentTenantToken(): string | null {
  const store = tenantStorage.getStore();
  return store?.token ?? null;
}

/** The tenant identity for the current async context, or null outside one. */
export function currentTenantIdentity(): TenantIdentity | null {
  return tenantStorage.getStore()?.identity ?? null;
}

/**
 * Run `fn` with the given tenant identity ambient. Mints the tenant JWT once
 * (fail-fast if the secret is unset), so a misconfiguration surfaces here rather
 * than as a silent fallback to the unscoped service-role client mid-request.
 */
export function runAsTenant<T>(identity: TenantIdentity, fn: () => Promise<T>): Promise<T> {
  const token = mintTenantJwt(identity);
  return tenantStorage.run({ identity, token }, fn);
}

/**
 * Bind the tenant identity to the current async context for the remainder of the
 * request, without wrapping a callback. Used at the dispatch boundary so the
 * long flat route chain runs inside the tenant context without re-indenting it.
 * `enterWith` propagates across the awaited continuations of this request and
 * is naturally scoped to the request (each request is its own async context).
 * Returns the minted token (or null if tenant auth is not initialized — the
 * pre-auth/global path, where the service-role client is used as-is).
 */
export function enterTenantContext(identity: TenantIdentity): string | null {
  if (!isTenantAuthInitialized()) return null;
  const token = mintTenantJwt(identity);
  tenantStorage.enterWith({ identity, token });
  return token;
}

/**
 * A `fetch` override for the shared supabase client. When a tenant context is
 * active, each database request is stamped with that tenant's JWT in both
 * Authorization and apikey (PostgREST accepts either); otherwise the request
 * passes through unchanged (the client's base service-role headers apply, used
 * only by the pre-auth/global routes).
 */
export function tenantAwareFetch(
  baseFetch: typeof globalThis.fetch,
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const token = currentTenantToken();
    if (token) {
      const headers = new Headers(init?.headers);
      headers.set("Authorization", `Bearer ${token}`);
      headers.set("apikey", token);
      init = { ...init, headers };
    }
    return baseFetch(input as RequestInfo, init);
  };
}
