import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";

/**
 * Transport-security policy for SecretVault (SV-020).
 *
 * The application is meant to sit behind a TLS-terminating reverse proxy
 * (Caddy, Nginx Proxy Manager, Tailscale Serve, …) in production. These
 * helpers keep that topology safe without breaking the local-development
 * plaintext path, and centralise the policy so it can be unit-tested.
 */

// Dev-only override flags. Both keys must be set, and the confirmation must
// match the literal acknowledgement — an empty prompt can never reach the
// unsafe path. Mirrors the database-TLS override in migrate.ts.
export const ALLOW_PLAINTEXT_EXTERNAL_CONFIRM = "I-know-this-is-insecure";

/** Whether the application itself terminates TLS with its own cert. */
export function isNativeTls(): boolean {
  const cert = process.env.SECRETVAULT_TLS_CERT;
  const key = process.env.SECRETVAULT_TLS_KEY;
  return Boolean(cert && key);
}

/**
 * The effective request scheme, honouring the supported reverse-proxy topology.
 * A proxy that terminates TLS forwards `X-Forwarded-Proto: https`; without a
 * proxy the listener's own protocol wins.
 */
export function effectiveScheme(req: IncomingMessage, nativeTls: boolean): "https" | "http" {
  const forwarded = String(req.headers["x-forwarded-proto"] ?? "").split(",")[0]?.trim().toLowerCase();
  if (forwarded === "https" || forwarded === "http") return forwarded;
  return nativeTls ? "https" : "http";
}

/** Effective host, honouring `X-Forwarded-Host` when a proxy is in front. */
export function effectiveHost(req: IncomingMessage): string {
  const forwarded = String(req.headers["x-forwarded-host"] ?? "").split(",")[0]?.trim();
  return forwarded || req.headers.host || "localhost";
}

/** Canonical origin (scheme://host) for the current request, proxy-aware. */
export function effectiveOrigin(req: IncomingMessage, nativeTls: boolean): string {
  const host = effectiveHost(req);
  const scheme = effectiveScheme(req, nativeTls);
  return `${scheme}://${host}`;
}

/**
 * The interface the listener binds to inside its runtime (container or host).
 * Defaults to loopback for bare-metal/dev runs. In the published container
 * image this is 0.0.0.0 so a TLS-terminating reverse proxy on the Compose
 * network can reach the app — that bind is container-internal and does NOT by
 * itself make plaintext externally reachable. External reachability is governed
 * by {@link publishHost} (the host-side publish mapping), which is what the
 * fail-closed guard below keys on.
 */
export function bindHost(): string {
  return process.env.SECRETVAULT_BIND_HOST?.trim() || "127.0.0.1";
}

/**
 * The HOST-side address port 3004 is published on (the Compose `ports:` left
 * side, i.e. `${SECRETVAULT_PUBLISH_HOST:-127.0.0.1}:3004:3004`). This is the
 * address that determines whether the plaintext listener is *externally*
 * reachable. It defaults to loopback; an operator must explicitly set it to a
 * non-loopback value to expose plaintext externally.
 *
 * For bare-metal/non-Compose deployments where there is no separate publish
 * mapping, the bind host itself is the externally reachable address, so we fall
 * back to {@link bindHost} when PUBLISH_HOST is unset.
 */
export function publishHost(): string {
  return process.env.SECRETVAULT_PUBLISH_HOST?.trim() || bindHost();
}

export function isLoopback(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

/**
 * Production plaintext guard. In production, when the plaintext (non-TLS)
 * listener is *externally reachable* — i.e. published on a non-loopback host
 * interface — it refuses to start unless the operator sets the explicit, noisy
 * override. Returns an error string when startup must abort, `null` when it may
 * proceed.
 *
 * Note (SV-AUD-001): exposure is judged from the publish host, not the
 * in-container bind host. A container may legitimately bind 0.0.0.0 (so a proxy
 * on its network can reach it) while publishing only on loopback; that topology
 * is safe and must not trip this guard.
 */
export function plaintextStartupError(nativeTls: boolean): string | null {
  if (nativeTls) return null;
  if (process.env.NODE_ENV !== "production") return null;

  const host = publishHost();
  if (isLoopback(host)) return null;

  const confirm = process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM;
  const allowed =
    process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL === "1" &&
    confirm === ALLOW_PLAINTEXT_EXTERNAL_CONFIRM;
  if (allowed) {
    console.warn(
      `[transport] WARNING: plaintext HTTP listener published on non-loopback ${host} ` +
        "(SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL=1). Only safe behind a TLS-terminating " +
        "reverse proxy on a trusted network.",
    );
    return null;
  }

  return (
    "Refusing to start: the production listener is plaintext (no SECRETVAULT_TLS_CERT/KEY) " +
    `and published on a non-loopback host interface (${host}). Externally reachable plaintext ` +
    "HTTP would expose passwords, sessions, setup codes, and step-up data. Terminate TLS with a " +
    "reverse proxy (see docs/install.md) and keep SECRETVAULT_PUBLISH_HOST=127.0.0.1, set " +
    "SECRETVAULT_TLS_CERT/KEY for native TLS, or set the development-only override " +
    "SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL=1 with SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM=" +
    `${ALLOW_PLAINTEXT_EXTERNAL_CONFIRM} if this is a trusted private network.`
  );
}

const HSTS_MAX_AGE = 31_536_000; // 1 year
const HSTS_HEADER = `max-age=${HSTS_MAX_AGE}; includeSubDomains`;

/**
 * Security headers applied to every response. HSTS is only emitted when the
 * request arrived over TLS (natively or via a proxy), so it never pins a
 * plaintext origin. Returns the headers without mutating the response so the
 * caller can merge them into its own header set.
 */
export function securityHeaders(req: IncomingMessage, nativeTls: boolean): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  };
  if (effectiveScheme(req, nativeTls) === "https") {
    headers["Strict-Transport-Security"] = HSTS_HEADER;
  }
  return headers;
}

/** Apply the security headers to a live response. */
export function applySecurityHeaders(req: IncomingMessage, res: ServerResponse, nativeTls: boolean): void {
  for (const [name, value] of Object.entries(securityHeaders(req, nativeTls))) {
    res.setHeader(name, value as string);
  }
}
