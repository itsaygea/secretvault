import dns from "node:dns/promises";
import net from "node:net";
import ipaddr from "ipaddr.js";

export const SERVICE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/;
export const ALLOWED_PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;
export const DEFAULT_PROXY_METHODS = [...ALLOWED_PROXY_METHODS];
export const DEFAULT_PROXY_PATH_PREFIXES = ["/"];

export function parseEgressAllowlist(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(",").map(value => value.trim()).filter(Boolean).flatMap(value => {
    try {
      const url = new URL(value);
      if (!/[a-z]+:/.test(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) return [];
      return [url.origin];
    } catch {
      return [];
    }
  });
}

export function isTargetOriginAllowed(target: URL, allowedOrigins: string[]): boolean {
  return allowedOrigins.includes(target.origin);
}

export function isValidServiceName(name: string): boolean {
  return SERVICE_NAME_PATTERN.test(name);
}

/**
 * Canonical form for a service/profile identifier: lowercase ASCII.
 *
 * Service profile names are matched against proxy scopes, which the authz
 * layer normalizes to lowercase (normalizeScopes). If profile names were
 * stored with their original casing, a mixed-case profile could never be
 * authorized consistently — `/proxy/GitHub/...` resolves scope `proxy:GitHub`
 * while the granted scope is `proxy:github`, and `getProfileForProxy` would
 * query `name = 'GitHub'` against a row stored as `github`. Canonicalizing
 * the name at creation, lookup, scope generation, and in the URL segment
 * makes casing irrelevant and removes the ambiguity (SV-053).
 */
export function canonicalServiceName(name: string): string {
  return name.toLowerCase();
}

export function normalizeProxyMethods(methods: unknown): string[] {
  if (!Array.isArray(methods)) return [...DEFAULT_PROXY_METHODS];
  return [...new Set(methods
    .filter((method): method is string => typeof method === "string")
    .map(method => method.trim().toUpperCase())
    .filter(method => (ALLOWED_PROXY_METHODS as readonly string[]).includes(method)))];
}

export function validateProxyPathPrefixes(prefixes: unknown): { valid: boolean; prefixes: string[]; error?: string } {
  const normalized = Array.isArray(prefixes)
    ? [...new Set(prefixes.filter((prefix): prefix is string => typeof prefix === "string").map(prefix => prefix.trim()))]
    : [...DEFAULT_PROXY_PATH_PREFIXES];
  if (normalized.length === 0 || normalized.some(prefix =>
    !prefix.startsWith("/") || prefix.startsWith("//") || prefix.includes("\\") ||
    prefix.includes("#") || /%(?:2f|5c|23)/i.test(prefix))) {
    return { valid: false, prefixes: normalized, error: "allowed_path_prefixes must contain safe absolute path prefixes" };
  }
  return { valid: true, prefixes: normalized };
}

export function isProxyPathAllowed(pathname: string, prefixes: string[]): boolean {
  return prefixes.some(prefix => pathname === prefix || pathname.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`));
}

// ── SV-022: injected header/cookie name validation ─────────────────
// RFC 7230 field-name token: VCHAR minus separators, no obs-text/CTL.
const HEADER_NAME_PATTERN = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}$/;
// Conservative cookie-name token (RFC 6265 token grammar).
const COOKIE_NAME_PATTERN = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}$/;

/**
 * Reserved header names that a service profile must never be allowed to inject.
 * These either change request framing/routing semantics, belong to the hop-by-hop
 * set, or assert identity that the proxy owns (Host, Authorization, Cookie).
 */
const RESERVED_INJECTABLE_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding", "te", "trailer",
  "upgrade", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
  "authorization", "cookie", "set-cookie", "www-authenticate",
  "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-real-ip", "via", "x-request-id",
]);

export function isValidHeaderName(name: string): boolean {
  return HEADER_NAME_PATTERN.test(name) && !RESERVED_INJECTABLE_HEADERS.has(name.toLowerCase());
}

export function isValidCookieName(name: string): boolean {
  return COOKIE_NAME_PATTERN.test(name);
}

export function validateInjectedName(kind: "header" | "cookie", value: string | undefined | null): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  if (kind === "header") return isValidHeaderName(value) ? value : null;
  return isValidCookieName(value) ? value : null;
}

// ── SV-023: complete hop-by-hop + Connection-nominated header policy ─
const HOP_BY_HOP_HEADERS = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
]);

const FORWARDING_HEADERS = new Set([
  "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
  "x-forwarded-port", "x-forwarded-cluster", "x-real-ip", "via",
]);

/**
 * Field names nominated for removal by a Connection header. RFC 7230 §6.1 lists
 * Connection as a hop-by-hop header whose value also names further per-hop fields.
 */
function connectionNominatedFields(connection: string | undefined | null): Set<string> {
  const fields = new Set<string>();
  if (!connection) return fields;
  for (const part of connection.split(",")) {
    const name = part.trim().toLowerCase();
    if (name) fields.add(name);
  }
  return fields;
}

function shouldRemoveForwardingHeader(
  name: string,
  nominated: Set<string>,
  options: { stripForwarding: boolean },
): boolean {
  if (HOP_BY_HOP_HEADERS.has(name) || nominated.has(name)) return true;
  return options.stripForwarding && FORWARDING_HEADERS.has(name);
}

export interface HeaderSanitizeOptions {
  /** Remove spoofable X-Forwarded-* / Forwarded / Via fields (true for outbound requests). */
  stripForwarding?: boolean;
}

/**
 * Copy inbound headers into an outbound proxy request, dropping the complete
 * hop-by-hop set, every Connection-nominated field, caller credentials, and
 * forwarding headers the caller must not control. Returns a fresh record so the
 * caller can deterministically set Host, Authorization, etc.
 */
export function sanitizeRequestHeaders(
  inbound: Record<string, string | string[] | undefined>,
  options: HeaderSanitizeOptions = {},
): Record<string, string> {
  const connection = pickHeader(inbound, "connection");
  const nominated = connectionNominatedFields(connection);
  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(inbound)) {
    const lower = key.toLowerCase();
    if (rawValue === undefined) continue;
    if (RESERVED_INJECTABLE_HEADERS.has(lower)) continue;
    if (shouldRemoveForwardingHeader(lower, nominated, { stripForwarding: options.stripForwarding ?? true })) continue;
    out[key] = Array.isArray(rawValue) ? rawValue.join(", ") : rawValue;
  }
  return out;
}

// ── SV-AUD-003: value-based response redaction ─────────────────────
/**
 * Every rendering of an injected credential, for the life of one request.
 * Response redaction is value-based, not name-based: the upstream is not
 * trusted to keep credentials out of arbitrary header names or error bodies,
 * so we track each form the secret can take and drop anything that contains it.
 *
 * `lengthLowerBound` avoids a substring scan against trivially short fragments
 * that could false-positive on unrelated content; only renderings at least that
 * long are registered as scannable values.
 */
const MIN_SENSITIVE_SCAN_LENGTH = 6;

export interface SensitiveValueSet {
  /** Every scannable rendering (lowercased for case-insensitive substring match). */
  readonly values: ReadonlySet<string>;
  /** Track an additional raw value and derive its common renderings. */
  add: (raw: string) => void;
}

/**
 * Build a per-request sensitive-value tracker. The set is deliberately empty
 * until the caller registers the injected raw credentials — no shared state,
 * bounded to one request.
 */
export function createSensitiveValueSet(initial: Iterable<string> = []): SensitiveValueSet {
  const values = new Set<string>();
  const add = (raw: string): void => {
    const trimmed = raw?.trim();
    if (!trimmed || trimmed.length < MIN_SENSITIVE_SCAN_LENGTH) return;
    // Raw value (and case-folded) — covers bearer/header/cookie direct echoes.
    values.add(trimmed);
    values.add(trimmed.toLowerCase());
    // base64 rendering — covers Basic auth base64 echoed verbatim or in JSON.
    try {
      const b64 = Buffer.from(trimmed, "utf8").toString("base64");
      if (b64 && b64.length >= MIN_SENSITIVE_SCAN_LENGTH) values.add(b64);
    } catch { /* ignore encoding failures */ }
  };
  for (const v of initial) add(v);
  return { values, add };
}

/** True if the candidate text contains any tracked sensitive rendering. */
export function containsSensitiveValue(text: string, set: SensitiveValueSet | undefined): boolean {
  if (!set || text.length < MIN_SENSITIVE_SCAN_LENGTH) return false;
  const lowered = text.toLowerCase();
  for (const value of set.values) {
    if (value.length >= MIN_SENSITIVE_SCAN_LENGTH && lowered.includes(value)) return true;
  }
  return false;
}

export interface ResponseSanitizeOptions extends HeaderSanitizeOptions {
  /** Tracked injected-credential renderings; any response header containing one is dropped. */
  sensitiveValues?: SensitiveValueSet;
}

/**
 * Copy upstream response headers back to the client, dropping the complete
 * hop-by-hop set, every Connection-nominated field, credential-bearing headers
 * the upstream must not be allowed to set on the caller, AND (SV-AUD-003) any
 * header whose value contains a tracked injected credential regardless of name.
 */
export function sanitizeResponseHeaders(
  upstreamHeaders: Record<string, string | string[] | undefined>,
  options: ResponseSanitizeOptions = {},
): Record<string, string> {
  const connection = pickHeader(upstreamHeaders, "connection");
  const nominated = connectionNominatedFields(connection);
  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(upstreamHeaders)) {
    const lower = key.toLowerCase();
    if (rawValue === undefined) continue;
    if (shouldRemoveForwardingHeader(lower, nominated, { stripForwarding: options.stripForwarding ?? false })) continue;
    // Credentials/identity the proxy owns.
    if (lower === "set-cookie" || lower === "www-authenticate" || lower === "authorization" || lower === "cookie" || lower === "x-request-id") continue;
    const rendered = Array.isArray(rawValue) ? rawValue.join(", ") : rawValue;
    // SV-AUD-003: value-based redaction — drop any header echoing an injected credential.
    if (containsSensitiveValue(rendered, options.sensitiveValues)) continue;
    out[key] = rendered;
  }
  return out;
}

function pickHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) {
      return Array.isArray(value) ? value.join(", ") : value;
    }
  }
  return undefined;
}

// ── SV-024: centralized, throwing-safe percent decoding ─────────────
/**
 * Decode a percent-encoded path segment, returning null (never throwing) for
 * malformed sequences. Callers translate null into a stable 400 response.
 */
export function safeDecodePathSegment(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function normalizeHost(hostname: string): string {
  return hostname.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
}

// ── SV-AUD-004: byte/CIDR classification via ipaddr.js ──────────────
// Replaces the hand-written octet checks. Every non-global-unicast range is
// denied by default; classification runs on a canonicalized address so IPv4-
// mapped IPv6 (including the hex-compressed form `::ffff:7f00:1`) cannot slip
// a private destination past the IPv6 branch. ipaddr.js's range() does not
// classify the benchmarking/docs bands, so those are listed explicitly as CIDR.
const DENIED_IPV4_CIDRS: [ipaddr.IPv4, number][] = [
  "0.0.0.0/8",          // "this network" / unspecified-source band
  "10.0.0.0/8",         // RFC1918 private
  "100.64.0.0/10",      // RFC6598 carrier-grade NAT
  "127.0.0.0/8",        // loopback
  "169.254.0.0/16",     // link-local (incl. cloud metadata 169.254.169.254)
  "172.16.0.0/12",      // RFC1918 private
  "192.0.0.0/24",       // IETF protocol assignments
  "192.0.2.0/24",       // TEST-NET-1 documentation
  "192.168.0.0/16",     // RFC1918 private
  "198.18.0.0/15",      // RFC2544 benchmarking (not classified by ipaddr range())
  "198.51.100.0/24",    // TEST-NET-2 documentation
  "203.0.113.0/24",     // TEST-NET-3 documentation
  "240.0.0.0/4",        // reserved / future use (class E)
  "255.255.255.255/32", // limited broadcast
].map(cidr => ipaddr.parseCIDR(cidr) as [ipaddr.IPv4, number]);

const DENIED_IPV6_CIDRS: [ipaddr.IPv6, number][] = [
  "::/128",             // unspecified
  "::1/128",            // loopback
  "fc00::/7",           // unique-local (ULA)
  "fe80::/10",          // link-local
  "ff00::/8",           // multicast
  "::ffff:0:0/96",      // IPv4-mapped band — re-checked as IPv4 below after canonicalization
  "64:ff9b::/96",       // NAT64 well-known prefix
  "100::/64",           // discard-only prefix
  "2001:db8::/32",      // documentation
].map(cidr => ipaddr.parseCIDR(cidr) as [ipaddr.IPv6, number]);

/**
 * Classify a parsed address as non-global-unicast. IPv4-mapped IPv6 is
 * canonicalized to its IPv4 form first, so the underlying private destination
 * (loopback, RFC1918, etc.) is evaluated against the IPv4 denylist regardless
 * of whether the caller supplied dotted, hex, expanded, or compressed notation.
 */
function isNonGlobalUnicast(addr: ipaddr.IPv4 | ipaddr.IPv6): boolean {
  if (addr.kind() === "ipv4") {
    const v4 = addr as ipaddr.IPv4;
    return DENIED_IPV4_CIDRS.some(range => v4.match(range));
  }
  const v6 = addr as ipaddr.IPv6;
  if (DENIED_IPV6_CIDRS.some(range => v6.match(range))) return true;
  // IPv4-mapped IPv6 (range() === "ipv4Mapped"): convert and re-classify as
  // IPv4 so ::ffff:7f00:1 / ::ffff:a00:1 are denied as loopback / RFC1918.
  if (v6.range() === "ipv4Mapped") {
    const asV4 = v6.toIPv4Address();
    if (DENIED_IPV4_CIDRS.some(range => asV4.match(range))) return true;
  }
  return false;
}

function isBlockedIp(address: string): boolean {
  const host = normalizeHost(address);
  if (!net.isIP(host)) return false;
  try {
    return isNonGlobalUnicast(ipaddr.parse(host));
  } catch {
    return false;
  }
}

function isBlockedHostname(hostname: string): boolean {
  const host = normalizeHost(hostname);
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
    host.endsWith(".internal") || host === "metadata.google.internal";
}

export function validateTargetUrl(configuredTarget: string, allowPrivateNetwork = false): URL {
  const target = new URL(configuredTarget);
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error("target_url must use http or https");
  }
  if (target.protocol === "http:" && !allowPrivateNetwork) {
    throw new Error("target_url must use https unless private-network mode is explicitly enabled");
  }
  if (target.username || target.password || target.hash) {
    throw new Error("target_url must not contain userinfo or a fragment");
  }

  const host = normalizeHost(target.hostname);
  if (!allowPrivateNetwork && (isBlockedIp(host) || isBlockedHostname(host))) {
    throw new Error("target_url resolves to a private or local destination");
  }
  return target;
}

/** Resolve and return the exact address that the connection must use. */
export async function validateResolvedTarget(target: URL, allowPrivateNetwork = false): Promise<{ address: string; family: 4 | 6 }> {
  validateTargetUrl(target.toString(), allowPrivateNetwork);
  const host = normalizeHost(target.hostname);
  const literalFamily = net.isIP(host);
  if (literalFamily) return { address: host, family: literalFamily === 6 ? 6 : 4 };

  const addresses = await dns.lookup(host, { all: true, verbatim: true });
  if (addresses.length === 0) throw new Error("target_url did not resolve");
  if (!allowPrivateNetwork && addresses.some(address => isBlockedIp(address.address))) {
    throw new Error("target_url resolves to a private or local destination");
  }
  const selected = addresses[0];
  return { address: selected.address, family: selected.family === 6 ? 6 : 4 };
}

/**
 * Resolve only path/query data against the profile's configured origin.
 * URL's normal scheme-relative behavior is intentionally not used here.
 */
export function buildProxyTargetUrl(
  requestUrl: string | undefined,
  serviceName: string,
  configuredTarget: string,
): { targetUrl: URL; pathAndQuery: string } {
  if (!isValidServiceName(serviceName)) {
    throw new Error("Invalid service profile name");
  }

  const base = new URL(configuredTarget);
  if (!["http:", "https:"].includes(base.protocol) || base.username || base.password || base.hash) {
    throw new Error("Invalid configured upstream URL");
  }

  const rawUrl = requestUrl || `/proxy/${serviceName}/`;
  const prefix = `/proxy/${serviceName}`;
  if (!rawUrl.startsWith(prefix)) {
    throw new Error("Proxy path does not match service profile");
  }

  let pathAndQuery = rawUrl.slice(prefix.length) || "/";
  if (pathAndQuery.startsWith("?")) pathAndQuery = `/${pathAndQuery}`;

  if (
    !pathAndQuery.startsWith("/") ||
    pathAndQuery.startsWith("//") ||
    pathAndQuery.includes("\\") ||
    pathAndQuery.includes("#") ||
    /%(?:2f|5c|23|40|3f)/i.test(pathAndQuery)
  ) {
    throw new Error("Invalid proxy path");
  }

  const targetUrl = new URL(pathAndQuery, base);
  if (targetUrl.origin !== base.origin || targetUrl.username || targetUrl.password || targetUrl.hash) {
    throw new Error("Proxy path changed the configured upstream origin");
  }

  return { targetUrl, pathAndQuery };
}
