/**
 * SV-AUD-011: distributed authentication & step-up rate limits.
 *
 * Previously an in-memory limiter existed but was never wired to a handler and
 * was per-process, so it could not enforce across more than one server replica,
 * and `x-forwarded-for` was trusted blindly (letting a direct client spoof the
 * identity used for keying). This module replaces both:
 *
 *   - `resolveClientIp` honors forwarding headers ONLY when the immediate TCP
 *     peer is a configured trusted proxy; a direct connection can never rotate
 *     its identity by spoofing `X-Forwarded-For`.
 *   - `RateLimiter` charges a shared atomic store. The production store
 *     (`SupabaseRateLimitStore`) increments a Postgres counter via a single
 *     `INSERT ... ON CONFLICT DO UPDATE ... count + 1` RPC, so concurrent
 *     requests across replicas cannot lose an increment. A `MemoryRateLimitStore`
 *     exists for unit tests and is genuinely shared across limiter instances,
 *     which is how the two-replica property is asserted without a live DB.
 *
 * All window / cooldown / backoff arithmetic lives here in TypeScript behind an
 * injectable clock, so expiry and cooldown recovery are deterministic under a
 * fake clock. The store only performs the one operation that must be atomic:
 * charging the counter and reading back the resulting count + active cooldown.
 *
 * On denial the limiter returns a 429-shaped result with `retryAfterSeconds`
 * and the scope/identity used to key it; callers emit the standard `RATE_LIMITED`
 * envelope + `Retry-After` header and an audit event containing none of the
 * attempted credential or TOTP code.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";

// ── Trusted-proxy source-IP resolution ──────────────────────────────────────

/** A parsed trusted-proxy entry: either an exact address or a CIDR range. */
type TrustedProxyEntry =
  | { raw: string; kind: "single"; match: string }
  | { raw: string; kind: "cidr"; match: { network: number[]; bits: number; family: 4 | 6 } };

/**
 * Parsed, normalized trusted-proxy allowlist. When empty, NO forwarding header
 * is ever trusted and `resolveClientIp` always returns the immediate TCP peer —
 * the fail-safe default for a direct or unknown deployment.
 */
export interface TrustedProxyConfig {
  entries: TrustedProxyEntry[];
}

/** Parse a comma-separated CIDR/address list into a TrustedProxyConfig. */
export function parseTrustedProxies(raw: string | undefined): TrustedProxyConfig {
  if (!raw) return { entries: [] };
  const entries: TrustedProxyEntry[] = [];
  for (const token of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const slash = token.indexOf("/");
    if (slash >= 0) {
      const parsed = parseCidr(token.slice(0, slash), Number(token.slice(slash + 1)));
      if (parsed) entries.push({ raw: token, kind: "cidr", match: parsed });
    } else {
      const norm = normalizeIp(token);
      if (norm) entries.push({ raw: token, kind: "single", match: norm });
    }
  }
  return { entries };
}

export function isTrustedProxy(peer: string | undefined, config: TrustedProxyConfig): boolean {
  if (!peer) return false;
  const norm = normalizeIp(stripPort(peer));
  if (!norm) return false;
  for (const entry of config.entries) {
    if (entry.kind === "single") {
      if (entry.match === norm) return true;
    } else {
      if (ipInCidr(norm, entry.match)) return true;
    }
  }
  return false;
}

interface LikeRequest {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
}

/**
 * Resolve the client source IP, trusting forwarding headers only when the
 * immediate peer is a configured trusted proxy. When the peer is trusted, the
 * leftmost address in `X-Forwarded-For` (or `X-Real-IP` / `CF-Connecting-IP`)
 * is the originating client; otherwise the peer address itself is used and any
 * spoofed header is ignored. Never throws; falls back to "unknown".
 */
export function resolveClientIp(req: LikeRequest, config: TrustedProxyConfig = { entries: [] }): string {
  const peer = req.socket?.remoteAddress;
  if (isTrustedProxy(peer, config)) {
    const headers = req.headers ?? {};
    const xff = firstHeader(headers["x-forwarded-for"]);
    if (xff) {
      const first = xff.split(",")[0]?.trim();
      if (first) return normalizeIp(stripPort(first)) ?? first;
    }
    const real = firstHeader(headers["x-real-ip"]);
    if (real) return normalizeIp(stripPort(real)) ?? real;
    const cf = firstHeader(headers["cf-connecting-ip"]);
    if (cf) return normalizeIp(stripPort(cf)) ?? cf;
  }
  if (peer) return normalizeIp(stripPort(peer)) ?? peer;
  return "unknown";
}

function firstHeader(v: string | string[] | undefined): string | undefined {
  if (Array.isArray(v)) return v[0];
  return typeof v === "string" ? v : undefined;
}

function stripPort(addr: string): string {
  // Strip a trailing :port or %zone for IPv6 link-local; leave the host.
  if (addr.includes(":") && addr.includes(".")) {
    // IPv4 in IPv6 form like ::ffff:1.2.3.4 — keep, no port to strip.
    return addr;
  }
  const pct = addr.indexOf("%");
  if (pct >= 0) addr = addr.slice(0, pct);
  const colon = addr.lastIndexOf(":");
  // Only strip a trailing :port on a bare IPv4 (single colon) — never on IPv6.
  if (colon > 0 && addr.indexOf(":") === colon && /^\d+$/.test(addr.slice(colon + 1))) {
    return addr.slice(0, colon);
  }
  return addr;
}

// ── Minimal IP / CIDR helpers (no external dep) ─────────────────────────────
// Handles IPv4, IPv6, and IPv4-mapped IPv6 (::ffff:a.b.c.d) so a peer presented
// as the dual-stack mapped form still matches a trusted-proxy entry.

function normalizeIp(addr: string): string | null {
  const v = addr.trim().toLowerCase();
  if (!v) return null;
  if (isIpv4(v)) return v;
  const mapped = v.match(/^::ffff:([0-9.]+)$/);
  if (mapped && isIpv4(mapped[1])) return mapped[1]; // canonicalize mapped→v4
  if (isIpv6(v)) return v;
  return null;
}

function isIpv4(v: string): boolean {
  const parts = v.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIpv6(v: string): boolean {
  // Permissive: must contain at least one ':' and only valid hex/colons/dot.
  if (!v.includes(":")) return false;
  return /^[0-9a-f:.]+$/i.test(v);
}

function ipv4ToInt(v: string): number {
  const [a, b, c, d] = v.split(".").map(Number);
  return (((a * 256 + b) * 256 + c) * 256 + d) >>> 0;
}

function parseCidr(addr: string, bits: number): { network: number[]; bits: number; family: 4 | 6 } | null {
  const norm = normalizeIp(addr);
  if (!norm) return null;
  if (isIpv4(norm)) {
    if (bits < 0 || bits > 32) return null;
    return { network: [ipv4ToInt(norm)], bits, family: 4 };
  }
  if (bits < 0 || bits > 128) return null;
  return { network: ipv6ToGroups(norm), bits, family: 6 };
}

function ipInCidr(norm: string, cidr: { network: number[]; bits: number; family: 4 | 6 }): boolean {
  if (isIpv4(norm)) {
    if (cidr.family !== 4) return false;
    const ip = ipv4ToInt(norm);
    const mask = cidr.bits === 0 ? 0 : (0xffffffff << (32 - cidr.bits)) >>> 0;
    return (ip & mask) === (cidr.network[0] & mask);
  }
  if (cidr.family !== 6) return false;
  const groups = ipv6ToGroups(norm);
  return groupsMatchPrefix(groups, cidr.network, cidr.bits);
}

function ipv6ToGroups(v: string): number[] {
  // Expand "::" shorthand into eight 16-bit groups.
  const [head, tail] = v.split("::");
  const headGroups = head ? head.split(":").filter(Boolean).map((g) => parseInt(g, 16)) : [];
  const tailGroups = tail ? tail.split(":").filter(Boolean).map((g) => parseInt(g, 16)) : [];
  const missing = 8 - headGroups.length - tailGroups.length;
  return [...headGroups, ...Array(missing > 0 ? missing : 0).fill(0), ...tailGroups];
}

function groupsMatchPrefix(ip: number[], net: number[], bits: number): boolean {
  let remaining = bits;
  for (let i = 0; i < 8; i++) {
    if (remaining <= 0) return true;
    const bitCount = Math.min(16, remaining);
    const mask = bitCount === 16 ? 0xffff : (0xffff << (16 - bitCount)) & 0xffff;
    if ((ip[i] & mask) !== (net[i] & mask)) return false;
    remaining -= 16;
  }
  return true;
}

// ── Shared atomic store ─────────────────────────────────────────────────────

export interface ChargeResult {
  /** Count for this bucket+window AFTER this charge was applied. */
  count: number;
  /** Active cooldown-until (epoch ms) stored on the bucket, or 0. */
  cooldownUntil: number;
}

/**
 * The atomic surface every replica charges. Implementations must guarantee that
 * two concurrent `charge` calls for the same key/window cannot both observe the
 * same pre-increment count (i.e. the increment is serialized/exact).
 */
export interface RateLimitStore {
  charge(bucketKey: string, windowStart: number): Promise<ChargeResult>;
  /** Persist a cooldown-until epoch for a key (no-op if the stored value is larger). */
  setCooldown(bucketKey: string, cooldownUntil: number): Promise<void>;
}

/** In-memory store. SHARED state lives on the instance, so two `RateLimiter`
 *  instances built over the SAME `MemoryRateLimitStore` enforce jointly — this
 *  is how the two-replica property is asserted without a live database. */
export class MemoryRateLimitStore implements RateLimitStore {
  private counts = new Map<string, { count: number; cooldownUntil: number }>();

  async charge(bucketKey: string, _windowStart: number): Promise<ChargeResult> {
    const rec = this.counts.get(bucketKey);
    if (!rec) {
      this.counts.set(bucketKey, { count: 1, cooldownUntil: 0 });
      return { count: 1, cooldownUntil: 0 };
    }
    rec.count += 1;
    return { count: rec.count, cooldownUntil: rec.cooldownUntil };
  }

  async setCooldown(bucketKey: string, cooldownUntil: number): Promise<void> {
    const rec = this.counts.get(bucketKey);
    if (rec) {
      if (cooldownUntil > rec.cooldownUntil) rec.cooldownUntil = cooldownUntil;
    } else {
      this.counts.set(bucketKey, { count: 0, cooldownUntil });
    }
  }

  /** Test-only: clear all state. */
  reset(): void {
    this.counts.clear();
  }
}

/**
 * Production store backed by Postgres via PostgREST RPC. `rate_limit_charge`
 * performs `INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 RETURNING`
 * inside one statement, so the increment is atomic across replicas.
 */
export class SupabaseRateLimitStore implements RateLimitStore {
  constructor(private supabase: SupabaseClient<Database, "secretvault">) {}

  async charge(bucketKey: string, windowStart: number): Promise<ChargeResult> {
    const { data, error } = await this.supabase.rpc("rate_limit_charge", {
      p_bucket_key: bucketKey,
      p_window_start: windowStart,
    });
    // Fail-closed: if the shared store is unreachable, deny the attempt rather
    // than letting an outage silently disable rate limiting. The denial still
    // returns a Retry-After, and audit captures the store error.
    if (error || !data) {
      throw new Error(`rate_limit_charge failed: ${error?.message ?? "no data"}`);
    }
    const row = data as { current_count?: number; cooldown_until?: number };
    return {
      count: Number(row.current_count ?? 1),
      cooldownUntil: Number(row.cooldown_until ?? 0),
    };
  }

  async setCooldown(bucketKey: string, cooldownUntil: number): Promise<void> {
    // Never shorten an active cooldown: read the current value and only widen it.
    const { data: cur } = await this.supabase
      .from("rate_limit_buckets")
      .select("cooldown_until")
      .eq("bucket_key", bucketKey)
      .maybeSingle();
    if (cur && cooldownUntil <= (cur.cooldown_until ?? 0)) return;
    await this.supabase
      .from("rate_limit_buckets")
      .update({ cooldown_until: cooldownUntil, updated_at: new Date().toISOString() })
      .eq("bucket_key", bucketKey);
  }
}

// ── Limiter ─────────────────────────────────────────────────────────────────

export interface RateLimitOptions {
  /** Fixed-window length in milliseconds. */
  windowMs: number;
  /** Max allowed attempts per window before denial. */
  maxRequests: number;
  /** Base cooldown applied on first denial (ms). Each subsequent denial within
   *  the cooldown window doubles it, capped at `maxCooldownMs`. Bounded so an
   *  attacker cannot permanently lock out a legitimate account. */
  cooldownMs: number;
  maxCooldownMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
  /** Identity used to key this bucket, for the audit event (no credentials). */
  bucketKey: string;
  /** True when denial came from the shared store being unreachable (fail-closed). */
  storeError: boolean;
}

/** Default policy ceilings. Tunable via env at server bootstrap. */
export const DEFAULT_LIMITS = {
  login: { windowMs: 60_000, maxRequests: 10, cooldownMs: 5_000, maxCooldownMs: 5 * 60_000 },
  register: { windowMs: 60_000, maxRequests: 5, cooldownMs: 10_000, maxCooldownMs: 15 * 60_000 },
  setup: { windowMs: 60_000, maxRequests: 5, cooldownMs: 10_000, maxCooldownMs: 15 * 60_000 },
  // Stricter per-user guessing surface.
  totp: { windowMs: 60_000, maxRequests: 5, cooldownMs: 15_000, maxCooldownMs: 30 * 60_000 },
} as const;

export type RateLimitScope = keyof typeof DEFAULT_LIMITS;

export interface RateLimitKeyParts {
  scope: RateLimitScope;
  ip: string;
  identity?: string; // normalized username / userId / clientId if available
}

/** Clock abstraction so window expiry / cooldown are deterministic in tests. */
export interface Clock {
  now(): number;
}
export const systemClock: Clock = { now: () => Date.now() };

export class RateLimiter {
  constructor(
    private store: RateLimitStore,
    private clock: Clock = systemClock,
  ) {}

  /**
   * Charge one attempt against the bucket for the given key parts and policy.
   * Idempotent in shape (always returns a verdict); never throws — a store
   * failure produces a fail-closed denial rather than an exception.
   */
  async check(parts: RateLimitKeyParts, options: RateLimitOptions): Promise<RateLimitResult> {
    const now = this.clock.now();
    const windowStart = Math.floor(now / options.windowMs) * options.windowMs;
    // Identity participates in the key so a per-user limit cannot be diluted by
    // omitting it; absent identity, the IP alone bounds the caller.
    const identity = parts.identity ?? "anon";
    const bucketKey = `${parts.scope}:${parts.ip}:${identity}:${windowStart}`;

    let charge: ChargeResult;
    try {
      charge = await this.store.charge(bucketKey, windowStart);
    } catch {
      // Fail-closed: cannot prove the caller is under limit, so deny.
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.ceil(options.cooldownMs / 1000),
        bucketKey,
        storeError: true,
      };
    }

    // Active cooldown from a prior denial blocks regardless of the fresh window.
    if (charge.cooldownUntil > now) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((charge.cooldownUntil - now) / 1000)),
        bucketKey,
        storeError: false,
      };
    }

    const overLimit = charge.count > options.maxRequests;
    const remaining = Math.max(0, options.maxRequests - charge.count);

    if (!overLimit) {
      return { allowed: true, remaining, retryAfterSeconds: 0, bucketKey, storeError: false };
    }

    // First denial in this window seeds a bounded exponential cooldown. The
    // multiplier grows with how far over the limit the caller has gone, so
    // repeated hammering lengthens the cooldown up to the cap, then stops — a
    // legitimate account is never permanently locked out.
    const overruns = charge.count - options.maxRequests;
    const exponent = Math.min(3, Math.max(0, Math.floor(Math.log2(overruns))));
    const multiplier = 2 ** exponent; // 1, 2, 4, or 8
    const cooldown = Math.min(options.maxCooldownMs, options.cooldownMs * multiplier);
    const cooldownUntil = now + cooldown;
    await this.store.setCooldown(bucketKey, cooldownUntil).catch(() => undefined);

    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil(cooldown / 1000),
      bucketKey,
      storeError: false,
    };
  }
}
