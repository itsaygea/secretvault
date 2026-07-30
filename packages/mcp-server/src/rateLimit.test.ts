import { describe, it, expect } from "vitest";
import {
  RateLimiter,
  MemoryRateLimitStore,
  parseTrustedProxies,
  resolveClientIp,
  isTrustedProxy,
  type Clock,
} from "./rateLimit.js";

// SV-AUD-011 rate-limit behaviour. The production store is Postgres-backed
// (asserted by the CI integration stack), but every property below is enforced
// by the limiter logic itself and is verified here against a SHARED in-memory
// store — including the cross-replica property, since two `RateLimiter`
// instances over one store is exactly two replicas over one database.

const OPTS = { windowMs: 60_000, maxRequests: 3, cooldownMs: 4_000, maxCooldownMs: 60_000 };

function fakeClock(start = 1_700_000_000_000): Clock & { advance(ms: number): void; set(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => { t += ms; },
    set: (ms) => { t = ms; },
  };
}

describe("rate limiter — window & cooldown", () => {
  it("allows up to the cap, then denies with a positive Retry-After", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter(new MemoryRateLimitStore(), clock);
    for (let i = 0; i < OPTS.maxRequests; i++) {
      expect((await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS)).allowed).toBe(true);
    }
    const denied = await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeGreaterThan(0);
    expect(denied.remaining).toBe(0);
  });

  it("resets after the window elapses (fake-clock boundary)", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter(new MemoryRateLimitStore(), clock);
    for (let i = 0; i < OPTS.maxRequests; i++) await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS);
    expect((await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS)).allowed).toBe(false);
    clock.advance(OPTS.windowMs + 1); // new window, but cooldown may still bite
    // Advance past the seeded cooldown too.
    clock.advance(OPTS.maxCooldownMs);
    expect((await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS)).allowed).toBe(true);
  });

  it("succeeds again after the cooldown elapses (recovery, no permanent lockout)", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter(new MemoryRateLimitStore(), clock);
    // Trip the limit and seed a cooldown.
    for (let i = 0; i < OPTS.maxRequests + 2; i++) await limiter.check({ scope: "login", ip: "9.9.9.9", identity: "u" }, OPTS);
    const whileCooling = await limiter.check({ scope: "login", ip: "9.9.9.9", identity: "u" }, OPTS);
    expect(whileCooling.allowed).toBe(false);
    expect(whileCooling.retryAfterSeconds).toBeGreaterThan(0);
    // Cool down fully; a fresh, valid attempt must be allowed again.
    clock.advance(OPTS.maxCooldownMs + OPTS.windowMs);
    expect((await limiter.check({ scope: "login", ip: "9.9.9.9", identity: "u" }, OPTS)).allowed).toBe(true);
  });

  it("cooldown is bounded — never exceeds maxCooldownMs", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter(new MemoryRateLimitStore(), clock);
    // Hammer far past the cap; the Retry-After must stay within the cap.
    for (let i = 0; i < OPTS.maxRequests + 100; i++) await limiter.check({ scope: "totp", ip: "8.8.8.8", identity: "u" }, OPTS);
    const denied = await limiter.check({ scope: "totp", ip: "8.8.8.8", identity: "u" }, OPTS);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeLessThanOrEqual(Math.ceil(OPTS.maxCooldownMs / 1000));
  });
});

describe("rate limiter — concurrency & cross-replica", () => {
  it("concurrent requests cannot exceed the limit (exact count)", async () => {
    const shared = new MemoryRateLimitStore();
    const limiter = new RateLimiter(shared, fakeClock());
    const N = 50;
    const results = await Promise.all(
      Array.from({ length: N }, () => limiter.check({ scope: "login", ip: "5.5.5.5", identity: "u" }, OPTS)),
    );
    const allowed = results.filter((r) => r.allowed).length;
    // Exactly maxRequests allowed — the atomic store increments are serialized.
    expect(allowed).toBe(OPTS.maxRequests);
  });

  it("two limiter instances over ONE shared store enforce jointly (replica property)", async () => {
    const shared = new MemoryRateLimitStore();
    const clock = fakeClock();
    const replicaA = new RateLimiter(shared, clock);
    const replicaB = new RateLimiter(shared, clock);
    const parts = { scope: "totp" as const, ip: "7.7.7.7", identity: "u" };
    // Interleave charges across the two replicas.
    const calls = [];
    for (let i = 0; i < OPTS.maxRequests; i++) calls.push(replicaA.check(parts, OPTS));
    for (let i = 0; i < OPTS.maxRequests; i++) calls.push(replicaB.check(parts, OPTS));
    const results = await Promise.all(calls);
    const allowed = results.filter((r) => r.allowed).length;
    // Shared store means the combined budget is the cap, not 2× the cap.
    expect(allowed).toBe(OPTS.maxRequests);
  });
});

describe("rate limiter — trusted source-IP keying", () => {
  it("spoofed X-Forwarded-For cannot rotate identity on a direct connection", () => {
    // No trusted proxy configured → header must be ignored; the peer address is used.
    const config = parseTrustedProxies("");
    const spoofed = {
      headers: { "x-forwarded-for": "204.0.0.1" }, // attacker tries to mint a fresh identity
      socket: { remoteAddress: "10.0.0.99" },
    };
    expect(resolveClientIp(spoofed, config)).toBe("10.0.0.99");
    expect(isTrustedProxy("10.0.0.99", config)).toBe(false);
  });

  it("X-Forwarded-For IS honored when the peer is a configured trusted proxy", () => {
    const config = parseTrustedProxies("10.0.0.0/8");
    const proxied = {
      headers: { "x-forwarded-for": "203.0.113.7" },
      socket: { remoteAddress: "10.0.0.5" }, // peer inside the trusted CIDR
    };
    expect(isTrustedProxy("10.0.0.5", config)).toBe(true);
    expect(resolveClientIp(proxied, config)).toBe("203.0.113.7");
  });

  it("different source IPs key to different buckets (no cross-contamination)", async () => {
    const limiter = new RateLimiter(new MemoryRateLimitStore(), fakeClock());
    for (let i = 0; i < OPTS.maxRequests; i++) await limiter.check({ scope: "login", ip: "1.1.1.1", identity: "u" }, OPTS);
    expect((await limiter.check({ scope: "login", ip: "1.1.1.1", identity: "u" }, OPTS)).allowed).toBe(false);
    // A different IP is a separate bucket and must still be allowed.
    expect((await limiter.check({ scope: "login", ip: "2.2.2.2", identity: "u" }, OPTS)).allowed).toBe(true);
  });

  it("CIDR matching handles IPv4-mapped IPv6 peers", () => {
    const config = parseTrustedProxies("10.0.0.0/8");
    // A dual-stack connection presents the peer as an IPv4-mapped IPv6 address.
    expect(isTrustedProxy("::ffff:10.0.0.5", config)).toBe(true);
    expect(isTrustedProxy("::ffff:11.0.0.5", config)).toBe(false);
  });
});

describe("rate limiter — store failure is fail-closed", () => {
  it("denies when the shared store is unreachable", async () => {
    const broken = {
      charge: async () => { throw new Error("db down"); },
      setCooldown: async () => { throw new Error("db down"); },
    };
    const limiter = new RateLimiter(broken as any, fakeClock());
    const res = await limiter.check({ scope: "login", ip: "1.2.3.4", identity: "u" }, OPTS);
    expect(res.allowed).toBe(false);
    expect(res.storeError).toBe(true);
    expect(res.retryAfterSeconds).toBeGreaterThan(0);
  });
});
