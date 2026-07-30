import { describe, it, expect } from "vitest";
import { RateLimiter, MemoryRateLimitStore, type Clock } from "./rateLimit.js";
import { encryptSecret, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { handleTotpAuthenticate, initStepUpAuth } from "./stepup.js";

describe("Authentication Resilience, Rate Limiting & Session Revocation", () => {
  it("rate limiter enforces the per-window cap and returns Retry-After", async () => {
    const store = new MemoryRateLimitStore();
    const limiter = new RateLimiter(store);
    const opts = { windowMs: 60_000, maxRequests: 3, cooldownMs: 5_000, maxCooldownMs: 60_000 };

    expect((await limiter.check({ scope: "login", ip: "127.0.0.1", identity: "alice" }, opts)).allowed).toBe(true);
    expect((await limiter.check({ scope: "login", ip: "127.0.0.1", identity: "alice" }, opts)).allowed).toBe(true);
    expect((await limiter.check({ scope: "login", ip: "127.0.0.1", identity: "alice" }, opts)).allowed).toBe(true);

    const denied = await limiter.check({ scope: "login", ip: "127.0.0.1", identity: "alice" }, opts);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("handleTotpAuthenticate skips backup code bcrypt scans for 6-digit TOTP inputs (SV-010)", async () => {
    const masterKey = Buffer.alloc(32, "c");
    initStepUpAuth(masterKey);
    const { encrypted } = await encryptSecret("JBSWY3DPEHPK3PXP", masterKey, {
      purpose: ENCRYPTION_PURPOSE.TOTP_PENDING,
      aad: buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: "user-1", recordId: "user-1" }),
    });
    let backupTableQueried = false;

    const mockSupabase: any = {
      from: (table: string) => {
        if (table === "totp_backup_codes") {
          backupTableQueried = true;
          return {
            select: () => ({
              eq: () => Promise.resolve({ data: [{ id: "bc-1", code_hash: "$2a$12$invalidhashcode..." }] }),
            }),
            delete: () => ({ eq: () => ({ eq: () => ({ select: () => ({ maybeSingle: async () => ({ data: null }) }) }) }) }),
          };
        }
        if (table === "access_logs") {
          return {
            insert: () => ({
              select: () => ({ single: async () => ({ data: { id: "audit-1" }, error: null }) }),
            }),
          };
        }
        return {
          select: () => ({
            eq: () => ({
              eq: () => ({
                maybeSingle: async () => ({
                  data: {
                    id: "totp-1",
                    secret_encrypted: encrypted,
                    verified: true,
                  },
                }),
              }),
            }),
          }),
        };
      },
    };

    // Passing invalid 6-digit TOTP input "123456" must not touch backup rows
    const res = await handleTotpAuthenticate(mockSupabase, Buffer.alloc(32, "c"), "user-1", { code: "123456" });
    expect(res.status).toBe(401);
    expect(backupTableQueried).toBe(false);
  });
});
