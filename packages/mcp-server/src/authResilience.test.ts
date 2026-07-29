import { describe, it, expect } from "vitest";
import { rateLimiter } from "./rateLimit.js";
import { sessionRevocation } from "./sessionRevocation.js";
import { handleTotpAuthenticate, initStepUpAuth } from "./stepup.js";
import { encryptSecret } from "@secretvault/shared";

describe("Authentication Resilience, Rate Limiting & Session Revocation", () => {
  it("rateLimiter enforces sliding window limits and returns Retry-After", () => {
    rateLimiter.clear();
    const opts = { windowMs: 60_000, maxRequests: 3 };

    expect(rateLimiter.check("ip-127.0.0.1", opts).allowed).toBe(true);
    expect(rateLimiter.check("ip-127.0.0.1", opts).allowed).toBe(true);
    expect(rateLimiter.check("ip-127.0.0.1", opts).allowed).toBe(true);

    const check4 = rateLimiter.check("ip-127.0.0.1", opts);
    expect(check4.allowed).toBe(false);
    expect(check4.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("sessionRevocation invalidates sessions issued before revocation timestamp", () => {
    sessionRevocation.clear();
    const tokenTime = Date.now() - 1000;

    expect(sessionRevocation.isTokenRevoked("user-bob", tokenTime)).toBe(false);

    sessionRevocation.revokeAllUserSessions("user-bob");

    expect(sessionRevocation.isTokenRevoked("user-bob", tokenTime)).toBe(true);
    expect(sessionRevocation.isTokenRevoked("user-bob", Date.now() + 1000)).toBe(false);
  });

  it("handleTotpAuthenticate skips backup code bcrypt scans for 6-digit TOTP inputs (SV-010)", async () => {
    const masterKey = Buffer.alloc(32, "c");
    initStepUpAuth(masterKey);
    const { encrypted } = await encryptSecret("JBSWY3DPEHPK3PXP", masterKey);
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
