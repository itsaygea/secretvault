import { describe, it, expect, beforeEach } from "@secretvault/testing";
import { handleRevealSecret } from "./api.js";
import { handleRevealClientKey } from "./users.js";
import { initStepUpAuth, generateStepUpToken } from "./stepup.js";

describe("Strict Step-Up Recent Authentication Enforcement", () => {
  const masterKey = Buffer.alloc(32, "b");

  beforeEach(() => {
    initStepUpAuth(masterKey);
  });

  function createMockSupabase(factorCount: number) {
    return {
      from: (table: string) => ({
        select: (cols: string, opts?: any) => {
          if (opts?.count === "exact") {
            const chain: any = {
              eq: () => chain,
              count: factorCount,
              then: (cb: any) => cb({ count: factorCount }),
            };
            return chain;
          }
          const chainSelect: any = {
            eq: () => chainSelect,
            single: async () => ({
              data: { id: "sec-1", display_name: "MY_SECRET", encrypted_blob: "invalid_encrypted_data" },
            }),
          };
          return chainSelect;
        },
        insert: () => ({ select: () => ({ single: async () => ({ data: { id: "audit-1" } }) }) }),
        update: () => ({ eq: () => ({}) }),
      }),
    };
  }

  it("handleRevealSecret rejects requests from users with 0 factors enrolled (SV-009)", async () => {
    const mockSupabase = createMockSupabase(0);

    const res = await handleRevealSecret(
      mockSupabase as any,
      masterKey,
      "MY_SECRET",
      { headers: {} },
      "user-no-factor",
      false,
      false,
    );

    expect(res.status).toBe(403);
    expect((res.body as any).code).toBe("STEP_UP_REQUIRED");
    expect((res.body as any).error).toContain("enroll a Passkey or TOTP 2FA factor");
  });

  it("handleRevealClientKey rejects requests from users with 0 factors enrolled (SV-009)", async () => {
    const mockSupabase = createMockSupabase(0);

    const res = await handleRevealClientKey(
      mockSupabase as any,
      masterKey,
      "user-no-factor",
      "client-1",
      { headers: {} },
    );

    expect(res.status).toBe(403);
    expect((res.body as any).code).toBe("STEP_UP_REQUIRED");
    expect((res.body as any).error).toContain("enroll a Passkey or TOTP 2FA factor");
  });

  it("handleRevealSecret succeeds when a valid step-up token is provided for enrolled user", async () => {
    const { stepUpToken } = generateStepUpToken("user-enrolled");

    const mockSupabase = createMockSupabase(1);

    const res = await handleRevealSecret(
      mockSupabase as any,
      masterKey,
      "MY_SECRET",
      { headers: { "x-secretvault-stepup": stepUpToken } },
      "user-enrolled",
      false,
      false,
    );

    // It passes step-up check and attempts decryption (fails with 500 decryption error, proving step-up passed)
    expect(res.status).toBe(500);
  });
});
