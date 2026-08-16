import { describe, expect, it } from "@secretvault/testing";
import { generateStepUpToken, verifyStepUpToken, verifyStepUpTokenForResource, initStepUpAuth } from "./stepup.js";
import { handleRegenerateClientKey, handleRevealClientKey } from "./users.js";

// Initialize the step-up HMAC key from a deterministic master key so token
// generation/verification is reproducible in this test process.
initStepUpAuth(Buffer.from("a".repeat(64), "hex"));

describe("resource-bound step-up tokens (SV-016)", () => {
  it("verifies a legacy token with no resource claim", () => {
    const { stepUpToken } = generateStepUpToken("user-1");
    expect(verifyStepUpToken(stepUpToken, "user-1")).toBe(true);
    // A legacy token is accepted for any resource (backward compatibility) but
    // is still user-bound.
    expect(verifyStepUpTokenForResource(stepUpToken, "user-1", "client-A")).toBe(true);
  });

  it("binds a resource-bound token to exactly that resource", () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-A");
    expect(verifyStepUpTokenForResource(stepUpToken, "user-1", "client-A")).toBe(true);
    // Wrong resource → rejected. This is the replay guard the ticket requires.
    expect(verifyStepUpTokenForResource(stepUpToken, "user-1", "client-B")).toBe(false);
  });

  it("rejects a token minted for a different user", () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-A");
    expect(verifyStepUpTokenForResource(stepUpToken, "user-2", "client-A")).toBe(false);
  });

  it("rejects a tampered resource claim", () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-A");
    // Swap the resource segment; signature no longer matches.
    const parts = stepUpToken.split(".");
    parts[4] = "client-B";
    const tampered = parts.join(".");
    expect(verifyStepUpTokenForResource(tampered, "user-1", "client-B")).toBe(false);
  });
});

/**
 * Minimal supabase mock for the regenerate/reveal handlers. The handlers issue
 * a bounded chain: select(...).eq(...).maybeSingle() for the client row, then
 * update(...).eq(...).eq(...).select(...).maybeSingle() for the atomic write.
 */
function mockSupabaseForRegen(opts: { found: boolean; updateMatched: boolean; updateError?: string }) {
  // A count query (factor-enrollment check on the reveal fallback path).
  const countResult = { count: 0 };
  const eqChain = {
    maybeSingle: async () => opts.found
      ? { data: { id: "client-1", app_name: "app", key_version: 1 } }
      : { data: null },
    // Additional .eq() calls are chainable and idempotent so the row-select
    // path (which chains two eqs before maybeSingle) works. On a count select,
    // the terminal awaitable resolves the count.
    eq: () => eqChain,
    then: (resolve: (v: any) => void) => resolve(countResult),
  };
  const builder = {
    select: () => ({ eq: () => eqChain }),
    update: () => ({
      eq: () => ({
        eq: () => ({
          select: () => ({
            maybeSingle: async () => {
              if (opts.updateError) return { data: null, error: { message: opts.updateError } };
              return opts.updateMatched ? { data: { id: "client-1" }, error: null } : { data: null, error: null };
            },
          }),
        }),
      }),
    }),
    insert: () => ({ select: () => ({ single: async () => ({ data: { id: "audit-1" }, error: null }) }) }),
  };
  return {
    from: (table: string) => {
      if (table === "access_logs") {
        return {
          insert: builder.insert,
          update: () => ({ eq: () => Promise.resolve({ error: null }) }),
          select: () => ({ eq: () => ({ eq: () => Promise.resolve(countResult) }) }),
        };
      }
      return builder;
    },
  } as any;
}

describe("client key regeneration lifecycle (SV-016)", () => {
  const masterKey = Buffer.from("b".repeat(64), "hex");

  it("rejects regeneration without a client-bound step-up", async () => {
    const supabase = mockSupabaseForRegen({ found: true, updateMatched: true });
    const res = await handleRegenerateClientKey(supabase, masterKey, "user-1", "client-1", { headers: {} });
    expect(res.status).toBe(403);
  });

  it("rejects regeneration when the step-up is bound to a different client", async () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-OTHER");
    const supabase = mockSupabaseForRegen({ found: true, updateMatched: true });
    const res = await handleRegenerateClientKey(supabase, masterKey, "user-1", "client-1", {
      headers: { "x-secretvault-stepup": stepUpToken },
    });
    expect(res.status).toBe(403);
  });

  it("regenerates and returns a one-time key when bound step-up is present", async () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-1");
    const supabase = mockSupabaseForRegen({ found: true, updateMatched: true });
    const res = await handleRegenerateClientKey(supabase, masterKey, "user-1", "client-1", {
      headers: { "x-secretvault-stepup": stepUpToken },
    });
    expect(res.status).toBe(200);
    const body = res.body as any;
    expect(body.regenerated).toBe(true);
    expect(body.linking_key).toMatch(/^sv_/);
  });

  it("returns 409 when a concurrent regeneration won the version race", async () => {
    const { stepUpToken } = generateStepUpToken("user-1", "client-1");
    // updateMatched: false → the conditional UPDATE matched zero rows because
    // the version moved under us. No key material was changed on our behalf.
    const supabase = mockSupabaseForRegen({ found: true, updateMatched: false });
    const res = await handleRegenerateClientKey(supabase, masterKey, "user-1", "client-1", {
      headers: { "x-secretvault-stepup": stepUpToken },
    });
    expect(res.status).toBe(409);
    expect((res.body as any).code).toBe("KEY_REGENERATE_CONFLICT");
  });
});

describe("client key reveal lifecycle (SV-016)", () => {
  const masterKey = Buffer.from("b".repeat(64), "hex");

  it("rejects reveal without a client-bound step-up", async () => {
    const supabase = mockSupabaseForRegen({ found: true, updateMatched: true });
    const res = await handleRevealClientKey(supabase, masterKey, "user-1", "client-1", { headers: {} });
    expect(res.status).toBe(403);
  });
});
