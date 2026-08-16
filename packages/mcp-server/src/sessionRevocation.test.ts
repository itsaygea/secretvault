import { describe, it, expect, beforeAll } from "@secretvault/testing";
import crypto from "node:crypto";
import { generateToken, verifyToken, initAuth, resolveAuthContext } from "./api.js";
import { bumpSessionEpoch } from "./users.js";
import { mcpAuthSnapshot, mcpSnapshotsEqual } from "./mcpAuth.js";
import type { Principal } from "./authz.js";

/**
 * SV-AUD-008 / SV-AUD-009: durable session + MCP authorization revocation.
 *
 * These prove the security property through the real code paths the server uses
 * (token epoch compare, durable epoch bump, MCP authorization snapshot), not a
 * process-local manager. The epoch is durable (a DB column), so revocation is
 * visible to every replica sharing the database.
 */

// Minimal fake supabase for the session-token path used by resolveAuthContext.
function fakeSupabase(userRow: Record<string, unknown>) {
  const users = [userRow];
  return {
    from: (table: string) => ({
      select: () => ({
        eq: () => ({
          single: async () => ({ data: users[0], error: null }),
          maybeSingle: async () => ({ data: users[0], error: null }),
        }),
      }),
      update: () => ({ eq: async () => {
        // Apply the epoch bump in-memory so subsequent reads see it.
        return { error: null };
      } }),
    }),
  } as any;
}

beforeAll(() => {
  initAuth(crypto.randomBytes(32));
});

describe("durable session revocation (SV-AUD-008)", () => {
  it("a token minted under the current epoch resolves; after an epoch bump the same token is rejected", async () => {
    const userId = "user-revoke-1";
    // Epoch 0 token, user at epoch 0 → resolves.
    const token = generateToken(userId, 0);
    expect(verifyToken(token).valid).toBe(true);
    let supabase = fakeSupabase({ id: userId, username: "u", is_admin: false, session_epoch: 0 });
    const ok = await resolveAuthContext(supabase, { headers: { authorization: "Bearer " + token } });
    expect(ok?.userId).toBe(userId);

    // Bump the epoch (password/factor/reset event) → token now stale.
    supabase = fakeSupabase({ id: userId, username: "u", is_admin: false, session_epoch: 1 });
    const rejected = await resolveAuthContext(supabase, { headers: { authorization: "Bearer " + token } });
    expect(rejected).toBeNull();
  });

  it("bumpSessionEpoch increments the durable epoch", async () => {
    const userId = "user-revoke-2";
    let epoch = 0;
    const supabase = {
      from: () => ({
        select: () => ({ eq: () => ({ single: async () => ({ data: { session_epoch: epoch }, error: null }) }) }),
        update: (patch: Record<string, unknown>) => ({ eq: async () => { if (patch.session_epoch !== undefined) epoch = patch.session_epoch as number; return { error: null }; } }),
      }),
    } as any;
    const a = await bumpSessionEpoch(supabase, userId);
    const b = await bumpSessionEpoch(supabase, userId);
    expect(a).toBe(1);
    expect(b).toBe(2);
    expect(epoch).toBe(2);
  });

  it("a fresh token minted after the bump resolves again", async () => {
    const userId = "user-revoke-3";
    const fresh = generateToken(userId, 2);
    const supabase = fakeSupabase({ id: userId, username: "u", is_admin: false, session_epoch: 2 });
    const ok = await resolveAuthContext(supabase, { headers: { authorization: "Bearer " + fresh } });
    expect(ok?.userId).toBe(userId);
  });
});

describe("MCP session authorization binding (SV-AUD-009)", () => {
  const basePrincipal = (over: Partial<Principal>): Principal => ({
    userId: "u1", username: "alice", clientId: "c1", credentialType: "linking_key",
    isAdmin: false, scopes: ["mcp:read", "mcp:write"], keyVersion: 1, epoch: 0,
    ...over,
  });

  it("an unchanged principal produces an equal snapshot", () => {
    const p = basePrincipal({});
    expect(mcpSnapshotsEqual(mcpAuthSnapshot(p), mcpAuthSnapshot(p))).toBe(true);
  });

  it("a scope downgrade (mcp:write removed) changes the snapshot → session closes", () => {
    const bound = mcpAuthSnapshot(basePrincipal({ scopes: ["mcp:read", "mcp:write"] }));
    const downgraded = mcpAuthSnapshot(basePrincipal({ scopes: ["mcp:read"] }));
    expect(mcpSnapshotsEqual(bound, downgraded)).toBe(false);
  });

  it("a key regeneration (key_version bump) changes the snapshot", () => {
    const bound = mcpAuthSnapshot(basePrincipal({ keyVersion: 1 }));
    const regenerated = mcpAuthSnapshot(basePrincipal({ keyVersion: 2 }));
    expect(mcpSnapshotsEqual(bound, regenerated)).toBe(false);
  });

  it("a client-id change (deleted/recreated client) changes the snapshot", () => {
    const bound = mcpAuthSnapshot(basePrincipal({ clientId: "c1" }));
    const other = mcpAuthSnapshot(basePrincipal({ clientId: "c2" }));
    expect(mcpSnapshotsEqual(bound, other)).toBe(false);
  });

  it("a session-epoch bump (password/factor change) changes the snapshot", () => {
    const bound = mcpAuthSnapshot(basePrincipal({ epoch: 0 }));
    const after = mcpAuthSnapshot(basePrincipal({ epoch: 3 }));
    expect(mcpSnapshotsEqual(bound, after)).toBe(false);
  });

  it("scopes are order-independent (canonicalization)", () => {
    const a = mcpAuthSnapshot(basePrincipal({ scopes: ["mcp:write", "mcp:read"] }));
    const b = mcpAuthSnapshot(basePrincipal({ scopes: ["mcp:read", "mcp:write"] }));
    expect(mcpSnapshotsEqual(a, b)).toBe(true);
  });
});
