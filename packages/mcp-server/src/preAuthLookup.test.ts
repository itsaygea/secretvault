import { describe, expect, it, vi } from "@secretvault/testing";
import { authenticateLinkingKey, hashLinkingKey } from "./users.js";
import { authenticateProxyAccessToken, hashProxyAccessToken } from "./proxyTokens.js";

describe("pre-auth credential lookup boundaries", () => {
  it("resolves linking keys through the narrow RPC without querying tenant tables", async () => {
    const rpc = vi.fn(async (name: string, args: Record<string, string>) => {
      expect(name).toBe("authenticate_linking_key");
      expect(args.p_key_hash).toBe(hashLinkingKey("sv_test_linking_key_123456"));
      return {
        data: [{
          client_id: "client-1",
          user_id: "user-1",
          scopes: ["proxy:github"],
          key_version: 4,
          username: "alice",
          is_admin: false,
          session_epoch: 3,
        }],
        error: null,
      };
    });
    const supabase = { rpc, from: vi.fn() } as any;

    const principal = await authenticateLinkingKey(supabase, "sv_test_linking_key_123456");

    expect(principal).toMatchObject({
      id: "user-1",
      clientId: "client-1",
      scopes: ["proxy:github"],
      keyVersion: 4,
      sessionEpoch: 3,
    });
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it("resolves proxy tokens through the narrow RPC and validates live binding fields", async () => {
    const rawToken = `svt_${"a".repeat(43)}`;
    const rpc = vi.fn(async (name: string, args: Record<string, string>) => {
      expect(name).toBe("authenticate_proxy_access_token");
      expect(args.p_token_hash).toBe(hashProxyAccessToken(rawToken));
      return {
        data: [{
          token_id: "token-1",
          user_id: "user-1",
          client_id: "client-1",
          token_scopes: ["proxy:github"],
          token_key_version: 4,
          token_session_epoch: 3,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          revoked_at: null,
          client_scopes: ["proxy:github"],
          client_key_version: 4,
          username: "alice",
          is_admin: false,
          user_session_epoch: 3,
        }],
        error: null,
      };
    });
    const supabase = { rpc, from: vi.fn() } as any;

    const principal = await authenticateProxyAccessToken(supabase, rawToken);

    expect(principal).toMatchObject({
      userId: "user-1",
      clientId: "client-1",
      credentialType: "proxy_token",
      scopes: ["proxy:github"],
      keyVersion: 4,
      epoch: 3,
    });
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it("fails closed when the production lookup RPC errors", async () => {
    const supabase = {
      rpc: vi.fn(async () => ({ data: null, error: { message: "function unavailable" } })),
      from: vi.fn(),
    } as any;

    expect(await authenticateLinkingKey(supabase, "sv_test_linking_key_123456")).toBeNull();
    expect(await authenticateProxyAccessToken(supabase, `svt_${"b".repeat(43)}`)).toBeNull();
    expect(supabase.from).not.toHaveBeenCalled();
  });
});
