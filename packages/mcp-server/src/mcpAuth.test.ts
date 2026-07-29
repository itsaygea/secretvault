import { describe, it, expect, vi } from "vitest";
import { resolveMcpAuth } from "./mcpAuth.js";
import { type IncomingMessage } from "node:http";

describe("MCP Connection Authorization & Principal Binding (resolveMcpAuth)", () => {
  const mockUserA = { id: "usr_a111", username: "alice", is_admin: false };
  const mockUserB = { id: "usr_b222", username: "bob", is_admin: true };

  function createMockSupabase(keyMap: Record<string, typeof mockUserA | null>) {
    return {
      from: (table: string) => {
        return {
          select: () => ({
            eq: (field: string, hash: string) => ({
              maybeSingle: async () => {
                const matchedUser = keyMap[hash] ?? null;
                if (matchedUser) {
                  return { data: { id: "client_1", scopes: ["proxy:*"], user_id: matchedUser.id, users: matchedUser } };
                }
                return { data: null };
              },
              single: async () => {
                const matchedUser = keyMap[hash] ?? null;
                return { data: matchedUser };
              },
            }),
          }),
          update: () => ({
            eq: () => ({
              then: () => {},
            }),
          }),
        };
      },
    };
  }

  // Pre-hashed values for test keys:
  // We can test with a mocked supabase client
  it("resolves a scoped principal from a valid Authorization: Bearer header", async () => {
    const mockSupabase = {
      from: (table: string) => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({
              data: {
                id: "client_app_1",
                scopes: ["mcp:read"],
                user_id: "user_123",
                users: { id: "user_123", username: "alice", is_admin: false },
              },
            }),
            single: async () => ({ data: null }),
          }),
        }),
        update: () => ({ eq: () => ({ then: () => {} }) }),
      }),
    };

    const req = {
      headers: {
        authorization: "Bearer sv_valid_key_123",
      },
    } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp");

    const auth = await resolveMcpAuth(req, url, mockSupabase as any);
    expect(auth).not.toBeNull();
    expect(auth?.userId).toBe("user_123");
    expect(auth?.isAdmin).toBe(false);
    expect(auth?.username).toBe("alice");
    expect(auth?.credentialType).toBe("linking_key");
    expect(auth?.clientId).toBe("client_app_1");
    expect(auth?.scopes).toEqual(["mcp:read"]);
  });

  it("does not accept linking keys in query parameters", async () => {
    const mockSupabase = {
      from: (table: string) => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: null }),
            single: async () => ({ data: { id: "user_456", username: "admin_bob", is_admin: true } }),
          }),
        }),
        update: () => ({ eq: () => ({ then: () => {} }) }),
      }),
    };

    const req = { headers: {} } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp?key=sv_api_key_456");

    const auth = await resolveMcpAuth(req, url, mockSupabase as any);
    expect(auth).toBeNull();
  });

  it("returns null when no authentication header or query parameter is provided (no admin fallback)", async () => {
    const mockSupabase = {
      from: vi.fn(),
    };

    const req = { headers: {} } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp");

    const auth = await resolveMcpAuth(req, url, mockSupabase as any);
    expect(auth).toBeNull();
    // Database should never even be queried when no auth token is provided
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it("returns null on malformed Authorization header (e.g. Basic or missing token)", async () => {
    const mockSupabase = { from: vi.fn() };
    const req1 = { headers: { authorization: "Basic dXNlcjpwYXNz" } } as unknown as IncomingMessage;
    const req2 = { headers: { authorization: "Bearer " } } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp");

    expect(await resolveMcpAuth(req1, url, mockSupabase as any)).toBeNull();
    expect(await resolveMcpAuth(req2, url, mockSupabase as any)).toBeNull();
  });

  it("returns null on revoked or invalid key", async () => {
    const mockSupabase = {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: null }),
            single: async () => ({ data: null }),
          }),
        }),
      }),
    };

    const req = { headers: { authorization: "Bearer sv_revoked_key" } } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp");

    const auth = await resolveMcpAuth(req, url, mockSupabase as any);
    expect(auth).toBeNull();
  });

  it("enforces strict user isolation: User A key returns User A principal, User B key returns User B principal", async () => {
    const mockSupabaseForUser = (user: typeof mockUserA) => ({
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({
              data: {
                id: `client_${user.id}`,
                scopes: [],
                user_id: user.id,
                users: user,
              },
            }),
            single: async () => ({ data: null }),
          }),
        }),
        update: () => ({ eq: () => ({ then: () => {} }) }),
      }),
    });

    const reqA = { headers: { authorization: "Bearer sv_key_alice" } } as unknown as IncomingMessage;
    const reqB = { headers: { authorization: "Bearer sv_key_bob" } } as unknown as IncomingMessage;
    const url = new URL("http://localhost:3004/mcp");

    const authA = await resolveMcpAuth(reqA, url, mockSupabaseForUser(mockUserA) as any);
    const authB = await resolveMcpAuth(reqB, url, mockSupabaseForUser(mockUserB) as any);

    expect(authA?.userId).toBe(mockUserA.id);
    expect(authA?.isAdmin).toBe(false);

    expect(authB?.userId).toBe(mockUserB.id);
    expect(authB?.isAdmin).toBe(true);
    expect(authA?.userId).not.toBe(authB?.userId);
  });
});
