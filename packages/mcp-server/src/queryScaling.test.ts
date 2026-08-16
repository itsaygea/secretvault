import { beforeAll, describe, expect, it, vi } from "@secretvault/testing";
import { clampPageSize, decodeCursor, decodeBeforeCursor, encodeCursor, encodeBeforeCursor, escapePostgrestValue, initCursorKey, paginateQuery } from "./pagination.js";
import { registerListSecrets } from "./tools/listSecrets.js";
import { registerSearchSecrets } from "./tools/searchSecrets.js";

const UUID_A = "00000000-0000-4000-8000-000000000001";
const UUID_B = "00000000-0000-4000-8000-000000000002";

// SV-AUD-014: cursor HMAC key is derived from the master key at boot.
beforeAll(() => {
  initCursorKey(Buffer.alloc(32, 7));
});

describe("pagination utilities", () => {
  describe("clampPageSize", () => {
    it("returns default for undefined", () => {
      expect(clampPageSize(undefined)).toBe(50);
    });

    it("returns default for null", () => {
      expect(clampPageSize(null)).toBe(50);
    });

    it("clamps to max", () => {
      expect(clampPageSize(500)).toBe(200);
    });

    it("clamps to min", () => {
      expect(clampPageSize(0)).toBe(1);
    });

    it("passes through valid value", () => {
      expect(clampPageSize(25)).toBe(25);
    });
  });

  describe("cursor encode/decode", () => {
    it("round-trips an after cursor", () => {
      const cursor = encodeCursor("my_secret", UUID_A);
      const decoded = decodeCursor(cursor);
      expect(decoded).toEqual({ after: "my_secret", tiebreaker: UUID_A });
    });

    it("returns null for malformed after cursor", () => {
      expect(decodeCursor("not-base64!!")).toBeNull();
    });

    it("round-trips a before cursor", () => {
      const cursor = encodeBeforeCursor("2026-07-26T00:00:00Z", UUID_B);
      const decoded = decodeBeforeCursor(cursor);
      expect(decoded).toEqual({ before: "2026-07-26T00:00:00Z", tiebreaker: UUID_B });
    });

    it("returns null for malformed before cursor", () => {
      expect(decodeBeforeCursor("garbage")).toBeNull();
    });

    // SV-AUD-014: a tampered signature must never reach the query builder.
    it("rejects a cursor whose signature was tampered with", () => {
      const cursor = encodeCursor("victim", UUID_A);
      const [ver, payload] = cursor.split(".");
      const forgedSig = "A".repeat(43); // valid base64url length, wrong value
      const tampered = `${ver}.${payload}.${forgedSig}`;
      expect(decodeCursor(tampered)).toBeNull();
      expect(decodeBeforeCursor(tampered)).toBeNull();
    });

    // SV-AUD-014 PoC: grammar-injection payload encoded into an unsigned
    // cursor must be rejected — it carries no valid signature.
    it("rejects a grammar-injection payload carried without a valid signature", () => {
      const poison = Buffer.from(
        `after:name),user_id.neq.victim|${UUID_A}`,
        "utf8",
      ).toString("base64url");
      expect(decodeCursor(`v1.${poison}.fakesig`)).toBeNull();
    });

    it("rejects a wrong version", () => {
      const cursor = encodeCursor("my_secret", UUID_A).replace(/^v1\./, "v2.");
      expect(decodeCursor(cursor)).toBeNull();
    });

    it("rejects a non-UUID tiebreaker", () => {
      const cursor = encodeCursor("my_secret", "not-a-uuid");
      expect(decodeCursor(cursor)).toBeNull();
    });

    it("rejects an empty field", () => {
      const cursor = encodeCursor("", UUID_A);
      expect(decodeCursor(cursor)).toBeNull();
    });

    it("rejects an oversize field", () => {
      const cursor = encodeCursor("x".repeat(300), UUID_A);
      expect(decodeCursor(cursor)).toBeNull();
    });

    it("escapes PostgREST-significant characters in values", () => {
      expect(escapePostgrestValue('a.b,(c)')).toBe('"a.b,(c)"');
      // embedded quotes are doubled
      expect(escapePostgrestValue('a"b')).toBe('"a""b"');
    });
  });

  describe("paginateQuery", () => {
    it("returns has_more=false and null cursor when fewer rows than pageSize", async () => {
      const rows: Array<{ id: string }> = [{ id: "1" }, { id: "2" }];
      const page = await paginateQuery(rows, 10, (r) => encodeCursor(r.id, r.id));
      expect(page.data).toHaveLength(2);
      expect(page.next_cursor).toBeNull();
    });

    it("returns has_more=true and a cursor when more rows than pageSize", async () => {
      const rows: Array<{ id: string }> = [{ id: "1" }, { id: "2" }, { id: "3" }];
      const page = await paginateQuery(rows, 2, (r) => encodeCursor(r.id, r.id));
      expect(page.data).toHaveLength(2);
      expect(page.next_cursor).not.toBeNull();
    });

    it("returns empty data for empty input", async () => {
      const page = await paginateQuery<{ id: string }>([], 10, (r) => encodeCursor(r.id, r.id));
      expect(page.data).toHaveLength(0);
      expect(page.next_cursor).toBeNull();
    });
  });
});

function mockMcpServer() {
  const tools: Record<string, { handler: Function }> = {};
  return {
    tool: vi.fn((name: string, _desc: string, _schema: any, handler: Function) => {
      tools[name] = { handler };
    }),
    _tools: tools,
  };
}

function mockPrincipal(userId = "user-1", isAdmin = false, clientId: string | null = null) {
  return {
    userId,
    username: "testuser",
    isAdmin,
    clientId,
    credentialType: "session" as const,
    scopes: ["mcp:read"],
  };
}

function mockQueryBuilder(returnedRows: any[]) {
  const captured: Record<string, any> = {};
  const builder: any = {
    select() { return builder; },
    eq(col: string, val: any) { captured[`eq_${col}`] = val; return builder; },
    or(expr: string) { captured.or = expr; return builder; },
    ilike(col: string, val: any) { captured[`ilike_${col}`] = val; return builder; },
    contains(col: string, val: any) { captured[`contains_${col}`] = val; return builder; },
    order() { return builder; },
    limit(n: number) { return Promise.resolve({ data: returnedRows.slice(0, n), error: null }); },
  };
  return { builder, captured };
}

describe("list_secrets tool pagination", () => {
  it("applies cursor predicate when cursor is provided", async () => {
    const rows = [
      { id: UUID_A, name: "alpha", display_name: "Alpha", environment: "production", masked_preview: "abc***xyz", tags: [] },
    ];
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const cursor = encodeCursor("alpha", UUID_A);
    const result = await handler({ cursor, page_size: 10 });

    // SV-AUD-014: validated cursor values are PostgREST-escaped (quoted).
    expect(captured.or).toContain('name.gt."alpha"');
    expect(captured.or).toContain(`id.gt."${UUID_A}"`);
    expect(result.content[0].text).toBeDefined();
  });

  // SV-AUD-014: a malformed/tampered cursor is dropped, never reaches .or().
  it("ignores an invalid cursor instead of building a predicate", async () => {
    const rows = [
      { id: UUID_A, name: "alpha", display_name: "Alpha", environment: "production", masked_preview: "abc***xyz", tags: [] },
    ];
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    await handler({ cursor: "after:name),user_id.neq.victim|bogus", page_size: 10 });

    expect(captured.or).toBeUndefined();
  });

  it("limits results to page_size + 1 for has-more detection", async () => {
    const rows = Array.from({ length: 15 }, (_, i) => ({
      id: `s${i}`,
      name: `secret_${i}`,
      display_name: `Secret ${i}`,
      environment: "development",
      masked_preview: "abc***xyz",
      tags: [],
    }));
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const result = await handler({ page_size: 10 });

    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(10);
    expect(body.next_cursor).not.toBeNull();
  });

  it("omits cursor on the last page", async () => {
    const rows = Array.from({ length: 5 }, (_, i) => ({
      id: `s${i}`,
      name: `secret_${i}`,
      display_name: `Secret ${i}`,
      environment: "development",
      masked_preview: "abc***xyz",
      tags: [],
    }));
    const { builder } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const result = await handler({ page_size: 50 });

    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(5);
    expect(body.next_cursor).toBeNull();
  });
});

describe("search_secrets tool pagination", () => {
  it("paginates search results", async () => {
    const rows = [
      { id: "s1", name: "alpha_key", display_name: "Alpha Key", environment: "production", masked_preview: "abc***xyz", tags: ["api"] },
      { id: "s2", name: "beta_key", display_name: "Beta Key", environment: "production", masked_preview: "def***uvw", tags: ["api"] },
    ];
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerSearchSecrets(server as any, supabase, principal);

    const handler = server._tools["search_secrets"].handler;
    const result = await handler({ query: "_key", page_size: 10 });

    expect(captured["ilike_name"]).toBe("%_key%");
    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(2);
    expect(body.next_cursor).toBeNull();
  });

  it("filters by tags and applies cursor", async () => {
    const rows = [
      { id: "s2", name: "beta_key", display_name: "Beta Key", environment: "production", masked_preview: "def***uvw", tags: ["api"] },
    ];
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerSearchSecrets(server as any, supabase, principal);

    const handler = server._tools["search_secrets"].handler;
    const cursor = encodeCursor("alpha_key", UUID_A);
    const result = await handler({ tags: ["api"], cursor, page_size: 50 });

    expect(captured["contains_tags"]).toEqual(["api"]);
    expect(captured.or).toContain(`id.gt."${UUID_A}"`);
    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(1);
  });
});

describe("pagination security and edge cases", () => {
  it("rejects malformed cursor gracefully", async () => {
    const rows = [
      { id: "s1", name: "alpha", display_name: "Alpha", environment: "production", masked_preview: "abc***xyz", tags: [] },
    ];
    const { builder } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const result = await handler({ cursor: "!!!invalid!!!", page_size: 10 });

    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(1);
  });

  it("enforces max page size of 200", async () => {
    const rows = Array.from({ length: 5 }, (_, i) => ({
      id: `s${i}`,
      name: `secret_${i}`,
      display_name: `Secret ${i}`,
      environment: "development",
      masked_preview: "abc***xyz",
      tags: [],
    }));
    const { builder } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const result = await handler({ page_size: 999 });

    const body = JSON.parse(result.content[0].text);
    expect(body.data).toHaveLength(5);
  });
});
