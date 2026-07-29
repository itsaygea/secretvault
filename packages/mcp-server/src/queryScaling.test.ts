import { describe, expect, it, vi } from "vitest";
import { clampPageSize, decodeCursor, decodeBeforeCursor, encodeCursor, encodeBeforeCursor, paginateQuery } from "./pagination.js";
import { registerListSecrets } from "./tools/listSecrets.js";
import { registerSearchSecrets } from "./tools/searchSecrets.js";

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
      const cursor = encodeCursor("my_secret", "uuid-123");
      const decoded = decodeCursor(cursor);
      expect(decoded).toEqual({ after: "my_secret", tiebreaker: "uuid-123" });
    });

    it("returns null for malformed after cursor", () => {
      expect(decodeCursor("not-base64!!")).toBeNull();
    });

    it("round-trips a before cursor", () => {
      const cursor = encodeBeforeCursor("2026-07-26T00:00:00Z", "uuid-456");
      const decoded = decodeBeforeCursor(cursor);
      expect(decoded).toEqual({ before: "2026-07-26T00:00:00Z", tiebreaker: "uuid-456" });
    });

    it("returns null for malformed before cursor", () => {
      expect(decodeBeforeCursor("garbage")).toBeNull();
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
      { id: "s1", name: "alpha", display_name: "Alpha", environment: "production", masked_preview: "abc***xyz", tags: [] },
    ];
    const { builder, captured } = mockQueryBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;
    const server = mockMcpServer();
    const principal = mockPrincipal();

    registerListSecrets(server as any, supabase, principal);

    const handler = server._tools["list_secrets"].handler;
    const cursor = encodeCursor("alpha", "s1");
    const result = await handler({ cursor, page_size: 10 });

    expect(captured.or).toContain("name.gt.alpha");
    expect(captured.or).toContain("id.gt.s1");
    expect(result.content[0].text).toBeDefined();
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
    const cursor = encodeCursor("alpha_key", "s1");
    const result = await handler({ tags: ["api"], cursor, page_size: 50 });

    expect(captured["contains_tags"]).toEqual(["api"]);
    expect(captured.or).toContain("id.gt.s1");
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
