import { beforeAll, describe, expect, it, vi } from "@secretvault/testing";
import {
  finishAuditEvent,
  sanitizeAuditCaller,
  startCriticalAuditEvent,
  recordAuditEvent,
  readAuditLogPage,
  setAuditAlertSink,
  type AuditAlertFn,
} from "./audit.js";
import { encodeBeforeCursor, initCursorKey } from "./pagination.js";

// SV-AUD-014: cursor HMAC key derived from master key at boot.
beforeAll(() => {
  initCursorKey(Buffer.alloc(32, 7));
});

describe("audit event sanitization", () => {
  it("redacts credential-like query parameters", () => {
    const sanitized = sanitizeAuditCaller("proxy:GET:/debug?token=secret&ok=yes&api_key=abc");
    expect(sanitized).toContain("token=%5BREDACTED%5D");
    expect(sanitized).toContain("api_key=%5BREDACTED%5D");
    expect(sanitized).toContain("ok=yes");
    expect(sanitized).not.toContain("secret");
  });

  it("creates an unknown critical event and finalizes the same row", async () => {
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-1" }, error: null })) })),
    }));
    const update = vi.fn(() => ({
      eq: vi.fn(async () => ({ error: null })),
    }));
    const supabase = { from: vi.fn(() => ({ insert, update })) } as any;

    const auditId = await startCriticalAuditEvent(supabase, {
      userId: "user-1",
      clientId: "client-1",
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });

    expect(auditId).toBe("audit-1");
    expect(insert).toHaveBeenCalledWith(expect.objectContaining({ outcome: "unknown", request_id: expect.any(String) }));
    expect(await finishAuditEvent(supabase, auditId!, "failed", { reason: "upstream_error" })).toBe(true);
    expect(update).toHaveBeenCalledWith({ outcome: "failed", metadata: { reason: "upstream_error" } });
  });

  it("rejects non-system events without a user id", async () => {
    const insert = vi.fn();
    const supabase = { from: vi.fn(() => ({ insert })) } as any;
    const auditId = await startCriticalAuditEvent(supabase, {
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });

    expect(auditId).toBeNull();
    expect(insert).not.toHaveBeenCalled();
  });
});

describe("audit fail-closed contract", () => {
  it("returns null when the initial write fails so callers can block the operation", async () => {
    // insert().select().single() returns an error → wrapper surfaces null
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: null, error: { message: "connection refused" } })) })),
    }));
    const supabase = { from: vi.fn(() => ({ insert })) } as any;

    const auditId = await startCriticalAuditEvent(supabase, {
      userId: "user-1",
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });

    expect(auditId).toBeNull();
  });

  it("leaves the row as unknown and returns false when finalization fails", async () => {
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-1" }, error: null })) })),
    }));
    const update = vi.fn(() => ({
      eq: vi.fn(async () => ({ error: { message: "update failed" } })),
    }));
    const supabase = { from: vi.fn(() => ({ insert, update })) } as any;

    const auditId = await startCriticalAuditEvent(supabase, {
      userId: "user-1",
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });
    expect(auditId).toBe("audit-1");

    const ok = await finishAuditEvent(supabase, auditId!, "succeeded");
    expect(ok).toBe(false);
    // Finalize attempted with the terminal outcome; the row stays unknown.
    expect(update).toHaveBeenCalledWith({ outcome: "succeeded" });
  });
});

describe("audit actor attribution", () => {
  it("records actor_username, source_ip and source_user_agent snapshots", async () => {
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-1" }, error: null })) })),
    }));
    const supabase = { from: vi.fn(() => ({ insert })) } as any;

    await recordAuditEvent(supabase, {
      userId: "user-1",
      secretName: "github_token",
      accessType: "ui_reveal",
      caller: "webui:reveal",
      actorUsername: "alice.admin",
      sourceIp: "10.0.0.5",
      sourceUserAgent: "Mozilla/5.0",
    });

    expect(insert).toHaveBeenCalledWith(expect.objectContaining({
      actor_username: "alice.admin",
      source_ip: "10.0.0.5",
      source_user_agent: "Mozilla/5.0",
    }));
  });

  it("records a system event with null user_id and client_id", async () => {
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-2" }, error: null })) })),
    }));
    const supabase = { from: vi.fn(() => ({ insert })) } as any;

    await recordAuditEvent(supabase, {
      secretName: "system",
      accessType: "login",
      caller: "rest:/api/auth/login",
      outcome: "failed",
      actorUsername: "unknown",
    });

    expect(insert).toHaveBeenCalledWith(expect.objectContaining({
      user_id: null,
      client_id: null,
      secret_name: "system",
      outcome: "failed",
    }));
  });

  it("accepts the 'account' sentinel for anonymous auth events (no user_id)", async () => {
    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-3" }, error: null })) })),
    }));
    const supabase = { from: vi.fn(() => ({ insert })) } as any;

    const id = await recordAuditEvent(supabase, {
      secretName: "account",
      accessType: "login",
      caller: "rest:/api/auth/login",
      outcome: "failed",
    });

    expect(id).toBe("audit-3");
    expect(insert).toHaveBeenCalledWith(expect.objectContaining({ secret_name: "account", user_id: null }));
  });
});

describe("audit alert sink", () => {
  it("fires a write_failed alert when the initial write errors", async () => {
    const alerts: Parameters<AuditAlertFn>[0][] = [];
    setAuditAlertSink((a) => { alerts.push(a); });

    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: null, error: { message: "boom" } })) })),
    }));
    const supabase = { from: vi.fn(() => ({ insert })) } as any;

    await recordAuditEvent(supabase, {
      userId: "user-1",
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });

    expect(alerts.some(a => a.kind === "write_failed")).toBe(true);

    // Restore default sink so other tests are unaffected.
    setAuditAlertSink(() => undefined);
  });

  it("fires an unknown_finalized alert when finalization fails", async () => {
    const alerts: Parameters<AuditAlertFn>[0][] = [];
    setAuditAlertSink((a) => { alerts.push(a); });

    const insert = vi.fn(() => ({
      select: vi.fn(() => ({ single: vi.fn(async () => ({ data: { id: "audit-1" }, error: null })) })),
    }));
    const update = vi.fn(() => ({ eq: vi.fn(async () => ({ error: { message: "x" } })) }));
    const supabase = { from: vi.fn(() => ({ insert, update })) } as any;

    const id = await startCriticalAuditEvent(supabase, {
      userId: "user-1",
      secretName: "github_token",
      accessType: "proxy",
      caller: "proxy:GET:/user",
    });
    await finishAuditEvent(supabase, id!, "succeeded");

    expect(alerts.some(a => a.kind === "unknown_finalized")).toBe(true);
    setAuditAlertSink(() => undefined);
  });
});

/**
 * Mock supabase query builder: records the captured predicates (eq/gte/lt/or)
 * and resolves the terminal `.limit()` to a fixture-driven page. The builder
 * is chainable — every filter method returns the same builder object.
 */
function mockReadBuilder(rows: any[]) {
  const captured: Record<string, any> = {};
  const builder: any = {
    select() { return builder; },
    eq(col: string, val: any) { captured[col] = val; return builder; },
    gte(col: string, val: any) { captured[col + "_gte"] = val; return builder; },
    lt(col: string, val: any) { captured[col + "_lt"] = val; return builder; },
    or(_expr: string) { captured.or = _expr; return builder; },
    order() { return builder; },
    limit(n: number) { return Promise.resolve({ data: rows.slice(0, n), error: null }); },
  };
  return { builder, captured };
}

describe("audit log cursor pagination", () => {
  it("returns a page and a next_cursor when more rows remain", async () => {
    // 3 rows, page_size 2 → returns 2 rows + a cursor.
    const rows = [
      { id: "3", created_at: "2026-07-26T00:00:03Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} },
      { id: "2", created_at: "2026-07-26T00:00:02Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} },
      { id: "1", created_at: "2026-07-26T00:00:01Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} },
    ];
    const { builder } = mockReadBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;

    const page = await readAuditLogPage(supabase, "u1", { pageSize: 2 });

    expect(page.events).toHaveLength(2);
    expect(page.events[0].id).toBe("3");
    expect(page.next_cursor).not.toBeNull();
  });

  it("returns null next_cursor on the last page", async () => {
    const rows = [
      { id: "2", created_at: "2026-07-26T00:00:02Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} },
      { id: "1", created_at: "2026-07-26T00:00:01Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} },
    ];
    const { builder } = mockReadBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;

    const page = await readAuditLogPage(supabase, "u1", { pageSize: 50 });
    expect(page.next_cursor).toBeNull();
    expect(page.events).toHaveLength(2);
  });

  it("applies outcome, access_type, from/to and clientId filters", async () => {
    const { builder, captured } = mockReadBuilder([]);
    const supabase = { from: vi.fn(() => builder) } as any;

    await readAuditLogPage(supabase, "u1", {
      outcome: "denied",
      accessType: "authorization_denied",
      from: "2026-01-01T00:00:00Z",
      to: "2026-02-01T00:00:00Z",
      clientId: "client-9",
    });

    expect(captured.outcome).toBe("denied");
    expect(captured.access_type).toBe("authorization_denied");
    expect(captured.created_at_gte).toBe("2026-01-01T00:00:00Z");
    expect(captured.created_at_lt).toBe("2026-02-01T00:00:00Z");
    expect(captured.client_id).toBe("client-9");
  });

  it("emits a strictly-before OR predicate from the cursor", async () => {
    const UUID5 = "00000000-0000-4000-8000-000000000005";
    const rows = [{ id: UUID5, created_at: "2026-07-26T00:00:00Z", user_id: "u1", secret_name: "system", access_type: "login", caller: "c", outcome: "succeeded", request_id: null, client_id: null, actor_username: null, metadata: {} }];
    // SV-AUD-014: cursor is HMAC-signed; build it via the shared encoder.
    const cursor = encodeBeforeCursor("2026-07-26T00:00:05Z", UUID5);
    const { builder, captured } = mockReadBuilder(rows);
    const supabase = { from: vi.fn(() => builder) } as any;

    await readAuditLogPage(supabase, "u1", { cursor });
    // Validated values are PostgREST-escaped (quoted).
    expect(captured.or).toContain('created_at.lt."2026-07-26T00:00:05Z"');
    expect(captured.or).toContain(`id.lt."${UUID5}"`);
  });

  // SV-AUD-014: a tampered/unsigned cursor never reaches .or().
  it("ignores an unsigned cursor instead of building a predicate", async () => {
    const { builder, captured } = mockReadBuilder([]);
    const supabase = { from: vi.fn(() => builder) } as any;
    const oldUnsigned = Buffer.from(`before:2026-07-26T00:00:05Z|5`, "utf8").toString("base64");
    await readAuditLogPage(supabase, "u1", { cursor: oldUnsigned });
    expect(captured.or).toBeUndefined();
  });
});
