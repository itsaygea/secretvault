import { describe, expect, it, vi } from "vitest";
import { handleCreateProfile } from "./serviceProfiles.js";

/**
 * SV-034 / SV-053 tests for atomic profile+secret creation and canonical
 * service-name normalization. Uses an in-memory mock supabase that records
 * every insert/delete so we can assert rollback leaves no orphan secrets and
 * that profile names are stored lowercase.
 */

interface MockRow { [col: string]: unknown; }

function buildMockSupabase(opts: { profileInsertError?: { code: string; message: string } } = {}) {
  const secrets: MockRow[] = [];
  const profiles: MockRow[] = [];
  const deletedSecrets: string[] = [];

  const supabase: any = {
    _secrets: secrets,
    _profiles: profiles,
    _deletedSecrets: deletedSecrets,
    from(table: string) {
      // audit writes go to access_logs; we don't need to model them — accept
      // any insert/select on that table without polluting the secrets/profiles
      // buckets.
      if (table === "access_logs") {
        const noop: any = {
          eq: () => noop,
          select: () => noop,
          insert: () => Object.assign(Promise.resolve({ data: [{ id: "audit-1" }], error: null }), { select: () => noop, single: async () => ({ data: { id: "audit-1" }, error: null }) }),
          update: () => Object.assign(Promise.resolve({ data: null, error: null }), { eq: () => noop }),
          single: async () => ({ data: { id: "audit-1" }, error: null }),
          maybeSingle: async () => ({ data: { id: "audit-1" }, error: null }),
        };
        return noop;
      }
      // Build a chain that records filters and supports the query shapes the
      // handler uses: select().eq().maybeSingle(), insert().select().single(),
      // and delete().eq().
      const filters: Array<[string, unknown]> = [];
      const matches = (r: MockRow) => filters.every(([c, v]) => r[c] === v);
      let pendingInsert: MockRow | null = null;

      const chain: any = {
        eq(col: string, value: unknown) { filters.push([col, value]); return chain; },
        async maybeSingle() {
          const store = table === "secrets" ? secrets : profiles;
          return { data: store.find(matches) ?? null, error: null };
        },
        async single() {
          // insert(...).select(...).single() — return the inserted row, or the
          // configured error.
          if (table === "service_profiles" && opts.profileInsertError) {
            return { data: null, error: opts.profileInsertError };
          }
          if (pendingInsert) {
            const store = table === "secrets" ? secrets : profiles;
            const row = { ...pendingInsert, id: crypto.randomUUID() };
            store.push(row);
            return { data: row, error: null };
          }
          return { data: null, error: null };
        },
        insert(payload: MockRow) {
          pendingInsert = payload;
          const store = table === "secrets" ? secrets : profiles;
          if (table === "secrets") {
            // secret insert: const { error } = await from("secrets").insert(...)
            store.push({ ...payload, id: crypto.randomUUID() });
            return Promise.resolve({ data: { ...payload }, error: null });
          }
          // service_profiles insert: from(...).insert(...).select(...).single()
          // Return the chain directly; .single() materializes the row (or error).
          if (opts.profileInsertError) {
            // .single() must surface the configured error and not push.
            const err = opts.profileInsertError;
            pendingInsert = null;
            const errChain: any = {
              select: () => errChain,
              single: async () => ({ data: null, error: err }),
            };
            return errChain;
          }
          return chain; // chain.select().single() pushes once
        },
        select: () => chain,
        async delete() {
          if (table === "secrets") {
            for (let i = secrets.length - 1; i >= 0; i--) {
              if (matches(secrets[i])) {
                deletedSecrets.push(String(secrets[i].name));
                secrets.splice(i, 1);
              }
            }
          }
          return { data: null, error: null };
        },
      };
      return chain;
    },
  };
  return supabase;
}

const ZERO_KEY = Buffer.alloc(32, 0);

describe("SV-053 canonical service-name normalization", () => {
  it("stores the profile name in lowercase", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "QBitTorrent",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "token",
    }, true, ZERO_KEY);
    expect(res.status).toBe(201);
    expect((res.body as any).name).toBe("qbittorrent");
    expect(supabase._profiles[0].name).toBe("qbittorrent");
  });
});

describe("SV-034 atomic profile + secret creation", () => {
  it("creates inline secrets and the profile together", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "basic",
      user_secret_name: "svc_user",
      pass_secret_name: "svc_pass",
      create_secrets: [
        { name: "svc_user", value: "alice" },
        { name: "svc_pass", value: "s3cret" },
      ],
    }, true, ZERO_KEY);

    expect(res.status).toBe(201);
    expect((res.body as any).created_secrets).toEqual(["svc_user", "svc_pass"]);
    expect(supabase._secrets).toHaveLength(2);
    expect(supabase._profiles).toHaveLength(1);
    // No plaintext leaked in the response.
    const body = JSON.stringify(res.body);
    expect(body).not.toContain("alice");
    expect(body).not.toContain("s3cret");
  });

  it("rolls back inline secrets when profile creation fails (no orphans)", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase({
      // Simulate the profile insert failing (e.g. unique violation).
      profileInsertError: { code: "23505", message: "duplicate" },
    });
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "basic",
      user_secret_name: "svc_user",
      pass_secret_name: "svc_pass",
      create_secrets: [
        { name: "svc_user", value: "alice" },
        { name: "svc_pass", value: "s3cret" },
      ],
    }, true, ZERO_KEY);

    expect(res.status).toBe(409);
    // The two secrets created inline must have been deleted on rollback.
    expect(supabase._secrets).toHaveLength(0);
    expect(supabase._deletedSecrets).toEqual(expect.arrayContaining(["svc_user", "svc_pass"]));
  });

  it("validates every inline secret before writing any", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "svc_pass",
      create_secrets: [
        { name: "good_secret", value: "ok" },
        { name: "bad name!", value: "ok" }, // invalid secret name
      ],
    }, true, ZERO_KEY);

    expect(res.status).toBe(400);
    expect(supabase._secrets).toHaveLength(0); // nothing written
  });

  it("rejects inline secret creation when no master key is in scope", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "svc_pass",
      create_secrets: [{ name: "svc_pass", value: "ok" }],
    }, true, undefined);

    expect(res.status).toBe(400);
    expect(supabase._secrets).toHaveLength(0);
  });

  it("refuses to inline-create a secret that already exists", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    // Pre-seed an existing secret the inline create collides with.
    supabase._secrets.push({ name: "svc_pass", user_id: "user-1", id: "exists" });
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "svc_pass",
      create_secrets: [{ name: "svc_pass", value: "ok" }],
    }, true, ZERO_KEY);

    expect(res.status).toBe(400);
    expect(String((res.body as any).error)).toMatch(/already exists/);
  });
});

describe("SV-033 all auth methods produce dispatchable profiles", () => {
  it.each([
    ["bearer", { pass_secret_name: "token" }],
    ["basic", { user_secret_name: "user", pass_secret_name: "pass" }],
    ["header", { pass_secret_name: "key", header_name: "X-Api-Key" }],
    ["cookie", { pass_secret_name: "sess", cookie_name: "session" }],
  ])("accepts auth_method %s with its required fields", async (method, extra) => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: method,
      target_url: "https://api.allowed.test/",
      auth_method: method,
      ...extra,
    } as any, true, ZERO_KEY);
    expect(res.status).toBe(201);
  });

  it("persisted policy fields round-trip through the create response", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");
    const supabase = buildMockSupabase();
    const res = await handleCreateProfile(supabase, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "token",
      allowed_methods: ["GET", "POST"],
      allowed_path_prefixes: ["/v1"],
      allow_private_network: false,
    }, true, ZERO_KEY);
    expect(res.status).toBe(201);
    const body = res.body as any;
    expect(body.allowed_methods).toEqual(["GET", "POST"]);
    expect(body.allowed_path_prefixes).toEqual(["/v1"]);
    expect(body.allow_private_network).toBe(false);
  });
});
