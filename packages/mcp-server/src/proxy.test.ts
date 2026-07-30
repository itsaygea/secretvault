import { describe, expect, it, afterEach } from "vitest";
import { PassThrough } from "node:stream";
import http from "node:http";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { encryptSecret, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { handleProxyRequest, destroyProxyAgents } from "./proxy.js";
import type { Principal } from "./authz.js";

describe("proxy keep-alive agents", () => {
  afterEach(() => {
    destroyProxyAgents();
  });

  it("exports destroyProxyAgents without error", () => {
    expect(typeof destroyProxyAgents).toBe("function");
    expect(() => destroyProxyAgents()).not.toThrow();
  });

  it("destroyProxyAgents is safe to call multiple times", () => {
    destroyProxyAgents();
    destroyProxyAgents();
  });
});

describe("proxy body streaming primitives", () => {
  it("PassThrough correctly sequences pipeline writes", async () => {
    const pt = new PassThrough({ highWaterMark: 65536 });
    const chunks: Buffer[] = [];
    pt.on("data", (c: Buffer) => chunks.push(c));

    pt.write(Buffer.from("chunk1"));
    pt.write(Buffer.from("chunk2"));
    pt.end();

    await new Promise<void>(resolve => pt.on("end", resolve));
    expect(Buffer.concat(chunks).toString()).toBe("chunk1chunk2");
  });

  it("PassThrough highWaterMark signals backpressure for large writes", () => {
    const pt = new PassThrough({ highWaterMark: 1024 });
    const large = Buffer.alloc(2048);
    expect(pt.write(large)).toBe(false);
    pt.destroy();
  });
});

// ── SV-AUD-003: credential reflection through the real proxy path ──
// Stands up a real local HTTP upstream that echoes the injected credential
// back in an arbitrary header and a 4xx body, then asserts the caller never
// receives it. handleProxyRequest runs inside a real http.Server so the full
// request→upstream→response path is exercised through public boundaries.
describe("proxy credential reflection (SV-AUD-003)", () => {
  afterEach(() => { destroyProxyAgents(); });

  function buildSupabase(
    rows: Record<string, string>,
    profile: Record<string, unknown>,
  ): SupabaseClient<Database, "secretvault"> {
    const selectRows = (table: string) => table === "service_profiles" ? [profile]
      : table === "secrets" ? Object.entries(rows).map(([name, encrypted_blob]) => ({ id: "sec-1", name, encrypted_blob }))
      : [];
    const makeChain = (table: string): unknown => {
      const chain: Record<string, (...a: unknown[]) => unknown> = {};
      chain.select = () => chain;
      chain.eq = () => chain;
      chain.in = () => chain;
      chain.single = () => ({ data: table === "service_profiles" ? profile : null, error: null });
      chain.insert = () => ({ select: () => ({ single: () => ({ data: { id: "audit-1" }, error: null }) }) });
      chain.update = () => ({ eq: () => ({ error: null }) });
      // A bare await of the chain (secrets.select().in().eq()) resolves the row set.
      (chain as unknown as { then: unknown }).then = (resolve: (v: unknown) => void) =>
        resolve({ data: selectRows(table), error: null });
      return chain;
    };
    return { from: (table: string) => makeChain(table) } as unknown as SupabaseClient<Database, "secretvault">;
  }

  const principal: Principal = {
    userId: "u1", username: "tester", clientId: null,
    credentialType: "session", isAdmin: false, scopes: ["proxy:svc"],
  };

  async function runProxy(
    upstreamHandler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
    path: string,
    authMethod: string,
    secretName: string,
  ): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
    const masterKey = crypto.randomBytes(32);
    const marker = "vault-secret-12345678";
    // Encrypt with the same context AAD the proxy will use to decrypt
    // (principal.userId "u1" + row id "sec-1").
    const secretAad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "sec-1" });
    const encrypted = (await encryptSecret(marker, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad: secretAad })).encrypted;

    const upstream = http.createServer(upstreamHandler);
    await new Promise<void>(r => upstream.listen(0, "127.0.0.1", r));
    const { port } = upstream.address() as AddressInfo;

    const profile: Record<string, unknown> = {
      id: "p1", name: "svc", target_url: `http://127.0.0.1:${port}`, auth_method: authMethod,
      user_secret_name: null, pass_secret_name: secretName, header_name: "x-api-key",
      cookie_name: "session", allow_private_network: true,
      allowed_methods: ["GET"], allowed_path_prefixes: ["/"],
    };
    const supabase = buildSupabase({ [secretName]: encrypted }, profile);

    const proxy = http.createServer((req, res) => {
      void handleProxyRequest(req, res, supabase, masterKey, principal, "svc");
    });
    await new Promise<void>(r => proxy.listen(0, "127.0.0.1", r));
    const { port: proxyPort } = proxy.address() as AddressInfo;

    try {
      const resp = await new Promise<http.IncomingMessage>((resolve, reject) => {
        const r = http.get(`http://127.0.0.1:${proxyPort}${path}`, resolve);
        r.on("error", reject);
      });
      const body = await new Promise<string>(resolve => {
        const chunks: Buffer[] = [];
        resp.on("data", (c: Buffer) => chunks.push(c));
        resp.on("end", () => resolve(Buffer.concat(chunks).toString()));
      });
      return { status: resp.statusCode ?? 0, headers: resp.headers, body };
    } finally {
      await Promise.all([
        new Promise<void>(r => upstream.close(() => r())),
        new Promise<void>(r => proxy.close(() => r())),
      ]);
    }
  }

  it("drops a bearer credential echoed in an arbitrary response header and a 4xx body", async () => {
    const marker = "vault-secret-12345678";
    const { status, headers, body } = await runProxy((_req, res) => {
      res.writeHead(401, { "content-type": "application/json", "x-debug-auth": `Bearer ${marker}` });
      res.end(JSON.stringify({ error: `bad token ${marker}` }));
    }, "/proxy/svc/leak", "bearer", "svc_pass");
    expect(status).toBe(401);
    expect(JSON.stringify(headers)).not.toContain(marker);
    expect(headers["x-debug-auth"]).toBeUndefined();
    expect(body).not.toContain(marker);
    expect(body).toContain("Upstream returned an error response");
  });

  it("drops a basic credential echoed in an arbitrary response header", async () => {
    const marker = "vault-secret-12345678";
    const { status, headers, body } = await runProxy((req, res) => {
      // Upstream reflects the Authorization it received.
      const auth = (req.headers.authorization ?? "") ;
      res.writeHead(401, { "x-debug-auth": auth });
      res.end(JSON.stringify({ error: auth }));
    }, "/proxy/svc/leak", "basic", "svc_pass");
    expect(status).toBe(401);
    expect(JSON.stringify(headers)).not.toContain(marker);
    expect(body).not.toContain(marker);
  });

  it("streams a successful upstream body through unchanged (streaming preserved)", async () => {
    const { status, headers, body } = await runProxy((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "x-trace": "ok" });
      res.end("hello upstream body");
    }, "/proxy/svc/data", "bearer", "svc_pass");
    expect(status).toBe(200);
    expect(body).toBe("hello upstream body");
    expect(headers["x-trace"]).toBe("ok");
  });
});
