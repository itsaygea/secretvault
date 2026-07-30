import crypto from "node:crypto";
import net from "node:net";
import { createServer, request as httpRequest, type IncomingMessage, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { encryptSecret, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";

process.env.NODE_ENV = "test";
process.env.SECRETVAULT_SUPABASE_URL = "http://supabase.test";
process.env.SECRETVAULT_SUPABASE_SERVICE_KEY = "test-service-key";
process.env.SECRETVAULT_MASTER_KEY = Buffer.alloc(32, 7).toString("hex");
process.env.SECRETVAULT_PROXY_TIMEOUT_MS = "50";

type Row = Record<string, any>;

class FakeQuery {
  private operation: "select" | "insert" | "update" | "delete" = "select";
  private payload: Row | Row[] | null = null;
  private filters: Array<[string, unknown]> = [];
  private singleResult = false;
  private maybeSingleResult = false;
  private limitCount: number | undefined;

  constructor(private readonly database: FakeSupabase, private readonly table: string) {}

  select(_fields?: string): this {
    return this;
  }

  insert(payload: Row | Row[]): this {
    this.operation = "insert";
    this.payload = payload;
    return this;
  }

  update(payload: Row): this {
    this.operation = "update";
    this.payload = payload;
    return this;
  }

  delete(): this {
    this.operation = "delete";
    return this;
  }

  eq(column: string, value: unknown): this {
    this.filters.push([column, value]);
    return this;
  }

  in(column: string, values: unknown[]): this {
    this.filters.push([column, values]);
    return this;
  }

  order(_column: string, _options?: unknown): this {
    return this;
  }

  limit(count: number): this {
    this.limitCount = count;
    return this;
  }

  single(): Promise<{ data: Row | null; error: Row | null }> {
    this.singleResult = true;
    return this.execute();
  }

  maybeSingle(): Promise<{ data: Row | null; error: Row | null }> {
    this.maybeSingleResult = true;
    return this.execute();
  }

  then<TResult1 = { data: unknown; error: null }, TResult2 = never>(
    onfulfilled?: ((value: { data: unknown; error: Row | null }) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled as any, onrejected as any);
  }

  private async execute(): Promise<{ data: any; error: Row | null }> {
    const rows = this.database.rows(this.table);
    const matches = rows.filter((row) => this.filters.every(([column, value]) => {
      if (Array.isArray(value)) return value.includes(row[column]);
      return row[column] === value;
    }));

    if (this.operation === "insert") {
      const inserts = Array.isArray(this.payload) ? this.payload : [this.payload ?? {}];
      const created = inserts.map((payload) => {
        const row = { id: this.database.nextId(), ...payload };
        rows.push(row);
        return row;
      });
      return { data: this.singleResult ? created[0] : created, error: null };
    }

    if (this.operation === "update") {
      for (const row of matches) Object.assign(row, this.payload ?? {});
      return { data: null, error: null };
    }

    if (this.operation === "delete") {
      this.database.remove(this.table, matches);
      return { data: null, error: null };
    }

    const selected = this.limitCount === undefined ? matches : matches.slice(0, this.limitCount);
    if (this.singleResult || this.maybeSingleResult) {
      if (selected.length === 0) return { data: null, error: this.singleResult ? { message: "not found" } : null };
      return { data: selected[0], error: null };
    }
    return { data: selected, error: null };
  }
}

class FakeSupabase {
  private id = 0;
  private readonly tables: Record<string, Row[]>;

  constructor(seed: Record<string, Row[]>) {
    this.tables = seed;
  }

  from(table: string): FakeQuery {
    return new FakeQuery(this, table);
  }

  rows(table: string): Row[] {
    return this.tables[table] ?? (this.tables[table] = []);
  }

  nextId(): string {
    this.id += 1;
    return `audit-${this.id}`;
  }

  remove(table: string, removed: Row[]): void {
    const rows = this.rows(table);
    for (const row of removed) {
      const index = rows.indexOf(row);
      if (index >= 0) rows.splice(index, 1);
    }
  }
}

function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind to a TCP port");
  return `http://127.0.0.1:${address.port}`;
}

const mainKey = "sv_main_conformance_key_1234567890";
const scopedKey = "sv_scoped_conformance_key_1234567890";
const masterKey = Buffer.alloc(32, 7);
const captured: { authorization?: string; trace?: string; path?: string; headers?: Record<string, string | string[] | undefined> } = {};

const { requestListener, configureServerForTests } = await import("./index.js");

let appServer: Server;
let upstreamServer: Server;
let appBaseUrl: string;
let upstreamBaseUrl: string;

beforeAll(async () => {
  upstreamServer = createServer((req, res) => {
    captured.authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
    captured.trace = typeof req.headers["x-conformance-trace"] === "string" ? req.headers["x-conformance-trace"] : undefined;
    captured.path = req.url;
    captured.headers = { ...req.headers };

    if (req.url?.startsWith("/slow")) {
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("slow");
      }, 250);
      return;
    }
    if (req.url?.startsWith("/stream")) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write("first");
      setTimeout(() => res.end("second"), 250);
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, authorization: captured.authorization, trace: captured.trace, path: captured.path }));
  });
  upstreamBaseUrl = await listen(upstreamServer);

  const encrypted = await encryptSecret("upstream-secret", masterKey, {
    purpose: ENCRYPTION_PURPOSE.SECRET,
    aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "user-1", recordId: "secret-1" }),
  });
  const user = { id: "user-1", username: "conformance", is_admin: false };
  const fakeSupabase = new FakeSupabase({
    client_applications: [
      { id: "client-main", key_hash: hashKey(mainKey), scopes: ["proxy:github", "mcp:read", "mcp:write"], user_id: user.id, users: user },
      { id: "client-scoped", key_hash: hashKey(scopedKey), scopes: [], user_id: user.id, users: user },
    ],
    users: [user],
    service_profiles: [{
      id: "profile-1",
      user_id: user.id,
      name: "github",
      target_url: upstreamBaseUrl,
      auth_method: "bearer",
      pass_secret_name: "UPSTREAM_TOKEN",
      user_secret_name: null,
      header_name: null,
      cookie_name: null,
      allow_private_network: true,
      allowed_methods: ["GET"],
      allowed_path_prefixes: ["/"],
    }],
    // Secret storage is canonicalized to lowercase; profiles may retain the
    // user-facing mixed-case name used to configure the credential.
    secrets: [{ id: "secret-1", user_id: user.id, name: "upstream_token", encrypted_blob: encrypted.encrypted }],
    access_logs: [],
  });

  configureServerForTests(fakeSupabase as any, masterKey);
  appServer = createServer(requestListener);
  appBaseUrl = await listen(appServer);
});

afterAll(async () => {
  await Promise.all([
    appServer && new Promise<void>((resolve, reject) => appServer.close((error) => error ? reject(error) : resolve())),
    upstreamServer && new Promise<void>((resolve, reject) => upstreamServer.close((error) => error ? reject(error) : resolve())),
  ].filter(Boolean));
});

async function jsonRequest(path: string, init?: RequestInit): Promise<{ response: Response; body: any }> {
  const response = await fetch(`${appBaseUrl}${path}`, init);
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : undefined };
}

/**
 * Send a raw HTTP request over a bare socket so we can inject hop-by-hop /
 * Connection-nominated headers that the Node/undici HTTP *client* would refuse
 * to send. This exercises the server's outbound header policy directly.
 */
function rawSocketRequest(rawHeaders: Record<string, string>, target = "/proxy/github/echo", method = "GET"): Promise<{ status: number; body: string }> {
  const url = new URL(target, appBaseUrl);
  const headerLines = Object.entries(rawHeaders).map(([k, v]) => `${k}: ${v}`).join("\r\n");
  const wire = `${method} ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\n${headerLines}\r\nConnection: close\r\n\r\n`;
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: url.hostname, port: Number(url.port || 80) }, () => socket.write(wire));
    let chunks = "";
    socket.setEncoding("utf8");
    socket.on("data", (data) => { chunks += data; });
    socket.on("end", () => {
      const idx = chunks.indexOf("\r\n\r\n");
      const head = idx >= 0 ? chunks.slice(0, idx) : "";
      const body = idx >= 0 ? chunks.slice(idx + 4) : "";
      const status = Number(head.split("\r\n")[0]?.split(" ")[1] ?? 0);
      resolve({ status, body });
    });
    socket.on("error", reject);
  });
}

function initializeBody() {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "secretvault-conformance", version: "1.0.0" },
    },
  };
}

describe("SecretVault public HTTP and MCP conformance", () => {
  it("publishes version metadata and request correlation over HTTP", async () => {
    const { response, body } = await jsonRequest("/v1/version", { headers: { "X-Request-ID": "conformance-version" } });
    expect(response.status).toBe(200);
    expect(response.headers.get("X-Request-ID")).toBe("conformance-version");
    expect(body).toMatchObject({ api_version: "v1", management_base_path: "/v1" });
  });

  it("returns the standard error envelope for unauthenticated management access", async () => {
    const { response, body } = await jsonRequest("/v1/me");
    expect(response.status).toBe(401);
    expect(body.error).toMatchObject({ code: "UNAUTHORIZED", status: 401 });
    expect(body.error.requestId).toBe(response.headers.get("X-Request-ID"));
  });

  it("enforces linking-key scopes at the public proxy seam", async () => {
    const { response, body } = await jsonRequest("/proxy/github/echo", {
      headers: { Authorization: `Bearer ${scopedKey}` },
    });
    expect(response.status).toBe(403);
    expect(body.error).toMatchObject({ code: "FORBIDDEN", status: 403 });
  });

  it("injects the profile credential and forwards safe request data to a mock upstream", async () => {
    const { response, body } = await jsonRequest("/proxy/github/echo?query=1", {
      headers: {
        Authorization: `Bearer ${mainKey}`,
        "X-Conformance-Trace": "trace-1",
      },
    });
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ ok: true, authorization: "Bearer upstream-secret", trace: "trace-1", path: "/echo?query=1" });
  });

  it("streams upstream response data without buffering the full body", async () => {
    const firstChunk = await new Promise<{ text: string; elapsed: number }>((resolve, reject) => {
      const started = Date.now();
      const request = httpRequest(`${appBaseUrl}/proxy/github/stream`, {
        headers: { Authorization: `Bearer ${mainKey}` },
      }, (response: IncomingMessage) => {
        response.once("data", (chunk: Buffer) => {
          resolve({ text: chunk.toString(), elapsed: Date.now() - started });
          response.resume();
        });
        response.on("error", reject);
      });
      request.once("error", reject);
      request.end();
    });
    expect(firstChunk.text).toBe("first");
    expect(firstChunk.elapsed).toBeLessThan(200);
  });

  it("turns an upstream timeout into the standard proxy error envelope", async () => {
    const { response, body } = await jsonRequest("/proxy/github/slow", {
      headers: { Authorization: `Bearer ${mainKey}` },
    });
    expect(response.status).toBe(502);
    expect(body.error).toMatchObject({ code: "UPSTREAM_CONNECTION_FAILED", status: 502 });
  });

  it("rejects unauthenticated and under-scoped MCP initialization through Streamable HTTP", async () => {
    const missing = await jsonRequest("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initializeBody()),
    });
    expect(missing.response.status).toBe(401);
    expect(missing.body.error.code).toBe(-32001);

    const underScoped = await jsonRequest("/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${scopedKey}`,
      },
      body: JSON.stringify(initializeBody()),
    });
    expect(underScoped.response.status).toBe(403);
    expect(underScoped.body.error.code).toBe(-32003);
  });

  it("initializes an authenticated MCP session through the public transport", async () => {
    const response = await fetch(`${appBaseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${mainKey}`,
      },
      body: JSON.stringify(initializeBody()),
    });
    const text = await response.text();
    const dataLine = text.split("\n").find((line) => line.startsWith("data: "));
    const body = dataLine ? JSON.parse(dataLine.slice("data: ".length)) : undefined;
    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBeTruthy();
    expect(body.result.serverInfo.name).toBe("secretvault");
  });
});

describe("proxy header policy and malformed-path containment (SV-022/023/024)", () => {
  it("strips hop-by-hop, Connection-nominated, and forwarding headers before forwarding", async () => {
    captured.headers = undefined;
    // Inject forbidden hop-by-hop / Connection-nominated headers over a raw
    // socket so the HTTP client can't refuse them; the server must strip them
    // before the upstream ever sees them. The Connection-nomination matrix is
    // also covered exhaustively in proxyPolicy.test.ts.
    const { status } = await rawSocketRequest({
      "Authorization": `Bearer ${mainKey}`,
      "Connection": "X-Hop-Custom, Keep-Alive",
      "Keep-Alive": "timeout=5",
      "TE": "trailers",
      "Trailer": "X-Foo",
      "Upgrade": "h2c",
      "Proxy-Authorization": "Bearer internal",
      "X-Forwarded-For": "1.2.3.4",
      "Forwarded": "for=1.2.3.4",
      "Via": "1.1 attacker",
      "X-Real-Ip": "1.2.3.4",
      "X-Hop-Custom": "leak-me",
      "X-Conformance-Trace": "hop-test",
    });
    expect(status).toBe(200);
    const headers: Record<string, string | string[] | undefined> = captured.headers ?? {};
    expect(headers["keep-alive"]).toBeUndefined();
    expect(headers["te"]).toBeUndefined();
    expect(headers["trailer"]).toBeUndefined();
    expect(headers["upgrade"]).toBeUndefined();
    expect(headers["proxy-authorization"]).toBeUndefined();
    expect(headers["x-forwarded-for"]).toBeUndefined();
    expect(headers["forwarded"]).toBeUndefined();
    expect(headers["via"]).toBeUndefined();
    expect(headers["x-real-ip"]).toBeUndefined();
    expect(headers["x-hop-custom"]).toBeUndefined();
    expect(headers["x-conformance-trace"]).toBe("hop-test");
  });

  it("does not leak raw secrets or upstream identity in an internal-error response body", async () => {
    // An unauthenticated request to a malformed-encoded management path must get
    // a clean envelope; the process must remain responsive afterward.
    const responses = await Promise.all([
      jsonRequest("/v1/secrets/%ZZ/reveal", { method: "POST" }),
      jsonRequest("/v1/secrets/%2/reveal", { method: "POST" }),
      jsonRequest("/api/secrets/bad%/rotate", { method: "POST" }),
    ]);
    for (const { response, body } of responses) {
      expect(response.status).toBeLessThan(500);
      expect(response.headers.get("X-Request-ID")).toBeTruthy();
      const text = JSON.stringify(body ?? {});
      expect(text).not.toMatch(/stack|at \/|node:/i);
    }
    // Process survival: a known-good endpoint still answers after malformed inputs.
    const { response: alive } = await jsonRequest("/health/ready");
    expect(alive.status).toBe(200);
  });

  it("rejects encoded separators and malformed proxy paths with a stable client error", async () => {
    const encodedSlash = await jsonRequest("/proxy/github/%2F..%2Fsecret", {
      headers: { Authorization: `Bearer ${mainKey}` },
    });
    expect(encodedSlash.response.status).toBe(400);
  });
});
