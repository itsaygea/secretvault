import { describe, expect, it, vi } from "@secretvault/testing";
import { SecretVaultClient } from "./index.js";

const key = "sv_testkey12345678901234567890123456789012345678901234";
const proxyToken = `svt_${"a".repeat(43)}`;

describe("SecretVaultClient", () => {
  it("exposes only proxy and health/capabilities operations", () => {
    const client = new SecretVaultClient({
      baseUrl: "https://vault.example",
      clientKey: key,
      fetch: vi.fn(),
    });
    expect(typeof client.proxy).toBe("function");
    expect(typeof client.proxyUrl).toBe("function");
    expect(typeof client.health).toBe("function");
    expect(typeof client.capabilities).toBe("function");
    expect((client as unknown as Record<string, unknown>).injectEnv).toBeUndefined();
    expect((client as unknown as Record<string, unknown>).resolve).toBeUndefined();
  });

  it("merges HeadersInit forms, forces the client key, and preserves the caller signal", async () => {
    const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).endsWith("/v1/client/token")) {
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
        return new Response(JSON.stringify({ access_token: proxyToken, expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      expect(new Headers(init?.headers).get("x-trace")).toBe("trace");
      expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${proxyToken}`);
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      return new Response("upstream", { status: 200 });
    });
    const client = new SecretVaultClient({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });
    const signal = new AbortController().signal;

    const response = await client.proxy("github", "/user?verbose=true", {
      headers: [["x-trace", "trace"]],
      signal,
    });

    expect(response.status).toBe(200);
    expect(fetcher).toHaveBeenCalledWith("https://vault.example/proxy/github/user?verbose=true", expect.anything());
  });

  it("caches proxy tokens and refreshes once after server-side revocation", async () => {
    const refreshedToken = `svt_${"b".repeat(43)}`;
    let exchanges = 0;
    let proxyCalls = 0;
    const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).endsWith("/v1/client/token")) {
        exchanges += 1;
        return new Response(JSON.stringify({ access_token: exchanges === 1 ? proxyToken : refreshedToken, expires_in: 900 }), { status: 200 });
      }
      proxyCalls += 1;
      const authorization = new Headers(init?.headers).get("authorization");
      if (proxyCalls === 1) {
        expect(authorization).toBe(`Bearer ${proxyToken}`);
        return new Response("expired", { status: 401 });
      }
      expect(authorization).toBe(`Bearer ${refreshedToken}`);
      return new Response("ok", { status: 200 });
    });
    const client = new SecretVaultClient({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });

    expect((await client.proxy("github", "/one")).status).toBe(200);
    expect((await client.proxy("github", "/two")).status).toBe(200);
    expect(exchanges).toBe(2);
    expect(proxyCalls).toBe(3);
  });

  it("throws a typed, retryable error for management failures", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      error: { code: "SERVICE_UNAVAILABLE", message: "Unavailable", requestId: "req-1", status: 503 },
    }), {
      status: 503,
      headers: { "Content-Type": "application/json", "X-Request-ID": "req-1" },
    }));
    const client = new SecretVaultClient({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });

    await expect(client.capabilities()).rejects.toMatchObject({
      code: "SERVICE_UNAVAILABLE",
      status: 503,
      requestId: "req-1",
      retryable: true,
    });
  });

  it("requires HTTPS by default and validates proxy inputs", () => {
    expect(() => new SecretVaultClient({ baseUrl: "http://vault.example", clientKey: key })).toThrow(/HTTPS/);
    const client = new SecretVaultClient({ baseUrl: "https://vault.example", clientKey: key });
    expect(() => client.proxyUrl("bad/name")).toThrow(/serviceName/);
    expect(() => client.proxyUrl("github", "//attacker.example/path")).toThrow(/proxy path/);
  });

  it("supports explicit insecure HTTP for local development", () => {
    const client = new SecretVaultClient({ baseUrl: "http://localhost:3004", clientKey: key, allowInsecureHttp: true });
    expect(client.proxyUrl("github", "/user")).toBe("http://localhost:3004/proxy/github/user");
  });

  it("turns a client timeout into a typed retryable error", async () => {
    const fetcher = vi.fn((_url: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted by timeout")), { once: true });
    }));
    const client = new SecretVaultClient({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });

    await expect(client.capabilities({ timeoutMs: 5 })).rejects.toMatchObject({
      code: "REQUEST_TIMEOUT",
      status: 408,
      retryable: true,
    });
  });
});
