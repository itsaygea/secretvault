import { describe, expect, it, vi } from "vitest";
import { SecretVaultClient } from "./index.js";

const key = "sv_testkey12345678901234567890123456789012345678901234";

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
    const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("x-trace")).toBe("trace");
      expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
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
