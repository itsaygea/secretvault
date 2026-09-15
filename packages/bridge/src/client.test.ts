import { describe, it, expect, vi } from "@secretvault/testing";
import { SecretBridge } from "./index.js";

describe("Client Security Invariants & Bridge API", () => {
  const bridge = new SecretBridge({
    serverUrl: "http://localhost:3004",
    linkingKey: "sv_testkey12345678901234567890123456789012345678901234",
  });

  it("keeps legacy bridge compatibility limited to proxy access", () => {
    expect((bridge as unknown as Record<string, unknown>).resolve).toBeUndefined();
    expect((bridge as unknown as Record<string, unknown>).injectEnv).toBeUndefined();
  });

  it("should generate proper proxy URLs without raw credentials", () => {
    const url = bridge.proxyUrl("openai", "/v1/chat/completions");
    expect(url).toBe("http://localhost:3004/proxy/openai/v1/chat/completions");
    expect(url).not.toContain("sk-");
  });

  it("should format authorization headers with a short-lived proxy token", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      access_token: `svt_${"c".repeat(43)}`,
      expires_in: 900,
    }), { status: 200 }));
    const tokenBridge = new SecretBridge({
      serverUrl: "http://localhost:3004",
      linkingKey: "sv_testkey12345678901234567890123456789012345678901234",
      fetch: fetcher,
    });
    const headers = await tokenBridge.proxyHeaders();
    expect(headers.Authorization).toMatch(/^Bearer svt_[A-Za-z0-9_-]{43}$/);
    expect(headers.Authorization).not.toContain("sv_testkey");
  });
});
