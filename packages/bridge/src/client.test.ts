import { describe, it, expect } from "vitest";
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

  it("should format authorization headers correctly using linking key", () => {
    const headers = bridge.proxyHeaders();
    expect(headers.Authorization).toBe("Bearer sv_testkey12345678901234567890123456789012345678901234");
  });
});
