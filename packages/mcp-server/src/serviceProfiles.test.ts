import { afterEach, describe, expect, it, vi } from "@secretvault/testing";
import { handleCreateProfile } from "./serviceProfiles.js";

describe("service-profile egress admission", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("requires an allowlisted public origin for non-admin profile creation", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");

    const result = await handleCreateProfile({} as any, "user-1", {
      name: "unapproved",
      target_url: "https://api.other.test/",
      auth_method: "bearer",
      pass_secret_name: "API_TOKEN",
    }, false);

    expect(result).toEqual({
      status: 403,
      body: { error: "Destination origin is not in the configured egress allowlist" },
    });
  });

  it("requires an administrator for private-network mode", async () => {
    const result = await handleCreateProfile({} as any, "user-1", {
      name: "internal",
      target_url: "http://10.0.0.10:8080/",
      auth_method: "bearer",
      pass_secret_name: "API_TOKEN",
      allow_private_network: true,
    }, false);

    expect(result).toEqual({
      status: 403,
      body: { error: "Private-network destinations require an administrator session" },
    });
  });
});

describe("service-profile injected name admission (SV-022)", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("requires and validates header_name for auth_method 'header' as an admin", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");

    const missing = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "header",
      pass_secret_name: "API_TOKEN",
    }, true);
    expect(missing.status).toBe(400);
    expect(String((missing.body as any).error)).toMatch(/header_name is required/);

    const reserved = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "header",
      pass_secret_name: "API_TOKEN",
      header_name: "Host",
    }, true);
    expect(reserved.status).toBe(400);
    expect(String((reserved.body as any).error)).toMatch(/reserved/);

    const smuggling = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "header",
      pass_secret_name: "API_TOKEN",
      header_name: "X-Evil\r\nInjected: yes",
    }, true);
    expect(smuggling.status).toBe(400);
  });

  it("requires and validates cookie_name for auth_method 'cookie' as an admin", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");

    const missing = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "cookie",
      pass_secret_name: "API_TOKEN",
    }, true);
    expect(missing.status).toBe(400);
    expect(String((missing.body as any).error)).toMatch(/cookie_name is required/);

    const bad = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "cookie",
      pass_secret_name: "API_TOKEN",
      cookie_name: "bad cookie",
    }, true);
    expect(bad.status).toBe(400);
    expect(String((bad.body as any).error)).toMatch(/valid cookie token/);
  });

  it("rejects header_name/cookie_name supplied for the wrong auth_method", async () => {
    vi.stubEnv("SECRETVAULT_EGRESS_ALLOWLIST", "https://api.allowed.test");

    const headerOnBearer = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "API_TOKEN",
      header_name: "X-Api-Key",
    }, true);
    expect(headerOnBearer.status).toBe(400);

    const cookieOnBearer = await handleCreateProfile({} as any, "user-1", {
      name: "svc",
      target_url: "https://api.allowed.test/",
      auth_method: "bearer",
      pass_secret_name: "API_TOKEN",
      cookie_name: "session",
    }, true);
    expect(cookieOnBearer.status).toBe(400);
  });
});
