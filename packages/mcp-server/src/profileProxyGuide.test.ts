import { describe, expect, it } from "@secretvault/testing";

// @ts-expect-error The browser UI helper is intentionally plain JavaScript.
const { buildProfileRoutePreview } = await import("../ui/js/features/profileProxyGuide.js");

describe("Service Profile proxy route guide", () => {
  it("splits a provider endpoint into the stored origin and client proxy URL", () => {
    const preview = buildProfileRoutePreview(
      "https://api.z.ai/api/coding/paas/v4",
      "zai",
      "https://vault.example.com/",
    );

    expect(preview.valid).toBe(true);
    expect(preview.targetOrigin).toBe("https://api.z.ai");
    expect(preview.proxyUrl).toBe("https://vault.example.com/proxy/zai/api/coding/paas/v4");
  });

  it("normalizes service names and trailing endpoint slashes", () => {
    const preview = buildProfileRoutePreview(
      "https://api.example.com/v1/resource///",
      "Example_Service",
      "https://vault.example.com",
    );

    expect(preview.targetOrigin).toBe("https://api.example.com");
    expect(preview.proxyUrl).toBe("https://vault.example.com/proxy/example_service/v1/resource");
  });

  it("rejects incomplete or unsafe route inputs", () => {
    expect(buildProfileRoutePreview("api.example.com/v1", "example", "https://vault.example.com").valid).toBe(false);
    expect(buildProfileRoutePreview("https://user:pass@example.com/v1", "example", "https://vault.example.com").valid).toBe(false);
    expect(buildProfileRoutePreview("https://api.example.com/v1", "../example", "https://vault.example.com").valid).toBe(false);
  });
});
