import { describe, expect, it } from "@secretvault/testing";
import { initTenantAuth, runAsTenant, tenantAwareFetch } from "./tenantContext.js";

describe("tenant-aware Supabase fetch", () => {
  it("keeps the gateway service key in apikey while using the tenant JWT for authorization", async () => {
    initTenantAuth("example-jwt-secret", "test-issuer");

    let forwarded: Headers | undefined;
    const fetchWithTenant = tenantAwareFetch(async (_input, init) => {
      forwarded = new Headers(init?.headers);
      return new Response(null, { status: 204 });
    });

    await runAsTenant(
      { userId: "EXAMPLE_USER_ID", clientId: null, isAdmin: false },
      () =>
        fetchWithTenant("https://vault.example.com/rest/v1/users", {
          headers: {
            apikey: "EXAMPLE_SERVICE_ROLE_KEY",
            Authorization: "Bearer EXAMPLE_SERVICE_ROLE_KEY",
          },
        }),
    );

    expect(forwarded?.get("apikey")).toBe("EXAMPLE_SERVICE_ROLE_KEY");
    expect(forwarded?.get("authorization")).toMatch(/^Bearer eyJ/);
    expect(forwarded?.get("authorization")).not.toContain("EXAMPLE_SERVICE_ROLE_KEY");
  });
});
