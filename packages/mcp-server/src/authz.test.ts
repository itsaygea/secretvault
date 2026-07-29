import { describe, expect, it } from "vitest";
import { hasScope, hasRunnerScope, validateLinkingKeyScopes, type Principal } from "./authz.js";

const linkingPrincipal: Principal = {
  userId: "user-1",
  username: "alice",
  clientId: "client-1",
  credentialType: "linking_key",
  isAdmin: false,
  scopes: ["proxy:github", "secrets:metadata:read"],
};

describe("linking-key authorization", () => {
  it("matches profile-specific and wildcard proxy scopes", () => {
    expect(hasScope(linkingPrincipal, "proxy:github")).toBe(true);
    expect(hasScope(linkingPrincipal, "proxy:gitlab")).toBe(false);
    expect(hasScope({ ...linkingPrincipal, scopes: ["proxy:*"] }, "proxy:gitlab")).toBe(true);
  });

  it("does not let an admin flag bypass linking-key scopes", () => {
    expect(hasScope({ ...linkingPrincipal, isAdmin: true }, "secrets:write")).toBe(false);
  });

  it("preserves full permissions for human sessions", () => {
    expect(hasScope({ ...linkingPrincipal, credentialType: "session", scopes: [] }, "secrets:write")).toBe(true);
  });

  it("rejects unknown scopes while allowing profile-specific proxy and runner scopes", () => {
    expect(validateLinkingKeyScopes(["proxy:github", "mcp:read", "runner:secret:openai_key"]).valid).toBe(true);
    expect(validateLinkingKeyScopes(["users:delete"]).valid).toBe(false);
  });

  it("enforces secret-specific runner capability and denies metadata scopes", () => {
    const metadataPrincipal: Principal = {
      ...linkingPrincipal,
      scopes: ["secrets:metadata:read"],
    };
    expect(hasRunnerScope(metadataPrincipal, "openai_key")).toBe(false);

    const runnerPrincipal: Principal = {
      ...linkingPrincipal,
      scopes: ["runner:secret:openai_key"],
    };
    expect(hasRunnerScope(runnerPrincipal, "openai_key")).toBe(true);
    expect(hasRunnerScope(runnerPrincipal, "other_key")).toBe(false);

    const wildcardRunnerPrincipal: Principal = {
      ...linkingPrincipal,
      scopes: ["runner:secret:*"],
    };
    expect(hasRunnerScope(wildcardRunnerPrincipal, "any_key")).toBe(true);
  });
});

