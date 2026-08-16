import { describe, expect, it } from "@secretvault/testing";
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
      scopes: ["mcp:read", "proxy:*", "secrets:metadata:read", "secrets:write"],
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

describe("SV-AUD-010 inline profile-secret authorization rule", () => {
  // The POST /api/service-profiles route admits an inline create_secrets array.
  // Creating secret rows through it is a secret write, so the route requires
  // secrets:write in addition to profiles:write whenever create_secrets is
  // nonempty. Human sessions bypass scope checks; the exploit path is a linking
  // key granted profiles:write without secrets:write. This encodes the exact
  // predicate the route evaluates.
  const admits = (principal: Principal, createSecrets: unknown[]) => {
    if (!hasScope(principal, "profiles:write")) return false;
    if (Array.isArray(createSecrets) && createSecrets.length > 0 && !hasScope(principal, "secrets:write")) return false;
    return true;
  };

  it("denies a profiles:write-only linking key when create_secrets is present", () => {
    const profilesOnly: Principal = { ...linkingPrincipal, scopes: ["profiles:write"] };
    expect(admits(profilesOnly, [{ name: "x", value: "y" }])).toBe(false);
    // ...but the same key may still create a profile with NO inline secrets.
    expect(admits(profilesOnly, [])).toBe(true);
  });

  it("admits a linking key holding both profiles:write and secrets:write", () => {
    const both: Principal = { ...linkingPrincipal, scopes: ["profiles:write", "secrets:write"] };
    expect(admits(both, [{ name: "x", value: "y" }])).toBe(true);
  });

  it("admits a human session regardless (sessions bypass scope checks)", () => {
    const session: Principal = { ...linkingPrincipal, credentialType: "session", scopes: [] };
    expect(admits(session, [{ name: "x", value: "y" }])).toBe(true);
  });
});


