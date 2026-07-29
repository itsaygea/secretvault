export type CredentialType = "session" | "linking_key";

export interface Principal {
  userId: string;
  username: string;
  clientId: string | null;
  credentialType: CredentialType;
  isAdmin: boolean;
  scopes: string[];
}

export const LINKING_KEY_SCOPES = [
  "proxy:*",
  "secrets:metadata:read",
  "secrets:write",
  "profiles:read",
  "profiles:write",
  "mcp:read",
  "mcp:write",
] as const;

export function normalizeScopes(scopes: unknown): string[] {
  if (!Array.isArray(scopes)) return [];
  return [...new Set(scopes
    .filter((scope): scope is string => typeof scope === "string")
    .map(scope => scope.trim().toLowerCase())
    .filter(Boolean))];
}

export function validateLinkingKeyScopes(scopes: unknown): { valid: boolean; scopes: string[]; error?: string } {
  const normalized = normalizeScopes(scopes);
  const invalid = normalized.filter(scope => {
    if ((LINKING_KEY_SCOPES as readonly string[]).includes(scope)) return false;
    if (scope.startsWith("proxy:") && scope.length > "proxy:".length) return false;
    if (scope.startsWith("runner:secret:") && scope.length > "runner:secret:".length) return false;
    return true;
  });

  if (invalid.length > 0) {
    return { valid: false, scopes: normalized, error: `Unsupported scope(s): ${invalid.join(", ")}` };
  }

  return { valid: true, scopes: normalized };
}

function scopeMatches(granted: string, required: string): boolean {
  if (granted === "*") return true;
  if (granted === required) return true;
  if (required.startsWith("proxy:") && granted === "proxy:*") return true;
  if (required.startsWith("runner:secret:") && (granted === "runner:secret:*" || granted === "*")) return true;
  return false;
}

/**
 * Human sessions retain the existing user-level permissions. Linking keys
 * are capability credentials and must explicitly carry each requested scope.
 */
export function hasScope(principal: Principal, required: string): boolean {
  if (principal.credentialType === "session") return true;
  return principal.scopes.some(scope => scopeMatches(scope, required));
}

export function hasRunnerScope(principal: Principal, canonicalSecretName: string): boolean {
  if (principal.credentialType === "session") return true;
  const canonical = canonicalSecretName.trim().toLowerCase();
  return principal.scopes.some(scope => {
    const s = scope.trim().toLowerCase();
    if (s === "runner:secret:*" || s === "*") return true;
    if (s === `runner:secret:${canonical}`) return true;
    return false;
  });
}

export function isSessionPrincipal(principal: Principal): boolean {
  return principal.credentialType === "session";
}

