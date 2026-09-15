import crypto from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { normalizeScopes, type Principal } from "./authz.js";
import { internalError } from "./dbErrors.js";

export const PROXY_ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
const PROXY_TOKEN_PREFIX = "svt_";
const PROXY_TOKEN_PATTERN = /^svt_[A-Za-z0-9_-]{43}$/;

export interface ProxyTokenIssuePrincipal {
  userId: string;
  username: string;
  isAdmin: boolean;
  clientId: string | null;
  credentialType: Principal["credentialType"];
  scopes: string[];
  keyVersion?: number;
  epoch?: number;
}

export function isProxyAccessToken(value: string): boolean {
  return PROXY_TOKEN_PATTERN.test(value);
}

export function hashProxyAccessToken(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function scopeStillGranted(granted: string, requested: string): boolean {
  if (granted === "*") return true;
  if (granted === requested) return true;
  return granted === "proxy:*" && requested.startsWith("proxy:") && requested !== "proxy:*";
}

function selectProxyScopes(currentScopes: unknown, requestedScopes: unknown): { scopes: string[]; error?: string } {
  const available = normalizeScopes(currentScopes)
    .filter(scope => scope === "proxy:*" || scope.startsWith("proxy:") && scope.length > "proxy:".length);
  if (available.length === 0) return { scopes: [], error: "Client has no proxy capability" };

  const requested = requestedScopes === undefined ? available : normalizeScopes(requestedScopes);
  if (requested.length === 0 || requested.some(scope => !scope.startsWith("proxy:"))) {
    return { scopes: [], error: "Only proxy scopes may be exchanged for a proxy access token" };
  }
  if (requested.some(scope => !available.some(granted => scopeStillGranted(granted, scope)))) {
    return { scopes: [], error: "Requested scope exceeds the client capability" };
  }
  return { scopes: requested };
}

/**
 * Resolve a short-lived proxy token before tenant context exists. The lookup
 * uses only the stored digest, then binds the result to the current client key
 * version, current account epoch, and current capability set.
 */
export async function authenticateProxyAccessToken(
  supabase: SupabaseClient<Database, "secretvault">,
  rawToken: string,
): Promise<Principal | null> {
  if (!isProxyAccessToken(rawToken)) return null;

  const tokenHash = hashProxyAccessToken(rawToken);
  let authRow: {
    token_id: string;
    user_id: string;
    client_id: string;
    token_scopes: string[];
    token_key_version: number;
    token_session_epoch: number;
    expires_at: string;
    revoked_at: string | null;
    client_scopes: string[];
    client_key_version: number;
    username: string;
    is_admin: boolean;
    user_session_epoch: number;
  } | null = null;

  if (typeof (supabase as any).rpc === "function") {
    // Production path: migration 028 resolves the token, current client
    // capability, and current account epoch through one narrow pre-auth RPC.
    // A missing/erroring RPC fails closed; it must not fall back to a global
    // tenant-table query after migration 024 has revoked that access.
    const { data, error } = await (supabase as any).rpc("authenticate_proxy_access_token", { p_token_hash: tokenHash });
    if (error) return null;
    authRow = (Array.isArray(data) ? data[0] : data) ?? null;
  } else {
    // Isolated unit-test doubles predate the RPC surface.
    const { data: token, error: tokenError } = await supabase
      .from("proxy_access_tokens")
      .select("id, user_id, client_id, scopes, key_version, session_epoch, expires_at, revoked_at")
      .eq("token_hash", tokenHash)
      .maybeSingle();
    if (tokenError || !token) return null;

    const [{ data: client }, { data: user }] = await Promise.all([
      supabase
        .from("client_applications")
        .select("id, user_id, scopes, key_version")
        .eq("id", token.client_id)
        .eq("user_id", token.user_id)
        .maybeSingle(),
      supabase
        .from("users")
        .select("id, username, is_admin, session_epoch")
        .eq("id", token.user_id)
        .maybeSingle(),
    ]);
    if (!client || !user) return null;
    authRow = {
      token_id: token.id,
      user_id: user.id,
      client_id: client.id,
      token_scopes: token.scopes,
      token_key_version: token.key_version,
      token_session_epoch: token.session_epoch,
      expires_at: token.expires_at,
      revoked_at: token.revoked_at,
      client_scopes: client.scopes,
      client_key_version: client.key_version,
      username: user.username,
      is_admin: user.is_admin,
      user_session_epoch: user.session_epoch,
    };
  }

  if (!authRow) return null;
  const expiresAt = Date.parse(authRow.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now() || authRow.revoked_at) return null;
  if (authRow.token_key_version !== (authRow.client_key_version ?? 1)) return null;
  if (authRow.token_session_epoch !== (authRow.user_session_epoch ?? 0)) return null;

  const tokenScopes = normalizeScopes(authRow.token_scopes);
  const currentScopes = normalizeScopes(authRow.client_scopes);
  if (tokenScopes.length === 0 || tokenScopes.some(scope => !scope.startsWith("proxy:"))) return null;
  if (tokenScopes.some(scope => !currentScopes.some(granted => scopeStillGranted(granted, scope)))) return null;

  return {
    userId: authRow.user_id,
    username: authRow.username,
    clientId: authRow.client_id,
    credentialType: "proxy_token",
    isAdmin: authRow.is_admin,
    scopes: tokenScopes,
    keyVersion: authRow.client_key_version ?? 1,
    epoch: authRow.user_session_epoch ?? 0,
  };
}

export async function issueProxyAccessToken(
  supabase: SupabaseClient<Database, "secretvault">,
  principal: ProxyTokenIssuePrincipal,
  requestedScopes: unknown,
): Promise<{ status: number; body: unknown }> {
  if (principal.credentialType !== "linking_key" || !principal.clientId) {
    return { status: 403, body: { error: "A client linking key is required" } };
  }

  const selected = selectProxyScopes(principal.scopes, requestedScopes);
  if (selected.error) return { status: 403, body: { error: selected.error } };

  const rawToken = `${PROXY_TOKEN_PREFIX}${crypto.randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + PROXY_ACCESS_TOKEN_TTL_SECONDS * 1000).toISOString();
  const { error } = await supabase.from("proxy_access_tokens").insert({
    user_id: principal.userId,
    client_id: principal.clientId,
    token_hash: hashProxyAccessToken(rawToken),
    scopes: selected.scopes,
    key_version: principal.keyVersion ?? 1,
    session_epoch: principal.epoch ?? 0,
    expires_at: expiresAt,
  });
  if (error) {
    const e = internalError();
    return { status: e.status, body: { error: e.message, code: e.code } };
  }

  return {
    status: 200,
    body: {
      access_token: rawToken,
      token_type: "Bearer",
      expires_in: PROXY_ACCESS_TOKEN_TTL_SECONDS,
      expires_at: expiresAt,
      scope: selected.scopes,
    },
  };
}
