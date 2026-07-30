import type { IncomingMessage } from "node:http";
import { authenticateLinkingKey } from "./users.js";
import { normalizeScopes, type Principal } from "./authz.js";

export async function resolveMcpAuth(
  req: IncomingMessage,
  url: URL,
  clientSupabase: any,
): Promise<Principal | null> {
  let key: string | null = null;
  const authHeader = req.headers["authorization"];
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      key = match[1].trim();
    }
  }
  // Linking keys in query strings leak through history, proxy logs, and
  // observability systems. MCP authentication is header-only.
  void url;

  if (key) {
    const user = await authenticateLinkingKey(clientSupabase, key);
    if (user) {
      return {
        userId: user.id,
        isAdmin: user.is_admin,
        username: user.username,
        clientId: user.clientId ?? null,
        credentialType: "linking_key",
        scopes: normalizeScopes(user.scopes),
        keyVersion: user.keyVersion ?? 0,
        epoch: user.sessionEpoch ?? 0,
      };
    }
  }

  return null;
}

/**
 * SV-AUD-009: a comparable authorization snapshot for an MCP session. An
 * established session is bound to the (user, client, key version, canonical
 * scopes, session epoch) in effect at initialize time. On every subsequent
 * request the live principal is re-resolved and its snapshot compared; any
 * mismatch (scope downgrade, key regeneration, client deletion, password/factor
 * change) closes the transport so long-lived SSE/streamable sessions cannot
 * retain revoked write scopes.
 *
 * `mcp:write` downgrade detection: if the bound session had `mcp:write` but the
 * current principal no longer does, the snapshot differs and the session closes.
 */
export interface McpAuthSnapshot {
  userId: string;
  clientId: string | null;
  keyVersion: number;
  /** Canonical, sorted scope set, including the write flag. */
  scopes: string;
  epoch: number;
}

export function mcpAuthSnapshot(p: Principal): McpAuthSnapshot {
  return {
    userId: p.userId,
    clientId: p.clientId ?? null,
    keyVersion: p.keyVersion ?? 0,
    scopes: [...p.scopes].sort().join(","),
    epoch: p.epoch ?? 0,
  };
}

/** True iff every field of the two snapshots matches exactly. */
export function mcpSnapshotsEqual(a: McpAuthSnapshot, b: McpAuthSnapshot): boolean {
  return a.userId === b.userId
    && a.clientId === b.clientId
    && a.keyVersion === b.keyVersion
    && a.scopes === b.scopes
    && a.epoch === b.epoch;
}
