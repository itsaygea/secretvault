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
      };
    }
  }

  return null;
}
