import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { canonicalName } from "@secretvault/shared";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { recordAuditEvent } from "../audit.js";

const inputSchema = {
  name: z.string().describe("Exact name of the secret"),
};

export function registerGetSecretReference(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, principal: Principal) {
  server.tool("get_secret_reference", "Get a reference token for a secret. Returns masked value and SDK usage example. Never returns raw value.", inputSchema, async ({ name: rawName }) => {
    if (!hasScope(principal, "mcp:read") && !hasScope(principal, "secrets:metadata:read")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:get_secret_reference",
        outcome: "denied",
        metadata: { reason: "missing_metadata_read_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP metadata-read scope is missing" }) }] };
    }
    const { userId } = principal;
    const name = canonicalName(rawName);
    let query = supabase
      .from("secrets")
      .select("id, name, display_name, environment, masked_preview, tags")
      .eq("name", name);

    if (!(principal.credentialType === "session" && principal.isAdmin)) {
      query = query.eq("user_id", userId);
    }

    const { data: secret, error } = await query.single();

    if (error || !secret) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: `Secret '${rawName}' not found` }) }] };
    }

    // Log access
    await recordAuditEvent(supabase, {
      secretId: secret.id,
      secretName: name,
      userId,
      clientId: principal.clientId,
      accessType: "mcp_reference",
      caller: "mcp:get_secret_reference",
    });

    const displayName = secret.display_name ?? name;
    const servicePrefix = name.includes("_") ? name.split("_")[0] : name;

    const result = {
      name,
      display_name: displayName,
      masked: secret.masked_preview,
      environment: secret.environment,
      tags: secret.tags,
      proxy_usage: `Authorization: Bearer <linking_key> against /proxy/${servicePrefix}/...`,
    };

    return { content: [{ type: "text" as const, text: safeResponse(result) }] };
  });
}
