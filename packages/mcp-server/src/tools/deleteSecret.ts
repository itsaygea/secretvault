import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { canonicalName } from "@secretvault/shared";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { finishAuditEvent, recordAuditEvent, startCriticalAuditEvent } from "../audit.js";
import { safeErrorMessage } from "../dbErrors.js";

const inputSchema = {
  name: z.string().describe("Name of the secret to delete"),
};

export function registerDeleteSecret(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, principal: Principal) {
  server.tool("delete_secret", "Delete a secret permanently.", inputSchema, async ({ name: rawName }) => {
    if (!hasScope(principal, "mcp:write") && !hasScope(principal, "secrets:write")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:delete_secret",
        outcome: "denied",
        metadata: { reason: "missing_secret_write_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP secret-write scope is missing" }) }] };
    }
    const { userId } = principal;
    const name = canonicalName(rawName);
    // Find the secret first to get id for logging
    let findQuery = supabase
      .from("secrets")
      .select("id, display_name")
      .eq("name", name);

    if (!(principal.credentialType === "session" && principal.isAdmin)) {
      findQuery = findQuery.eq("user_id", userId);
    }

    const { data: secret } = await findQuery.single();

    if (!secret) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: `Secret '${rawName}' not found` }) }] };
    }

    const auditId = await startCriticalAuditEvent(supabase, {
      secretId: secret.id,
      secretName: name,
      userId,
      clientId: principal.clientId,
      accessType: "mcp_secret_delete",
      caller: "mcp:delete_secret",
    });
    if (!auditId) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" }) }] };
    }

    const { error } = await supabase
      .from("secrets")
      .delete()
      .eq("id", secret.id);

    if (error) {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_delete_failed" });
      return { content: [{ type: "text" as const, text: safeResponse({ error: safeErrorMessage(error) }) }] };
    }

    await finishAuditEvent(supabase, auditId, "succeeded");

    const result = {
      deleted: true,
      name,
      display_name: secret.display_name ?? name,
    };

    return { content: [{ type: "text" as const, text: safeResponse(result) }] };
  });
}
