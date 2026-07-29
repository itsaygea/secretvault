import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { encryptSecret, maskSecret, generatePrefixSuffix, canonicalName } from "@secretvault/shared";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { finishAuditEvent, recordAuditEvent, startCriticalAuditEvent } from "../audit.js";

const inputSchema = {
  name: z.string().describe("Name of the secret to rotate"),
  new_value: z.string().describe("The new secret value"),
};

export function registerRotateSecret(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, masterKey: Buffer, principal: Principal) {
  server.tool("rotate_secret", "Rotate a secret's value. The old value is replaced. Never echoes back the raw value.", inputSchema, async ({ name: rawName, new_value }) => {
    if (!hasScope(principal, "mcp:write") && !hasScope(principal, "secrets:write")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:rotate_secret",
        outcome: "denied",
        metadata: { reason: "missing_secret_write_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP secret-write scope is missing" }) }] };
    }
    const { userId } = principal;
    const name = canonicalName(rawName);
    // Find existing secret
    let findQuery = supabase
      .from("secrets")
      .select("id, display_name")
      .eq("name", name);

    if (!(principal.credentialType === "session" && principal.isAdmin)) {
      findQuery = findQuery.eq("user_id", userId);
    }

    const { data: existing, error: findError } = await findQuery.single();

    if (findError || !existing) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: `Secret '${rawName}' not found` }) }] };
    }

    const auditId = await startCriticalAuditEvent(supabase, {
      secretId: existing.id,
      secretName: name,
      userId,
      clientId: principal.clientId,
      accessType: "mcp_secret_rotate",
      caller: "mcp:rotate_secret",
    });
    if (!auditId) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" }) }] };
    }

    try {
      // Encrypt new value
      const { encrypted } = await encryptSecret(new_value, masterKey);
      const masked = maskSecret(new_value);
      const { prefix, suffix } = generatePrefixSuffix(new_value);

      const { error: updateError } = await supabase
        .from("secrets")
        .update({
          encrypted_blob: encrypted,
          masked_preview: masked,
          key_prefix: prefix,
          key_suffix: suffix,
        })
        .eq("id", existing.id);

      if (updateError) {
        await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_update_failed" });
        return { content: [{ type: "text" as const, text: safeResponse({ error: updateError.message }) }] };
      }

      await finishAuditEvent(supabase, auditId, "succeeded");

      // NEVER echo back the raw value
      const result = {
        rotated: true,
        name,
        display_name: existing.display_name ?? name,
        new_masked_preview: masked,
      };

      return { content: [{ type: "text" as const, text: safeResponse(result) }] };
    } catch {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_rotate_failed" });
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Failed to rotate secret" }) }] };
    }
  });
}
