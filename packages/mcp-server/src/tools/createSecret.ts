import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { encryptSecret, maskSecret, generatePrefixSuffix, validateSecretName, canonicalName } from "@secretvault/shared";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { finishAuditEvent, recordAuditEvent, startCriticalAuditEvent } from "../audit.js";

const inputSchema = {
  name: z.string().describe("Name for the secret"),
  value: z.string().describe("The secret value to store"),
  environment: z.string().default("development").describe("Environment (development, staging, production)"),
  tags: z.array(z.string()).default([]).describe("Tags for categorization"),
};

export function registerCreateSecret(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, masterKey: Buffer, principal: Principal) {
  server.tool("create_secret", "Create a new secret. The value is encrypted locally before storage. Never echoes back the raw value.", inputSchema, async ({ name: displayName, value, environment, tags }) => {
    if (!hasScope(principal, "mcp:write") && !hasScope(principal, "secrets:write")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:create_secret",
        outcome: "denied",
        metadata: { reason: "missing_secret_write_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP secret-write scope is missing" }) }] };
    }
    const { userId } = principal;
    // Validate name format
    try {
      validateSecretName(displayName);
    } catch (err) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: (err as Error).message }) }] };
    }

    const name = canonicalName(displayName);

    // Check if secret already exists (case-insensitive)
    const { data: existing } = await supabase
      .from("secrets")
      .select("id, display_name")
      .eq("name", name)
      .eq("user_id", userId)
      .maybeSingle();

    if (existing) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: `Secret '${existing.display_name ?? name}' already exists. Use rotate_secret to update it.` }) }] };
    }

    const auditId = await startCriticalAuditEvent(supabase, {
      secretName: name,
      userId,
      clientId: principal.clientId,
      accessType: "mcp_secret_create",
      caller: "mcp:create_secret",
    });
    if (!auditId) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" }) }] };
    }

    try {
      // Encrypt the value
      const { encrypted } = await encryptSecret(value, masterKey);
      const masked = maskSecret(value);
      const { prefix, suffix } = generatePrefixSuffix(value);

      const { error } = await supabase.from("secrets").insert({
        name,
        display_name: displayName,
        environment,
        encrypted_blob: encrypted,
        masked_preview: masked,
        key_prefix: prefix,
        key_suffix: suffix,
        tags,
        user_id: userId,
      });

      if (error) {
        await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_insert_failed" });
        return { content: [{ type: "text" as const, text: safeResponse({ error: error.message }) }] };
      }

      await finishAuditEvent(supabase, auditId, "succeeded");

      // NEVER echo back the raw value
      const result = {
        created: true,
        name,
        display_name: displayName,
        masked_preview: masked,
        environment,
        tags,
      };

      return { content: [{ type: "text" as const, text: safeResponse(result) }] };
    } catch {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_create_failed" });
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Failed to create secret" }) }] };
    }
  });
}
