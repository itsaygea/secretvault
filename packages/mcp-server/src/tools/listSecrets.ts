import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { recordAuditEvent } from "../audit.js";
import { clampPageSize, decodeCursor, encodeCursor, paginateQuery, escapePostgrestValue, type PageResult } from "../pagination.js";
import { safeErrorMessage } from "../dbErrors.js";

const inputSchema = {
  environment: z
    .enum(["development", "production", "staging"])
    .optional()
    .describe("Filter by environment"),
  cursor: z
    .string()
    .optional()
    .describe("Opaque cursor from a previous page's next_cursor"),
  page_size: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe("Number of results per page (default 50, max 200)"),
};

export function registerListSecrets(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, principal: Principal) {
  server.tool("list_secrets", "List all secrets with masked values. Never returns raw values.", inputSchema, async ({ environment, cursor, page_size }) => {
    if (!hasScope(principal, "mcp:read") && !hasScope(principal, "secrets:metadata:read")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:list_secrets",
        outcome: "denied",
        metadata: { reason: "missing_metadata_read_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP metadata-read scope is missing" }) }] };
    }
    const { userId } = principal;
    const pageSize = clampPageSize(page_size);
    let query = supabase
      .from("secrets")
      .select("id, name, display_name, environment, masked_preview, tags");

    if (!(principal.credentialType === "session" && principal.isAdmin)) {
      query = query.eq("user_id", userId);
    }

    if (environment) {
      query = query.eq("environment", environment);
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      if (decoded) {
        query = query.or(`name.gt.${escapePostgrestValue(decoded.after)},and(name.eq.${escapePostgrestValue(decoded.after)},id.gt.${escapePostgrestValue(decoded.tiebreaker)})`);
      }
    }

    query = query.order("name").order("id");

    const { data: secrets, error } = await query.limit(pageSize + 1);

    if (error) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: safeErrorMessage(error) }) }] };
    }

    const page = await paginateQuery<{ id: string; name: string; display_name: string | null; environment: string; masked_preview: string; tags: string[] }>(
      secrets ?? [],
      pageSize,
      (row) => encodeCursor(row.name, row.id),
    );

    const results = page.data.map((s) => ({
      name: s.name,
      display_name: s.display_name ?? s.name,
      masked: s.masked_preview,
      environment: s.environment,
      tags: s.tags,
    }));

    // Single summary audit event per query instead of N per-result events
    void recordAuditEvent(supabase, {
      secretName: "system",
      userId,
      clientId: principal.clientId,
      accessType: "mcp_list_secrets",
      caller: "mcp:list_secrets",
      metadata: {
        result_count: String(results.length),
        has_more: String(page.next_cursor !== null),
      },
    }).catch(() => undefined);

    return {
      content: [{
        type: "text" as const,
        text: safeResponse({
          data: results,
          next_cursor: page.next_cursor,
        }),
      }],
    };
  });
}
