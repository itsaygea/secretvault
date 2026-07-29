import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { safeResponse } from "../safeResponse.js";
import { hasScope, type Principal } from "../authz.js";
import { recordAuditEvent } from "../audit.js";
import { clampPageSize, decodeCursor, encodeCursor, paginateQuery } from "../pagination.js";

const inputSchema = {
  query: z.string().optional().describe("Search pattern for secret name (case-insensitive)"),
  tags: z.array(z.string()).optional().describe("Filter by tags"),
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

export function registerSearchSecrets(server: McpServer, supabase: SupabaseClient<Database, "secretvault">, principal: Principal) {
  server.tool("search_secrets", "Search secrets by name pattern or tags. Returns masked values only.", inputSchema, async ({ query, tags, cursor, page_size }) => {
    if (!hasScope(principal, "mcp:read") && !hasScope(principal, "secrets:metadata:read")) {
      void recordAuditEvent(supabase, {
        userId: principal.userId,
        clientId: principal.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: "mcp:search_secrets",
        outcome: "denied",
        metadata: { reason: "missing_metadata_read_scope" },
      }).catch(() => undefined);
      return { content: [{ type: "text" as const, text: safeResponse({ error: "Forbidden: required MCP metadata-read scope is missing" }) }] };
    }
    const { userId } = principal;
    const pageSize = clampPageSize(page_size);
    let qb = supabase
      .from("secrets")
      .select("id, name, display_name, environment, masked_preview, tags");

    if (!(principal.credentialType === "session" && principal.isAdmin)) {
      qb = qb.eq("user_id", userId);
    }

    if (query) {
      qb = qb.ilike("name", `%${query}%`);
    }

    if (tags && tags.length > 0) {
      qb = qb.contains("tags", tags);
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      if (decoded) {
        qb = qb.or(`name.gt.${decoded.after},and(name.eq.${decoded.after},id.gt.${decoded.tiebreaker})`);
      }
    }

    qb = qb.order("name").order("id");

    const { data: secrets, error } = await qb.limit(pageSize + 1);

    if (error) {
      return { content: [{ type: "text" as const, text: safeResponse({ error: error.message }) }] };
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

    // Single summary audit event per query
    void recordAuditEvent(supabase, {
      secretName: "system",
      userId,
      clientId: principal.clientId,
      accessType: "mcp_search_secrets",
      caller: "mcp:search_secrets",
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
