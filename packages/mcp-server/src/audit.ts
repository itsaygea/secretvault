import crypto from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database, Json } from "@secretvault/shared";
import { decodeBeforeCursor, encodeBeforeCursor, escapePostgrestValue } from "./pagination.js";

export type AuditOutcome = "succeeded" | "failed" | "denied" | "unknown";

export type AuditMetadata = Record<string, string | number | boolean | null>;

export interface AuditEvent {
  userId?: string | null;
  clientId?: string | null;
  secretId?: string | null;
  /** Use "system" for account, policy, and authentication events. */
  secretName?: string | null;
  accessType: string;
  caller: string;
  outcome?: AuditOutcome;
  requestId?: string | null;
  metadata?: AuditMetadata;
  /** Immutable snapshot of the actor's username at event time. */
  actorUsername?: string | null;
  /** Originating source metadata, when surfaced by the transport. */
  sourceIp?: string | null;
  sourceUserAgent?: string | null;
}

const SENSITIVE_QUERY_KEYS = /^(?:authorization|api[_-]?key|code|credential|key|password|secret|sig(?:nature)?|state|token)$/i;

/**
 * Operational alert sink. Set by the server at boot (see index.ts). When an
 * audit write/finalization fails, or a row is left in the `unknown` terminal
 * state, this callback fires so operators can route the signal to metrics or a
 * webhook. The default sink logs to stderr so failures are never silent.
 */
export type AuditAlertFn = (alert: {
  kind: "write_failed" | "finalize_failed" | "unknown_finalized" | "repeated_denials" | "suspicious_activity";
  accessType: string;
  detail: string;
}) => void;

let alertSink: AuditAlertFn = ({ kind, accessType, detail }) => {
  console.error(`[audit:alert] ${kind} ${accessType}: ${detail}`);
};

export function setAuditAlertSink(fn: AuditAlertFn): void {
  alertSink = fn;
}

function emitAlert(alert: Parameters<AuditAlertFn>[0]): void {
  try {
    alertSink(alert);
  } catch {
    // An alerting failure must never escape into the audit write path.
  }
}

export function sanitizeAuditCaller(caller: string): string {
  const queryIndex = caller.indexOf("?");
  if (queryIndex < 0) return caller.slice(0, 512);

  const prefix = caller.slice(0, queryIndex);
  const query = caller.slice(queryIndex + 1).split("#", 1)[0];
  const params = new URLSearchParams(query);
  for (const key of params.keys()) {
    if (SENSITIVE_QUERY_KEYS.test(key)) params.set(key, "[REDACTED]");
  }
  return `${prefix}?${params.toString()}`.slice(0, 512);
}

function normalizeRequestId(requestId: string | null | undefined): string {
  if (requestId && /^[A-Za-z0-9._:-]{1,128}$/.test(requestId)) return requestId;
  return crypto.randomUUID();
}

function truncate(value: string | null | undefined, max: number): string | null {
  if (!value) return null;
  const v = value.trim();
  if (!v) return null;
  return v.length > max ? v.slice(0, max) : v;
}

function normalizeMetadata(metadata: AuditMetadata | undefined): Json {
  if (!metadata) return {};
  const safe: AuditMetadata = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (/^[A-Za-z0-9_.-]{1,64}$/.test(key)) safe[key] = value;
  }
  return safe;
}

function normalizeEvent(event: AuditEvent): Database["secretvault"]["Tables"]["access_logs"]["Insert"] | null {
  const secretName = (event.secretName ?? "system").trim() || "system";
  const accessType = event.accessType.trim();
  const caller = sanitizeAuditCaller(event.caller.trim());
  if (!/^[a-z][a-z0-9_.:-]{1,63}$/.test(accessType) || !caller || caller.length > 512) {
    console.error("[audit] rejected malformed audit event");
    emitAlert({ kind: "write_failed", accessType: event.accessType, detail: "rejected malformed audit event" });
    return null;
  }
  // "system" and "account" are the two non-secret sentinel targets: account
  // covers authentication and identity lifecycle, system covers policy and
  // infrastructure. Neither requires a user_id (the actor may be anonymous, as
  // on a failed login), so they are exempt from the non-secret-requires-user
  // rule.
  const isNonSecret = secretName === "system" || secretName === "account";
  if (!isNonSecret && !event.userId) {
    console.error("[audit] rejected non-system event without user_id");
    emitAlert({ kind: "write_failed", accessType: event.accessType, detail: "rejected non-system event without user_id" });
    return null;
  }
  return {
    user_id: event.userId ?? null,
    client_id: event.clientId ?? null,
    secret_id: event.secretId ?? null,
    secret_name: secretName,
    access_type: accessType,
    caller,
    outcome: event.outcome ?? "succeeded",
    request_id: normalizeRequestId(event.requestId),
    metadata: normalizeMetadata(event.metadata),
    actor_username: truncate(event.actorUsername, 64),
    source_ip: truncate(event.sourceIp, 64),
    source_user_agent: truncate(event.sourceUserAgent, 512),
  };
}

/**
 * The only write path for access_logs. Callers deliberately do not get to
 * omit actor/target fields, and failures are surfaced to the caller so
 * security-sensitive operations can choose a fail-closed policy.
 */
export async function recordAuditEvent(
  supabase: SupabaseClient<Database, "secretvault">,
  event: AuditEvent,
): Promise<string | null> {
  const payload = normalizeEvent(event);
  if (!payload) return null;

  try {
    const { data, error } = await supabase.from("access_logs").insert(payload).select("id").single();

    if (error) {
      console.error(`[audit] failed to record ${event.accessType}: ${error.message}`);
      emitAlert({ kind: "write_failed", accessType: event.accessType, detail: error.message });
      return null;
    }
    return data?.id ?? null;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error(`[audit] failed to record ${event.accessType}: ${detail}`);
    emitAlert({ kind: "write_failed", accessType: event.accessType, detail });
    return null;
  }
}

/** Gate a secret-bearing operation on the ability to write its audit event. */
export async function startCriticalAuditEvent(
  supabase: SupabaseClient<Database, "secretvault">,
  event: Omit<AuditEvent, "outcome">,
): Promise<string | null> {
  return recordAuditEvent(supabase, { ...event, outcome: "unknown" });
}

/** Finalization failure deliberately leaves the row as unknown for alerting. */
export async function finishAuditEvent(
  supabase: SupabaseClient<Database, "secretvault">,
  auditId: string,
  outcome: Exclude<AuditOutcome, "unknown">,
  metadata?: AuditMetadata,
): Promise<boolean> {
  const update: { outcome: Exclude<AuditOutcome, "unknown">; metadata?: Json } = { outcome };
  if (metadata) update.metadata = normalizeMetadata(metadata);
  try {
    const { error } = await supabase.from("access_logs").update(update).eq("id", auditId);
    if (error) {
      console.error(`[audit] failed to finalize ${auditId} as ${outcome}: ${error.message}`);
      emitAlert({ kind: "finalize_failed", accessType: outcome, detail: `${auditId}: ${error.message}` });
      // The row stays `unknown` — surface it as the alerting contract requires.
      emitAlert({ kind: "unknown_finalized", accessType: outcome, detail: auditId });
      return false;
    }
    return true;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error(`[audit] failed to finalize ${auditId} as ${outcome}: ${detail}`);
    emitAlert({ kind: "finalize_failed", accessType: outcome, detail: `${auditId}: ${detail}` });
    emitAlert({ kind: "unknown_finalized", accessType: outcome, detail: auditId });
    return false;
  }
}

/** Cursor pagination parameters for audit-log reads. */
export interface AuditLogQuery {
  /** Opaque cursor returned in the previous page's `next_cursor`. */
  cursor?: string | null;
  pageSize?: number;
  /** Inclusive lower bound on created_at (ISO 8601). */
  from?: string | null;
  /** Exclusive upper bound on created_at (ISO 8601). */
  to?: string | null;
  accessType?: string | null;
  outcome?: string | null;
  secretName?: string | null;
  clientId?: string | null;
}

export interface AuditLogRow {
  id: string;
  secret_name: string;
  access_type: string;
  caller: string;
  outcome: AuditOutcome;
  request_id: string | null;
  created_at: string;
  user_id: string | null;
  client_id: string | null;
  actor_username: string | null;
  metadata: Json;
}

export interface AuditLogPage {
  events: AuditLogRow[];
  /** Opaque cursor for the next page; null when the page is the last. */
  next_cursor: string | null;
}

const MAX_PAGE_SIZE = 200;
const DEFAULT_PAGE_SIZE = 50;

/**
 * Filtered, cursor-paginated read over access_logs scoped to a single user.
 * Ordering is (created_at DESC, id DESC) so the cursor is stable across
 * concurrent inserts. Pass `clientId` to further scope to one client app.
 */
export async function readAuditLogPage(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  query: AuditLogQuery,
): Promise<AuditLogPage> {
  const pageSize = Math.min(Math.max(query.pageSize ?? DEFAULT_PAGE_SIZE, 1), MAX_PAGE_SIZE);

  let q = supabase
    .from("access_logs")
    .select("id, secret_name, access_type, caller, outcome, request_id, created_at, user_id, client_id, actor_username, metadata")
    .eq("user_id", userId);

  if (query.from) q = q.gte("created_at", query.from);
  if (query.to) q = q.lt("created_at", query.to);
  if (query.accessType) q = q.eq("access_type", query.accessType);
  if (query.outcome) q = q.eq("outcome", query.outcome as AuditOutcome);
  if (query.secretName) q = q.eq("secret_name", query.secretName);
  if (query.clientId) q = q.eq("client_id", query.clientId);

  if (query.cursor) {
    const decoded = decodeBeforeCursor(query.cursor);
    if (decoded) {
      // SV-AUD-014: cursor is HMAC-authenticated and field-validated before it
      // ever reaches here; values are escaped as defense-in-depth. A malformed/
      // tampered cursor decodes to null and is ignored (first page).
      q = q.or(`created_at.lt.${escapePostgrestValue(decoded.before)},and(created_at.eq.${escapePostgrestValue(decoded.before)},id.lt.${escapePostgrestValue(decoded.tiebreaker)})`);
    }
  }

  q = q.order("created_at", { ascending: false }).order("id", { ascending: false });

  const { data, error } = await q.limit(pageSize + 1);
  if (error) {
    emitAlert({ kind: "write_failed", accessType: "audit_read", detail: error.message });
    return { events: [], next_cursor: null };
  }

  const rows = (data ?? []) as AuditLogRow[];
  const hasMore = rows.length > pageSize;
  const page = hasMore ? rows.slice(0, pageSize) : rows;
  const next_cursor = hasMore && page.length > 0 ? encodeBeforeCursor(page[page.length - 1].created_at, page[page.length - 1].id) : null;

  return { events: page, next_cursor };
}
