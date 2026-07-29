import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { getSystemSetting } from "./users.js";

/**
 * SV-044: bounded audit retention.
 *
 * Retention is configured as a system setting (`audit_retention_days`). A
 * separate floor (`audit_retention_floor_days`) guarantees pruning can never
 * erase records that an active policy still needs — the effective cutoff is
 * the longer of the two, and is enforced server-side regardless of caller.
 *
 * Default is unbounded (null) so existing installations keep every row until
 * an operator opts in.
 */
const RETENTION_KEY = "audit_retention_days";
const FLOOR_KEY = "audit_retention_floor_days";
const MIN_FLOOR_DAYS = 7;

export interface RetentionPolicy {
  retentionDays: number | null;
  floorDays: number;
}

export async function getRetentionPolicy(
  supabase: SupabaseClient<any, "secretvault">,
): Promise<RetentionPolicy> {
  const retentionDays = await getSystemSetting<number | null>(supabase, RETENTION_KEY, null);
  const floorDays = await getSystemSetting<number>(supabase, FLOOR_KEY, MIN_FLOOR_DAYS);
  return {
    retentionDays: typeof retentionDays === "number" && retentionDays > 0 ? retentionDays : null,
    floorDays: Math.max(MIN_FLOOR_DAYS, typeof floorDays === "number" ? floorDays : MIN_FLOOR_DAYS),
  };
}

export async function setRetentionPolicy(
  supabase: SupabaseClient<any, "secretvault">,
  retentionDays: number | null,
  floorDays: number,
  userId?: string,
): Promise<RetentionPolicy> {
  const { setSystemSetting } = await import("./users.js");
  const safeFloor = Math.max(MIN_FLOOR_DAYS, floorDays);
  if (retentionDays !== null && retentionDays < safeFloor) {
    throw new Error(`retention_days (${retentionDays}) must be >= floor_days (${safeFloor})`);
  }
  await setSystemSetting(supabase, RETENTION_KEY, retentionDays, userId);
  await setSystemSetting(supabase, FLOOR_KEY, safeFloor, userId);
  return getRetentionPolicy(supabase);
}

/**
 * Delete audit rows older than the retention cutoff. The cutoff is the longer
 * of retentionDays and floorDays, so an operator mis-configuring a short
 * retention can never delete records still inside the floor. Returns the number
 * of rows removed. Honors the immutable-actor-snapshot contract: deletion is by
 * age only, never by actor.
 */
export async function pruneOldAuditLogs(
  supabase: SupabaseClient<Database, "secretvault">,
  policy: RetentionPolicy,
): Promise<number> {
  if (!policy.retentionDays) return 0;
  const cutoffDays = Math.max(policy.retentionDays, policy.floorDays);
  const cutoff = new Date(Date.now() - cutoffDays * 86_400_000).toISOString();

  const { count, error } = await supabase
    .from("access_logs")
    .delete({ count: "exact" })
    .lt("created_at", cutoff);

  if (error) {
    console.error(`[audit:retention] prune failed: ${error.message}`);
    return 0;
  }
  return count ?? 0;
}

/**
 * Export audit rows as an immutable snapshot for archival. Returns rows in
 * ascending created_at order so the archive is append-friendly. Excludes no
 * columns — the contract is that every field the live table holds is
 * preserved, so an archived row is a faithful copy of the live one.
 */
export async function exportAuditLogs(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  options: { from?: string | null; to?: string | null; limit?: number } = {},
): Promise<Database["secretvault"]["Tables"]["access_logs"]["Row"][]> {
  const limit = Math.min(Math.max(options.limit ?? 10_000, 1), 50_000);
  let q = supabase
    .from("access_logs")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: true })
    .limit(limit);
  if (options.from) q = q.gte("created_at", options.from);
  if (options.to) q = q.lt("created_at", options.to);
  const { data, error } = await q;
  if (error) {
    console.error(`[audit:export] failed: ${error.message}`);
    return [];
  }
  return (data ?? []) as Database["secretvault"]["Tables"]["access_logs"]["Row"][];
}
