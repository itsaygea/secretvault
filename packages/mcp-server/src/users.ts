import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { decryptSecret, encryptSecret, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { validateLinkingKeyScopes } from "./authz.js";
import { recordAuditEvent } from "./audit.js";
import { verifyStepUpToken, verifyStepUpTokenForResource, wipeUserTotpState } from "./stepup.js";
import { internalError } from "./dbErrors.js";
import { validateUsername, validatePassword, validateBoundedString, LIMITS, validationErrorResponse, ValidationError } from "./validation.js";

/** Stable 500 body for unexpected database failures — never raw DB text (SV-047). */
function internalErrorResponse(): { status: number; body: { error: string; code: string } } {
  const e = internalError();
  return { status: e.status, body: { error: e.message, code: e.code } };
}

const BCRYPT_ROUNDS = 12;
let setupCodeHash: string | null = null;

// ── Setup Code ────────────────────────────────────────────────────────

export async function initSetupCode(supabase: SupabaseClient<Database, "secretvault">): Promise<void> {
  const { data: admin } = await supabase
    .from("users")
    .select("id")
    .eq("is_admin", true)
    .maybeSingle();

  if (admin) {
    setupCodeHash = null;
    return;
  }

  // No admin exists — generate a one-time setup code
  const code = `setup_${crypto.randomBytes(16).toString("hex")}`;
  setupCodeHash = crypto.createHash("sha256").update(code).digest("hex");
  console.error("");
  console.error("╔══════════════════════════════════════════════════════════════╗");
  console.error("║  SecretVault Initial Setup                                   ║");
  console.error("║                                                              ║");
  console.error("║  No admin user found. Use this setup code to create one:     ║");
  console.error(`║  ${code}`);
  console.error("║                                                              ║");
  console.error("║  This code will NOT be shown again.                          ║");
  console.error("╚══════════════════════════════════════════════════════════════╝");
  console.error("");
}

export async function handleAuthStatus(
  supabase: SupabaseClient<Database, "secretvault">,
): Promise<{ status: number; body: unknown }> {
  const { data: admin } = await supabase
    .from("users")
    .select("id")
    .eq("is_admin", true)
    .maybeSingle();

  return { status: 200, body: { initialized: !!admin } };
}

export async function handleSetup(
  supabase: SupabaseClient<Database, "secretvault">,
  body: { setup_code?: string; username?: string; password?: string },
  tokenGenerator?: (userId: string) => string,
): Promise<{ status: number; body: unknown }> {
  const { setup_code, username, password } = body;

  if (!setup_code || !username || !password) {
    return { status: 400, body: { error: "setup_code, username, and password are required" } };
  }

  // Check if admin already exists
  const { data: existing } = await supabase
    .from("users")
    .select("id")
    .eq("is_admin", true)
    .maybeSingle();

  if (existing) {
    return { status: 409, body: { error: "Admin user already exists. Use normal login." } };
  }

  // Validate setup code
  if (!setupCodeHash) {
    return { status: 403, body: { error: "No setup code active. Restart the server if no admin exists." } };
  }

  const codeHash = crypto.createHash("sha256").update(setup_code).digest("hex");
  if (codeHash !== setupCodeHash) {
    return { status: 401, body: { error: "Invalid setup code" } };
  }

  // Validate username
  try {
    validateUsername(username);
    validatePassword(password);
  } catch (err) {
    return validationErrorResponse(err);
  }

  // Invalidate setup code immediately
  setupCodeHash = null;

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { data: user, error } = await supabase
    .from("users")
    .insert({ username, password_hash: passwordHash, is_admin: true })
    .select("id, username, is_admin")
    .single();

  if (error) {
    if (error.code === "23505") return { status: 409, body: { error: `User '${username}' already exists` } };
    return internalErrorResponse();
  }

  console.error(`[setup] Admin user "${username}" created successfully`);
  const token = tokenGenerator ? tokenGenerator(user.id) : undefined;
  return { status: 201, body: { created: true, username: user.username, token } };
}

// ── Helpers ──────────────────────────────────────────────────────────

export function hashLinkingKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

export function generateLinkingKey(): { key: string; hash: string; prefix: string } {
  const key = `sv_${crypto.randomBytes(24).toString("hex")}`;
  const hash = hashLinkingKey(key);
  const prefix = key.substring(0, 11); // "sv_" + 8 hex chars
  return { key, hash, prefix };
}

// ── Bootstrap ────────────────────────────────────────────────────────

export async function bootstrapAdmin(
  supabase: SupabaseClient<Database, "secretvault">,
  uiPassword: string,
): Promise<void> {
  const { data: existing } = await supabase
    .from("users")
    .select("id")
    .eq("is_admin", true)
    .maybeSingle();

  if (existing) return;

  const passwordHash = await bcrypt.hash(uiPassword, BCRYPT_ROUNDS);
  const { error } = await supabase.from("users").insert({
    username: "admin",
    password_hash: passwordHash,
    is_admin: true,
  });

  if (error) {
    console.error(`[bootstrap] Failed to create admin user:`, JSON.stringify(error));
  } else {
    console.error("[bootstrap] Created admin user from SECRETVAULT_UI_PASSWORD");
  }
}

// ── Auth ─────────────────────────────────────────────────────────────

export async function authenticateUser(
  supabase: SupabaseClient<Database, "secretvault">,
  username: string,
  password: string,
): Promise<{ id: string; username: string; is_admin: boolean; session_epoch: number } | null> {
  const { data: user } = await supabase
    .from("users")
    .select("id, username, is_admin, password_hash, session_epoch")
    .eq("username", username)
    .single();

  if (!user) return null;
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return null;

  return { id: user.id, username: user.username, is_admin: user.is_admin, session_epoch: user.session_epoch ?? 0 };
}

/**
 * SV-AUD-002: invalidate every existing session for a user by advancing their
 * session epoch. Session tokens fold the epoch into their HMAC signature and are
 * rejected on validation when the embedded epoch no longer matches the DB value.
 * Returns the new epoch, or null on failure. Idempotent in effect (any monotonic
 * bump invalidates prior tokens); used after factor replacement/removal.
 */
export async function bumpSessionEpoch(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
): Promise<number | null> {
  const { data: user } = await supabase
    .from("users")
    .select("session_epoch")
    .eq("id", userId)
    .single();
  const nextEpoch = (user?.session_epoch ?? 0) + 1;
  const { error } = await supabase
    .from("users")
    .update({ session_epoch: nextEpoch })
    .eq("id", userId);
  if (error) return null;
  return nextEpoch;
}

// ── Debounced last_used_at batch updater ──────────────────────────
// Accumulates client IDs and flushes in batches every 5s to avoid one
// synchronous write per proxy request. Fire-and-forget; failures are
// silently dropped since the value is informational, not auth-critical.

const pendingLastUsed = new Map<string, string>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const LAST_USED_FLUSH_MS = 5_000;

function debouncedLastUsedUpdate(supabase: SupabaseClient<any, "secretvault">, clientId: string): void {
  pendingLastUsed.set(clientId, new Date().toISOString());
  if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushTimer = null;
      const batch = [...pendingLastUsed.entries()];
      pendingLastUsed.clear();
      for (const [id, ts] of batch) {
        Promise.resolve(supabase.from("client_applications").update({ last_used_at: ts }).eq("id", id).then()).catch(() => {});
      }
    }, LAST_USED_FLUSH_MS);
  }
}

export async function authenticateLinkingKey(
  supabase: SupabaseClient<any, "secretvault">,
  key: string,
): Promise<{ id: string; username: string; is_admin: boolean; clientId?: string; scopes?: string[]; keyVersion?: number; sessionEpoch?: number } | null> {
  const hash = hashLinkingKey(key);

  const { data: clientApp } = await supabase
    .from("client_applications")
    .select("id, scopes, key_version, user_id, users(id, username, is_admin, session_epoch)")
    .eq("key_hash", hash)
    .maybeSingle();

  if (clientApp && clientApp.users) {
    debouncedLastUsedUpdate(supabase, clientApp.id);

    const u = clientApp.users as any;
    return { id: u.id, username: u.username, is_admin: u.is_admin, clientId: clientApp.id, scopes: clientApp.scopes ?? [], keyVersion: clientApp.key_version ?? 1, sessionEpoch: u.session_epoch ?? 0 };
  }

  const { data: user } = await supabase
    .from("users")
    .select("id, username, is_admin, session_epoch")
    .eq("api_key_hash", hash)
    .single();

  // Legacy api_key_hash records predate client_applications. Treat them as
  // the least-privileged compatibility credential rather than as a session.
  return user ? { ...user, clientId: undefined, scopes: ["proxy:*"], keyVersion: 0, sessionEpoch: user.session_epoch ?? 0 } : null;
}

// ── System Settings ──────────────────────────────────────────────────

export async function getSystemSetting<T>(
  supabase: SupabaseClient<any, "secretvault">,
  key: string,
  defaultValue: T,
): Promise<T> {
  const { data } = await supabase
    .from("system_settings")
    .select("value")
    .eq("key", key)
    .maybeSingle();

  if (!data || data.value === undefined || data.value === null) {
    return defaultValue;
  }
  return data.value as T;
}

export async function setSystemSetting<T>(
  supabase: SupabaseClient<any, "secretvault">,
  key: string,
  value: T,
  userId?: string,
): Promise<void> {
  await supabase
    .from("system_settings")
    .upsert(
      {
        key,
        value: value as any,
        updated_at: new Date().toISOString(),
        updated_by: userId ?? null,
      },
      { onConflict: "key" },
    );
}

export async function handleGetPublicSettings(
  supabase: SupabaseClient<any, "secretvault">,
): Promise<{ status: number; body: unknown }> {
  const openReg = await getSystemSetting<boolean>(supabase, "open_registration_enabled", false);
  return { status: 200, body: { open_registration_enabled: openReg } };
}

export async function handleGetSystemSettings(
  supabase: SupabaseClient<any, "secretvault">,
): Promise<{ status: number; body: unknown }> {
  const openReg = await getSystemSetting<boolean>(supabase, "open_registration_enabled", false);
  return { status: 200, body: { open_registration_enabled: openReg } };
}

export async function handleUpdateSystemSettings(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  body: { open_registration_enabled?: boolean },
): Promise<{ status: number; body: unknown }> {
  if (typeof body.open_registration_enabled === "boolean") {
    await setSystemSetting(supabase, "open_registration_enabled", body.open_registration_enabled, userId);
    void recordAuditEvent(supabase, {
      userId,
      secretName: "system",
      accessType: "system_setting_change",
      caller: "rest:/api/settings",
      metadata: { key: "open_registration_enabled", value: String(body.open_registration_enabled) },
    }).catch(() => undefined);
  }
  const openReg = await getSystemSetting<boolean>(supabase, "open_registration_enabled", false);
  return { status: 200, body: { open_registration_enabled: openReg } };
}

export async function handleSelfRegister(
  supabase: SupabaseClient<Database, "secretvault">,
  body: { username?: string; password?: string },
): Promise<{ status: number; body: unknown }> {
  const openReg = await getSystemSetting<boolean>(supabase, "open_registration_enabled", false);
  if (!openReg) {
    return { status: 403, body: { error: "Public registration is currently closed by system administrator." } };
  }

  const { username, password } = body;
  if (!username || !password) {
    return { status: 400, body: { error: "username and password are required" } };
  }

  try {
    validateUsername(username);
    validatePassword(password);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { data, error } = await supabase
    .from("users")
    .insert({ username, password_hash: passwordHash, is_admin: false })
    .select("id, username, is_admin, created_at")
    .single();

  if (error) {
    if (error.code === "23505") return { status: 409, body: { error: `Username '${username}' is already taken` } };
    return internalErrorResponse();
  }

  console.error(`[auth] New user self-registered: "${username}"`);
  return { status: 201, body: data };
}

// ── CRUD handlers ────────────────────────────────────────────────────

export async function handleListUsers(
  supabase: SupabaseClient<any, "secretvault">,
  query?: { cursor?: string | null; pageSize?: number },
): Promise<{ status: number; body: unknown }> {
  const { clampPageSize, decodeCursor, encodeCursor, escapePostgrestValue, paginateQuery } = await import("./pagination.js");
  const pageSize = clampPageSize(query?.pageSize);
  let q = supabase
    .from("users")
    .select("id, username, is_admin, api_key_prefix, created_at");

  if (query?.cursor) {
    const decoded = decodeCursor(query.cursor);
    if (!decoded) {
      // SV-AUD-014: reject tampered/malformed cursors.
      return { status: 400, body: { error: "Invalid cursor", code: "INVALID_CURSOR" } };
    }
    q = q.or(`created_at.gt.${escapePostgrestValue(decoded.after)},and(created_at.eq.${escapePostgrestValue(decoded.after)},id.gt.${escapePostgrestValue(decoded.tiebreaker)})`);
  }

  q = q.order("created_at").order("id");

  const { data: users, error } = await q.limit(pageSize + 1);

  if (error) return internalErrorResponse();

  const page = await paginateQuery<any>(users ?? [], pageSize, (row) => encodeCursor(row.created_at, row.id));

  const { data: webauthn } = await supabase.from("webauthn_credentials").select("user_id");
  const { data: totp } = await supabase.from("totp_secrets").select("user_id, verified").eq("verified", true);

  const webauthnUsers = new Set((webauthn ?? []).map((w: any) => w.user_id));
  const totpUsers = new Set((totp ?? []).map((t: any) => t.user_id));

  const enriched = (page.data ?? []).map((u: any) => ({
    ...u,
    has_passkey: webauthnUsers.has(u.id),
    has_totp: totpUsers.has(u.id),
  }));

  return { status: 200, body: { data: enriched, next_cursor: page.next_cursor } };
}

export async function handleCreateUser(
  supabase: SupabaseClient<Database, "secretvault">,
  body: { username?: string; password?: string; is_admin?: boolean },
  actor?: { userId: string; username: string | null },
): Promise<{ status: number; body: unknown }> {
  const { username, password, is_admin = false } = body;
  if (!username || !password) return { status: 400, body: { error: "username and password are required" } };

  try {
    validateUsername(username);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { data, error } = await supabase
    .from("users")
    .insert({ username, password_hash: passwordHash, is_admin })
    .select("id, username, is_admin, created_at")
    .single();

  if (error) {
    if (error.code === "23505") return { status: 409, body: { error: `User '${username}' already exists` } };
    return internalErrorResponse();
  }

  void recordAuditEvent(supabase, {
    userId: actor?.userId ?? null,
    actorUsername: actor?.username ?? null,
    secretName: "account",
    accessType: "user_create",
    caller: "rest:/api/users",
    metadata: { target_user_id: data.id, target_username: data.username, is_admin: String(is_admin) },
  }).catch(() => undefined);

  return { status: 201, body: data };
}

export async function handleDeleteUser(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  callerUserId?: string,
): Promise<{ status: number; body: unknown }> {
  if (callerUserId && callerUserId === userId) {
    return { status: 409, body: { error: "Conflict: Cannot delete your own active administrator account" } };
  }

  const { data: targetUser } = await supabase
    .from("users")
    .select("id, username, is_admin")
    .eq("id", userId)
    .maybeSingle();

  if (!targetUser) return { status: 404, body: { error: "User not found" } };

  if (targetUser.is_admin) {
    const { count } = await supabase
      .from("users")
      .select("id", { count: "exact", head: true })
      .eq("is_admin", true);

    if (count !== null && count <= 1) {
      return { status: 409, body: { error: "Conflict: Cannot delete the final remaining administrator account" } };
    }
  }

  // Pre-delete audit log preservation: nullify user_id so logs remain immutable
  await supabase.from("access_logs").update({ user_id: null } as any).eq("user_id", userId);
  // Delete user secrets
  await supabase.from("secrets").delete().eq("user_id", userId);

  const { error } = await supabase.from("users").delete().eq("id", userId);
  if (error) return internalErrorResponse();

  void recordAuditEvent(supabase, {
    userId: callerUserId ?? null,
    secretName: "account",
    accessType: "user_delete",
    caller: "rest:/api/users/:id",
    metadata: { target_user_id: userId, target_username: targetUser.username },
  }).catch(() => undefined);

  return { status: 200, body: { deleted: true, username: targetUser.username } };
}

export async function handleAdminResetUserPassword(
  supabase: SupabaseClient<any, "secretvault">,
  targetUserId: string,
  body: { new_password?: string },
  actor?: { userId: string; username: string | null },
): Promise<{ status: number; body: unknown }> {
  const { new_password } = body;
  let validatedPassword: string;
  try {
    validatedPassword = validatePassword(new_password);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const { data: targetUser } = await supabase.from("users").select("id, username").eq("id", targetUserId).maybeSingle();
  if (!targetUser) return { status: 404, body: { error: "User not found" } };

  const hash = await bcrypt.hash(validatedPassword, BCRYPT_ROUNDS);
  const { error } = await supabase.from("users").update({ password_hash: hash }).eq("id", targetUserId);
  if (error) return internalErrorResponse();

  await bumpSessionEpoch(supabase, targetUserId);

  // Actor is the acting admin; target user is recorded in metadata so the
  // user_id column reflects who performed the reset, not who was reset.
  await recordAuditEvent(supabase, {
    userId: actor?.userId ?? null,
    actorUsername: actor?.username ?? null,
    secretName: "account",
    accessType: "admin_password_reset",
    caller: "webui:admin_user_mgmt",
    metadata: { target_user_id: targetUserId, target_username: targetUser.username },
  });

  return { status: 200, body: { reset: true, username: targetUser.username } };
}

export async function handleAdminResetUser2FA(
  supabase: SupabaseClient<any, "secretvault">,
  targetUserId: string,
  actor?: { userId: string; username: string | null },
): Promise<{ status: number; body: unknown }> {
  const { data: targetUser } = await supabase.from("users").select("id, username").eq("id", targetUserId).maybeSingle();
  if (!targetUser) return { status: 404, body: { error: "User not found" } };

  await supabase.from("webauthn_credentials").delete().eq("user_id", targetUserId);
  await wipeUserTotpState(supabase, targetUserId);

  await bumpSessionEpoch(supabase, targetUserId);

  await recordAuditEvent(supabase, {
    userId: actor?.userId ?? null,
    actorUsername: actor?.username ?? null,
    secretName: "account",
    accessType: "admin_2fa_reset",
    caller: "webui:admin_user_mgmt",
    metadata: { target_user_id: targetUserId, target_username: targetUser.username },
  });

  return { status: 200, body: { reset_2fa: true, username: targetUser.username } };
}

export async function handleGenerateLinkingKey(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  const { data: user } = await supabase.from("users").select("id, username").eq("id", userId).single();
  if (!user) return { status: 404, body: { error: "User not found" } };

  const { key, hash, prefix } = generateLinkingKey();

  const { error } = await supabase
    .from("users")
    .update({ api_key_hash: hash, api_key_prefix: prefix })
    .eq("id", userId);

  if (error) return internalErrorResponse();

  // Linking-key lifecycle is a credential-bearing operation: fail closed if
  // the audit event cannot be recorded, and roll back the new key so the
  // system never holds an un-audited credential.
  const auditId = await recordAuditEvent(supabase, {
    userId,
    actorUsername: actorUsername ?? user.username,
    secretName: "account",
    accessType: "linking_key_generate",
    caller: "webui:linking_key",
  });
  if (!auditId) {
    await supabase.from("users").update({ api_key_hash: null, api_key_prefix: null }).eq("id", userId);
    return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };
  }

  return {
    status: 200,
    body: {
      username: user.username,
      linking_key: key,
      prefix,
      warning: "Store this key securely. It will not be shown again.",
    },
  };
}

export async function handleChangePassword(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  body: { current_password?: string; new_password?: string },
): Promise<{ status: number; body: unknown }> {
  const { current_password, new_password } = body;
  if (!current_password || !new_password) {
    return { status: 400, body: { error: "current_password and new_password are required" } };
  }
  try {
    validatePassword(new_password);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const { data: user } = await supabase
    .from("users")
    .select("id, password_hash")
    .eq("id", userId)
    .single();

  if (!user) return { status: 404, body: { error: "User not found" } };

  const valid = await bcrypt.compare(current_password, user.password_hash);
  if (!valid) return { status: 401, body: { error: "Current password is incorrect" } };

  const hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
  const { error } = await supabase.from("users").update({ password_hash: hash }).eq("id", userId);
  if (error) return internalErrorResponse();

  await bumpSessionEpoch(supabase, userId);
  void recordAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "password_change",
    caller: "rest:/api/auth/change-password",
  }).catch(() => undefined);
  console.error(`[auth] Password changed for user ${userId}`);
  return { status: 200, body: { changed: true } };
}

export async function handleGetMe(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<{ status: number; body: unknown }> {
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("id, username, is_admin, api_key_prefix, created_at")
    .eq("id", userId)
    .single();

  if (userError || !user) return { status: 404, body: { error: "User not found" } };

  const { data: passkeys, error: passkeyError } = await supabase
    .from("webauthn_credentials")
    .select("id")
    .eq("user_id", userId);
  if (passkeyError) return internalErrorResponse();

  const { data: totp, error: totpError } = await supabase
    .from("totp_secrets")
    .select("id, verified")
    .eq("user_id", userId)
    .maybeSingle();
  if (totpError) return internalErrorResponse();

  const { count: backupCount, error: backupError } = await supabase
    .from("totp_backup_codes")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId);
  if (backupError) return internalErrorResponse();

  const has_totp = Boolean(totp && totp.verified);
  const has_passkey = Boolean(passkeys && passkeys.length > 0);
  const backup_codes_remaining = has_totp ? (backupCount ?? 0) : 0;

  return {
    status: 200,
    body: {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin,
      api_key_prefix: user.api_key_prefix,
      created_at: user.created_at,
      has_totp,
      has_passkey,
      factors: {
        passkey: has_passkey,
        totp: has_totp,
        backup_codes_remaining,
      },
    },
  };
}

// ── Client Applications Management ───────────────────────────────────

export async function handleListClients(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  query?: { cursor?: string | null; pageSize?: number },
): Promise<{ status: number; body: unknown }> {
  const { clampPageSize, decodeBeforeCursor, encodeBeforeCursor, escapePostgrestValue, paginateQuery } = await import("./pagination.js");
  const pageSize = clampPageSize(query?.pageSize);
  let q = supabase
    .from("client_applications")
    .select("id, app_name, key_prefix, scopes, last_used_at, created_at")
    .eq("user_id", userId);

  if (query?.cursor) {
    const decoded = decodeBeforeCursor(query.cursor);
    if (!decoded) {
      // SV-AUD-014: reject tampered/malformed cursors.
      return { status: 400, body: { error: "Invalid cursor", code: "INVALID_CURSOR" } };
    }
    q = q.or(`created_at.lt.${escapePostgrestValue(decoded.before)},and(created_at.eq.${escapePostgrestValue(decoded.before)},id.lt.${escapePostgrestValue(decoded.tiebreaker)})`);
  }

  q = q.order("created_at", { ascending: false }).order("id", { ascending: false });

  const { data, error } = await q.limit(pageSize + 1);

  if (error) return internalErrorResponse();

  const page = await paginateQuery<any>(data ?? [], pageSize, (row) => encodeBeforeCursor(row.created_at, row.id));

  return { status: 200, body: { data: page.data, next_cursor: page.next_cursor } };
}

export async function handleCreateClient(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  body: { app_name?: string; scopes?: string[] },
): Promise<{ status: number; body: unknown }> {
  const { app_name, scopes = ["proxy:*"] } = body;
  let normalizedAppName: string;
  try {
    normalizedAppName = validateBoundedString(app_name, "app_name", LIMITS.APP_NAME_MAX);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const scopeResult = validateLinkingKeyScopes(scopes);
  if (!scopeResult.valid) {
    return { status: 400, body: { error: scopeResult.error } };
  }

  const { key, hash, prefix } = generateLinkingKey();
  // SV-AUD-005: bind client-key ciphertext to (userId, clientId).
  const newClientId = crypto.randomUUID();
  const { encrypted } = await encryptSecret(key, masterKey, {
    purpose: ENCRYPTION_PURPOSE.CLIENT_KEY,
    aad: buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId, recordId: newClientId, clientId: newClientId }),
  });

  const { data, error } = await supabase
    .from("client_applications")
    .insert({
      id: newClientId,
      user_id: userId,
      app_name: normalizedAppName,
      key_hash: hash,
      key_prefix: prefix,
      encrypted_key: encrypted,
      scopes: scopeResult.scopes,
    })
    .select("id, app_name, key_prefix, scopes, created_at")
    .single();

  if (error) return internalErrorResponse();

  void recordAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "client_create",
    caller: "rest:/api/clients",
    metadata: { client_id: data.id, app_name: data.app_name },
  }).catch(() => undefined);

  return {
    status: 201,
    body: {
      client: data,
      linking_key: key,
    },
  };
}

export async function handleRevealClientKey(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  clientId: string,
  req: { headers: Record<string, string | string[] | undefined> },
): Promise<{ status: number; body: unknown }> {
  // Revealing a client key discloses credential material, so it is a critical
  // operation requiring a recent, client-bound step-up. A step-up minted for a
  // different client (or none) is rejected.
  const stepUpHeader = req.headers["x-secretvault-stepup"];
  const stepUpToken = typeof stepUpHeader === "string" ? stepUpHeader : "";
  if (!stepUpToken || !verifyStepUpTokenForResource(stepUpToken, userId, clientId)) {
    const { count: passkeyCount } = await supabase
      .from("webauthn_credentials")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId);
    const { count: totpCount } = await supabase
      .from("totp_secrets")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("verified", true);
    const enrolled = (passkeyCount ?? 0) > 0 || (totpCount ?? 0) > 0;
    return {
      status: 403,
      body: enrolled
        ? { error: "Step-up authentication required and must be bound to this client. Re-authenticate for this client, then retry.", code: "STEP_UP_REQUIRED" }
        : { error: "Step-up authentication required. Please enroll a Passkey or TOTP 2FA factor before revealing client keys.", code: "STEP_UP_REQUIRED" },
    };
  }

  const { data: client } = await supabase
    .from("client_applications")
    .select("id, app_name, encrypted_key")
    .eq("id", clientId)
    .eq("user_id", userId)
    .maybeSingle();

  if (!client) return { status: 404, body: { error: "Client application not found" } };

  if (!client.encrypted_key) {
    return {
      status: 400,
      body: { error: "Legacy client key cannot be revealed directly. Click 'Regenerate Key' to generate a new key." },
    };
  }

  const { startCriticalAuditEvent, finishAuditEvent } = await import("./audit.js");
  const auditId = await startCriticalAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "client_key_reveal",
    caller: "rest:/api/clients/:id/reveal",
    metadata: { client_id: clientId, app_name: client.app_name },
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  try {
    const linking_key = await decryptSecret(client.encrypted_key, masterKey, {
      purpose: ENCRYPTION_PURPOSE.CLIENT_KEY,
      aad: buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId, recordId: clientId, clientId }),
    });
    if (!(await finishAuditEvent(supabase, auditId, "succeeded"))) {
      return { status: 503, body: { error: "Audit logging unavailable; reveal blocked", code: "AUDIT_UNAVAILABLE" } };
    }
    return { status: 200, body: { linking_key } };
  } catch {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "client_key_decrypt_failed" });
    return { status: 500, body: { error: "Failed to decrypt client key" } };
  }
}

export async function handleRegenerateClientKey(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  clientId: string,
  req: { headers: Record<string, string | string[] | undefined> },
): Promise<{ status: number; body: unknown }> {
  // Regeneration discloses fresh credential material and invalidates the prior
  // key, so it is a critical operation requiring a recent, client-bound step-up.
  const stepUpHeader = req.headers["x-secretvault-stepup"];
  const stepUpToken = typeof stepUpHeader === "string" ? stepUpHeader : "";
  if (!stepUpToken || !verifyStepUpTokenForResource(stepUpToken, userId, clientId)) {
    return { status: 403, body: { error: "Step-up authentication required and must be bound to this client.", code: "STEP_UP_REQUIRED" } };
  }

  const { data: existing } = await supabase
    .from("client_applications")
    .select("id, app_name, key_version")
    .eq("id", clientId)
    .eq("user_id", userId)
    .maybeSingle();

  if (!existing) return { status: 404, body: { error: "Client application not found" } };

  const { key, hash, prefix } = generateLinkingKey();
  const { encrypted } = await encryptSecret(key, masterKey, {
    purpose: ENCRYPTION_PURPOSE.CLIENT_KEY,
    aad: buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId, recordId: clientId, clientId }),
  });

  const { startCriticalAuditEvent, finishAuditEvent } = await import("./audit.js");
  const auditId = await startCriticalAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "client_key_regenerate",
    caller: "rest:/api/clients/:id/regenerate",
    metadata: { client_id: clientId, app_name: existing.app_name, from_version: String(existing.key_version) },
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  // Conditional UPDATE: only persist the new key if the row is still at the
  // version we read. A concurrent regeneration that already advanced the
  // version makes this match zero rows, so the loser's freshly-generated key is
  // never stored — at most one key is ever valid, and a retry never leaves two.
  const expectedVersion = existing.key_version;
  const { data: updated, error } = await supabase
    .from("client_applications")
    .update({
      key_hash: hash,
      key_prefix: prefix,
      encrypted_key: encrypted,
      key_version: expectedVersion + 1,
    })
    .eq("id", clientId)
    .eq("key_version", expectedVersion)
    .select("id")
    .maybeSingle();

  if (error) {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "client_key_update_failed" });
    return internalErrorResponse();
  }
  if (!updated) {
    // Lost the race: another regeneration landed first. The caller must retry
    // with a fresh step-up; no key material was changed on our behalf.
    await finishAuditEvent(supabase, auditId, "failed", { reason: "client_key_regenerate_race" });
    return { status: 409, body: { error: "Key was regenerated concurrently; retry to fetch the current key.", code: "KEY_REGENERATE_CONFLICT" } };
  }

  await finishAuditEvent(supabase, auditId, "succeeded", { to_version: String(expectedVersion + 1) });
  return { status: 200, body: { regenerated: true, linking_key: key, key_prefix: prefix } };
}

export async function handleUpdateClient(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  clientId: string,
  body: { app_name?: string; scopes?: string[] },
): Promise<{ status: number; body: unknown }> {
  const { app_name, scopes } = body;
  const updates: Record<string, unknown> = {};

  if (app_name !== undefined) {
    try {
      updates.app_name = validateBoundedString(app_name, "app_name", LIMITS.APP_NAME_MAX);
    } catch (err) {
      return validationErrorResponse(err);
    }
  }

  if (scopes !== undefined) {
    const scopeResult = validateLinkingKeyScopes(scopes);
    if (!scopeResult.valid) {
      return { status: 400, body: { error: scopeResult.error } };
    }
    updates.scopes = scopeResult.scopes;
  }

  if (Object.keys(updates).length === 0) {
    return { status: 400, body: { error: "No fields provided to update" } };
  }

  const { data, error } = await supabase
    .from("client_applications")
    .update(updates)
    .eq("id", clientId)
    .eq("user_id", userId)
    .select("id, app_name, key_prefix, scopes, created_at")
    .maybeSingle();

  if (error) return internalErrorResponse();
  if (!data) return { status: 404, body: { error: "Client application not found" } };

  void recordAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "client_update",
    caller: "rest:/api/clients/:id",
    metadata: { client_id: clientId, app_name: data.app_name },
  }).catch(() => undefined);

  return { status: 200, body: data };
}

export async function handleDeleteClient(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  clientId: string,
): Promise<{ status: number; body: unknown }> {
  const { data: existing } = await supabase
    .from("client_applications")
    .select("id, app_name")
    .eq("id", clientId)
    .eq("user_id", userId)
    .maybeSingle();

  if (!existing) return { status: 404, body: { error: "Client application not found" } };

  const { error } = await supabase
    .from("client_applications")
    .delete()
    .eq("id", clientId);

  if (error) return internalErrorResponse();

  void recordAuditEvent(supabase, {
    userId,
    secretName: "account",
    accessType: "client_delete",
    caller: "rest:/api/clients/:id",
    metadata: { client_id: clientId, app_name: existing.app_name },
  }).catch(() => undefined);

  return { status: 200, body: { revoked: true, id: clientId, app_name: existing.app_name } };
}

export async function handleGetClientLogs(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  clientId: string,
  query: { cursor?: string | null; pageSize?: number; from?: string | null; to?: string | null; accessType?: string | null; outcome?: string | null } = {},
): Promise<{ status: number; body: unknown }> {
  const { readAuditLogPage } = await import("./audit.js");
  const page = await readAuditLogPage(supabase as SupabaseClient<Database, "secretvault">, userId, { ...query, clientId });
  return { status: 200, body: page };
}

// ── Emergency Break-Glass Admin Password Reset (CLI) ─────────────────

export async function handleResetAdminPasswordCLI(
  supabase: SupabaseClient<any, "secretvault">,
  username: string,
  newPassword: string,
  reset2FA = false,
): Promise<{ success: boolean; message: string }> {
  if (newPassword.length < 6) {
    return { success: false, message: "New password must be at least 6 characters" };
  }

  const { data: user } = await supabase
    .from("users")
    .select("id, username")
    .eq("username", username)
    .maybeSingle();

  if (!user) return { success: false, message: `User '${username}' not found` };

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  const { error } = await supabase
    .from("users")
    .update({ password_hash: passwordHash })
    .eq("id", user.id);

  if (error) return { success: false, message: error.message };

  if (reset2FA) {
    await supabase.from("webauthn_credentials").delete().eq("user_id", user.id);
    await wipeUserTotpState(supabase, user.id);
  }

  // Invalidate every active session for the target so a compromised session
  // cannot survive the password reset. Mirrors the HTTP admin reset path
  // (handleAdminResetUserPassword). Note: this only revokes sessions held by
  // the current process image; in a multi-replica deployment, restart each
  // replica or rely on the shared revocation store.
  try {
    await bumpSessionEpoch(supabase, user.id);
  } catch {
    // Session revocation is best-effort during break-glass; the password reset
    // and audit record are the authoritative recovery actions.
  }

  await recordAuditEvent(supabase, {
    userId: user.id,
    secretName: "account",
    accessType: "emergency_cli_password_reset",
    caller: "cli_break_glass",
  });

  return { success: true, message: `Password reset successfully for user '${username}'` };
}
