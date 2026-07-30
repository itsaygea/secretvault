import crypto from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { encryptSecret, decryptSecret, maskSecret, generatePrefixSuffix, validateSecretName, canonicalName, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { authenticateUser, authenticateLinkingKey } from "./users.js";
import { verifyStepUpToken } from "./stepup.js";
import { normalizeScopes, type Principal } from "./authz.js";
import { finishAuditEvent, startCriticalAuditEvent, recordAuditEvent, readAuditLogPage, type AuditLogQuery } from "./audit.js";
import { publicDbCode, internalError } from "./dbErrors.js";
import {
  LIMITS,
  ValidationError,
  validateBoundedString,
  validateEnvironment,
  validateTags,
  validationErrorResponse,
} from "./validation.js";
import { clampPageSize, decodeCursor, encodeCursor, escapePostgrestValue, paginateQuery, type PaginationParams } from "./pagination.js";

// ── Auth helpers ────────────────────────────────────────────────────

const UI_PASSWORD = process.env.SECRETVAULT_UI_PASSWORD ?? "";
let TOKEN_HMAC_KEY: Buffer;

export function initAuth(masterKey: Buffer): void {
  TOKEN_HMAC_KEY = crypto.createHmac("sha256", masterKey)
    .update("secretvault:token-signing-v1")
    .digest();
}

function isUiConfigured(): boolean {
  return UI_PASSWORD.length > 0;
}

function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  const maxLen = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  bufA.copy(paddedA, maxLen - bufA.length);
  bufB.copy(paddedB, maxLen - bufB.length);
  return crypto.timingSafeEqual(paddedA, paddedB);
}

export function generateToken(userId: string, epoch: number = 0): string {
  const ts = Date.now().toString(36);
  const nonce = crypto.randomBytes(8).toString("hex");
  const sig = crypto.createHmac("sha256", TOKEN_HMAC_KEY).update(`${userId}.${epoch}.${ts}.${nonce}`).digest("hex");
  return `${userId}.${epoch}.${ts}.${nonce}.${sig}`;
}

export function verifyToken(token: string): { userId: string; epoch: number | null; valid: boolean } {
  const parts = token.split(".");
  // SV-AUD-002: 5-part tokens carry the session epoch (userId.epoch.ts.nonce.sig).
  // Legacy 4-part tokens (no epoch) are accepted only as epoch 0 so the cutover
  // is forward-only; once a user's epoch is bumped, all their old 4-part tokens
  // are rejected because the DB epoch no longer matches the implicit 0.
  let userId: string, epoch: number, ts: string, nonce: string, sig: string;
  if (parts.length === 5) {
    [userId, epoch, ts, nonce, sig] = [parts[0], Number(parts[1]), parts[2], parts[3], parts[4]];
    if (!Number.isFinite(epoch)) return { userId: "", epoch: null, valid: false };
  } else if (parts.length === 4) {
    [userId, ts, nonce, sig] = parts;
    epoch = 0;
  } else {
    return { userId: "", epoch: null, valid: false };
  }
  const expected = crypto.createHmac("sha256", TOKEN_HMAC_KEY).update(`${userId}.${epoch}.${ts}.${nonce}`).digest("hex");
  if (!timingSafeEqual(sig, expected)) return { userId: "", epoch: null, valid: false };
  const age = Date.now() - parseInt(ts, 36);
  if (age >= 86_400_000) return { userId: "", epoch: null, valid: false };
  return { userId, epoch, valid: true };
}

export function getAuthHeader(req: { headers: Record<string, string | string[] | undefined> }): string | null {
  const auth = req.headers["authorization"];
  if (!auth || typeof auth !== "string") return null;
  if (!auth.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

// Resolves auth from either a session token or a linking key
export async function resolveAuthContext(
  supabase: SupabaseClient<Database, "secretvault">,
  req: { headers: Record<string, string | string[] | undefined> },
): Promise<Principal | null> {
  const raw = getAuthHeader(req);
  if (!raw) return null;

  // Try linking key first (sv_... prefix)
  if (raw.startsWith("sv_")) {
    const result = await authenticateLinkingKey(supabase, raw);
    if (!result) return null;
    return {
      userId: result.id,
      username: result.username,
      isAdmin: result.is_admin,
      clientId: result.clientId ?? null,
      credentialType: "linking_key",
      scopes: normalizeScopes(result.scopes),
    };
  }

  // Try session token
  const { userId, epoch, valid } = verifyToken(raw);
  if (!valid) return null;

  const { data: user } = await supabase
    .from("users")
    .select("id, username, is_admin, session_epoch")
    .eq("id", userId)
    .single();

  if (!user) return null;
  // SV-AUD-002: reject tokens minted under a prior session epoch. After a factor
  // replacement/removal the epoch is bumped, invalidating every older token.
  const dbEpoch = user.session_epoch ?? 0;
  if (epoch !== dbEpoch) return null;
  return {
    userId: user.id,
    username: user.username,
    isAdmin: user.is_admin,
    clientId: null,
    credentialType: "session",
    scopes: [],
  };
}

// ── Route handlers ──────────────────────────────────────────────────

export async function handleAuthLogin(
  supabase: SupabaseClient<Database, "secretvault">,
  reqBody: { username?: string; password?: string },
): Promise<{ status: number; body: unknown }> {
  const { username, password } = reqBody;

  if (!username || !password) {
    return { status: 400, body: { error: "username and password are required" } };
  }

  const user = await authenticateUser(supabase, username, password);
  if (!user) {
    // Login failures are metadata reads per CONTEXT.md: log the terminal
    // outcome afterward, alert rather than block when logging fails. Record
    // without a user_id since the actor identity could not be established.
    void recordAuditEvent(supabase, {
      secretName: "account",
      accessType: "login",
      caller: "rest:/api/auth/login",
      outcome: "failed",
      actorUsername: username,
      metadata: { reason: "invalid_credentials" },
    }).catch(() => undefined);
    return { status: 401, body: { error: "Invalid username or password" } };
  }

  void recordAuditEvent(supabase, {
    userId: user.id,
    secretName: "account",
    accessType: "login",
    caller: "rest:/api/auth/login",
    outcome: "succeeded",
    actorUsername: user.username,
  }).catch(() => undefined);

  return { status: 200, body: { token: generateToken(user.id, user.session_epoch ?? 0), user: { id: user.id, username: user.username, is_admin: user.is_admin } } };
}

export async function handleListSecrets(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  isAdmin: boolean,
  query: PaginationParams = {},
): Promise<{ status: number; body: unknown }> {
  const pageSize = clampPageSize(query.pageSize);
  let q = supabase
    .from("secrets")
    .select("id, name, display_name, environment, masked_preview, tags, created_at, updated_at")
    .eq("user_id", userId);

  if (query.cursor) {
    const decoded = decodeCursor(query.cursor);
    if (!decoded) {
      // SV-AUD-014: reject tampered / malformed / unsigned cursors rather than
      // silently falling back to the first page.
      return { status: 400, body: { error: "Invalid cursor", code: "INVALID_CURSOR" } };
    }
    q = q.or(`name.gt.${escapePostgrestValue(decoded.after)},and(name.eq.${escapePostgrestValue(decoded.after)},id.gt.${escapePostgrestValue(decoded.tiebreaker)})`);
  }

  q = q.order("name").order("id");

  const { data, error } = await q.limit(pageSize + 1);

  if (error) return { status: internalError().status, body: { error: internalError().message, code: internalError().code } };

  const page = await paginateQuery<{ id: string; name: string; display_name: string | null; environment: string; masked_preview: string; tags: string[]; created_at: string; updated_at: string }>(
    data ?? [],
    pageSize,
    (row) => encodeCursor(row.name, row.id),
  );

  // Summary audit event
  void recordAuditEvent(supabase, {
    secretName: "system",
    userId,
    accessType: "rest_list_secrets",
    caller: "rest:/api/secrets",
    metadata: {
      result_count: String(page.data.length),
      has_more: String(page.next_cursor !== null),
    },
  }).catch(() => undefined);

  return { status: 200, body: page };
}

export async function handleGetAdminStats(
  supabase: SupabaseClient<any, "secretvault">,
): Promise<{ status: number; body: unknown }> {
  // SV-049: each metric is queried independently and its outcome tracked. A
  // failed query is reported as unavailable — never silently folded into a
  // believable zero. If every metric fails we return 503 so a dead database
  // cannot masquerade as a valid empty system.
  const metrics = [
    { key: "totalUsers", label: "users", table: "users" as const },
    { key: "totalSecrets", label: "secrets", table: "secrets" as const },
    { key: "totalClientApps", label: "client_applications", table: "client_applications" as const },
    { key: "totalLogs", label: "access_logs", table: "access_logs" as const },
  ];

  const body: Record<string, unknown> = {};
  const unavailable: string[] = [];
  for (const metric of metrics) {
    const { count, error } = await supabase
      .from(metric.table)
      .select("*", { count: "exact", head: true });
    if (error) {
      body[metric.key] = null;
      body[`${metric.key}Available`] = false;
      unavailable.push(metric.label);
      // Structured log with no sensitive detail — the public response carries
      // only the metric name and a stable code, never the raw DB error.
      console.error(
        `[stats] metric '${metric.label}' unavailable: ${publicDbCode(error)}`,
      );
    } else {
      body[metric.key] = count ?? 0;
      body[`${metric.key}Available`] = true;
    }
  }

  if (unavailable.length === metrics.length) {
    // Total failure: surface as a service-unavailable error so callers and the
    // UI cannot read it as a healthy empty deployment.
    return {
      status: 503,
      body: { error: "Admin statistics unavailable", code: "STATS_UNAVAILABLE" },
    };
  }

  body.status = unavailable.length === 0 ? "ok" : "partial";
  if (unavailable.length > 0) body.unavailable = unavailable;
  return { status: 200, body };
}

export async function handleGetUserLogs(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  query: AuditLogQuery = {},
): Promise<{ status: number; body: unknown }> {
  const page = await readAuditLogPage(supabase as SupabaseClient<Database, "secretvault">, userId, query);
  return { status: 200, body: page };
}

export async function handleCreateSecret(
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  body: { name?: string; value?: string; environment?: string; tags?: string[] },
  userId: string,
  clientId: string | null = null,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  const { value } = body;
  const displayName = body.name;
  if (!displayName || !value) return { status: 400, body: { error: "name and value are required" } };

  // SV-048: centralized validation with explicit limits on every field.
  try {
    validateSecretName(displayName);
    validateBoundedString(value, "value", LIMITS.SECRET_VALUE_MAX);
    const environment = validateEnvironment(body.environment ?? "development");
    const tags = validateTags(body.tags);
    return await createSecretValidated(supabase, masterKey, displayName, value, environment, tags, userId, clientId, actorUsername);
  } catch (err) {
    if (err instanceof ValidationError) return validationErrorResponse(err);
    throw err;
  }
}

export async function createSecretValidated(
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  displayName: string,
  value: string,
  environment: string,
  tags: string[],
  userId: string,
  clientId: string | null,
  actorUsername: string | null,
): Promise<{ status: number; body: unknown }> {
  const name = canonicalName(displayName);

  // Check if exists (scoped to this user)
  const { data: existing } = await supabase.from("secrets").select("id, display_name").eq("name", name).eq("user_id", userId).maybeSingle();
  if (existing) return { status: 409, body: { error: `Secret '${existing.display_name ?? name}' already exists` } };

  const auditId = await startCriticalAuditEvent(supabase, {
    secretName: name,
    userId,
    clientId,
    actorUsername,
    accessType: "secret_create",
    caller: "webui:create",
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  try {
    // SV-AUD-005: generate the immutable record id before encryption so the
    // ciphertext is bound to (userId, secretId) via AAD.
    const secretId = crypto.randomUUID();
    const { encrypted } = await encryptSecret(value, masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId, recordId: secretId }),
    });
    const masked = maskSecret(value);
    const { prefix, suffix } = generatePrefixSuffix(value);

    const { error } = await supabase.from("secrets").insert({
      id: secretId,
      name,
      display_name: displayName,
      user_id: userId,
      environment,
      encrypted_blob: encrypted,
      masked_preview: masked,
      key_prefix: prefix,
      key_suffix: suffix,
      tags,
    });

    if (error) {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_insert_failed" });
      const e = internalError();
      return { status: e.status, body: { error: e.message, code: e.code } };
    }

    await finishAuditEvent(supabase, auditId, "succeeded");

    return { status: 201, body: { created: true, name, display_name: displayName, masked_preview: masked } };
  } catch {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_create_failed" });
    return { status: 500, body: { error: "Failed to create secret" } };
  }
}

export async function handleRotateSecret(
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  rawName: string,
  body: { new_value?: string },
  userId: string,
  isAdmin: boolean,
  clientId: string | null = null,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  const name = canonicalName(rawName);
  const { new_value } = body;
  if (!new_value) return { status: 400, body: { error: "new_value is required" } };
  try {
    validateBoundedString(new_value, "new_value", LIMITS.SECRET_VALUE_MAX);
  } catch (err) {
    return validationErrorResponse(err);
  }

  const { data: existing, error: findError } = await supabase
    .from("secrets")
    .select("id, display_name")
    .eq("name", name)
    .eq("user_id", userId)
    .single();

  if (findError || !existing) return { status: 404, body: { error: `Secret '${rawName}' not found` } };

  const auditId = await startCriticalAuditEvent(supabase, {
    secretId: existing.id,
    secretName: name,
    userId,
    clientId,
    actorUsername,
    accessType: "secret_rotate",
    caller: "webui:rotate",
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  try {
    const { encrypted } = await encryptSecret(new_value, masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId, recordId: existing.id }),
    });
    const masked = maskSecret(new_value);
    const { prefix, suffix } = generatePrefixSuffix(new_value);

    const { error: updateError } = await supabase
      .from("secrets")
      .update({ encrypted_blob: encrypted, masked_preview: masked, key_prefix: prefix, key_suffix: suffix })
      .eq("id", existing.id);

    if (updateError) {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_update_failed" });
      const e = internalError();
      return { status: e.status, body: { error: e.message, code: e.code } };
    }

    await finishAuditEvent(supabase, auditId, "succeeded");

    return { status: 200, body: { rotated: true, name, display_name: existing.display_name ?? name, new_masked_preview: masked } };
  } catch {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_rotate_failed" });
    return { status: 500, body: { error: "Failed to rotate secret" } };
  }
}

export async function handleDeleteSecret(
  supabase: SupabaseClient<Database, "secretvault">,
  rawName: string,
  userId: string,
  isAdmin: boolean,
  clientId: string | null = null,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  const name = canonicalName(rawName);

  const { data: existing, error: findError } = await supabase
    .from("secrets")
    .select("id, display_name")
    .eq("name", name)
    .eq("user_id", userId)
    .single();

  if (findError || !existing) return { status: 404, body: { error: `Secret '${rawName}' not found` } };

  const auditId = await startCriticalAuditEvent(supabase, {
    secretId: existing.id,
    secretName: name,
    userId,
    clientId,
    actorUsername,
    accessType: "secret_delete",
    caller: "webui:delete",
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  const { error: deleteError } = await supabase.from("secrets").delete().eq("id", existing.id);
  if (deleteError) {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_delete_failed" });
    const e = internalError();
    return { status: e.status, body: { error: e.message, code: e.code } };
  }

  await finishAuditEvent(supabase, auditId, "succeeded");

  return { status: 200, body: { deleted: true, name, display_name: existing.display_name ?? name } };
}

export async function handleRevealSecret(
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  rawName: string,
  req: { headers: Record<string, string | string[] | undefined> },
  userId: string,
  isAdmin: boolean,
  isLinkingKey: boolean,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  // Linking keys are strictly forbidden from human reveal endpoints
  if (isLinkingKey) {
    return { status: 403, body: { error: "Linking keys cannot access human reveal endpoints" } };
  }

  // Require step-up authentication token for human reveal operations
  const { count: passkeyCount } = await supabase
    .from("webauthn_credentials")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);
  const { count: totpCount } = await supabase
    .from("totp_secrets")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId)
    .eq("verified", true);

  if ((passkeyCount ?? 0) === 0 && (totpCount ?? 0) === 0) {
    return {
      status: 403,
      body: { error: "Step-up authentication required. Please enroll a Passkey or TOTP 2FA factor before revealing plaintext secret values.", code: "STEP_UP_REQUIRED" },
    };
  }

  const stepUpHeader = req.headers["x-secretvault-stepup"];
  const stepUpToken = typeof stepUpHeader === "string" ? stepUpHeader : "";
  if (!stepUpToken || !verifyStepUpToken(stepUpToken, userId)) {
    return {
      status: 403,
      body: { error: "Step-up authentication required (Passkey or 2FA)", code: "STEP_UP_REQUIRED" },
    };
  }

  const name = canonicalName(rawName);

  const { data: existing, error: findError } = await supabase
    .from("secrets")
    .select("id, display_name, encrypted_blob")
    .eq("name", name)
    .eq("user_id", userId)
    .single();

  if (findError || !existing) return { status: 404, body: { error: `Secret '${rawName}' not found` } };

  const auditId = await startCriticalAuditEvent(supabase, {
    secretId: existing.id,
    secretName: name,
    userId,
    actorUsername,
    accessType: "ui_reveal",
    caller: "webui:reveal",
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  try {
    const plaintext = await decryptSecret(existing.encrypted_blob, masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId, recordId: existing.id }),
    });

    if (!(await finishAuditEvent(supabase, auditId, "succeeded"))) {
      return { status: 503, body: { error: "Audit logging unavailable; reveal blocked", code: "AUDIT_UNAVAILABLE" } };
    }

    return {
      status: 200,
      body: {
        name,
        display_name: existing.display_name ?? name,
        plaintext,
      },
    };
  } catch (err: any) {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_decrypt_failed" });
    return { status: 500, body: { error: "Failed to decrypt secret" } };
  }
}

export async function handleClientGetSecret(
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  rawName: string,
  userId: string,
  clientId: string | null = null,
  actorUsername: string | null = null,
): Promise<{ status: number; body: unknown }> {
  const name = canonicalName(rawName);
  const { data: existing } = await supabase
    .from("secrets")
    .select("id, name, display_name, encrypted_blob")
    .eq("name", name)
    .eq("user_id", userId)
    .maybeSingle();

  if (!existing) return { status: 404, body: { error: `Secret '${rawName}' not found` } };

  const auditId = await startCriticalAuditEvent(supabase, {
    secretId: existing.id,
    secretName: name,
    userId,
    clientId,
    actorUsername,
    accessType: "client_secret_read",
    caller: "client:get_secret",
  });
  if (!auditId) return { status: 503, body: { error: "Audit logging unavailable; operation blocked", code: "AUDIT_UNAVAILABLE" } };

  try {
    const value = await decryptSecret(existing.encrypted_blob, masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId, recordId: existing.id }),
    });
    await finishAuditEvent(supabase, auditId, "succeeded");
    return {
      status: 200,
      body: {
        name,
        display_name: existing.display_name ?? name,
        value,
      },
    };
  } catch (err) {
    await finishAuditEvent(supabase, auditId, "failed", { reason: "secret_decrypt_failed" });
    return { status: 500, body: { error: "Failed to decrypt secret" } };
  }
}
