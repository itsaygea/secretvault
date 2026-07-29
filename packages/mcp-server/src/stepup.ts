import crypto from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { decryptSecret, encryptSecret } from "@secretvault/shared";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { recordAuditEvent } from "./audit.js";

let STEP_UP_HMAC_KEY: Buffer;

export function initStepUpAuth(masterKey: Buffer): void {
  STEP_UP_HMAC_KEY = crypto.createHmac("sha256", masterKey)
    .update("secretvault:stepup-token-v1")
    .digest();
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

// ── Step-Up Session Tokens (5-minute TTL) ────────────────────────────

export function generateStepUpToken(userId: string, resource?: string): { stepUpToken: string; expiresAt: number } {
  const now = Date.now();
  const expiresAt = now + 300_000; // 5 minutes
  const ts = now.toString(36);
  const nonce = crypto.randomBytes(8).toString("hex");
  // When a resource (e.g. a client id) is supplied it is folded into the signed
  // payload, binding the token to that specific resource so a step-up minted to
  // reveal client A cannot be replayed to reveal client B.
  const safeResource = resource ? resource.replace(/\./g, "-") : "";
  const signed = safeResource
    ? `stepup.${userId}.${ts}.${nonce}.${safeResource}`
    : `stepup.${userId}.${ts}.${nonce}`;
  const sig = crypto.createHmac("sha256", STEP_UP_HMAC_KEY).update(signed).digest("hex");
  const stepUpToken = safeResource
    ? `stepup.${userId}.${ts}.${nonce}.${safeResource}.${sig}`
    : `stepup.${userId}.${ts}.${nonce}.${sig}`;
  return { stepUpToken, expiresAt };
}

function verifyTokenShape(token: string, expectedUserId: string): { ts: number; sig: string; signed: string; resource: string | null } | null {
  if (!token || !token.startsWith("stepup.")) return null;
  const parts = token.split(".");
  if (parts.length !== 5 && parts.length !== 6) return null;
  const [, userId, ts, nonce, fifth, sixth] = parts;
  if (userId !== expectedUserId) return null;
  const issueTime = parseInt(ts, 36);
  const age = Date.now() - issueTime;
  if (!(age >= 0 && age < 300_000)) return null;

  if (parts.length === 5) {
    const signed = `stepup.${userId}.${ts}.${nonce}`;
    return { ts: issueTime, sig: fifth, signed, resource: null };
  }
  // 6 parts: resource-bound token.
  const signed = `stepup.${userId}.${ts}.${nonce}.${fifth}`;
  return { ts: issueTime, sig: sixth, signed, resource: fifth };
}

export function verifyStepUpToken(token: string, expectedUserId: string): boolean {
  const shape = verifyTokenShape(token, expectedUserId);
  if (!shape) return false;
  const expectedSig = crypto.createHmac("sha256", STEP_UP_HMAC_KEY).update(shape.signed).digest("hex");
  return timingSafeEqual(shape.sig, expectedSig);
}

/**
 * Verify a resource-bound step-up token. Accepts a token that either carries
 * no resource (legacy, for backward compatibility) or carries exactly the
 * expected resource. A token bound to a different resource is rejected.
 */
export function verifyStepUpTokenForResource(token: string, expectedUserId: string, expectedResource: string): boolean {
  const shape = verifyTokenShape(token, expectedUserId);
  if (!shape) return false;
  if (shape.resource !== null && shape.resource !== expectedResource.replace(/\./g, "-")) return false;
  const expectedSig = crypto.createHmac("sha256", STEP_UP_HMAC_KEY).update(shape.signed).digest("hex");
  return timingSafeEqual(shape.sig, expectedSig);
}

// ── In-Memory Challenge Cache ───────────────────────────────────────

const challengeCache = new Map<string, { challenge: string; expiresAt: number }>();

function setChallenge(userId: string, challenge: string): void {
  challengeCache.set(userId, { challenge, expiresAt: Date.now() + 300_000 });
}

function getChallenge(userId: string): string | null {
  const item = challengeCache.get(userId);
  if (!item) return null;
  if (Date.now() > item.expiresAt) {
    challengeCache.delete(userId);
    return null;
  }
  return item.challenge;
}

function clearChallenge(userId: string): void {
  challengeCache.delete(userId);
}

// ── WebAuthn Handlers ───────────────────────────────────────────────

export async function handleWebAuthnRegisterOptions(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  username: string,
  rpID: string,
): Promise<{ status: number; body: unknown }> {
  const { data: userCreds } = await supabase
    .from("webauthn_credentials")
    .select("credential_id, transports")
    .eq("user_id", userId);

  const excludeCredentials = (userCreds ?? []).map((c: any) => ({
    id: c.credential_id,
    transports: c.transports ?? [],
  }));

  const options = await generateRegistrationOptions({
    rpName: "SecretVault",
    rpID,
    userID: Buffer.from(userId, "utf8"),
    userName: username,
    userDisplayName: username,
    attestationType: "none",
    excludeCredentials,
    authenticatorSelection: {
      userVerification: "preferred",
      residentKey: "preferred",
    },
  });

  setChallenge(userId, options.challenge);
  return { status: 200, body: options };
}

export async function handleWebAuthnRegisterVerify(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  rpID: string,
  origin: string,
  body: { response?: any; device_name?: string },
): Promise<{ status: number; body: unknown }> {
  const { response, device_name = "Passkey" } = body;
  if (!response) return { status: 400, body: { error: "response is required" } };

  const expectedChallenge = getChallenge(userId);
  if (!expectedChallenge) return { status: 400, body: { error: "Challenge expired or invalid. Restart registration." } };

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err: any) {
    return { status: 400, body: { error: err.message || "Registration verification failed" } };
  }

  clearChallenge(userId);

  if (!verification.verified || !verification.registrationInfo) {
    return { status: 400, body: { error: "WebAuthn verification failed" } };
  }

  const { credential } = verification.registrationInfo;

  const { error } = await supabase.from("webauthn_credentials").insert({
    user_id: userId,
    credential_id: credential.id,
    public_key: Buffer.from(credential.publicKey).toString("base64url"),
    counter: credential.counter,
    transports: credential.transports ?? [],
    device_name,
  });

  if (error) return { status: 500, body: { error: error.message } };

  await recordAuditEvent(supabase, {
    userId,
    accessType: "webauthn_register",
    caller: "webui:webauthn",
  });

  return { status: 200, body: { verified: true, device_name } };
}

export async function handleWebAuthnAuthOptions(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  rpID: string,
): Promise<{ status: number; body: unknown }> {
  const { data: userCreds } = await supabase
    .from("webauthn_credentials")
    .select("credential_id, transports")
    .eq("user_id", userId);

  if (!userCreds || userCreds.length === 0) {
    return { status: 404, body: { error: "No passkeys registered for this user" } };
  }

  const allowCredentials = userCreds.map((c: any) => ({
    id: c.credential_id,
    transports: c.transports ?? [],
  }));

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: "preferred",
  });

  setChallenge(userId, options.challenge);
  return { status: 200, body: options };
}

export async function handleWebAuthnAuthVerify(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  rpID: string,
  origin: string,
  body: { response?: any; resource?: string },
): Promise<{ status: number; body: unknown }> {
  const { response, resource } = body;
  if (!response) return { status: 400, body: { error: "response is required" } };

  const expectedChallenge = getChallenge(userId);
  if (!expectedChallenge) return { status: 400, body: { error: "Challenge expired or invalid" } };

  const credentialId = response.id;
  const { data: dbCred } = await supabase
    .from("webauthn_credentials")
    .select("id, credential_id, public_key, counter")
    .eq("user_id", userId)
    .eq("credential_id", credentialId)
    .maybeSingle();

  if (!dbCred) return { status: 404, body: { error: "Credential not found" } };

  let verification: VerifiedAuthenticationResponse;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: dbCred.credential_id,
        publicKey: Buffer.from(dbCred.public_key, "base64url"),
        counter: Number(dbCred.counter),
      },
    });
  } catch (err: any) {
    return { status: 400, body: { error: err.message || "Authentication verification failed" } };
  }

  clearChallenge(userId);

  if (!verification.verified || !verification.authenticationInfo) {
    return { status: 400, body: { error: "WebAuthn authentication failed" } };
  }

  // Update sign counter & last_used_at
  await supabase
    .from("webauthn_credentials")
    .update({
      counter: verification.authenticationInfo.newCounter,
      last_used_at: new Date().toISOString(),
    })
    .eq("id", dbCred.id);

  await recordAuditEvent(supabase, {
    userId,
    accessType: "webauthn_auth",
    caller: "webui:webauthn",
  });

  const { stepUpToken, expiresAt } = generateStepUpToken(userId, resource);
  return { status: 200, body: { verified: true, stepUpToken, expiresAt } };
}

// ── TOTP Handlers ───────────────────────────────────────────────────

const TOTP_PENDING_TTL_MS = 15 * 60_000;
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_PATTERN = /^[a-zA-Z0-9]{8,12}$/;

async function generateBackupCodeSet(): Promise<{ raw: string[]; rows: { user_id: string; code_hash: string }[] }> {
  const raw: string[] = [];
  const rows: { user_id: string; code_hash: string }[] = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = crypto.randomBytes(5).toString("hex");
    raw.push(code);
    rows.push({ user_id: "", code_hash: await bcrypt.hash(code, 10) });
  }
  return { raw, rows };
}

async function replaceBackupCodes(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<{ status: number; body?: unknown; raw?: string[] }> {
  const { raw, rows } = await generateBackupCodeSet();
  const prepared = rows.map((r) => ({ user_id: userId, code_hash: r.code_hash }));

  const { error: delErr } = await supabase.from("totp_backup_codes").delete().eq("user_id", userId);
  if (delErr) return { status: 500, body: { error: delErr.message } };

  const { error: insErr } = await supabase.from("totp_backup_codes").insert(prepared);
  if (insErr) return { status: 500, body: { error: insErr.message } };

  return { status: 200, raw };
}

/**
 * Atomically consume one backup code via compare-and-delete on its row.
 * Concurrent consumers of the same code: exactly one DELETE returns a row.
 */
export async function consumeBackupCode(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  code: string,
): Promise<boolean> {
  const trimmed = code.trim();
  if (!BACKUP_CODE_PATTERN.test(trimmed)) return false;

  const { data: rows } = await supabase
    .from("totp_backup_codes")
    .select("id, code_hash")
    .eq("user_id", userId);

  if (!rows || rows.length === 0) return false;

  let matchedId: string | null = null;
  for (const row of rows) {
    if (await bcrypt.compare(trimmed, row.code_hash)) {
      matchedId = row.id;
      break;
    }
  }
  if (!matchedId) return false;

  const { data: deleted } = await supabase
    .from("totp_backup_codes")
    .delete()
    .eq("id", matchedId)
    .eq("user_id", userId)
    .select("id")
    .maybeSingle();

  return Boolean(deleted?.id);
}

export async function handleTotpSetup(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  username: string,
): Promise<{ status: number; body: unknown }> {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(username, "SecretVault", secret);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);
  const { encrypted } = await encryptSecret(secret, masterKey);
  const expiresAt = new Date(Date.now() + TOTP_PENDING_TTL_MS).toISOString();

  const { data: existing } = await supabase
    .from("totp_secrets")
    .select("id")
    .eq("user_id", userId)
    .eq("verified", true)
    .maybeSingle();

  // SV-013: pending enrollment only — verified factor stays usable until swap
  const { error } = await supabase
    .from("totp_pending_enrollments")
    .upsert({
      user_id: userId,
      secret_encrypted: encrypted,
      expires_at: expiresAt,
    }, { onConflict: "user_id" });

  if (error) return { status: 500, body: { error: error.message } };

  await recordAuditEvent(supabase, {
    userId,
    accessType: "totp_enroll_start",
    caller: "webui:totp",
    outcome: "succeeded",
    metadata: { replacement: Boolean(existing) },
  });

  return { status: 200, body: { qr_code: qrCodeDataUrl, secret, expires_at: expiresAt } };
}

export async function handleTotpCancelSetup(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<{ status: number; body: unknown }> {
  const { error } = await supabase
    .from("totp_pending_enrollments")
    .delete()
    .eq("user_id", userId);

  if (error) return { status: 500, body: { error: error.message } };

  await recordAuditEvent(supabase, {
    userId,
    accessType: "totp_enroll_cancel",
    caller: "webui:totp",
    outcome: "succeeded",
  });

  return { status: 200, body: { cancelled: true } };
}

export async function handleTotpVerifySetup(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  body: { code?: string },
): Promise<{ status: number; body: unknown }> {
  const { code } = body;
  if (!code || code.length !== 6) return { status: 400, body: { error: "6-digit TOTP code is required" } };

  const { data: pending } = await supabase
    .from("totp_pending_enrollments")
    .select("id, secret_encrypted, expires_at")
    .eq("user_id", userId)
    .maybeSingle();

  if (!pending) return { status: 404, body: { error: "No TOTP setup active. Call setup first." } };

  if (new Date(pending.expires_at).getTime() < Date.now()) {
    await supabase.from("totp_pending_enrollments").delete().eq("id", pending.id);
    await recordAuditEvent(supabase, {
      userId,
      accessType: "totp_enroll_cancel",
      caller: "webui:totp",
      outcome: "failed",
      metadata: { reason: "expired" },
    });
    return { status: 400, body: { error: "TOTP setup expired. Start setup again." } };
  }

  const secret = await decryptSecret(pending.secret_encrypted, masterKey);
  const valid = authenticator.verify({ token: code, secret });

  if (!valid) {
    await recordAuditEvent(supabase, {
      userId,
      accessType: "totp_enroll_verify",
      caller: "webui:totp",
      outcome: "failed",
    });
    return { status: 401, body: { error: "Invalid TOTP code" } };
  }

  // Atomic swap: promote pending secret into verified factor
  const { error: upsertErr } = await supabase
    .from("totp_secrets")
    .upsert({
      user_id: userId,
      secret_encrypted: pending.secret_encrypted,
      verified: true,
    }, { onConflict: "user_id" });

  if (upsertErr) return { status: 500, body: { error: upsertErr.message } };

  const backup = await replaceBackupCodes(supabase, userId);
  if (backup.status !== 200 || !backup.raw) {
    return { status: backup.status, body: backup.body ?? { error: "Failed to store backup codes" } };
  }

  await supabase.from("totp_pending_enrollments").delete().eq("id", pending.id);

  await recordAuditEvent(supabase, {
    userId,
    accessType: "totp_enroll_complete",
    caller: "webui:totp",
    outcome: "succeeded",
    metadata: { backup_codes_issued: backup.raw.length },
  });

  return { status: 200, body: { verified: true, backup_codes: backup.raw } };
}

export async function handleTotpAuthenticate(
  supabase: SupabaseClient<any, "secretvault">,
  masterKey: Buffer,
  userId: string,
  body: { code?: string; resource?: string },
): Promise<{ status: number; body: unknown }> {
  const { code, resource } = body;
  if (!code) return { status: 400, body: { error: "code is required" } };

  const { data: totp } = await supabase
    .from("totp_secrets")
    .select("id, secret_encrypted, verified")
    .eq("user_id", userId)
    .eq("verified", true)
    .maybeSingle();

  if (!totp) return { status: 404, body: { error: "TOTP 2FA is not enabled for this user" } };

  let isValid = false;
  let usedBackup = false;
  const trimmed = code.trim();

  // Try 6-digit TOTP code (SV-010: skip backup bcrypt for pure 6-digit input)
  if (trimmed.length === 6 && /^[0-9]{6}$/.test(trimmed)) {
    const secret = await decryptSecret(totp.secret_encrypted, masterKey);
    isValid = authenticator.verify({ token: trimmed, secret });
  }

  // Backup recovery code — atomic compare-and-delete (SV-015)
  if (!isValid && BACKUP_CODE_PATTERN.test(trimmed)) {
    isValid = await consumeBackupCode(supabase, userId, trimmed);
    usedBackup = isValid;
  }

  if (!isValid) {
    await recordAuditEvent(supabase, {
      userId,
      accessType: "stepup_failed",
      caller: "webui:totp",
      outcome: "failed",
    });
    return { status: 401, body: { error: "Invalid TOTP verification code" } };
  }

  await recordAuditEvent(supabase, {
    userId,
    accessType: usedBackup ? "totp_backup_used" : "totp_auth",
    caller: "webui:totp",
    outcome: "succeeded",
  });

  const { stepUpToken, expiresAt } = generateStepUpToken(userId, resource);
  return { status: 200, body: { verified: true, stepUpToken, expiresAt } };
}

export async function handleTotpRegenerateBackupCodes(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  stepUpHeader: string | string[] | undefined,
): Promise<{ status: number; body: unknown }> {
  const token = Array.isArray(stepUpHeader) ? stepUpHeader[0] : stepUpHeader;
  if (!token || !verifyStepUpToken(token, userId)) {
    return {
      status: 403,
      body: {
        error: "Recent authentication required to regenerate recovery codes",
        code: "STEP_UP_REQUIRED",
      },
    };
  }

  const { data: totp } = await supabase
    .from("totp_secrets")
    .select("id")
    .eq("user_id", userId)
    .eq("verified", true)
    .maybeSingle();

  if (!totp) return { status: 404, body: { error: "TOTP 2FA is not enabled for this user" } };

  const backup = await replaceBackupCodes(supabase, userId);
  if (backup.status !== 200 || !backup.raw) {
    return { status: backup.status, body: backup.body ?? { error: "Failed to regenerate backup codes" } };
  }

  await recordAuditEvent(supabase, {
    userId,
    accessType: "totp_backup_regenerate",
    caller: "webui:totp",
    outcome: "succeeded",
    metadata: { backup_codes_issued: backup.raw.length },
  });

  return { status: 200, body: { backup_codes: backup.raw } };
}

// ── Passkey List & Delete ───────────────────────────────────────────

export async function handleListPasskeys(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<{ status: number; body: unknown }> {
  const { data, error } = await supabase
    .from("webauthn_credentials")
    .select("id, device_name, created_at, last_used_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });

  if (error) return { status: 500, body: { error: error.message } };
  return { status: 200, body: data };
}

export async function handleDeletePasskey(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
  passkeyId: string,
): Promise<{ status: number; body: unknown }> {
  const { data: existing } = await supabase
    .from("webauthn_credentials")
    .select("id, device_name")
    .eq("id", passkeyId)
    .eq("user_id", userId)
    .maybeSingle();

  if (!existing) return { status: 404, body: { error: "Passkey not found" } };

  const { error } = await supabase
    .from("webauthn_credentials")
    .delete()
    .eq("id", passkeyId);

  if (error) return { status: 500, body: { error: error.message } };

  return { status: 200, body: { deleted: true, id: passkeyId, device_name: existing.device_name } };
}

export async function handleDisableTotp(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<{ status: number; body: unknown }> {
  await supabase.from("totp_pending_enrollments").delete().eq("user_id", userId);
  await supabase.from("totp_backup_codes").delete().eq("user_id", userId);

  const { error } = await supabase
    .from("totp_secrets")
    .delete()
    .eq("user_id", userId);

  if (error) return { status: 500, body: { error: error.message } };

  await recordAuditEvent(supabase, {
    userId,
    accessType: "totp_factor_remove",
    caller: "webui:totp",
    outcome: "succeeded",
  });

  return { status: 200, body: { disabled: true } };
}

/** Wipe all TOTP-related rows for a user (admin reset / break-glass). */
export async function wipeUserTotpState(
  supabase: SupabaseClient<any, "secretvault">,
  userId: string,
): Promise<void> {
  await supabase.from("totp_pending_enrollments").delete().eq("user_id", userId);
  await supabase.from("totp_backup_codes").delete().eq("user_id", userId);
  await supabase.from("totp_secrets").delete().eq("user_id", userId);
}
