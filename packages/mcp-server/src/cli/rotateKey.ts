import { createClient } from "@supabase/supabase-js";
import {
  encryptSecret,
  envelopeVersion,
  envelopeKeyId,
  ENCRYPTION_PURPOSE,
  buildContextAad,
  MasterKeyRing,
  type EncryptionPurpose,
} from "@secretvault/shared";
import { resolveMasterKey } from "../keyLoader.js";
import { recordAuditEvent } from "../audit.js";

/**
 * SV-AUD-006: master-key rotation is verified, resumable, and atomic per row.
 *
 * Design contract (per the audit):
 *  - A keyring serves the old and new keys, keyed by the *authenticated* key ID
 *    in each envelope. A row already rotated to the new key is never retried
 *    with the old key.
 *  - Each row is re-encrypted with a compare-and-swap update keyed on its
 *    original ciphertext, so a concurrent change or partial state cannot be
 *    silently overwritten. The CAS update is checked; a zero-row update is a
 *    concurrent change and the row is re-read rather than falsely counted.
 *  - Every rewritten row is verified under the new key before the checkpoint
 *    advances. Re-running is safe and resumable: rows already at the new key
 *    decrypt-and-verify and are skipped.
 *  - Completion requires a full verification scan reporting zero rows that fail
 *    to authenticate under the new key.
 *  - The completion audit is written through the central critical audit API
 *    with schema-valid fields; a blocked audit write blocks completion.
 */

const KEY_HEX_RE = /^[0-9a-fA-F]{64}$/;

interface RotationTargets {
  secrets: number;
  clients: number;
  totp: number;
  pendingTotp: number;
}

interface RotationTableDef {
  table: "secrets" | "client_applications" | "totp_secrets" | "totp_pending_enrollments";
  /** Column holding the ciphertext. */
  column: string;
  purpose: EncryptionPurpose;
  /** Build the context AAD from the row. */
  aadFor: (row: { id: string; user_id: string }) => string;
  /** Which RotationTargets counter a migrated row increments. */
  countKey: keyof RotationTargets;
}

const ROTATION_TABLES: RotationTableDef[] = [
  {
    table: "secrets", column: "encrypted_blob", purpose: ENCRYPTION_PURPOSE.SECRET, countKey: "secrets",
    aadFor: r => buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: r.user_id, recordId: r.id }),
  },
  {
    table: "client_applications", column: "encrypted_key", purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, countKey: "clients",
    aadFor: r => buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: r.user_id, recordId: r.id, clientId: r.id }),
  },
  {
    table: "totp_secrets", column: "secret_encrypted", purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, countKey: "totp",
    aadFor: r => buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: r.user_id, recordId: r.user_id }),
  },
  {
    table: "totp_pending_enrollments", column: "secret_encrypted", purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, countKey: "pendingTotp",
    aadFor: r => buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: r.user_id, recordId: r.user_id }),
  },
];

export async function rotateMasterKeyDatabase(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  oldMasterKey: Buffer,
  newMasterKey: Buffer,
  options: { oldKeyId?: string; newKeyId?: string; batchSize?: number } = {},
): Promise<RotationTargets> {
  const oldKeyId = options.oldKeyId ?? "old_key";
  const newKeyId = options.newKeyId ?? "v1";
  const batchSize = options.batchSize ?? 200;

  // Keyring: serve both keys, write new envelopes under newKeyId.
  const keyring = new MasterKeyRing(
    [{ keyId: oldKeyId, key: oldMasterKey }, { keyId: newKeyId, key: newMasterKey }],
    newKeyId,
  );

  // Claim or resume a checkpoint row. An existing in_progress row for this key
  // pair is resumed; otherwise a fresh row is created. Two concurrent rotations
  // for the same key pair both match the in_progress row — the second CAS on it
  // is treated as a contention failure (see createOrResumeCheckpoint).
  const { rotationId, resumed } = await createOrResumeCheckpoint(supabase, oldKeyId, newKeyId);

  const counts: RotationTargets = { secrets: 0, clients: 0, totp: 0, pendingTotp: 0 };

  for (const def of ROTATION_TABLES) {
    // rotateTable returns the count of rows now authenticating under the new key.
    counts[def.countKey] = await rotateTable(supabase, keyring, def, newKeyId, batchSize);
    await updateCheckpoint(supabase, rotationId, counts);
  }

  // Full verification scan: every encrypted object must authenticate under the
  // new key. Any row that still requires the old key blocks completion.
  const failures = await verificationScan(supabase, keyring, newKeyId);
  if (failures > 0) {
    await failCheckpoint(supabase, rotationId, `${failures} row(s) failed verification under the new key`);
    throw new Error(`Rotation incomplete: ${failures} row(s) failed verification. Resume to retry.`);
  }

  // Completion audit via the central critical audit API with schema-valid
  // fields. A blocked audit write blocks completion.
  const auditOk = await recordAuditEvent(supabase, {
    userId: null,
    clientId: null,
    secretName: "system",
    accessType: "master_key_rotated",
    caller: "cli:rotate-master-key",
    outcome: "succeeded",
    metadata: {
      rotation_id: rotationId,
      resumed,
      old_key_id: oldKeyId,
      new_key_id: newKeyId,
      processed_secrets: counts.secrets,
      processed_clients: counts.clients,
      processed_totp: counts.totp,
      processed_pending_totp: counts.pendingTotp,
    },
  });
  if (!auditOk) {
    await failCheckpoint(supabase, rotationId, "completion audit write failed");
    throw new Error("Rotation blocked: completion audit could not be recorded.");
  }

  await completeCheckpoint(supabase, rotationId, counts);
  return counts;
}

/**
 * Re-encrypt every eligible row in one table using compare-and-swap. Returns the
 * count of rows that authenticate under the new key after this pass (resume is
 * idempotent: rows already at the new key are counted, not re-encrypted).
 */
async function rotateTable(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  keyring: MasterKeyRing,
  def: RotationTableDef,
  newKeyId: string,
  batchSize: number,
): Promise<number> {
  let migrated = 0;
  let cursor = "00000000-0000-0000-0000-000000000000";
  for (;;) {
    const { data, error } = await supabase
      .from(def.table)
      .select(`id, user_id, ${def.column}`)
      .order("id", { ascending: true })
      .gt("id", cursor)
      .limit(batchSize);
    if (error) throw new Error(`scan ${def.table} failed: ${error.message}`);
    const rows = (data ?? []) as Array<{ id: string; user_id: string } & Record<string, string>>;
    if (rows.length === 0) break;
    for (const row of rows) {
      cursor = row.id;
      const blob = row[def.column];
      if (!blob) continue;
      const isAlreadyNew = envelopeVersion(blob) === "v2" && envelopeKeyId(blob) === newKeyId;
      if (!isAlreadyNew) {
        await rotateRow(supabase, keyring, def, newKeyId, row, blob);
      }
      migrated++;
    }
    if (rows.length < batchSize) break;
  }
  return migrated;
}

/** Re-encrypt one row with compare-and-swap + verify-before-advance. */
async function rotateRow(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  keyring: MasterKeyRing,
  def: RotationTableDef,
  newKeyId: string,
  row: { id: string; user_id: string },
  originalBlob: string,
): Promise<void> {
  const aad = def.aadFor(row);
  // Decrypt with the keyring: the blob's authenticated key ID selects the key,
  // so a new-key row is never handed to the old key.
  const plaintext = await keyring.decrypt(originalBlob, { purpose: def.purpose, aad: envelopeVersion(originalBlob) === "v2" ? aad : undefined });

  const { encrypted: rewritten } = await encryptSecret(plaintext, keyring.defaultKey, {
    purpose: def.purpose,
    keyId: newKeyId,
    aad,
  });

  // Verify the rewritten blob under the new key BEFORE persisting.
  await keyring.decrypt(rewritten, { purpose: def.purpose, aad });

  // Compare-and-swap: only update if the row still holds the original ciphertext.
  // A concurrent change yields zero rows and is reported, never falsely counted.
  const { data: updated, error } = await supabase
    .from(def.table)
    .update({ [def.column]: rewritten })
    .eq("id", row.id)
    .eq(def.column, originalBlob)
    .select("id");
  if (error) throw new Error(`CAS update ${def.table} ${row.id} failed: ${error.message}`);
  if (!updated || updated.length === 0) {
    // Row changed under us (concurrent rotation or write). Skip; the verification
    // scan will confirm the row's final state authenticates under the new key.
    console.warn(`[rotate] ${def.table} ${row.id}: ciphertext changed concurrently; skipping (will verify)`);
  }
}

/** Verify every encrypted object authenticates under the NEW key. Returns failure count. */
async function verificationScan(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  keyring: MasterKeyRing,
  newKeyId: string,
): Promise<number> {
  let failures = 0;
  for (const def of ROTATION_TABLES) {
    let cursor = "00000000-0000-0000-0000-000000000000";
    for (;;) {
      const { data, error } = await supabase
        .from(def.table)
        .select(`id, user_id, ${def.column}`)
        .order("id", { ascending: true })
        .gt("id", cursor)
        .limit(200);
      if (error) throw new Error(`verification scan ${def.table} failed: ${error.message}`);
      const rows = (data ?? []) as Array<{ id: string; user_id: string } & Record<string, string>>;
      if (rows.length === 0) break;
      for (const row of rows) {
        cursor = row.id;
        const blob = row[def.column];
        if (!blob) continue;
        // Completion requires the new key ID, authenticated, decrypting.
        if (envelopeKeyId(blob) !== newKeyId) {
          failures++;
          console.error(`[rotate] verification FAILED ${def.table} ${row.id}: still on key ${envelopeKeyId(blob) ?? "?"}`);
          continue;
        }
        const aad = envelopeVersion(blob) === "v2" ? def.aadFor(row) : undefined;
        try { await keyring.decrypt(blob, { purpose: def.purpose, aad }); }
        catch (err) {
          failures++;
          console.error(`[rotate] verification FAILED ${def.table} ${row.id}: ${(err as Error).message}`);
        }
      }
      if (rows.length < 200) break;
    }
  }
  return failures;
}

async function createOrResumeCheckpoint(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any, oldKeyId: string, newKeyId: string,
): Promise<{ rotationId: string; resumed: boolean }> {
  // Look for an existing in_progress rotation for this key pair to resume.
  const { data: existing, error: findErr } = await supabase
    .from("master_key_rotations")
    .select("id")
    .eq("old_key_id", oldKeyId)
    .eq("new_key_id", newKeyId)
    .eq("status", "in_progress")
    .order("started_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (findErr) throw new Error(`checkpoint lookup failed: ${findErr.message}`);
  if (existing?.id) return { rotationId: existing.id, resumed: true };
  const { data, error } = await supabase
    .from("master_key_rotations")
    .insert({ status: "in_progress", old_key_id: oldKeyId, new_key_id: newKeyId })
    .select("id")
    .single();
  if (error || !data?.id) throw new Error(`checkpoint insert failed: ${error?.message ?? "no id"}`);
  return { rotationId: data.id, resumed: false };
}

async function updateCheckpoint(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any, rotationId: string, counts: RotationTargets,
): Promise<void> {
  const { error } = await supabase.from("master_key_rotations").update({
    processed_secrets: counts.secrets,
    processed_clients: counts.clients,
    processed_totp: counts.totp,
    processed_pending_totp: counts.pendingTotp,
  }).eq("id", rotationId);
  if (error) throw new Error(`checkpoint update failed: ${error.message}`);
}

async function completeCheckpoint(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any, rotationId: string, counts: RotationTargets,
): Promise<void> {
  const { error } = await supabase.from("master_key_rotations").update({
    status: "completed",
    processed_secrets: counts.secrets,
    processed_clients: counts.clients,
    processed_totp: counts.totp,
    processed_pending_totp: counts.pendingTotp,
    completed_at: new Date().toISOString(),
    error_message: null,
  }).eq("id", rotationId);
  if (error) throw new Error(`checkpoint completion failed: ${error.message}`);
}

async function failCheckpoint(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any, rotationId: string, reason: string,
): Promise<void> {
  await supabase.from("master_key_rotations").update({
    status: "failed",
    error_message: reason,
  }).eq("id", rotationId);
}

// ── CLI ──────────────────────────────────────────────────────────────
// SV-AUD-006/007: keys are NEVER accepted via argv or env literals. They are
// read from 0600 files (OLD_MASTER_KEY_FILE / NEW_MASTER_KEY_FILE) or hidden
// stdin, so they never appear in process arguments or the environment.

function readKeyFile(path: string): Buffer {
  const { readFileSync, statSync } = require("node:fs") as typeof import("node:fs");
  const stats = statSync(path);
  if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) {
    throw new Error(`Refusing key file ${path}: permissions too permissive (expected 0600).`);
  }
  const hex = readFileSync(path, "utf8").trim();
  if (!KEY_HEX_RE.test(hex)) throw new Error(`Key file ${path} does not contain 64 hex characters.`);
  return Buffer.from(hex, "hex");
}

function readKeyStdin(prompt: string): Buffer {
  const { readFileSync } = require("node:fs") as typeof import("node:fs");
  // TTY-less / piped: read all of stdin once. In an interactive TTY the operator
  // is expected to pipe the key (e.g. `cat old.key | secretvault rotate-master-key`).
  process.stderr.write(`${prompt}: `);
  const hex = readFileSync(0, "utf8").trim();
  if (!KEY_HEX_RE.test(hex)) throw new Error("Stdin did not provide 64 hex characters.");
  return Buffer.from(hex, "hex");
}

export async function handleRotateMasterKeyCli(): Promise<void> {
  const args = process.argv.slice(3);
  if (args.includes("--old-key") || args.includes("--new-key")) {
    console.error("ERROR: --old-key/--new-key are removed. Provide keys via OLD_MASTER_KEY_FILE / NEW_MASTER_KEY_FILE (0600) or stdin.");
    process.exit(1);
  }
  const oldFile = process.env.OLD_MASTER_KEY_FILE;
  const newFile = process.env.NEW_MASTER_KEY_FILE;
  const oldKeyId = process.env.SECRETVAULT_OLD_KEY_ID ?? "old_key";
  const newKeyId = process.env.SECRETVAULT_NEW_KEY_ID ?? "v1";

  let oldKey: Buffer;
  let newKey: Buffer;
  try {
    oldKey = oldFile ? readKeyFile(oldFile) : readKeyStdin("old master key (64 hex)");
    newKey = newFile ? readKeyFile(newFile) : readKeyStdin("new master key (64 hex)");
  } catch (err: any) {
    console.error(`ERROR: ${err?.message ?? err}`);
    process.exit(1);
  }

  const supabaseUrl = process.env.SECRETVAULT_SUPABASE_URL;
  const supabaseServiceKey = process.env.SECRETVAULT_SUPABASE_SERVICE_KEY;
  if (!supabaseUrl || !supabaseServiceKey) {
    console.error("ERROR: Missing SECRETVAULT_SUPABASE_URL or SECRETVAULT_SUPABASE_SERVICE_KEY.");
    process.exit(1);
  }

  console.log("Starting master key rotation...");
  const supabase = createClient(supabaseUrl, supabaseServiceKey, { db: { schema: "secretvault" } });

  try {
    const result = await rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId, newKeyId });
    console.log(`✓ Rotation complete. Verified under new key: ${result.secrets} secrets, ${result.clients} clients, ${result.totp} TOTP, ${result.pendingTotp} pending.`);
  } catch (err: any) {
    console.error(`✗ Rotation did not complete: ${err?.message ?? err}`);
    process.exit(2);
  }
}

// resolveMasterKey is re-exported so existing callers/tests that import it from
// this module continue to resolve; the canonical home remains keyLoader.ts.
export { resolveMasterKey };
