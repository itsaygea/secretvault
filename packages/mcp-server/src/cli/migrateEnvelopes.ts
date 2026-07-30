import { createClient } from "@supabase/supabase-js";
import {
  decryptSecret,
  encryptSecret,
  envelopeVersion,
  ENCRYPTION_PURPOSE,
  buildContextAad,
} from "@secretvault/shared";
import { resolveMasterKey } from "../keyLoader.js";

/**
 * SV-AUD-005: in-place envelope migration v1/legacy → v2 (context-bound).
 *
 * Re-wraps each stored ciphertext with the v2 envelope bound to its tenant +
 * record context (AAD), using the SAME master key. This is a re-wrap, not a
 * re-key — it adds authentication of (version, keyId, purpose, tenant, record)
 * to rows that predate context binding. The online reader (decryptSecret)
 * already dual-reads v1/legacy/v2, so this can run while the server is live.
 *
 * Safety contract (per ticket 04):
 *  - Idempotent: rows already at v2 are skipped.
 *  - Verify-before-write: a row is never overwritten until the freshly produced
 *    v2 blob round-trips (encrypt → decrypt with the same AAD) successfully.
 *  - Verification-only mode (--verify-only): reports counts and any rows that
 *    cannot be re-wrapped, without writing.
 *
 * A storage backup made before migration can always restore v1 rows, which the
 * dual-read reader continues to accept during the compatibility window.
 */
export interface EnvelopeMigrationCounts {
  secretsScanned: number;
  secretsMigrated: number;
  clientsScanned: number;
  clientsMigrated: number;
  totpScanned: number;
  totpMigrated: number;
  pendingTotpScanned: number;
  pendingTotpMigrated: number;
  skipped: number;
  failed: number;
}

export async function migrateEnvelopes(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  masterKey: Buffer,
  options: { verifyOnly?: boolean; keyId?: string } = {},
): Promise<EnvelopeMigrationCounts> {
  const verifyOnly = options.verifyOnly ?? false;
  const keyId = options.keyId ?? "k1";
  const counts: EnvelopeMigrationCounts = {
    secretsScanned: 0, secretsMigrated: 0,
    clientsScanned: 0, clientsMigrated: 0,
    totpScanned: 0, totpMigrated: 0,
    pendingTotpScanned: 0, pendingTotpMigrated: 0,
    skipped: 0, failed: 0,
  };

  // Re-wrap a single field. Returns true if migrated (or would-be in verify mode).
  const rewrap = async (
    table: string,
    idColumn: string,
    row: { id: string; user_id: string },
    column: string,
    blob: string,
    purpose: typeof ENCRYPTION_PURPOSE[keyof typeof ENCRYPTION_PURPOSE],
    clientId?: string,
  ): Promise<void> => {
    const version = envelopeVersion(blob);
    if (version === "v2") { counts.skipped++; return; }
    // v1/legacy → decrypt (dual-read tolerates absent AAD for these envelopes),
    // then re-encrypt as v2 with the row's context bound into AAD.
    const decryptAad = version === "v1" || version === "legacy" ? undefined
      : buildContextAad(purpose, { userId: row.user_id, recordId: row.id, clientId: clientId ?? row.id });
    const plaintext = await decryptSecret(blob, masterKey, { purpose, aad: decryptAad });

    const aad = buildContextAad(purpose, { userId: row.user_id, recordId: row.id, clientId: clientId ?? row.id });
    const { encrypted: rewrapped } = await encryptSecret(plaintext, masterKey, { purpose, keyId, aad });

    // Verify-before-write: round-trip the v2 blob before any persistence.
    await decryptSecret(rewrapped, masterKey, { purpose, aad });

    if (!verifyOnly) {
      const { error } = await supabase.from(table).update({ [column]: rewrapped } as Record<string, string>).eq(idColumn, row.id);
      if (error) throw new Error(`update ${table}.${column} for ${row.id} failed: ${error.message}`);
    }
    switch (table) {
      case "secrets": counts.secretsMigrated++; break;
      case "client_applications": counts.clientsMigrated++; break;
      case "totp_secrets": counts.totpMigrated++; break;
      case "totp_pending_enrollments": counts.pendingTotpMigrated++; break;
    }
  };

  const scanTable = async <T extends { id: string; user_id: string }>(
    table: string, column: string, purpose: typeof ENCRYPTION_PURPOSE[keyof typeof ENCRYPTION_PURPOSE],
    countKey: keyof EnvelopeMigrationCounts,
    clientId?: (r: T) => string,
  ): Promise<void> => {
    const { data, error } = await supabase.from(table).select(`id, user_id, ${column}`);
    if (error) throw new Error(`scan ${table} failed: ${error.message}`);
    counts[countKey] = (counts[countKey] as number) + (data?.length ?? 0);
    for (const row of (data ?? []) as T[]) {
      const blob = (row as unknown as Record<string, string>)[column];
      if (!blob) continue;
      try {
        await rewrap(table, "id", row, column, blob, purpose, clientId?.(row));
      } catch (err) {
        counts.failed++;
        console.error(`[migrate-envelopes] ${table} ${row.id}: ${(err as Error).message}`);
      }
    }
  };

  await scanTable<{ id: string; user_id: string }>("secrets", "encrypted_blob", ENCRYPTION_PURPOSE.SECRET, "secretsScanned");
  await scanTable<{ id: string; user_id: string }>("client_applications", "encrypted_key", ENCRYPTION_PURPOSE.CLIENT_KEY, "clientsScanned", r => r.id);
  await scanTable<{ id: string; user_id: string }>("totp_secrets", "secret_encrypted", ENCRYPTION_PURPOSE.TOTP_PENDING, "totpScanned");
  await scanTable<{ id: string; user_id: string }>("totp_pending_enrollments", "secret_encrypted", ENCRYPTION_PURPOSE.TOTP_PENDING, "pendingTotpScanned");

  return counts;
}

export async function handleMigrateEnvelopesCli(): Promise<void> {
  const args = process.argv.slice(3);
  const verifyOnly = args.includes("--verify-only");
  const keyIdArg = args[args.indexOf("--key-id") + 1];

  const masterKey = resolveMasterKey({
    envKey: process.env.SECRETVAULT_MASTER_KEY,
    envFile: process.env.SECRETVAULT_MASTER_KEY_FILE,
  });

  const supabaseUrl = process.env.SECRETVAULT_SUPABASE_URL;
  const supabaseServiceKey = process.env.SECRETVAULT_SUPABASE_SERVICE_KEY;
  if (!supabaseUrl || !supabaseServiceKey) {
    console.error("ERROR: Missing SECRETVAULT_SUPABASE_URL or SECRETVAULT_SUPABASE_SERVICE_KEY environment variables.");
    process.exit(1);
  }

  const supabase = createClient(supabaseUrl, supabaseServiceKey, {
    db: { schema: "secretvault" },
  });

  console.log(`[migrate-envelopes] ${verifyOnly ? "VERIFY-ONLY" : "MIGRATE"} mode starting…`);
  const counts = await migrateEnvelopes(supabase, masterKey, { verifyOnly, keyId: keyIdArg });
  console.log("[migrate-envelopes] result:", counts);
  if (counts.failed > 0) {
    console.error(`[migrate-envelopes] ${counts.failed} row(s) could not be re-wrapped; see errors above.`);
    process.exit(2);
  }
  process.exit(0);
}
