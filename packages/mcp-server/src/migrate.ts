import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";

const MIGRATION_LOCK_NAME = "secretvault:migrations";
const MIGRATION_HISTORY_TABLE = "secretvault.schema_migrations";

export interface MigrationFile {
  version: string;
  filename: string;
  sql: string;
  checksum: string;
}

export function migrationChecksum(sql: string): string {
  return createHash("sha256").update(sql).digest("hex");
}

export function sortMigrationNames(names: string[]): string[] {
  return [...names]
    .filter((name) => name.endsWith(".sql"))
    .sort((left, right) => left.localeCompare(right, "en"));
}

export async function loadMigrations(migrationsDir: string): Promise<MigrationFile[]> {
  const filenames = sortMigrationNames(await readdir(migrationsDir));
  return Promise.all(filenames.map(async (filename) => {
    const sql = await readFile(join(migrationsDir, filename), "utf8");
    return {
      version: filename.slice(0, -4),
      filename,
      sql,
      checksum: migrationChecksum(sql),
    };
  }));
}

/**
 * Production-safe database TLS configuration.
 *
 * Defaults (no env set): TLS ON with certificate verification ON. This is the
 * only posture that protects a remote database from MITM — SV-021 was the
 * previous default, which encrypted the link but accepted any certificate.
 *
 * Operators who genuinely need to disable verification (private LAN, dev) must
 * opt in explicitly and loudly: set SECRETVAULT_DATABASE_SSL_INSECURE=1 AND
 * SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM to the literal acknowledgement
 * string. The two-key check means an empty prompt can never silently land on
 * the insecure path.
 *
 * Env surface:
 *  - SECRETVAULT_DATABASE_SSL=false            → disable TLS entirely (plaintext)
 *  - SECRETVAULT_DATABASE_SSL_CA_FILE=<path>   → pin a CA bundle (PEM)
 *  - SECRETVAULT_DATABASE_SSL_CA=<pem>         → pin a CA bundle (inline PEM)
 *  - SECRETVAULT_DATABASE_SSL_SERVERNAME=<sn>  → override SNI / hostname check
 *  - SECRETVAULT_DATABASE_SSL_INSECURE=1
 *    SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM=I-know-this-is-insecure
 *                                              → disable verification (dev only)
 */
export const DATABASE_SSL_INSECURE_CONFIRM = "I-know-this-is-insecure";

export function databaseSsl(): false | { rejectUnauthorized: boolean; ca?: string; servername?: string } {
  // Explicit plaintext override.
  if (process.env.SECRETVAULT_DATABASE_SSL?.toLowerCase() === "false") return false;

  // CA bundle: file takes precedence over inline material.
  const caFile = process.env.SECRETVAULT_DATABASE_SSL_CA_FILE;
  const caMaterial = process.env.SECRETVAULT_DATABASE_SSL_CA;
  const ca = caFile && existsSync(caFile)
    ? readFileSync(caFile, "utf8")
    : caMaterial || undefined;

  const servername = process.env.SECRETVAULT_DATABASE_SSL_SERVERNAME?.trim() || undefined;

  // Explicit, noisy dev override. Both keys must be set, and the confirmation
  // must match the literal acknowledgement — empty prompts cannot reach this.
  const insecure =
    process.env.SECRETVAULT_DATABASE_SSL_INSECURE === "1" &&
    process.env.SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM === DATABASE_SSL_INSECURE_CONFIRM;
  if (insecure) {
    console.warn(
      "[migrate] WARNING: database TLS certificate verification is DISABLED " +
        "(SECRETVAULT_DATABASE_SSL_INSECURE=1). This is a development-only " +
        "override and MUST NOT be used against an untrusted network.",
    );
  }

  return {
    rejectUnauthorized: !insecure,
    ...(ca ? { ca } : {}),
    ...(servername ? { servername } : {}),
  };
}

function defaultMigrationsDir(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../../../supabase/migrations");
}

async function ensureHistoryTable(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE SCHEMA IF NOT EXISTS secretvault;
    CREATE TABLE IF NOT EXISTS ${MIGRATION_HISTORY_TABLE} (
      version TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

async function acquireMigrationLock(client: PoolClient): Promise<void> {
  await client.query("SELECT pg_advisory_lock(hashtext($1))", [MIGRATION_LOCK_NAME]);
}

async function releaseMigrationLock(client: PoolClient): Promise<void> {
  await client.query("SELECT pg_advisory_unlock(hashtext($1))", [MIGRATION_LOCK_NAME]);
}

async function recordBaseline(
  client: PoolClient,
  migrations: MigrationFile[],
  baseline: string,
): Promise<void> {
  const baselineIndex = migrations.findIndex((migration) => migration.version === baseline);
  if (baselineIndex < 0) {
    throw new Error(`SECRETVAULT_MIGRATIONS_BASELINE '${baseline}' does not match a migration file`);
  }

  const existingSchema = await client.query<{ schema_name: string | null }>(
    "SELECT to_regclass('secretvault.secrets') AS schema_name",
  );
  if (!existingSchema.rows[0]?.schema_name) {
    throw new Error("SECRETVAULT_MIGRATIONS_BASELINE is only valid for an existing SecretVault database");
  }

  await client.query("BEGIN");
  try {
    for (const migration of migrations.slice(0, baselineIndex + 1)) {
      await client.query(
        `INSERT INTO ${MIGRATION_HISTORY_TABLE} (version, checksum) VALUES ($1, $2)`,
        [migration.version, migration.checksum],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  }

  console.warn(`[migrate] recorded existing database baseline through ${baseline}`);
}

async function applyMigration(client: PoolClient, migration: MigrationFile): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(migration.sql);
    await client.query(
      `INSERT INTO ${MIGRATION_HISTORY_TABLE} (version, checksum) VALUES ($1, $2)`,
      [migration.version, migration.checksum],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  }
}

export async function runMigrations(options: {
  databaseUrl?: string;
  migrationsDir?: string;
  baseline?: string;
} = {}): Promise<void> {
  const databaseUrl = options.databaseUrl ?? process.env.SECRETVAULT_DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("SECRETVAULT_DATABASE_URL is required before the server can start");
  }

  const migrations = await loadMigrations(options.migrationsDir ?? defaultMigrationsDir());
  if (migrations.length === 0) throw new Error("No SQL migrations were found");

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: databaseSsl(),
    max: 1,
  });
  const client = await pool.connect();
  let lockHeld = false;

  try {
    await acquireMigrationLock(client);
    lockHeld = true;
    await ensureHistoryTable(client);

    const appliedResult = await client.query<{ version: string; checksum: string }>(
      `SELECT version, checksum FROM ${MIGRATION_HISTORY_TABLE}`,
    );
    const applied = new Map(appliedResult.rows.map((row) => [row.version, row.checksum]));

    const knownVersions = new Set(migrations.map((migration) => migration.version));
    for (const version of applied.keys()) {
      if (!knownVersions.has(version)) {
        throw new Error(`Migration history contains '${version}', but its SQL file is missing from the image`);
      }
    }

    if (applied.size === 0 && options.baseline) {
      await recordBaseline(client, migrations, options.baseline);
      for (const migration of migrations.slice(0, migrations.findIndex((item) => item.version === options.baseline) + 1)) {
        applied.set(migration.version, migration.checksum);
      }
    }

    for (const migration of migrations) {
      const recordedChecksum = applied.get(migration.version);
      if (recordedChecksum) {
        if (recordedChecksum !== migration.checksum) {
          throw new Error(`Migration checksum mismatch for ${migration.filename}; restore the original file or create a new migration`);
        }
        continue;
      }

      console.log(`[migrate] applying ${migration.filename}`);
      await applyMigration(client, migration);
    }
  } finally {
    if (lockHeld) await releaseMigrationLock(client).catch(() => undefined);
    client.release();
    await pool.end();
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === currentFile) {
  runMigrations({ baseline: process.env.SECRETVAULT_MIGRATIONS_BASELINE })
    .then(() => console.log("[migrate] database schema is up to date"))
    .catch((error: unknown) => {
      console.error(`[migrate] startup migration failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    });
}
