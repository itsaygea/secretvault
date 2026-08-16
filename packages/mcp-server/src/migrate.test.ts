import { resolve } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "@secretvault/testing";
import { databaseSsl, DATABASE_SSL_INSECURE_CONFIRM, loadMigrations, migrationChecksum, sortMigrationNames } from "./migrate.js";

describe("startup migration helpers", () => {
  it("orders only SQL migrations lexically by their numbered filename", () => {
    expect(sortMigrationNames(["011_last.sql", "README.md", "002_second.sql", "001_first.sql"])).toEqual([
      "001_first.sql",
      "002_second.sql",
      "011_last.sql",
    ]);
  });

  it("produces stable checksums for migration drift detection", () => {
    expect(migrationChecksum("CREATE SCHEMA secretvault;"))
      .toBe("4b6c5a59a6d02f82c421bfd0e4a4e0bbbb73489e6ab8d092543e84cfc73b89a3");
    expect(migrationChecksum("CREATE SCHEMA secretvault;"))
      .toBe(migrationChecksum("CREATE SCHEMA secretvault;"));
  });

  it("loads the checked-in migration set in startup order", async () => {
    const migrations = await loadMigrations(resolve(process.cwd(), "supabase/migrations"));
    expect(migrations[0]?.filename).toBe("001_create_tables.sql");
    expect(migrations.at(-1)?.filename).toBe("023_restore_service_role_grants.sql");
    // Guard against silent drift if a migration is added without updating
    // this test: assert the exact current count.
    expect(migrations).toHaveLength(23);
  });
});

describe("databaseSsl — production-safe TLS defaults (SV-021)", () => {
  const envKeys = [
    "SECRETVAULT_DATABASE_SSL",
    "SECRETVAULT_DATABASE_SSL_CA_FILE",
    "SECRETVAULT_DATABASE_SSL_CA",
    "SECRETVAULT_DATABASE_SSL_SERVERNAME",
    "SECRETVAULT_DATABASE_SSL_INSECURE",
    "SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM",
  ];
  const original: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const key of envKeys) {
      original[key] = process.env[key];
      delete process.env[key];
    }
  });
  afterEach(() => {
    for (const key of envKeys) {
      if (original[key] === undefined) delete process.env[key];
      else process.env[key] = original[key];
    }
  });

  it("verifies the server certificate by default (no env set)", () => {
    const ssl = databaseSsl();
    expect(ssl).not.toBe(false);
    expect(ssl).toEqual({ rejectUnauthorized: true });
  });

  it("disables TLS entirely when SECRETVAULT_DATABASE_SSL=false", () => {
    process.env.SECRETVAULT_DATABASE_SSL = "false";
    expect(databaseSsl()).toBe(false);
  });

  it("pins a trusted CA bundle from a file", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "sv-ca-"));
    writeFileSync(resolve(dir, "ca.pem"), "FAKE-CA-PEM");
    process.env.SECRETVAULT_DATABASE_SSL_CA_FILE = resolve(dir, "ca.pem");
    expect(databaseSsl()).toEqual({ rejectUnauthorized: true, ca: "FAKE-CA-PEM" });
  });

  it("pins a trusted CA bundle from inline material", () => {
    process.env.SECRETVAULT_DATABASE_SSL_CA = "INLINE-CA-PEM";
    expect(databaseSsl()).toEqual({ rejectUnauthorized: true, ca: "INLINE-CA-PEM" });
  });

  it("overrides the SNI / hostname check via SERVERNAME", () => {
    process.env.SECRETVAULT_DATABASE_SSL_SERVERNAME = "pg.internal";
    expect(databaseSsl()).toEqual({ rejectUnauthorized: true, servername: "pg.internal" });
  });

  it("requires the literal confirmation to disable verification", () => {
    // Setting the flag alone must NOT disable verification.
    process.env.SECRETVAULT_DATABASE_SSL_INSECURE = "1";
    expect(databaseSsl()).toEqual({ rejectUnauthorized: true });
  });

  it("disables verification only with the explicit noisy dev override", () => {
    process.env.SECRETVAULT_DATABASE_SSL_INSECURE = "1";
    process.env.SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM = DATABASE_SSL_INSECURE_CONFIRM;
    expect(databaseSsl()).toEqual({ rejectUnauthorized: false });
  });
});
