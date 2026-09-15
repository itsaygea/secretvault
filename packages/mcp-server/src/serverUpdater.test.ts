import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "@secretvault/testing";

const root = resolve(import.meta.dirname, "..", "..", "..");
const scriptPath = resolve(root, "upgrade-server.sh");
const script = readFileSync(scriptPath, "utf8");
const executableLines = script
  .split("\n")
  .filter((line) => !line.trim().startsWith("#"))
  .join("\n");

describe("server updater safety contract (SV-AUD-015)", () => {
  it("is a syntactically valid fail-closed shell script", () => {
    expect(script).toMatch(/^#!\/usr\/bin\/env bash/);
    expect(script).toMatch(/set -euo pipefail/);
    expect(() => execFileSync("bash", ["-n", scriptPath])).not.toThrow();
  });

  it("requires and verifies an immutable commit", () => {
    expect(script).toMatch(/SECRETVAULT_UPDATE_REF/);
    expect(script).toMatch(/COMMIT_SHA_RE/);
    expect(script).toMatch(/release ref must be an exact 40-character commit SHA/);
    expect(script).toMatch(/rev-parse FETCH_HEAD/);
    expect(script).toMatch(/fetched commit did not match the requested immutable release/);
  });

  it("takes a database, environment, and project backup before applying the release", () => {
    expect(script).toMatch(/cp -- \"\$ENV_FILE\" \"\$BACKUP_DIR\/\.env\"/);
    expect(script).toMatch(/secretvault-project\.tgz/);
    expect(script).toMatch(/pg_dump/);
    expect(script).toMatch(/pg_dumpall/);
    expect(script).toMatch(/SHA256SUMS/);
    expect(script).toMatch(/backup_all\n  fetch_release\n  apply_release/);
  });

  it("supports the bundled and external/shared HA database topologies", () => {
    expect(script).toMatch(/docker-compose\.bundled\.yml/);
    expect(script).toMatch(/external PostgreSQL \(including shared\/HA deployments\)/);
    expect(script).toMatch(/SECRETVAULT_DATABASE_URL/);
    expect(script).toMatch(/compose exec -T postgres pg_dump/);
  });

  it("refuses dirty tracked checkouts, registry-image mode, and destructive rollback commands", () => {
    expect(script).toMatch(/git -C \"\$APP_DIR\" diff --quiet/);
    expect(script).toMatch(/tracked changes are present/);
    expect(script).toMatch(/registry-image deployments are not handled/);
    expect(executableLines).not.toMatch(/git[^\n]*reset\s+--hard/);
    expect(executableLines).not.toMatch(/docker[^\n]*compose[^\n]*down\s+-v/);
  });

  it("never sources .env or prints its credential values", () => {
    expect(script).toMatch(/never eval or source \.env/);
    expect(executableLines).not.toMatch(/(^|[;&|])\s*(?:source|\.)\s+.*\.env/);
    expect(executableLines).not.toMatch(/(?:cat|echo|printf)[^\n]*\.env/);
  });

  it("keeps Compose interpolation tied to the existing environment and verifies readiness", () => {
    expect(script).toMatch(/--env-file \"\$ENV_FILE\"/);
    expect(script).toMatch(/compose up -d --build/);
    expect(script).toMatch(/health\/ready/);
    expect(script).toMatch(/compose exec -T secretvault-mcp wget/);
  });
});
