import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * CI infrastructure contract tests (SV-029).
 *
 * These do not spin up Docker. They assert the static facts that make the
 * real-PostgREST CI stack enforceable: the grants migration exists and covers
 * every table, the service-role JWT in ci/secretvault.env matches the minter,
 * and the CI compose references PostgREST (not the removed mock).
 */
const repoRoot = resolve(__dirname, "..", "..", "..");
const migrationsDir = join(repoRoot, "supabase", "migrations");

function runNode(script: string, args: string[] = []): string {
  return execFileSync("node", [join(repoRoot, script), ...args], {
    encoding: "utf8",
    cwd: repoRoot,
  }).trim();
}

function readCiEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  const text = readFileSync(join(repoRoot, "ci", "secretvault.env"), "utf8");
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m && !line.startsWith("#")) {
      env[m[1]!] = m[2]!;
    }
  }
  return env;
}

describe("SV-029 grants migration", () => {
  it("ships a PostgREST grants migration", () => {
    const files = readdirSync(migrationsDir).filter((f) => f.endsWith(".sql"));
    const grants = files.find((f) => /postgrest_grants/i.test(f));
    expect(grants, "expected a *postgrest_grants.sql migration").toBeDefined();
    const text = readFileSync(join(migrationsDir, grants!), "utf8");
    // The durable least-privilege primitives.
    expect(text).toMatch(/GRANT USAGE ON SCHEMA secretvault TO service_role/);
    expect(text).toMatch(/ALTER DEFAULT PRIVILEGES IN SCHEMA secretvault/);
    expect(text).toMatch(/GRANT SELECT, INSERT, UPDATE, DELETE/);
    expect(text).toMatch(/REVOKE ALL ON SCHEMA secretvault FROM PUBLIC/);
  });

  it("grants service_role on the original 001 tables (secrets, access_logs)", () => {
    const files = readdirSync(migrationsDir).filter((f) => f.endsWith(".sql"));
    const grants = files.find((f) => /postgrest_grants/i.test(f))!;
    const text = readFileSync(join(migrationsDir, grants), "utf8");
    expect(text).toMatch(/secretvault\.secrets/);
    expect(text).toMatch(/secretvault\.access_logs/);
  });
});

describe("SV-029 CI PostgREST stack", () => {
  it("ci/secretvault.env service key matches the deterministic JWT minter", () => {
    const env = readCiEnv();
    const expected = runNode("ci/mint-jwt.mjs", ["service_role"]);
    expect(env.SECRETVAULT_SUPABASE_SERVICE_KEY).toBe(expected);
  });

  it("ci/secretvault.env points the app at PostgREST, not the removed mock", () => {
    const env = readCiEnv();
    expect(env.SECRETVAULT_SUPABASE_URL).toMatch(/postgrest/);
    expect(env.SECRETVAULT_SUPABASE_URL).not.toMatch(/supabase-mock/);
  });

  it("the mock Supabase server has been removed", () => {
    expect(existsSync(join(repoRoot, "ci", "mock-supabase.mjs"))).toBe(false);
  });

  it("ci/docker-compose.ci.yml uses real PostgREST and a migrate one-shot", () => {
    const compose = readFileSync(join(repoRoot, "ci", "docker-compose.ci.yml"), "utf8");
    expect(compose).toMatch(/postgrest\/postgrest/);
    expect(compose).toMatch(/PGRST_DB_SCHEMAS:\s*"secretvault"/);
    expect(compose).toMatch(/PGRST_DB_ANON_ROLE:\s*"anon"/);
    expect(compose).toMatch(/service_completed_successfully/);
    expect(compose).not.toMatch(/mock-supabase/);
  });

  it("the postgres-init creates the authenticator + anon roles PostgREST needs", () => {
    const init = readFileSync(join(repoRoot, "ci", "postgres-init.sql"), "utf8");
    expect(init).toMatch(/CREATE ROLE authenticator LOGIN/);
    expect(init).toMatch(/CREATE ROLE anon NOLOGIN/);
    expect(init).toMatch(/IN ROLE sv_runtime, service_role, anon/);
  });
});

describe("SV-030 break-glass executable", () => {
  it("ships a break-glass script in the image build context", () => {
    const script = readFileSync(join(repoRoot, "docker", "break-glass.sh"), "utf8");
    // Noninteractive safety checks.
    expect(script).toMatch(/--confirm/);
    expect(script).toMatch(/--password-file/);
    expect(script).toMatch(/--password-stdin/);
    expect(script).toMatch(/refusing to run without --confirm/);
  });

  it("the Dockerfile installs the break-glass executable", () => {
    const dockerfile = readFileSync(join(repoRoot, "Dockerfile"), "utf8");
    expect(dockerfile).toMatch(/docker\/break-glass\.sh/);
    expect(dockerfile).toMatch(/secretvault-break-glass/);
  });

  it("docs/ops.md documents the executable, not the npm script", () => {
    const ops = readFileSync(join(repoRoot, "docs", "ops.md"), "utf8");
    expect(ops).toMatch(/secretvault-break-glass/);
    expect(ops).not.toMatch(/npm run reset-admin-password/);
  });
});

describe("SV-031 registry image distribution", () => {
  it("ships a distribution Compose that pulls a pinned registry image", () => {
    const dist = readFileSync(join(repoRoot, "docker-compose.dist.yml"), "utf8");
    expect(dist).toMatch(/SECRETVAULT_IMAGE/);
    expect(dist).toMatch(/SECRETVAULT_DIGEST/);
    // It removes the source build in favor of a pullable image.
    expect(dist).toMatch(/build: !reset null/);
  });

  it("dist Compose requires SECRETVAULT_IMAGE (no silent local build)", () => {
    const dist = readFileSync(join(repoRoot, "docker-compose.dist.yml"), "utf8");
    expect(dist).toMatch(/\$\{SECRETVAULT_IMAGE:\?/);
  });

  it("the base Compose is build-from-source; dist overlays it cleanly", () => {
    const base = readFileSync(join(repoRoot, "docker-compose.yml"), "utf8");
    expect(base).toMatch(/build: \./);
  });

  it("install.md no longer offers the broken individual-files build", () => {
    const install = readFileSync(join(repoRoot, "docs", "install.md"), "utf8");
    expect(install).not.toMatch(/Download Individual Files/);
    expect(install).toMatch(/docker-compose\.dist\.yml/);
    expect(install).toMatch(/SECRETVAULT_IMAGE/);
  });

  it("a publish workflow builds multi-arch + provenance", () => {
    const wf = readFileSync(join(repoRoot, ".github", "workflows", "publish.yml"), "utf8");
    expect(wf).toMatch(/linux\/amd64,linux\/arm64/);
    expect(wf).toMatch(/provenance: true/);
    expect(wf).toMatch(/attest-build-provenance/);
  });
});
