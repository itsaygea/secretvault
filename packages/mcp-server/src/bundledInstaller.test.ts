import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// #93 / #94 / #95 — Bundled PostgreSQL + PostgREST contract tests.
//
// Validates docker-compose.bundled.yml as a stable overlay contract the
// installer (#94) and verification script (#95) depend on. Asserting the file
// text keeps the test free of a YAML dependency and matches the repo's existing
// installerHardening.test.ts pattern. The merge behaviour it implies is also
// exercised at deploy time by `docker compose -f ... -f ... config`.
const repoRoot = resolve(__dirname, "..", "..", "..");
const bundled = readFileSync(
  resolve(repoRoot, "docker-compose.bundled.yml"),
  "utf8",
);

// Repo-root compose files, loaded once.
const base = readFileSync(
  resolve(repoRoot, "docker-compose.yml"),
  "utf8",
);

// The installer is parsed as text so the test asserts the static contract a
// `curl | bash` run depends on, without executing it (mirrors
// installerHardening.test.ts / installerEgress.test.ts).
const installer = readFileSync(resolve(repoRoot, "install-server.sh"), "utf8");

describe("#93 bundled PostgreSQL — postgres service", () => {
  it("uses postgres:16-alpine", () => {
    expect(bundled).toMatch(/image:\s*postgres:16-alpine/);
  });

  it("configures POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD", () => {
    expect(bundled).toMatch(/POSTGRES_DB:/);
    expect(bundled).toMatch(/POSTGRES_USER:/);
    // Password is required (no insecure baked-in default) so the bundled mode
    // cannot silently boot with a known credential.
    expect(bundled).toMatch(/POSTGRES_PASSWORD:\s*\$\{POSTGRES_PASSWORD:\?/);
  });

  it("declares a pg_isready healthcheck", () => {
    expect(bundled).toMatch(/healthcheck:/);
    expect(bundled).toMatch(/pg_isready/);
  });

  it("mounts a persistent named postgres_data volume", () => {
    expect(bundled).toMatch(/postgres_data:\/var\/lib\/postgresql\/data/);
    expect(bundled).toMatch(/^volumes:\s*$/m);
    expect(bundled).toMatch(/postgres_data:/);
  });
});

describe("#93 bundled PostgreSQL — secretvault-mcp wiring", () => {
  it("depends_on postgres with a healthy gate", () => {
    // Migrations must only run once the cluster accepts connections.
    expect(bundled).toMatch(/depends_on:/);
    expect(bundled).toMatch(/postgres:/);
    expect(bundled).toMatch(/condition:\s*service_healthy/);
  });

  it("points the migration runner at the bundled postgres", () => {
    expect(bundled).toMatch(/SECRETVAULT_DATABASE_URL:.*postgresql:\/\/.*@postgres:5432/);
  });

  it("disables database TLS for the plaintext alpine socket", () => {
    // migrate.ts defaults TLS ON with verification; the bundled container has
    // no TLS, so the overlay must explicitly opt out or connections fail.
    expect(bundled).toMatch(/SECRETVAULT_DATABASE_SSL:\s*"false"/);
  });
});

describe("#93 bundled PostgreSQL — backwards compatibility", () => {
  it("does not inject bundled env into the base compose", () => {
    // Users running external/Supabase/managed PostgreSQL use docker-compose.yml
    // alone; the base file must stay free of bundled DATABASE_URL/SSL wiring.
    expect(base).not.toMatch(/SECRETVAULT_DATABASE_SSL:\s*"false"/);
    expect(base).not.toMatch(/@postgres:5432/);
    expect(base).not.toMatch(/^  postgres:/);
  });

  it("base compose still loads .env as the single source of config", () => {
    expect(base).toMatch(/env_file:/);
  });
});

// #94/#95 architecture seam: bundled mode must mirror ci/docker-compose.ci.yml
// so runtime API queries (via @supabase/supabase-js /rest/v1/) flow through a
// local PostgREST sidecar, not a stubbed host. Migrations run once as a one-shot
// so PostgREST caches the schema after the tables exist.
describe("#94 bundled PostgREST sidecar — full stack", () => {
  it("runs a migrate one-shot before PostgREST starts", () => {
    expect(bundled).toMatch(/^  migrate:/m);
    expect(bundled).toMatch(/service_completed_successfully/);
    expect(bundled).toMatch(/packages\/mcp-server\/dist\/migrate\.js/);
  });

  it("ships the pinned PostgREST sidecar the CI stack uses", () => {
    expect(bundled).toMatch(/postgrest\/postgrest:v12\.2\.3/);
    expect(bundled).toMatch(/PGRST_DB_SCHEMAS:\s*"secretvault"/);
    expect(bundled).toMatch(/PGRST_DB_ANON_ROLE:\s*"anon"/);
    // Legacy GUCs ON so auth.role() / 001 RLS policies resolve the request role.
    expect(bundled).toMatch(/PGRST_DB_USE_LEGACY_GUCS:\s*"true"/);
  });

  it("requires a per-install PGRST_JWT_SECRET (no baked-in default)", () => {
    expect(bundled).toMatch(/PGRST_JWT_SECRET:\s*\$\{PGRST_JWT_SECRET:\?/);
  });

  it("fronts PostgREST with the /rest/v1/ nginx proxy supabase-js expects", () => {
    expect(bundled).toMatch(/^  postgrest-proxy:/m);
    expect(bundled).toMatch(/nginx:1\.27-alpine/);
    expect(bundled).toMatch(/bundled\/postgrest-proxy\.conf/);
    // The app's supabase-js client calls /rest/v1/<table>, so the app URL must
    // target the proxy, not raw PostgREST (which serves /<table>).
    expect(bundled).toMatch(/SECRETVAULT_SUPABASE_URL:\s*http:\/\/postgrest-proxy:8000/);
  });

  it("gates the app on schema existence + PostgREST startup", () => {
    const appBlock = bundled.split(/^  secretvault-mcp:/m).pop()!;
    expect(appBlock).toMatch(/service_completed_successfully/);
    expect(appBlock).toMatch(/postgrest:/);
    expect(appBlock).toMatch(/postgrest-proxy:/);
  });

  it("bootstraps PostgREST roles (authenticator/anon/service_role) on first boot", () => {
    const init = readFileSync(
      resolve(repoRoot, "bundled", "postgres-init.sql"),
      "utf8",
    );
    expect(init).toMatch(/CREATE ROLE service_role NOLOGIN/);
    expect(init).toMatch(/CREATE ROLE anon NOLOGIN/);
    expect(init).toMatch(/CREATE ROLE authenticator LOGIN/);
    expect(init).toMatch(/auth\.role\(\)/);
  });

  it("ships the bundled nginx proxy config that rewrites /rest/v1/", () => {
    const conf = readFileSync(
      resolve(repoRoot, "bundled", "postgrest-proxy.conf"),
      "utf8",
    );
    expect(conf).toMatch(/location \/rest\/v1\//);
    expect(conf).toMatch(/proxy_pass http:\/\/postgrest:3000/);
  });
});

// #94 installer: 1-click bundled backend selector + auto-generated secrets.
describe("#94 installer — bundled backend selector", () => {
  it("offers the three database backends with bundled as the recommended default", () => {
    expect(installer).toMatch(/1\) Bundled Local PostgreSQL \(Recommended\)/);
    expect(installer).toMatch(/2\) Existing PostgreSQL/);
    expect(installer).toMatch(/3\) Supabase Cloud/);
    expect(installer).toMatch(/BACKEND_OPTION=\$\(prompt_with_default "Select backend" "1"\)/);
  });

  it("loads the bundled overlay only when bundled mode is chosen", () => {
    expect(installer).toMatch(/BUNDLED_MODE=true/);
    expect(installer).toMatch(/COMPOSE_FILES=\(-f docker-compose\.yml\)/);
    expect(installer).toMatch(/COMPOSE_FILES\+=\(-f docker-compose\.bundled\.yml\)/);
    // The startup command must pass the selected compose files through.
    expect(installer).toMatch(/"\$DOCKER_COMPOSE_CMD" "\$\{COMPOSE_FILES\[@\]\}" up -d --build/);
  });

  it("auto-generates the bundled stack credentials with openssl", () => {
    expect(installer).toMatch(/POSTGRES_PASSWORD=\$\(openssl rand -hex 24\)/);
    expect(installer).toMatch(/PGRST_JWT_SECRET=\$\(openssl rand -hex 32\)/);
    // The service key is a real HS256 service_role JWT minted in-process.
    expect(installer).toMatch(/mint_service_role_jwt/);
    expect(installer).toMatch(/SECRETVAULT_SUPABASE_SERVICE_KEY=\$\(mint_service_role_jwt/);
  });

  it("writes bundled credentials into .env under a bundled section", () => {
    expect(installer).toMatch(/POSTGRES_DB=%s.*POSTGRES_DB/);
    expect(installer).toMatch(/POSTGRES_PASSWORD=%s.*POSTGRES_PASSWORD/);
    expect(installer).toMatch(/PGRST_JWT_SECRET=%s.*PGRST_JWT_SECRET/);
  });

  it("mints an HS256 JWT carrying role=service_role against the JWT secret", () => {
    // The mint helper must produce the role claim PostgREST switches on.
    expect(installer).toMatch(/"role":"service_role"/);
    expect(installer).toMatch(/openssl dgst -sha256 -mac HMAC/);
  });

  it("keeps .env restricted to 0600", () => {
    expect(installer).toMatch(/umask 077/);
    expect(installer).toMatch(/chmod 600 "\$ENV_FILE"/);
  });

  it("validates ports, booleans, and URLs before writing .env", () => {
    expect(installer).toMatch(/validate_port/);
    expect(installer).toMatch(/validate_boolean/);
    expect(installer).toMatch(/validate_url/);
  });

  it("verifies post-install health on /health/live and /health/ready", () => {
    expect(installer).toMatch(/\/health\/live/);
    expect(installer).toMatch(/\/health\/ready/);
  });

  it("preserves backwards compatibility: existing-config fast path detects bundled mode", () => {
    // Re-running against an existing bundled .env must reload the bundled overlay.
    expect(installer).toMatch(/grep -q "\^POSTGRES_PASSWORD=" "\$ENV_FILE"/);
    expect(installer).toMatch(/COMPOSE_FILES\+=\(-f docker-compose\.bundled\.yml\)/);
  });
});

// #95 verification: the test file itself is the contract surface. Guard it.
describe("#95 bundled installer — verification surface exists", () => {
  it("the bundled assets directory exists alongside the overlay", () => {
    expect(existsSync(resolve(repoRoot, "bundled", "postgres-init.sql"))).toBe(true);
    expect(existsSync(resolve(repoRoot, "bundled", "postgrest-proxy.conf"))).toBe(true);
    expect(existsSync(resolve(repoRoot, "docker-compose.bundled.yml"))).toBe(true);
  });
});

// #95 end-to-end dry-run: render the merged Compose configuration the installer
// actually loads and assert every bundled service is present and the file set
// is mutually valid. This is `docker compose config` (no containers started),
// so it stays within the repo's "do not spin up Docker" testing convention
// while still exercising the real merge the operator gets at deploy time. The
// test is skipped when the Docker CLI is unavailable (minimal/CI-less envs).
const hasDockerCompose = (() => {
  try {
    execFileSync("docker", ["compose", "version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe.skipIf(!hasDockerCompose)("#95 bundled installer — docker compose config dry-run", () => {
  const envFile = resolve(repoRoot, ".env");
  const composeFiles = ["-f", "docker-compose.yml", "-f", "docker-compose.bundled.yml"];
  // The base compose file declares `env_file: .env`; `config` resolves it at
  // render time, so a throwaway .env must exist with the required variables.
  const requiredEnv = {
    SECRETVAULT_MASTER_KEY: "0".repeat(64),
    SECRETVAULT_SUPABASE_URL: "http://postgrest-proxy:8000",
    SECRETVAULT_SUPABASE_SERVICE_KEY: "dry-run-service-key",
    SECRETVAULT_DATABASE_URL: "postgresql://secretvault:dryrun@postgres:5432/secretvault",
    SECRETVAULT_DATABASE_SSL: "false",
    SECRETVAULT_UI_PASSWORD: "dryrun",
    SECRETVAULT_ALLOWED_ORIGINS: "http://localhost:3004",
    POSTGRES_DB: "secretvault",
    POSTGRES_USER: "secretvault",
    POSTGRES_PASSWORD: "dryrun",
    PGRST_JWT_SECRET: "dry-run-jwt-secret",
  };

  let rendered = "";

  it("renders the merged bundled configuration without error", () => {
    const hadEnv = existsSync(envFile);
    if (!hadEnv) {
      const lines = Object.entries(requiredEnv).map(([k, v]) => `${k}=${v}\n`);
      writeFileSync(envFile, lines.join(""));
    }
    try {
      rendered = execFileSync("docker", ["compose", ...composeFiles, "config"], {
        encoding: "utf8",
        cwd: repoRoot,
        env: { ...process.env, ...requiredEnv },
      });
    } finally {
      if (!hadEnv && existsSync(envFile)) {
        unlinkSync(envFile);
      }
    }
    // Non-empty rendered config means Compose accepted both overlays together.
    expect(rendered.length).toBeGreaterThan(0);
  });

  it("includes every bundled service", () => {
    // `config` re-emits services with their original keys.
    for (const svc of ["postgres:", "migrate:", "postgrest:", "postgrest-proxy:", "secretvault-mcp:"]) {
      // Match as a top-level-ish service key (two-space indent under services:).
      expect(rendered).toMatch(new RegExp(`^  ${svc}`, "m"));
    }
  });

  it("wires the app at the bundled postgrest-proxy URL", () => {
    expect(rendered).toMatch(/SECRETVAULT_SUPABASE_URL:\s*http:\/\/postgrest-proxy:8000/);
    expect(rendered).toMatch(/SECRETVAULT_DATABASE_SSL:\s*"?false"?/);
  });
});
