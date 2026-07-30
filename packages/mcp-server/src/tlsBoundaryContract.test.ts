import { execFileSync } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * SV-AUD-001 — fail-closed TLS boundary contract tests.
 *
 * These exercise the *deployment topology*, not the runtime guard (which lives
 * in transportSecurity.test.ts). They render the real Compose files with
 * `docker compose config` so the assertions see exactly what an operator would
 * deploy, after Compose interpolation and overlay merging.
 *
 * They require the `docker` CLI (Compose v2). They skip gracefully when it is
 * absent (e.g. minimal CI runners) rather than failing — the runtime-guard unit
 * tests are the hard gate; these are defence-in-depth for the topology.
 */

const repoRoot = resolve(__dirname, "..", "..", "..");
const envFilePath = resolve(repoRoot, ".env");

function dockerAvailable(): boolean {
  try {
    const out = execFileSync("docker", ["compose", "version", "--short"], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
      timeout: 8000,
    });
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * docker-compose.yml declares `env_file: - .env` on the service, which Compose
 * validates (and fails on) even during `config`. A real deployment always has a
 * `.env` (created by install-server.sh); it is gitignored and absent from the
 * repo. For rendering only, we stage a minimal empty `.env` and remove it
 * afterwards so the repo is never modified persistently.
 */
let createdEnvFile = false;
function stageEnvFile(): void {
  if (existsSync(envFilePath)) return;
  // touch an empty file
  const fd = openSync(envFilePath, "w");
  closeSync(fd);
  createdEnvFile = true;
}
function removeStagedEnvFile(): void {
  if (createdEnvFile && existsSync(envFilePath)) {
    rmSync(envFilePath, { force: true });
  }
  createdEnvFile = false;
}

interface ComposePort {
  host_ip?: string;
  mode?: string;
  published?: string | number;
  target?: number;
  protocol?: string;
}
interface ComposeConfig {
  services: Record<string, { ports?: ComposePort[] }>;
}

/** Normalise a parsed port entry to a `host_ip:published:target` string. */
function portString(p: ComposePort): string {
  const host = p.host_ip ?? "0.0.0.0";
  const published = p.published ?? "";
  const target = p.target ?? "";
  return `${host}:${published}:${target}`;
}

/** Render the given compose files (plus optional env) into the merged config. */
function composeConfig(files: string[], env: Record<string, string> = {}): ComposeConfig {
  const args = ["compose", ...files.flatMap((f) => ["-f", f]), "config", "--format", "json"];
  const out = execFileSync("docker", args, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 15000,
    env: { ...process.env, ...env },
  });
  return JSON.parse(out) as ComposeConfig;
}

const dockerIt = dockerAvailable() ? it : it.skip;

describe("SV-AUD-001 — Compose TLS boundary (topology contract)", () => {
  const base = "docker-compose.yml";
  const caddy = "docker-compose.caddy.yml";

  beforeAll(() => {
    for (const f of [base, caddy]) {
      if (!existsSync(resolve(repoRoot, f))) {
        throw new Error(`required compose file missing: ${f}`);
      }
    }
    stageEnvFile();
  });
  afterAll(() => removeStagedEnvFile());

  dockerIt("publishes port 3004 on 127.0.0.1 by default (not all interfaces)", () => {
    const cfg = composeConfig([base]);
    const ports = (cfg.services["secretvault-mcp"]?.ports ?? []).map(portString);
    expect(ports).toContain("127.0.0.1:3004:3004");
    // No binding to 0.0.0.0 / all-interfaces in the default shape.
    for (const p of ports) {
      expect(p).not.toBe("0.0.0.0:3004:3004");
      expect(p).not.toBe("0.0.0.0:3004:3004".slice(2)); // guard against bare "3004:3004"
    }
  });

  dockerIt("honours SECRETVAULT_PUBLISH_HOST for an explicit external publish", () => {
    const cfg = composeConfig([base], { SECRETVAULT_PUBLISH_HOST: "0.0.0.0" });
    const ports = (cfg.services["secretvault-mcp"]?.ports ?? []).map(portString);
    expect(ports).toContain("0.0.0.0:3004:3004");
  });

  dockerIt("Caddy overlay removes the host-side port 3004 entirely", () => {
    // Even if an operator left a non-loopback publish set, the Caddy stack must
    // make Caddy the only externally reachable path: the app must NOT publish
    // port 3004 to the host at all.
    const cfg = composeConfig([base, caddy], { SECRETVAULT_PUBLISH_HOST: "0.0.0.0" });
    const ports = cfg.services["secretvault-mcp"]?.ports ?? [];
    expect(ports).toEqual([]);
    // Caddy itself only exposes 80/443 (TLS), never 3004.
    const caddyPorts = cfg.services.caddy?.ports ?? [];
    for (const p of caddyPorts) {
      expect(String(p.target)).not.toBe("3004");
    }
  });
});

describe("SV-AUD-001 — Dockerfile does not bake in the plaintext bypass", () => {
  const dockerfile = readFileSync(resolve(repoRoot, "Dockerfile"), "utf8");

  // The runtime ENV block: lines between `FROM ... AS runtime` and the next blank section.
  const runtimeStart = dockerfile.indexOf("AS runtime");
  const runtimeSection = runtimeStart >= 0 ? dockerfile.slice(runtimeStart) : dockerfile;

  it("does not set SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL in the image", () => {
    expect(runtimeSection).not.toMatch(/SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL\s*=/);
  });

  it("does not set SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM in the image", () => {
    expect(runtimeSection).not.toMatch(/SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM\s*=/);
  });
});
