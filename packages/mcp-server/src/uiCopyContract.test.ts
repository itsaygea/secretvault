import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

/**
 * UI copy / endpoint contract test (SV-072).
 *
 * The Web UI is plain JavaScript that calls into the V1 API by hard-coded path
 * string. When the server's route registry drifts from those literals, features
 * silently break (e.g. the password-change flow posted to a nonexistent
 * `/v1/me/password` for a long time). This test extracts every `/v1/...` path
 * literal from the UI source and asserts each one is a real route in the
 * registry (or a parameterized child of one).
 *
 * It also asserts the documented key/setup-code prefixes match what the server
 * actually generates, so user-facing copy can't diverge from runtime again.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_DIR = resolve(__dirname, "..", "ui");
const SRC_DIR = resolve(__dirname);

function readUiSources(): string {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = resolve(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js") || entry.name.endsWith(".html")) files.push(full);
    }
  };
  walk(UI_DIR);
  return files.map((f) => readFileSync(f, "utf8")).join("\n");
}

/** Read the route registry source and pull out every registered V1 path. */
function readRegistryPaths(): Set<string> {
  const src = readFileSync(resolve(SRC_DIR, "routeRegistry.ts"), "utf8");
  const paths = new Set<string>();
  // Match: path: "/v1/..." possibly with {param} segments.
  const re = /path:\s*"(\/v1\/[^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    // Normalize: strip {param} segments and any trailing slash.
    const normalized = m[1].replace(/\/\{[^}]+\}/g, "").replace(/\/$/, "");
    paths.add(normalized);
  }
  return paths;
}

/** Extract /v1/... path literals from UI source, normalizing id segments. */
function extractUiPaths(ui: string): Set<string> {
  const found = new Set<string>();
  const re = /["'`](\/v1\/[a-zA-Z0-9_/-]+)["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(ui)) !== null) {
    let p = m[1];
    // Drop concrete id-like trailing segments the UI builds dynamically
    // (e.g. /v1/clients/<uuid>, /v1/secrets/<name>, /v1/auth/webauthn/credentials/<id>).
    p = p
      .replace(/\/v1\/secrets\/.+$/, "/v1/secrets")
      .replace(/\/v1\/clients\/.+$/, "/v1/clients")
      .replace(/\/v1\/service-profiles\/.+$/, "/v1/service-profiles")
      .replace(/\/v1\/users\/.+$/, "/v1/users")
      .replace(/\/v1\/auth\/webauthn\/credentials\/.+$/, "/v1/auth/webauthn/credentials")
      .replace(/\/$/, "");
    found.add(p);
  }
  return found;
}

describe("UI copy / endpoint contract (SV-072)", () => {
  const registry = readRegistryPaths();
  const ui = readUiSources();
  const uiPaths = extractUiPaths(ui);

  it("every /v1 path called by the UI exists in the route registry", () => {
    const missing: string[] = [];
    for (const p of uiPaths) {
      if (!registry.has(p)) missing.push(p);
    }
    expect(missing, `UI calls unregistered endpoints:\n${missing.join("\n")}`).toEqual([]);
  });

  it("the password-change UI posts to the real /v1/auth/change-password route", () => {
    expect(ui).toContain("/v1/auth/change-password");
    expect(ui).not.toContain("/v1/me/password");
    expect(registry.has("/v1/auth/change-password")).toBe(true);
  });

  it("UI copy uses the sv_ key prefix that matches the generator", () => {
    // Server: sv_<48 hex> (users.ts generateLinkingKey). UI must not claim a
    // different prefix (e.g. the stale sv_live_... copy the audit flagged).
    expect(ui).toMatch(/sv_/);
    expect(ui).not.toMatch(/sv_live_/);
  });

  it("UI setup-code placeholder matches the server's setup_<hex> format", () => {
    expect(ui).toContain("setup_");
    expect(ui).not.toMatch(/setup_code_[A-Z]/);
  });
});
