import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import http from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { buildChildSpawn } from "./runner.js";

// Resolve the built CLI relative to this test file's package, independent of cwd.
const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI_JS = join(PKG_DIR, "dist", "index.js");

/**
 * SV-AUD-007: secrets must never appear in a child process's command-line
 * arguments (/proc/<pid>/cmdline, ps, shell history).
 *
 * Two layers of proof:
 *  1. Unit: buildChildSpawn (the runner's argv/env decision) never substitutes
 *     the secret into argv by default, and always injects it into env.
 *  2. Process: spawn the real `secretvault run` against a mock vault and scan
 *     the whole /proc table for the marker — it must not appear in any cmdline.
 */
const isLinux = process.platform === "linux";
const MARKER = "argv-safety-marker-9f3c7e1d";

describe("runner: substitution decision (SV-AUD-007) — unit", () => {
  const cmdArgs = ["echo", "use-$API_KEY", "and-%API_KEY%"];

  it("injects the secret into env and leaves argv untouched by default", () => {
    const { env, argv } = buildChildSpawn("API_KEY", MARKER, cmdArgs, false);
    expect(env.API_KEY).toBe(MARKER);
    expect(argv).toEqual(cmdArgs);            // verbatim, no substitution
    expect(argv.join(" ")).not.toContain(MARKER);
  });

  it("only substitutes into argv under explicit opt-in", () => {
    const { env, argv } = buildChildSpawn("API_KEY", MARKER, cmdArgs, true);
    expect(env.API_KEY).toBe(MARKER);
    expect(argv.join(" ")).toContain(MARKER); // opt-in path substitutes
    expect(argv).not.toEqual(cmdArgs);
  });

  it("handles both $NAME and %NAME% forms under opt-in", () => {
    const { argv } = buildChildSpawn("API_KEY", MARKER, ["$API_KEY", "%API_KEY%"], true);
    expect(argv).toEqual([MARKER, MARKER]);
  });
});

let vault: http.Server;
let vaultPort = 0;

beforeAll(async () => {
  vault = http.createServer((req, res) => {
    if (req.url?.startsWith("/v1/client/secrets/")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ value: MARKER }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => vault.listen(0, "127.0.0.1", r));
  vaultPort = (vault.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>(r => vault.close(() => r()));
});

describe("runner: no secrets in any process cmdline (SV-AUD-007) — process", () => {
  it("keeps the marker out of every /proc/<pid>/cmdline after a real run", async () => {
    if (!isLinux) return; // /proc is Linux-only.
    const child = spawn(process.execPath, [
      CLI_JS, "run", "--secret", "API_KEY",
      "--", process.execPath, "-e", "setInterval(()=>{},50)",
    ], {
      cwd: PKG_DIR,
      env: {
        ...process.env,
        SECRETVAULT_URL: `http://127.0.0.1:${vaultPort}`,
        SECRETVAULT_CLIENT_KEY: "sv-test-key",
      },
    });
    await new Promise<void>(r => setTimeout(r, 900));
    let leaked = false;
    try {
      const { readdirSync } = await import("node:fs");
      for (const entry of readdirSync("/proc")) {
        if (!/^\d+$/.test(entry)) continue;
        try {
          const cmd = readFileSync(`/proc/${entry}/cmdline`, "utf8").replace(/\0/g, " ");
          if (cmd.includes(MARKER)) { leaked = true; break; }
        } catch { /* process exited */ }
      }
    } catch { /* /proc read race */ }
    child.kill("SIGKILL");
    expect(leaked).toBe(false);
  }, 10000);
});

describe("setup: generated MCP config carries no raw client key (SV-AUD-007)", () => {
  it("setup.ts writes a 0600 credential file + launcher and references them, not the key", () => {
    const src = readFileSync(join(PKG_DIR, "src", "cli", "setup.ts"), "utf8");
    expect(src).not.toMatch(/`Authorization: Bearer \$\{clientKey\}`/);
    expect(src).toMatch(/mode: 0o600/);
    expect(src).toMatch(/writeSecureMcpLauncher/);
  });
});
