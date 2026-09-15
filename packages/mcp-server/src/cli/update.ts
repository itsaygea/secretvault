import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const UPDATE_REPOSITORY = "itsaygea/secretvault";
const UPDATE_API_URL = `https://api.github.com/repos/${UPDATE_REPOSITORY}/commits/main`;
const UPDATE_SCRIPT_BASE_URL = `https://raw.githubusercontent.com/${UPDATE_REPOSITORY}`;
const COMMIT_SHA_RE = /^[0-9a-f]{40}$/i;

interface CommitResponse {
  sha?: unknown;
}

export function isImmutableCommitRef(value: string): boolean {
  return COMMIT_SHA_RE.test(value);
}

async function fetchText(url: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const response = await fetchImpl(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "secretvault-cli-updater",
    },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`remote update source returned HTTP ${response.status}`);
  return response.text();
}

export async function resolveUpdateCommit(fetchImpl: typeof fetch = fetch): Promise<string> {
  const configuredRef = process.env.SECRETVAULT_UPDATE_REF?.trim();
  if (configuredRef) {
    if (!isImmutableCommitRef(configuredRef)) {
      throw new Error("SECRETVAULT_UPDATE_REF must be a 40-character commit SHA");
    }
    return configuredRef.toLowerCase();
  }

  const payload = JSON.parse(await fetchText(UPDATE_API_URL, fetchImpl)) as CommitResponse;
  if (typeof payload.sha !== "string" || !isImmutableCommitRef(payload.sha)) {
    throw new Error("update source did not return an immutable commit SHA");
  }
  return payload.sha.toLowerCase();
}

export function buildUpdateEnvironment(
  commit: string,
  baseEnvironment: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  if (!isImmutableCommitRef(commit)) throw new Error("refusing to run an update without an immutable commit SHA");
  // The installer is third-party code from outside the running process. Give
  // it only the process context needed to build/install, never the server,
  // client, cloud, or package-registry credentials inherited by the CLI.
  const allowedKeys = new Set([
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP",
    "LANG", "LC_ALL", "CI", "TERM", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "npm_config_cache", "NPM_CONFIG_CACHE", "NPM_CONFIG_PREFIX",
  ]);
  const safeEnvironment: NodeJS.ProcessEnv = {};
  for (const key of allowedKeys) {
    if (baseEnvironment[key] !== undefined) safeEnvironment[key] = baseEnvironment[key];
  }
  return {
    ...safeEnvironment,
    SECRETVAULT_RELEASE_TAG: commit,
    SECRETVAULT_NON_INTERACTIVE: "1",
  };
}

async function downloadInstaller(commit: string, directory: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const script = await fetchText(`${UPDATE_SCRIPT_BASE_URL}/${commit}/install-client.sh`, fetchImpl);
  if (!script.startsWith("#!/usr/bin/env bash") || !script.includes("set -euo pipefail")) {
    throw new Error("downloaded installer failed its safety checks");
  }
  const scriptPath = join(directory, "install-client.sh");
  await writeFile(scriptPath, script, { encoding: "utf8", mode: 0o700 });
  return scriptPath;
}

function runInstaller(scriptPath: string, environment: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolve) => {
    // Execute a local file fetched at the immutable commit. This avoids the
    // old curl | bash pipeline and preserves the child exit status.
    const child = spawn("bash", [scriptPath], {
      stdio: "inherit",
      env: environment,
    });
    child.on("close", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(1));
  });
}

export async function handleUpdateCli(): Promise<void> {
  console.log("\x1b[1;36m");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("       ⚡ SecretVault CLI Auto-Updater                                  ");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("\x1b[0m");
  console.log("\n\x1b[36mResolving and installing the latest SecretVault CLI...\x1b[0m");
  console.log("\x1b[90mExisting local credential files will be left untouched.\x1b[0m\n");

  let temporaryDirectory: string | null = null;
  try {
    const commit = await resolveUpdateCommit();
    temporaryDirectory = await mkdtemp(join(tmpdir(), "secretvault-update-"));
    const installerPath = await downloadInstaller(commit, temporaryDirectory);
    console.log(`\x1b[36mUsing immutable source commit ${commit.slice(0, 12)}…\x1b[0m\n`);

    const exitCode = await runInstaller(installerPath, buildUpdateEnvironment(commit));
    if (exitCode === 0) {
      console.log("\n\x1b[1;32m========================================================================\x1b[0m");
      console.log("\x1b[1;32m       🎉 SECRETVAULT CLI UPDATED SUCCESSFULLY                          \x1b[0m");
      console.log("\x1b[1;32m========================================================================\x1b[0m\n");
    } else {
      console.error(`\n\x1b[1;31mUpdate failed with exit code ${exitCode}\x1b[0m\n`);
      process.exitCode = exitCode;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown update error";
    console.error(`\n\x1b[1;31mUpdate failed: ${message}\x1b[0m\n`);
    process.exitCode = 1;
  } finally {
    if (temporaryDirectory) {
      await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}
