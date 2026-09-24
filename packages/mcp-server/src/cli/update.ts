import { mkdtemp, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";

const UPDATE_REPOSITORY = "itsaygea/secretvault";
const UPDATE_API_URL = `https://api.github.com/repos/${UPDATE_REPOSITORY}/commits/main`;
const UPDATE_SCRIPT_BASE_URL = `https://raw.githubusercontent.com/${UPDATE_REPOSITORY}`;
const COMMIT_SHA_RE = /^[0-9a-f]{40}$/i;
const INSTALL_MARKER_PATH = [".local", "share", "secretvault-cli", "current-commit"] as const;
const PERSISTENT_RUNTIME_RE = /(?:^|\/)secretvault-cli\/([0-9a-f]{40})\/packages\/mcp-server\/dist\/index\.js$/i;

interface CommitResponse {
  sha?: unknown;
}

export function isImmutableCommitRef(value: string): boolean {
  return COMMIT_SHA_RE.test(value);
}

export function shouldSkipUpdate(latestCommit: string, installedCommit: string | null): boolean {
  return installedCommit !== null && latestCommit.toLowerCase() === installedCommit.toLowerCase();
}

export function extractInstalledCommit(runtimePath: string): string | null {
  const match = runtimePath.match(PERSISTENT_RUNTIME_RE);
  return match?.[1]?.toLowerCase() ?? null;
}

function installedCommitPath(home = process.env.HOME || homedir()): string {
  return join(home, ...INSTALL_MARKER_PATH);
}

async function readInstalledCommit(home?: string): Promise<string | null> {
  try {
    const marker = (await readFile(installedCommitPath(home), "utf8")).trim();
    if (isImmutableCommitRef(marker)) return marker.toLowerCase();
  } catch {
    // Older installers did not write a marker; fall back to their persistent
    // runtime path below.
  }

  try {
    if (!process.argv[1]) return null;
    return extractInstalledCommit(await realpath(process.argv[1]));
  } catch {
    return null;
  }
}

async function writeInstalledCommit(commit: string, home?: string): Promise<void> {
  if (!isImmutableCommitRef(commit)) throw new Error("refusing to record an invalid installed commit");
  const markerPath = installedCommitPath(home);
  await mkdir(dirname(markerPath), { recursive: true, mode: 0o700 });
  const temporaryMarkerPath = `${markerPath}.tmp-${process.pid}`;
  await writeFile(temporaryMarkerPath, `${commit.toLowerCase()}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryMarkerPath, markerPath);
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

export interface UpdateCliDependencies {
  fetchImpl?: typeof fetch;
  runInstaller?: (scriptPath: string, environment: NodeJS.ProcessEnv) => Promise<number>;
  home?: string;
}

export async function handleUpdateCli(dependencies: UpdateCliDependencies = {}): Promise<void> {
  console.log("\x1b[1;36m");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("       ⚡ SecretVault CLI Auto-Updater                                  ");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("\x1b[0m");
  console.log("\n\x1b[36mResolving the latest SecretVault CLI...\x1b[0m");
  console.log("\x1b[90mExisting local credential files will be left untouched.\x1b[0m\n");

  let temporaryDirectory: string | null = null;
  try {
    const fetchImpl = dependencies.fetchImpl ?? fetch;
    const commit = await resolveUpdateCommit(fetchImpl);
    const installedCommit = await readInstalledCommit(dependencies.home);
    if (shouldSkipUpdate(commit, installedCommit)) {
      await writeInstalledCommit(commit, dependencies.home).catch(() => undefined);
      console.log(`\n\x1b[1;32mSecretVault CLI is already up to date (${commit.slice(0, 12)}…). No build required.\x1b[0m\n`);
      return;
    }

    temporaryDirectory = await mkdtemp(join(tmpdir(), "secretvault-update-"));
    const installerPath = await downloadInstaller(commit, temporaryDirectory, fetchImpl);
    console.log(`\x1b[36mUsing immutable source commit ${commit.slice(0, 12)}…\x1b[0m\n`);

    const runInstallerImpl = dependencies.runInstaller ?? runInstaller;
    const exitCode = await runInstallerImpl(installerPath, buildUpdateEnvironment(commit));
    if (exitCode === 0) {
      await writeInstalledCommit(commit, dependencies.home);
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
