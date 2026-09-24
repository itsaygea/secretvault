import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "@secretvault/testing";
import {
  buildUpdateEnvironment,
  extractInstalledCommit,
  handleUpdateCli,
  isImmutableCommitRef,
  shouldSkipUpdate,
} from "./cli/update.js";

describe("CLI Auto-Updater (SV-AUD-007 / SV-AUD-012)", () => {
  it("exports handleUpdateCli as an async function", () => {
    expect(typeof handleUpdateCli).toBe("function");
  });

  it("only accepts immutable 40-character commit references", () => {
    expect(isImmutableCommitRef("0".repeat(40))).toBe(true);
    expect(isImmutableCommitRef("main")).toBe(false);
    expect(isImmutableCommitRef("0".repeat(39))).toBe(false);
  });

  it("skips an update when the installed commit already matches", () => {
    const current = "a".repeat(40);
    const newer = "b".repeat(40);
    expect(shouldSkipUpdate(current, current)).toBe(true);
    expect(shouldSkipUpdate(newer, current)).toBe(false);
  });

  it("recognizes the persistent runtime commit used by the client installer", () => {
    const commit = "c".repeat(40);
    expect(extractInstalledCommit(
      `/home/example/.local/share/secretvault-cli/${commit}/packages/mcp-server/dist/index.js`,
    )).toBe(commit);
    expect(extractInstalledCommit("/home/example/.local/bin/securevault")).toBe(null);
  });

  it("does not download or run the installer when the installed commit matches", async () => {
    const commit = "d".repeat(40);
    const home = await mkdtemp(join(tmpdir(), "secretvault-update-test-"));
    const markerPath = join(home, ".local", "share", "secretvault-cli", "current-commit");
    await mkdir(join(home, ".local", "share", "secretvault-cli"), { recursive: true });
    await writeFile(markerPath, `${commit}\n`, "utf8");

    const previousRef = process.env.SECRETVAULT_UPDATE_REF;
    let fetchCalls = 0;
    let installerRuns = 0;
    process.env.SECRETVAULT_UPDATE_REF = commit;
    try {
      await handleUpdateCli({
        home,
        fetchImpl: (async () => {
          fetchCalls += 1;
          throw new Error("unexpected network request");
        }) as typeof fetch,
        runInstaller: async () => {
          installerRuns += 1;
          return 0;
        },
      });
    } finally {
      if (previousRef === undefined) delete process.env.SECRETVAULT_UPDATE_REF;
      else process.env.SECRETVAULT_UPDATE_REF = previousRef;
      await rm(home, { recursive: true, force: true });
    }

    expect(fetchCalls).toBe(0);
    expect(installerRuns).toBe(0);
  });

  it("pins the installer to the immutable ref and never carries credential values", () => {
    const environment = buildUpdateEnvironment("a".repeat(40), {
      PATH: "/bin",
      SECRETVAULT_MASTER_KEY: "EXAMPLE_MASTER_KEY",
      NPM_TOKEN: "EXAMPLE_NPM_TOKEN",
    });
    expect(environment.SECRETVAULT_RELEASE_TAG).toBe("a".repeat(40));
    expect(environment.SECRETVAULT_NON_INTERACTIVE).toBe("1");
    expect(environment.SECRETVAULT_CLIENT_KEY).toBeUndefined();
    expect(environment.SECRETVAULT_MASTER_KEY).toBeUndefined();
    expect(environment.NPM_TOKEN).toBeUndefined();
  });
});
