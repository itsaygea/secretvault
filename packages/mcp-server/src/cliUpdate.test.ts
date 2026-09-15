import { describe, it, expect } from "@secretvault/testing";
import { buildUpdateEnvironment, handleUpdateCli, isImmutableCommitRef } from "./cli/update.js";

describe("CLI Auto-Updater (SV-AUD-007 / SV-AUD-012)", () => {
  it("exports handleUpdateCli as an async function", () => {
    expect(typeof handleUpdateCli).toBe("function");
  });

  it("only accepts immutable 40-character commit references", () => {
    expect(isImmutableCommitRef("0".repeat(40))).toBe(true);
    expect(isImmutableCommitRef("main")).toBe(false);
    expect(isImmutableCommitRef("0".repeat(39))).toBe(false);
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
