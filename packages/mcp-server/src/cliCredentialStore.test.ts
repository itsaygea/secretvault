import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { saveClientCredentials, loadClientCredentials, getCredentialPath, getSecretVaultDir } from "./cli/credentialStore.js";

describe("CLI Credential Store (SV-AUD-007 / SV-AUD-012)", () => {
  const credentialFile = getCredentialPath();
  const legacyFile = path.join(getSecretVaultDir(), "mcp-credential.key");
  const vaultDir = getSecretVaultDir();
  let backupContent: string | null = null;
  let legacyBackupContent: string | null = null;

  beforeEach(() => {
    if (fs.existsSync(credentialFile)) {
      backupContent = fs.readFileSync(credentialFile, "utf8");
      fs.unlinkSync(credentialFile);
    } else {
      backupContent = null;
    }

    if (fs.existsSync(legacyFile)) {
      legacyBackupContent = fs.readFileSync(legacyFile, "utf8");
      fs.unlinkSync(legacyFile);
    } else {
      legacyBackupContent = null;
    }
  });

  afterEach(() => {
    if (backupContent !== null) {
      if (!fs.existsSync(vaultDir)) {
        fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(credentialFile, backupContent, { mode: 0o600 });
    } else if (fs.existsSync(credentialFile)) {
      fs.unlinkSync(credentialFile);
    }

    if (legacyBackupContent !== null) {
      if (!fs.existsSync(vaultDir)) {
        fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(legacyFile, legacyBackupContent, { mode: 0o600 });
    } else if (fs.existsSync(legacyFile)) {
      fs.unlinkSync(legacyFile);
    }
  });

  it("saves and loads client credentials atomically with 0600 mode", () => {
    const testUrl = "https://vault.example.com";
    const testKey = "sv_test_linking_key_1234567890abcdef";

    saveClientCredentials(testUrl, testKey);

    expect(fs.existsSync(credentialFile)).toBe(true);

    if (process.platform !== "win32") {
      const stat = fs.statSync(credentialFile);
      const mode = stat.mode & 0o777;
      expect(mode).toBe(0o600);
    }

    const loaded = loadClientCredentials();
    expect(loaded).not.toBeNull();
    expect(loaded?.url).toBe(testUrl);
    expect(loaded?.clientKey).toBe(testKey);
  });

  it("returns null when credential file is missing or invalid JSON", () => {
    if (fs.existsSync(credentialFile)) fs.unlinkSync(credentialFile);

    expect(loadClientCredentials()).toBeNull();

    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(credentialFile, "{ invalid json", { mode: 0o600 });

    expect(loadClientCredentials()).toBeNull();
  });
});
