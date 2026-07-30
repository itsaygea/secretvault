import { describe, expect, it } from "vitest";
import { encryptSecret, decryptSecret, deriveDEK, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { resolveMasterKey } from "./keyLoader.js";
import { writeFileSync, unlinkSync, chmodSync } from "node:fs";
import { resolve } from "node:path";

describe("crypto operations & key envelope (SV-018 / SV-AUD-005)", () => {
  const masterKey = Buffer.from("a".repeat(64), "hex");

  it("encrypts with the v2 context-bound envelope format v2:keyId:purpose:iv:ct:tag", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const { encrypted } = await encryptSecret("my-super-secret", masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      keyId: "k1",
      aad,
    });
    expect(encrypted).toMatch(/^v2:k1:secret:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
  });

  it("decrypts a v2 envelope with matching context", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const { encrypted } = await encryptSecret("secret-value-123", masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      keyId: "k1",
      aad,
    });
    const decrypted = await decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad });
    expect(decrypted).toBe("secret-value-123");
  });

  it("fails decryption if the purpose context does not match (cross-purpose transplant)", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const { encrypted } = await encryptSecret("secret-value-123", masterKey, {
      purpose: ENCRYPTION_PURPOSE.SECRET,
      keyId: "k1",
      aad,
    });
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad }),
    ).rejects.toThrow();
  });

  it("decrypts legacy 3-part iv:ct:tag format for backwards compatibility", async () => {
    const legacyCiphertext = "iv1234567890:ciphertext:tag1234567890123";
    await expect(decryptSecret(legacyCiphertext, masterKey)).rejects.toThrow();
  });

  it("derives domain-separated DEK via HKDF", () => {
    const salt = Buffer.from("b".repeat(32), "hex");
    const dekSecret = deriveDEK(masterKey, salt, "secret");
    const dekClient = deriveDEK(masterKey, salt, "client_key");

    expect(dekSecret.length).toBe(32);
    expect(dekClient.length).toBe(32);
    expect(dekSecret.equals(dekClient)).toBe(false);
  });
});

describe("master key loader (SV-019)", () => {
  const validHex = "1".repeat(64);
  const testFilePath = resolve(process.cwd(), "test_master_key.key");

  it("loads key from env var SECRETVAULT_MASTER_KEY", () => {
    const key = resolveMasterKey({ envKey: validHex });
    expect(key.toString("hex")).toBe(validHex);
  });

  it("loads key from file path SECRETVAULT_MASTER_KEY_FILE", () => {
    writeFileSync(testFilePath, `${validHex}\n`, "utf8");
    try {
      if (process.platform !== "win32") {
        chmodSync(testFilePath, 0o600);
      }
      const key = resolveMasterKey({ envFile: testFilePath });
      expect(key.toString("hex")).toBe(validHex);
    } finally {
      try {
        unlinkSync(testFilePath);
      } catch {}
    }
  });

  // SV-AUD-014: a world/group-readable key file is refused in production.
  (process.platform === "win32" ? it.skip : it)(
    "fails closed on a permissive (0644) key file in production",
    () => {
      writeFileSync(testFilePath, `${validHex}\n`, "utf8");
      try {
        chmodSync(testFilePath, 0o644);
        expect(() => resolveMasterKey({ envFile: testFilePath, production: true })).toThrow(
          /permissions too permissive/,
        );
      } finally {
        try {
          unlinkSync(testFilePath);
        } catch {}
      }
    },
  );

  (process.platform === "win32" ? it.skip : it)(
    "still loads (with warning) a permissive key file in development",
    () => {
      writeFileSync(testFilePath, `${validHex}\n`, "utf8");
      try {
        chmodSync(testFilePath, 0o644);
        const key = resolveMasterKey({ envFile: testFilePath, production: false });
        expect(key.toString("hex")).toBe(validHex);
      } finally {
        try {
          unlinkSync(testFilePath);
        } catch {}
      }
    },
  );

  it("fails closed when both SECRETVAULT_MASTER_KEY and SECRETVAULT_MASTER_KEY_FILE are set", () => {
    expect(() =>
      resolveMasterKey({ envKey: validHex, envFile: "/tmp/somekey" }),
    ).toThrow(/Ambiguous configuration/);
  });

  it("fails closed when master key is invalid length or hex", () => {
    expect(() => resolveMasterKey({ envKey: "short_key" })).toThrow(
      /Invalid master key format/,
    );
  });
});

