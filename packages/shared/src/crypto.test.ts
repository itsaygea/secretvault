import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { encryptSecret, decryptSecret, generateReference } from "./crypto.js";

describe("Crypto Invariants & AES-256-GCM", () => {
  const masterKey = randomBytes(32);

  it("should encrypt and decrypt a secret round-trip correctly", async () => {
    const original = "super-secret-api-key-12345";
    const { encrypted } = await encryptSecret(original, masterKey);
    const decrypted = await decryptSecret(encrypted, masterKey);
    expect(decrypted).toBe(original);
  });

  it("should generate a unique IV for every encryption call", async () => {
    const secret = "same-secret-value";
    const { encrypted: e1 } = await encryptSecret(secret, masterKey);
    const { encrypted: e2 } = await encryptSecret(secret, masterKey);
    expect(e1).not.toBe(e2);

    const parts1 = e1.split(":");
    const parts2 = e2.split(":");
    const iv1 = parts1.length === 5 ? parts1[2] : parts1[0];
    const iv2 = parts2.length === 5 ? parts2[2] : parts2[0];
    expect(iv1).not.toBe(iv2);
  });

  it("should fail decryption if auth tag or ciphertext is tampered with", async () => {
    const { encrypted } = await encryptSecret("sensitive-data", masterKey);
    const parts = encrypted.split(":");
    const ctIndex = parts.length === 5 ? 3 : 1;
    parts[ctIndex] = parts[ctIndex]!.slice(0, -2) + "00";
    const tamperedBlob = parts.join(":");

    await expect(decryptSecret(tamperedBlob, masterKey)).rejects.toThrow();
  });

  it("should generate valid reference tokens", () => {
    const ref = generateReference("openai_key");
    expect(ref.startsWith("ref:")).toBe(true);
    expect(ref.length).toBeGreaterThan(16);
  });
});
