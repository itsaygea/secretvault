import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  encryptSecret,
  decryptSecret,
  envelopeVersion,
  ENCRYPTION_PURPOSE,
  buildContextAad,
} from "./crypto.js";

describe("Crypto Invariants & AES-256-GCM", () => {
  const masterKey = randomBytes(32);

  it("should encrypt and decrypt a secret round-trip correctly", async () => {
    const original = "super-secret-api-key-12345";
    const { encrypted } = await encryptSecret(original, masterKey);
    const decrypted = await decryptSecret(encrypted, masterKey);
    expect(decrypted).toBe(original);
  });

  it("should emit the v2 context-bound envelope by default", async () => {
    const { encrypted } = await encryptSecret("x", masterKey);
    expect(envelopeVersion(encrypted)).toBe("v2");
    expect(encrypted.split(":").length).toBe(6);
  });

  it("should generate a unique IV for every encryption call", async () => {
    const secret = "same-secret-value";
    const aad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const { encrypted: e1 } = await encryptSecret(secret, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad });
    const { encrypted: e2 } = await encryptSecret(secret, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad });
    expect(e1).not.toBe(e2);

    // v2 layout: v2:keyId:purpose:iv:ct:tag — iv at index 3.
    const iv1 = e1.split(":")[3];
    const iv2 = e2.split(":")[3];
    expect(iv1).not.toBe(iv2);
  });

  it("should fail decryption if auth tag or ciphertext is tampered with", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const { encrypted } = await encryptSecret("sensitive-data", masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad });
    const parts = encrypted.split(":");
    // v2 ct at index 4.
    parts[4] = parts[4]!.slice(0, -2) + "00";
    const tamperedBlob = parts.join(":");

    await expect(decryptSecret(tamperedBlob, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad })).rejects.toThrow();
  });
});

// SV-AUD-005: ciphertext must be bound to tenant, record, purpose, version,
// and key ID. A storage actor who relocates a blob across any of those axes
// must fail GCM authentication — the server cannot become a decryption oracle.
describe("context binding & transplant protection (SV-AUD-005)", () => {
  const masterKey = randomBytes(32);

  const encryptFor = async (
    purpose: typeof ENCRYPTION_PURPOSE[keyof typeof ENCRYPTION_PURPOSE],
    userId: string,
    recordId: string,
    value = "user-a-plaintext-secret",
  ) => {
    const aad = buildContextAad(purpose, { userId, recordId });
    const { encrypted } = await encryptSecret(value, masterKey, { purpose, aad });
    return { encrypted, aad };
  };

  it("decrypts when tenant + record + purpose all match", async () => {
    const { encrypted, aad } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad }),
    ).resolves.toBe("user-a-plaintext-secret");
  });

  it("fails when the blob is transplanted across tenants (user a → user b)", async () => {
    const { encrypted } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    const attackerAad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "user-b", recordId: "rec-1" });
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad: attackerAad }),
    ).rejects.toThrow();
  });

  it("fails when the blob is transplanted across records", async () => {
    const { encrypted } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    const otherRecord = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "user-a", recordId: "rec-2" });
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad: otherRecord }),
    ).rejects.toThrow();
  });

  it("fails when the blob is decrypted under a different purpose (secret vs client_key)", async () => {
    const { encrypted } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad: buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: "user-a", recordId: "rec-1", clientId: "rec-1" }) }),
    ).rejects.toThrow();
  });

  it("fails when the envelope key ID is tampered", async () => {
    const { encrypted } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    const parts = encrypted.split(":");
    parts[1] = "evil"; // keyId at index 1
    await expect(
      decryptSecret(parts.join(":"), masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "user-a", recordId: "rec-1" }) }),
    ).rejects.toThrow();
  });

  it("fails when the envelope version tag is tampered (v2 → v1)", async () => {
    const { encrypted, aad } = await encryptFor(ENCRYPTION_PURPOSE.SECRET, "user-a", "rec-1");
    const tampered = "v1" + encrypted.slice(2); // claim v1 but keep v2 body
    await expect(
      decryptSecret(tampered, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad }),
    ).rejects.toThrow();
  });

  it("binds client keys to (userId, clientId)", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: "user-a", recordId: "c1", clientId: "c1" });
    const { encrypted } = await encryptSecret("linking-key-value", masterKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad });
    await expect(decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad })).resolves.toBe("linking-key-value");
    // Wrong client id fails.
    const otherClient = buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: "user-a", recordId: "c2", clientId: "c2" });
    await expect(decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad: otherClient })).rejects.toThrow();
  });

  it("binds TOTP seeds to the owning user", async () => {
    const aad = buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: "user-a", recordId: "user-a" });
    const { encrypted } = await encryptSecret("totp-seed-base32", masterKey, { purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, aad });
    await expect(decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, aad })).resolves.toBe("totp-seed-base32");
    const otherUser = buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: "user-b", recordId: "user-b" });
    await expect(decryptSecret(encrypted, masterKey, { purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, aad: otherUser })).rejects.toThrow();
  });
});

describe("v1 compatibility read window (SV-AUD-005)", () => {
  const masterKey = randomBytes(32);

  it("reads legacy v1 envelopes (no AAD) produced before context binding", async () => {
    // Hand-build a v1 envelope via the v1 path by encrypting with no context,
    // then re-tag it as v1. We produce a valid v1 by using a fixed fixture:
    // encrypt under current code yields v2; instead simulate a v1 row by
    // decrypting a known-shape v1 blob. Constructed via direct GCM below.
    const { createCipheriv } = await import("node:crypto");
    const iv = randomBytes(12);
    const { deriveDEK } = await import("./crypto.js");
    const dek = deriveDEK(masterKey, iv, "secret");
    const cipher = createCipheriv("aes-256-gcm", dek, iv);
    const ct = Buffer.concat([cipher.update("legacy-value", "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    const v1Blob = `v1:k1:${iv.toString("base64")}:${ct.toString("base64")}:${tag.toString("base64")}`;
    expect(envelopeVersion(v1Blob)).toBe("v1");
    await expect(decryptSecret(v1Blob, masterKey, { purpose: ENCRYPTION_PURPOSE.SECRET })).resolves.toBe("legacy-value");
  });

  it("rejects an unknown envelope shape", async () => {
    await expect(decryptSecret("garbage:blob:shape", masterKey)).rejects.toThrow();
  });
});
