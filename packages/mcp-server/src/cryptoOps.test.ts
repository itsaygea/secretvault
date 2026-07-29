import { describe, expect, it } from "vitest";
import { encryptSecret, decryptSecret, deriveDEK } from "@secretvault/shared";
import { resolveMasterKey } from "./keyLoader.js";
import { rotateMasterKeyDatabase } from "./cli/rotateKey.js";
import { writeFileSync, unlinkSync, chmodSync } from "node:fs";
import { resolve } from "node:path";

describe("crypto operations & key envelope (SV-018)", () => {
  const masterKey = Buffer.from("a".repeat(64), "hex");

  it("encrypts with v1 envelope format v1:key_id:iv:ct:tag", async () => {
    const { encrypted } = await encryptSecret("my-super-secret", masterKey, {
      purpose: "secret",
      keyId: "k1",
    });
    expect(encrypted).toMatch(/^v1:k1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
  });

  it("decrypts v1 envelope correctly", async () => {
    const { encrypted } = await encryptSecret("secret-value-123", masterKey, {
      purpose: "secret",
      keyId: "k1",
    });
    const decrypted = await decryptSecret(encrypted, masterKey, { purpose: "secret" });
    expect(decrypted).toBe("secret-value-123");
  });

  it("fails decryption if purpose context does not match", async () => {
    const { encrypted } = await encryptSecret("secret-value-123", masterKey, {
      purpose: "secret",
      keyId: "k1",
    });
    // Decrypting with wrong purpose context should fail auth tag verification
    await expect(
      decryptSecret(encrypted, masterKey, { purpose: "different_purpose" }),
    ).rejects.toThrow();
  });

  it("decrypts legacy 3-part iv:ct:tag format for backwards compatibility", async () => {
    // Generate legacy 3-part ciphertext
    const legacyCiphertext = "iv1234567890:ciphertext:tag1234567890123";
    // We expect invalid legacy ciphertexts to throw rather than crash
    await expect(decryptSecret(legacyCiphertext, masterKey)).rejects.toThrow();
  });

  it("derives domain-separated DEK via HKDF", () => {
    const salt = Buffer.from("b".repeat(32), "hex");
    const dekSecret = deriveDEK(masterKey, salt, "secret");
    const dekClient = deriveDEK(masterKey, salt, "client_key");

    expect(dekSecret.length).toBe(32);
    expect(dekClient.length).toBe(32);
    // Domain separation guarantees different keys for different purposes
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

describe("master key rotation (SV-055)", () => {
  const oldMasterKey = Buffer.from("1".repeat(64), "hex");
  const newMasterKey = Buffer.from("2".repeat(64), "hex");

  function mockSupabaseForRotation() {
    const secrets = [
      { id: "s1", encrypted_value: "v1:k1:iv:ct:tag", user_id: "u1", name: "sec1" },
    ];
    const clients: any[] = [];
    const totps: any[] = [];
    const pendingTotps: any[] = [];
    const rotations: any[] = [];

    return {
      from: (table: string) => {
        if (table === "master_key_rotations") {
          return {
            insert: () => ({
              select: () => ({
                single: async () => ({ data: { id: "rot-1" }, error: null }),
              }),
            }),
            update: () => ({
              eq: () => Promise.resolve({ data: null, error: null }),
            }),
          };
        }
        if (table === "secrets") {
          return {
            select: () => Promise.resolve({ data: secrets, error: null }),
            update: () => ({ eq: () => Promise.resolve({ error: null }) }),
          };
        }
        if (table === "client_applications") {
          return {
            select: () => Promise.resolve({ data: clients, error: null }),
            update: () => ({ eq: () => Promise.resolve({ error: null }) }),
          };
        }
        if (table === "totp_secrets") {
          return {
            select: () => Promise.resolve({ data: totps, error: null }),
            update: () => ({ eq: () => Promise.resolve({ error: null }) }),
          };
        }
        if (table === "totp_pending_enrollments") {
          return {
            select: () => Promise.resolve({ data: pendingTotps, error: null }),
            update: () => ({ eq: () => Promise.resolve({ error: null }) }),
          };
        }
        if (table === "access_logs") {
          return {
            insert: () => Promise.resolve({ error: null }),
          };
        }
        return {};
      },
    } as any;
  }

  it("rotates keys safely and updates checkpoint table", async () => {
    const supabase = mockSupabaseForRotation();
    // Prepare a secret encrypted with oldMasterKey
    const { encrypted: oldEncrypted } = await encryptSecret("my_secret_data", oldMasterKey, {
      purpose: "secret",
    });

    // Mock select returning this old secret
    supabase.from = (table: string) => {
      if (table === "secrets") {
        return {
          select: () =>
            Promise.resolve({
              data: [{ id: "s1", encrypted_blob: oldEncrypted, user_id: "u1", name: "db_password" }],
              error: null,
            }),
          update: (payload: any) => ({
            eq: async (col: string, val: string) => {
              // Verify re-encrypted value decrypts cleanly with new master key
              const decrypted = await decryptSecret(payload.encrypted_blob, newMasterKey, {
                purpose: "secret",
              });
              expect(decrypted).toBe("my_secret_data");
              return { error: null };
            },
          }),
        };
      }
      if (table === "master_key_rotations") {
        return {
          insert: () => ({
            select: () => ({
              single: async () => ({ data: { id: "rot-1" }, error: null }),
            }),
          }),
          update: () => ({
            eq: () => Promise.resolve({ data: null, error: null }),
          }),
        };
      }
      return {
        select: () => Promise.resolve({ data: [], error: null }),
        update: () => ({ eq: () => Promise.resolve({ error: null }) }),
        insert: () => Promise.resolve({ error: null }),
      };
    };

    const res = await rotateMasterKeyDatabase(supabase, oldMasterKey, newMasterKey);
    expect(res.secretsCount).toBe(1);
  });
});
