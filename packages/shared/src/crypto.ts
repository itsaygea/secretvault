import { randomBytes, pbkdf2, createCipheriv, createDecipheriv, createHmac, hkdfSync } from "node:crypto";

/**
 * Derives a 32-byte master key from a passphrase using PBKDF2
 * with 600,000 iterations and SHA-512.
 */
export async function deriveMasterKey(
  passphrase: string,
  salt: Buffer,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    pbkdf2(passphrase, salt, 600_000, 32, "sha512", (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Derives a 32-byte Data Encryption Key (DEK) using HKDF-SHA256
 * with an explicit domain-separation purpose context string.
 */
export function deriveDEK(
  masterKey: Buffer,
  salt: Buffer,
  purpose: string = "secret",
): Buffer {
  const info = Buffer.from(`secretvault:dek:v1:${purpose}`, "utf8");
  return Buffer.from(hkdfSync("sha256", masterKey, salt, info, 32));
}

export interface EncryptOptions {
  purpose?: string;
  keyId?: string;
  aad?: string;
}

export interface DecryptOptions {
  purpose?: string;
  aad?: string;
}

/**
 * Encrypts a secret value using AES-256-GCM and HKDF key derivation.
 * Returns a versioned base64/ASCII string: "v1:key_id:iv:ciphertext:authTag".
 */
export async function encryptSecret(
  value: string,
  masterKey: Buffer,
  options?: EncryptOptions,
): Promise<{ encrypted: string }> {
  const purpose = options?.purpose ?? "secret";
  const keyId = options?.keyId ?? "k1";

  // AES-GCM standard IV is 12 bytes (96 bits)
  const iv = randomBytes(12);
  const dek = deriveDEK(masterKey, iv, purpose);

  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  if (options?.aad) {
    cipher.setAAD(Buffer.from(options.aad, "utf8"));
  }

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const blob = `v1:${keyId}:${iv.toString("base64")}:${encrypted.toString("base64")}:${authTag.toString("base64")}`;
  return { encrypted: blob };
}

/**
 * Decrypts a secret value supporting both v1 envelope ("v1:key_id:iv:ct:tag")
 * and legacy 3-part ("iv:ct:tag") formats.
 */
export async function decryptSecret(
  encryptedBlob: string,
  masterKey: Buffer,
  options?: DecryptOptions,
): Promise<string> {
  const parts = encryptedBlob.split(":");

  // Versioned v1 envelope: v1:keyId:iv:ct:tag
  if (parts.length === 5 && parts[0] === "v1") {
    const [, _keyId, ivB64, ctB64, tagB64] = parts;
    const iv = Buffer.from(ivB64!, "base64");
    const ct = Buffer.from(ctB64!, "base64");
    const tag = Buffer.from(tagB64!, "base64");

    const purpose = options?.purpose ?? "secret";
    const dek = deriveDEK(masterKey, iv, purpose);

    const decipher = createDecipheriv("aes-256-gcm", dek, iv);
    decipher.setAuthTag(tag);
    if (options?.aad) {
      decipher.setAAD(Buffer.from(options.aad, "utf8"));
    }

    const decrypted = Buffer.concat([
      decipher.update(ct),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  }

  // Legacy format: iv:ct:tag (3 parts)
  if (parts.length === 3) {
    const [ivB64, ctB64, tagB64] = parts;
    const iv = Buffer.from(ivB64!, "base64");
    const ct = Buffer.from(ctB64!, "base64");
    const tag = Buffer.from(tagB64!, "base64");

    // First try direct masterKey (legacy pre-HKDF implementation)
    try {
      const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([
        decipher.update(ct),
        decipher.final(),
      ]);
      return decrypted.toString("utf8");
    } catch {
      // Fall back to legacy HKDF attempt
      const dek = deriveDEK(masterKey, iv, options?.purpose ?? "secret");
      const decipher = createDecipheriv("aes-256-gcm", dek, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([
        decipher.update(ct),
        decipher.final(),
      ]);
      return decrypted.toString("utf8");
    }
  }

  throw new Error("Invalid ciphertext envelope format");
}

/**
 * Generates a reference token for a secret that is both opaque and
 * name-derived. The secretName is HMAC'd into the token so references
 * are verifiable against the name that created them.
 */
export function generateReference(secretName: string): string {
  const nonce = randomBytes(8).toString("hex");
  const sig = createHmac("sha256", Buffer.from(nonce, "hex"))
    .update(secretName)
    .digest("hex")
    .slice(0, 16);
  return `ref:${nonce}${sig}`;
}
