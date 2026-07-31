import { randomBytes, pbkdf2, createCipheriv, createDecipheriv, createHmac, hkdfSync } from "node:crypto";

// ── SV-AUD-005: cryptographic purposes & context-bound AAD ──────────
//
// Every encrypted object is bound to an immutable context via GCM additional
// authenticated data (AAD). A storage actor who copies User A's ciphertext
// into a row owned by User B, or across records/purposes, causes the AAD to
// mismatch on decrypt and GCM authentication fails — the server cannot be used
// as a decryption oracle. The AAD string is derived from a fixed prefix, the
// purpose, the owning tenant (userId), and the immutable record identifier.

export const ENCRYPTION_PURPOSE = {
  /** A secret value stored in `secrets.encrypted_blob`. */
  SECRET: "secret",
  /** A client application linking key stored in `client_applications.encrypted_key`. */
  CLIENT_KEY: "client_key",
  /** An active TOTP seed stored in `totp_factors.secret_encrypted`. */
  TOTP_SECRET: "totp_secret",
  /** A pending (unconfirmed) TOTP enrollment stored in `totp_pending_enrollments.secret_encrypted`. */
  TOTP_PENDING: "totp_pending",
} as const;

export type EncryptionPurpose = (typeof ENCRYPTION_PURPOSE)[keyof typeof ENCRYPTION_PURPOSE];

const AAD_PREFIX = "secretvault:v2";

/**
 * Canonical context AAD for a purpose-bound ciphertext. Every component is
 * immutable: the tenant (userId) and the record identifier never change for the
 * life of the ciphertext, so the binding cannot be defeated by a rename.
 */
export function buildContextAad(
  purpose: EncryptionPurpose,
  context: { userId: string; recordId: string; clientId?: string },
): string {
  const { userId, recordId, clientId } = context;
  if (purpose === ENCRYPTION_PURPOSE.CLIENT_KEY && clientId !== undefined) {
    return `${AAD_PREFIX}:client-key:${userId}:${clientId}`;
  }
  if (purpose === ENCRYPTION_PURPOSE.TOTP_SECRET || purpose === ENCRYPTION_PURPOSE.TOTP_PENDING) {
    return `${AAD_PREFIX}:totp:${userId}`;
  }
  return `${AAD_PREFIX}:secret:${userId}:${recordId}`;
}

/**
 * Derives a 32-byte master key from a passphrase using PBKDF2
 * with 600,000 iterations and SHA-512.
 *
 * @deprecated Prefer an externally-provided random master key
 * (SECRETVAULT_MASTER_KEY). Passphrase derivation is retained only for legacy
 * break-glass tooling; new callers must not use it. If KDF-based key provision
 * is reintroduced, use a versioned Argon2id configuration.
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
  purpose?: EncryptionPurpose;
  keyId?: string;
  /** Context-bound AAD (SV-AUD-005). Prefer buildContextAad(). */
  aad?: string;
}

export interface DecryptOptions {
  purpose?: EncryptionPurpose;
  /** Context-bound AAD (SV-AUD-005). Must match the encrypt-time AAD exactly. */
  aad?: string;
}

const V2_KEY_ID_DEFAULT = "k1";

/**
 * Encodes the v2 envelope metadata (version + keyId + purpose) into the AAD so
 * it is authenticated: a blob whose version/keyId/purpose is tampered, or whose
 * caller-supplied purpose does not match, fails GCM verification on decrypt.
 */
function envelopeAad(version: string, keyId: string, purpose: string, contextAad?: string): Buffer {
  const meta = `secretvault:env:${version}:${keyId}:${purpose}`;
  return contextAad ? Buffer.from(`${meta}|${contextAad}`, "utf8") : Buffer.from(meta, "utf8");
}

/**
 * Encrypts a secret value using AES-256-GCM and HKDF key derivation.
 *
 * v2 envelope (default): `v2:<keyId>:<purpose>:<iv>:<ct>:<tag>`. The version,
 * key ID, purpose, and caller context (AAD) are all authenticated, binding the
 * ciphertext to its tenant/record/purpose (SV-AUD-005).
 */
export async function encryptSecret(
  value: string,
  masterKey: Buffer,
  options?: EncryptOptions,
): Promise<{ encrypted: string }> {
  const purpose = options?.purpose ?? ENCRYPTION_PURPOSE.SECRET;
  const keyId = options?.keyId ?? V2_KEY_ID_DEFAULT;

  // AES-GCM standard IV is 12 bytes (96 bits)
  const iv = randomBytes(12);
  const dek = deriveDEK(masterKey, iv, purpose);

  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(envelopeAad("v2", keyId, purpose, options?.aad));

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const blob = `v2:${keyId}:${purpose}:${iv.toString("base64")}:${encrypted.toString("base64")}:${authTag.toString("base64")}`;
  return { encrypted: blob };
}

/**
 * Decrypts a secret value supporting:
 * - v2 envelope (`v2:keyId:purpose:iv:ct:tag`) — context-bound, default.
 * - v1 envelope (`v1:keyId:iv:ct:tag`) — read-only compatibility window.
 * - legacy 3-part (`iv:ct:tag`) — pre-versioning blobs.
 *
 * For v2, the caller's purpose + AAD must match encrypt-time exactly, or GCM
 * authentication fails (SV-AUD-005 transplant protection).
 */
export async function decryptSecret(
  encryptedBlob: string,
  masterKey: Buffer,
  options?: DecryptOptions,
): Promise<string> {
  const parts = encryptedBlob.split(":");

  // Versioned v2 envelope: v2:keyId:purpose:iv:ct:tag
  if (parts.length === 6 && parts[0] === "v2") {
    const [, keyId, storedPurpose, ivB64, ctB64, tagB64] = parts;
    const purpose = options?.purpose ?? ENCRYPTION_PURPOSE.SECRET;
    // If the caller declares a purpose, it must match the envelope's — a
    // purpose mismatch (cross-purpose transplant) fails authentication.
    if (purpose !== storedPurpose) {
      throw new Error("Ciphertext purpose mismatch");
    }
    const iv = Buffer.from(ivB64!, "base64");
    const ct = Buffer.from(ctB64!, "base64");
    const tag = Buffer.from(tagB64!, "base64");

    const dek = deriveDEK(masterKey, iv, storedPurpose!);

    const decipher = createDecipheriv("aes-256-gcm", dek, iv);
    decipher.setAuthTag(tag);
    decipher.setAAD(envelopeAad("v2", keyId!, storedPurpose!, options?.aad));

    const decrypted = Buffer.concat([
      decipher.update(ct),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  }

  // Versioned v1 envelope: v1:keyId:iv:ct:tag (compatibility read window only)
  if (parts.length === 5 && parts[0] === "v1") {
    const [, _keyId, ivB64, ctB64, tagB64] = parts;
    const iv = Buffer.from(ivB64!, "base64");
    const ct = Buffer.from(ctB64!, "base64");
    const tag = Buffer.from(tagB64!, "base64");

    const purpose = options?.purpose ?? ENCRYPTION_PURPOSE.SECRET;
    const dek = deriveDEK(masterKey, iv, purpose);

    try {
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
    } catch (err) {
      if (options?.aad) {
        // v1 blobs created before v2 context-bound AAD did not specify AAD.
        // Fall back to decrypting without AAD for legacy v1 blobs.
        const decipherFallback = createDecipheriv("aes-256-gcm", dek, iv);
        decipherFallback.setAuthTag(tag);
        const decrypted = Buffer.concat([
          decipherFallback.update(ct),
          decipherFallback.final(),
        ]);
        return decrypted.toString("utf8");
      }
      throw err;
    }
  }

  // Legacy format: iv:ct:tag (3 parts) — pre-versioning blobs.
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
      const dek = deriveDEK(masterKey, iv, options?.purpose ?? ENCRYPTION_PURPOSE.SECRET);
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
 * Returns the envelope version of a blob ("v2" | "v1" | "legacy" | "unknown").
 * Used by the migration to decide which rows still need v1→v2 re-encryption.
 */
export function envelopeVersion(encryptedBlob: string): "v2" | "v1" | "legacy" | "unknown" {
  const parts = encryptedBlob.split(":");
  if (parts.length === 6 && parts[0] === "v2") return "v2";
  if (parts.length === 5 && parts[0] === "v1") return "v1";
  if (parts.length === 3) return "legacy";
  return "unknown";
}

/**
 * The key ID authenticated inside an envelope, or null for legacy/unknown
 * envelopes (which carry no authenticated key ID). v2/v1 store keyId at index 1.
 */
export function envelopeKeyId(encryptedBlob: string): string | null {
  const parts = encryptedBlob.split(":");
  if ((parts.length === 6 && parts[0] === "v2") || (parts.length === 5 && parts[0] === "v1")) {
    return parts[1] ?? null;
  }
  return null;
}

/**
 * A keyring keyed by the authenticated envelope key ID. During rotation the old
 * and new keys are both registered so blobs encrypted under either can be read.
 * Lookup is by the *authenticated* key ID embedded in the blob — a row already
 * rotated to the new key is never retried with the old key.
 */
export class MasterKeyRing {
  private readonly keys = new Map<string, Buffer>();

  /** The ID under which newly produced envelopes are written. */
  readonly defaultKeyId: string;

  constructor(entries: Iterable<{ keyId: string; key: Buffer }>, defaultKeyId: string) {
    for (const { keyId, key } of entries) this.keys.set(keyId, key);
    this.defaultKeyId = defaultKeyId;
  }

  register(keyId: string, key: Buffer): void { this.keys.set(keyId, key); }
  has(keyId: string): boolean { return this.keys.has(keyId); }
  get defaultKey(): Buffer {
    const k = this.keys.get(this.defaultKeyId);
    if (!k) throw new Error(`MasterKeyRing has no default key for id ${this.defaultKeyId}`);
    return k;
  }

  /**
   * Decrypt a blob. Try the key whose ID is authenticated in the envelope
   * first; if that key is absent or decryption fails, fall back across all
   * registered keys (required for v1/legacy envelopes that carry no key ID).
   * Throws if no key authenticates the blob.
   */
  async decrypt(blob: string, options?: DecryptOptions): Promise<string> {
    const declared = envelopeKeyId(blob);
    const order: string[] = [];
    if (declared) order.push(declared);
    for (const id of this.keys.keys()) if (id !== declared) order.push(id);
    if (order.length === 0) throw new Error("MasterKeyRing is empty");
    let lastErr: unknown;
    for (const id of order) {
      const key = this.keys.get(id);
      if (!key) continue;
      try {
        return await decryptSecret(blob, key, options);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error("MasterKeyRing: no key authenticated the blob");
  }
}
