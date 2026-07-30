export type {
  Secret,
  AccessLog,
  CreateSecretInput,
  SecretVaultConfig,
  User,
} from "./types.js";

export type { Database, Json } from "./database.js";

export { maskSecret, generatePrefixSuffix } from "./masking.js";

export {
  deriveMasterKey,
  deriveDEK,
  encryptSecret,
  decryptSecret,
  envelopeVersion,
  envelopeKeyId,
  ENCRYPTION_PURPOSE,
  buildContextAad,
  MasterKeyRing,
  type EncryptOptions,
  type DecryptOptions,
  type EncryptionPurpose,
} from "./crypto.js";

export { canonicalName, extractPrefix, validateSecretName } from "./naming.js";
