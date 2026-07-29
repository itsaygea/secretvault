export type {
  Secret,
  SecretReference,
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
  generateReference,
  type EncryptOptions,
  type DecryptOptions,
} from "./crypto.js";

export { canonicalName, extractPrefix, validateSecretName } from "./naming.js";
