/**
 * @deprecated Use @secretvault/client for proxy access and @secretvault/admin
 * for management operations. This package remains as a migration alias.
 *
 * @deprecated Will be removed in v2.0. Migrate to @secretvault/client and
 * @secretvault/admin individually.
 */
console.warn(
  "[deprecation] @secretvault/sdk is deprecated. Use @secretvault/client and @secretvault/admin directly. " +
  "See https://github.com/itsaygea/secretvault for migration guide."
);

export * from "@secretvault/admin";
export * from "@secretvault/client";
export { SecretVaultAdmin as SecretVaultSDK } from "@secretvault/admin";
