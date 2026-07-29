import { readFileSync, statSync } from "node:fs";

export interface KeyLoaderOptions {
  envKey?: string;
  envFile?: string;
}

/**
 * Resolves the 32-byte master key from either SECRETVAULT_MASTER_KEY or
 * SECRETVAULT_MASTER_KEY_FILE. Fails closed if both are set or format is invalid.
 */
export function resolveMasterKey(options?: KeyLoaderOptions): Buffer {
  const envKey = options?.envKey ?? process.env.SECRETVAULT_MASTER_KEY;
  const envFile = options?.envFile ?? process.env.SECRETVAULT_MASTER_KEY_FILE;

  if (envKey && envFile) {
    throw new Error(
      "Ambiguous configuration: both SECRETVAULT_MASTER_KEY and SECRETVAULT_MASTER_KEY_FILE are set. Specify exactly one.",
    );
  }

  let hex: string | undefined;

  if (envFile) {
    try {
      const stats = statSync(envFile);
      if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) {
        console.warn(
          `[keyLoader] WARNING: Master key file ${envFile} permissions are too permissive (${(stats.mode & 0o777).toString(8)}). Expected 0600.`,
        );
      }
      hex = readFileSync(envFile, "utf8").trim();
    } catch (err: any) {
      throw new Error(`Failed to read master key file from ${envFile}: ${err?.message}`);
    }
  } else if (envKey) {
    hex = envKey.trim();
  }

  if (!hex) {
    throw new Error(
      "Missing master encryption key. Set SECRETVAULT_MASTER_KEY or SECRETVAULT_MASTER_KEY_FILE.",
    );
  }

  // Validate exact 64 hex characters (32 bytes)
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      `Invalid master key format: must be exactly 32 bytes (64 hex characters), got length ${hex.length}`,
    );
  }

  return Buffer.from(hex, "hex");
}
