import { readFileSync, statSync } from "node:fs";

export interface KeyLoaderOptions {
  envKey?: string;
  envFile?: string;
  /** Override the production check (tests). Defaults to NODE_ENV === "production". */
  production?: boolean;
}

/**
 * Resolves the 32-byte master key from either SECRETVAULT_MASTER_KEY or
 * SECRETVAULT_MASTER_KEY_FILE. Fails closed if both are set or format is invalid.
 *
 * Per SV-AUD-014 (informational): in production a key file with group/world
 * permissions is refused outright rather than merely warned about. A warning
 * still suffices in development; set SECRETVAULT_ALLOW_PERMISSIVE_KEY_FILE=1 to
 * keep the lenient behavior in production for a break-glass operator workflow.
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
        const modeOctal = (stats.mode & 0o777).toString(8);
        const isProduction = options?.production ?? process.env.NODE_ENV === "production";
        const allowPermissive = process.env.SECRETVAULT_ALLOW_PERMISSIVE_KEY_FILE === "1";
        if (isProduction && !allowPermissive) {
          // SV-AUD-014: fail closed — do not load a key from a world/group-readable file.
          throw new Error(
            `Refusing to read master key file ${envFile}: permissions too permissive (got ${modeOctal}, expected 0600). Restrict the file mode, or set SECRETVAULT_ALLOW_PERMISSIVE_KEY_FILE=1 to override.`,
          );
        }
        console.warn(
          `[keyLoader] WARNING: Master key file ${envFile} permissions are too permissive (${modeOctal}). Expected 0600.`,
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
