const SECRET_NAME_RE = /^[a-zA-Z0-9_-]{1,128}$/;

/**
 * Converts a secret name to its canonical lowercase form.
 * All storage and lookups use this canonical form.
 */
export function canonicalName(name: string): string {
  return name.toLowerCase();
}

/**
 * Extracts the prefix from a canonical secret name (everything before the first _).
 * Example: "qbittorrent_user" → "qbittorrent"
 */
export function extractPrefix(canonicalName: string): string {
  const idx = canonicalName.indexOf("_");
  return idx > 0 ? canonicalName.substring(0, idx) : canonicalName;
}

/**
 * Validates that a secret name matches the allowed pattern.
 * Accepts mixed case input — canonicalize before storing/querying.
 */
export function validateSecretName(name: string): void {
  if (!SECRET_NAME_RE.test(name)) {
    throw new Error(
      `Invalid secret name '${name}'. Names must be 1-128 characters, matching /^[a-zA-Z0-9_-]{1,128}$/`,
    );
  }
}
