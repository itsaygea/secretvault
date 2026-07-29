/**
 * Masks a secret value based on its length:
 * - < 8 chars: [REDACTED]
 * - 8-16 chars: first 2 + **** + last 2 (e.g., sk****yz)
 * - 17-32 chars: first 4 + **** + last 4 (e.g., sk-p****wxyz)
 * - > 32 chars: first 6 + **** + last 4 (e.g., sk-prod****xyz)
 */
export function maskSecret(value: string): string {
  const len = value.length;

  if (len < 8) {
    return "[REDACTED]";
  } else if (len <= 16) {
    return `${value.slice(0, 2)}****${value.slice(-2)}`;
  } else if (len <= 32) {
    return `${value.slice(0, 4)}****${value.slice(-4)}`;
  } else {
    return `${value.slice(0, 6)}****${value.slice(-4)}`;
  }
}

/**
 * Generates prefix and suffix strings for a secret value using the same
 * length-based rules as maskSecret.
 */
export function generatePrefixSuffix(
  value: string,
): { prefix: string; suffix: string } {
  const len = value.length;

  if (len < 8) {
    return { prefix: "", suffix: "" };
  } else if (len <= 16) {
    return { prefix: value.slice(0, 2), suffix: value.slice(-2) };
  } else if (len <= 32) {
    return { prefix: value.slice(0, 4), suffix: value.slice(-4) };
  } else {
    return { prefix: value.slice(0, 6), suffix: value.slice(-4) };
  }
}
