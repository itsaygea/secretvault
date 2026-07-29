/**
 * Defense-in-depth: scans stringified responses for patterns that look like
 * leaked API keys. If detected, logs a CRITICAL warning to stderr and strips
 * the suspicious content.
 */

const SUSPICIOUS_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/g,
  /key_[a-zA-Z0-9]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[a-zA-Z0-9]{36}/g,
  /glpat-[a-zA-Z0-9\-]{20,}/g,
  /xox[bpsa]-[a-zA-Z0-9\-]{10,}/g,
  /-----BEGIN[A-Z ]*PRIVATE KEY-----/g,
  /:[/][/][^/\s"']+:[^/\s"']+@/g,
];

export function safeResponse(data: unknown): string {
  let json = JSON.stringify(data, null, 2);

  for (const pattern of SUSPICIOUS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(json)) {
      console.error(
        `[CRITICAL] Potential secret leak detected in response! Stripping suspicious content.`,
      );
      pattern.lastIndex = 0;
      json = json.replace(pattern, "[REDACTED_BY_SAFETY]");
    }
  }

  return json;
}
