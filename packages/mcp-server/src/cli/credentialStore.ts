import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface StoredClientCredentials {
  url?: string;
  clientKey?: string;
}

export function getSecretVaultDir(): string {
  return path.join(os.homedir(), ".secretvault");
}

export function getCredentialPath(): string {
  return path.join(getSecretVaultDir(), "credential.json");
}

/**
 * SV-AUD-007 / SV-AUD-012: Save client credentials to a secure 0600 file.
 * The file resides in ~/.secretvault/credential.json and is written atomically.
 */
export function saveClientCredentials(url: string, clientKey: string): void {
  const dir = getSecretVaultDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const payload: StoredClientCredentials = {
    url: url.trim(),
    clientKey: clientKey.trim(),
  };

  const jsonContent = JSON.stringify(payload, null, 2);
  const targetPath = getCredentialPath();
  const tmpPath = `${targetPath}.tmp.${Date.now()}`;

  fs.writeFileSync(tmpPath, jsonContent, { mode: 0o600, encoding: "utf8" });
  fs.renameSync(tmpPath, targetPath);
  try {
    if (process.platform !== "win32") {
      fs.chmodSync(targetPath, 0o600);
    }
  } catch {
    /* best effort */
  }
}

/**
 * Load default client credentials from ~/.secretvault/credential.json.
 * Returns null if the file does not exist or contains invalid JSON.
 */
export function loadClientCredentials(): StoredClientCredentials | null {
  const targetPath = getCredentialPath();
  if (!fs.existsSync(targetPath)) {
    // Also check for legacy mcp-credential.key file created by older launchers
    const legacyKeyPath = path.join(getSecretVaultDir(), "mcp-credential.key");
    if (fs.existsSync(legacyKeyPath)) {
      try {
        const key = fs.readFileSync(legacyKeyPath, "utf8").trim();
        if (key) {
          return { clientKey: key };
        }
      } catch {
        /* ignore read error */
      }
    }
    return null;
  }

  try {
    const raw = fs.readFileSync(targetPath, "utf8");
    const data = JSON.parse(raw) as Record<string, unknown>;
    const url = typeof data.url === "string" ? data.url.trim() : undefined;
    const clientKey = typeof data.clientKey === "string"
      ? data.clientKey.trim()
      : typeof data.client_key === "string"
        ? data.client_key.trim()
        : undefined;

    if (!url && !clientKey) return null;
    return { url, clientKey };
  } catch {
    return null;
  }
}
