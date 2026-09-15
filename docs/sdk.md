# SecretVault SDKs & Client Libraries Guide

SecretVault provides client libraries and SDK packages for integrating credential proxying and programmatic management into your applications, Python scripts, and Node.js microservices.

---

## 1. Application Proxy Client (`@secretvault/client`)

For Node.js / TypeScript applications making outbound HTTP requests through SecretVault's reverse proxy:

### Installation
```bash
npm install @secretvault/client
```

### Usage
`SecretVaultClient` automatically loads your local credentials from `~/.secretvault/credential.json` if `baseUrl` and `clientKey` are omitted:

```typescript
import { SecretVaultClient } from "@secretvault/client";

// Auto-loads ~/.secretvault/credential.json
const vault = new SecretVaultClient();

// Route requests through SecretVault proxy
const response = await vault.proxy("qbittorrent", "/api/v2/torrents/info");
const data = await response.json();
```

The client exchanges the stored linking key for a short-lived, client-bound
proxy access token automatically. Proxy calls send the
`svt_1234567890abcdef...` token; the
linking key is used only for the token exchange. Set
`useProxyAccessTokens: false` only for compatibility with an older server.

---

## 2. Programmatic Admin Client (`@secretvault/admin`)

For administrative scripts and management applications:

### Installation
```bash
npm install @secretvault/admin
```

### Usage
```typescript
import { SecretVaultAdmin } from "@secretvault/admin";

const admin = new SecretVaultAdmin({
  baseUrl: "https://vault.example.com",
  sessionToken: "YOUR_ADMIN_SESSION_TOKEN",
});

const secrets = await admin.listSecrets();
```

---

## 3. Python & Bash Script Integration

For Python or Bash scripts (such as statusline scripts, cron jobs, or monitoring tools), read credentials dynamically from `~/.secretvault/credential.json` (`0600` mode) so zero tokens are hardcoded:

### Python Example
```python
import os, json, urllib.request

# Load stored local credentials
cred_file = os.path.expanduser("~/.secretvault/credential.json")
with open(cred_file) as f:
    creds = json.load(f)

vault_url = creds.get("url", "https://vault.example.com")
client_key = creds["clientKey"]

# Exchange the long-lived client key for a short-lived proxy token
exchange = urllib.request.Request(
    f"{vault_url}/v1/client/token",
    data=b"{}",
    headers={
        "Authorization": f"Bearer {client_key}",
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(exchange) as resp:
    proxy_token = json.loads(resp.read().decode())["access_token"]

# Issue request through SecretVault reverse proxy
req = urllib.request.Request(
    f"{vault_url}/proxy/example_service/v1/resource",
    headers={"Authorization": f"Bearer {proxy_token}"}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
```

### Bash & Curl Example
```bash
# Read clientKey directly from ~/.secretvault/credential.json
KEY=$(jq -r .clientKey ~/.secretvault/credential.json)
URL=$(jq -r .url ~/.secretvault/credential.json)

# Exchange it for a short-lived proxy token before making proxy requests.
TOKEN=$(curl -fsS -X POST "$URL/v1/client/token" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{}' | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" "$URL/proxy/example_service/v1/resource"
unset KEY TOKEN URL
```
