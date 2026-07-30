# SecretVault Integration & Usage Guide

This guide covers connecting Claude Code / Desktop via Model Context Protocol (MCP), integrating applications using `@secretvault/client` and `@secretvault/admin`, and managing secrets through the Web UI.

## HTTP Contract

Management and metadata endpoints are versioned under `/v1`. The checked-in [OpenAPI 3.1 document](openapi.json) is also served at `/docs/openapi.json`, and `GET /v1/version` reports the supported API version and contract locations. The previous `/api/...` paths remain temporary compatibility aliases and return a `Deprecation: true` response header with a successor link.

SecretVault-generated REST and proxy errors use this envelope:

```json
{
  "error": {
    "code": "PROFILE_NOT_FOUND",
    "message": "Service profile not found",
    "requestId": "8f6c8d12-...",
    "status": 404
  }
}
```

The `X-Request-ID` response header carries the same correlation ID. Clients may send a safe `X-Request-ID` value; invalid values are replaced with a generated ID.

---

## 1. Automated Client Tool Setup (`secretvault-mcp setup`)

Instead of manually editing config files, you can auto-detect and configure your local developer tools (**Antigravity IDE**, **Claude Code CLI**, **Claude Desktop**, **OpenCode**, and **Codex**) using the interactive setup wizard:

```bash
# Automated 1-liner execution:
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash

# Or via package runner:
npx @secretvault/mcp-server setup
```

The wizard will:
1. Detect installed developer AI tools on your system.
2. Prompt for your SecretVault Server URL and Client Key (`sv_...`).
3. Allow logging in as Admin (+ TOTP 2FA) over SSH to auto-provision a new client key on the server.
4. Safely inject formatted `secretvault` MCP configuration blocks without overwriting your existing MCP tools.

---

## 2. Terminal Secret Manager CLI (`secretvault-mcp secret`)

Manage secrets directly from your terminal over SSH without opening the Web UI:

```bash
# List secrets (canonical name, display name, masked preview, tags)
npx @secretvault/mcp-server secret list --url http://localhost:3004 --key sv_...

# Add a new secret (hidden input prompt for value)
npx @secretvault/mcp-server secret create

# Rotate an existing secret value
npx @secretvault/mcp-server secret rotate

# Delete a secret
npx @secretvault/mcp-server secret delete
```

---

## 3. Connecting Claude Code / Claude Desktop via MCP

SecretVault provides a native Model Context Protocol (MCP) server supporting **Streamable HTTP** (`/mcp`) and **SSE** (`/sse`).

MCP authentication is header-only. Use a linking key with `mcp:read` and `secrets:metadata:read` for metadata tools; write tools additionally require `mcp:write` and `secrets:write`. Query-string keys are rejected because URLs leak into logs and browser history.

> [!IMPORTANT]
> **Bounded Egress Gateway Security Model**
> SecretVault MCP tools do not provide plaintext secret retrieval endpoints to AI agents. Agents receive masked previews (e.g. `sk-live-***1234`). Plaintext secret retrieval via standard MCP metadata tokens (`mcp:read`) is strictly forbidden. Subprocess environment injection requires dedicated, secret-specific runner capability grants (`runner:secret:<name>`). Actual credentials are injected server-side into approved outbound requests by the reverse proxy. Upstream response bodies reside within the upstream service's trust boundary.

### Claude Code CLI Registration

To add SecretVault to Claude Code manually, run:

```bash
claude mcp add secretvault http://your-vault-host:3004/mcp \
  --header "Authorization: Bearer sv_your_linking_key"
```

### Available MCP Tools

Once connected, Claude can use the following tools:

- `list_secrets`: List stored secrets for your user (masked previews only).
- `search_secrets`: Search secrets by keyword or tag.
- `get_secret_reference`: Retrieve reference tokens & proxy usage code examples.
- `create_secret`: Store a new secret (encrypted on server before writing to DB).
- `rotate_secret`: Update an existing secret value.
- `delete_secret`: Delete a secret permanently.

---

## 2. Application & Agent Integration (`@secretvault/client`)

Applications and AI agents access services through the credential proxy using the proxy-only `@secretvault/client`. Use `@secretvault/admin` separately for management operations.

The proxy remains intentionally separate from the versioned management API at `/proxy/<profile>/<path>`. The profile controls the upstream origin, credential injection, allowed methods, and path prefixes. Query parameters pass through as query data. Outbound requests apply a complete hop-by-hop header policy: caller credentials, framing, routing, and forwarding headers are stripped, along with every field nominated by a caller-supplied `Connection` header. Service-profile `header_name` and `cookie_name` are validated against the HTTP field-name / cookie token grammars and may not name a reserved hop-by-hop, framing, routing, or credential header. Upstream response bodies are opaque and are not claimed to be sanitized; upstream responses additionally drop the complete hop-by-hop set and credential headers before returning to the caller. Malformed percent-encoded path segments receive a stable `400` error and never escape the request handler. SecretVault-generated proxy failures use the error envelope above, while upstream responses retain their upstream status and body semantics.

### Installation

```bash
npm install @secretvault/client @secretvault/admin
```

### Proxy Client Usage (`proxy`)

Instead of fetching raw secret values, your application routes HTTP requests through SecretVault's reverse proxy using `proxy`:

```typescript
import { SecretVaultClient } from "@secretvault/client";

const vault = new SecretVaultClient({
  baseUrl: "https://your-vault-host",
  clientKey: "sv_your_linking_key", // Generated in Web UI
});

// Sends request through SecretVault proxy; credentials injected server-side
const response = await vault.proxy("qbittorrent", "/api/v2/torrents/info", {
  signal: AbortSignal.timeout(10_000),
});
const torrents = await response.json();
```

For local development over plain HTTP, set `allowInsecureHttp: true` explicitly. The client validates HTTPS, service-profile names, and proxy paths by default. `vault.health()` and `vault.capabilities()` expose operational health and the versioned protocol metadata.

Management and administration operations require user/admin session credentials, using `@secretvault/admin`:

```typescript
import { SecretVaultAdmin } from "@secretvault/admin";

// Option A: Authenticate as user/administrator using username & password
const admin = await SecretVaultAdmin.login(
  { baseUrl: "https://your-vault-host" },
  { username: "admin", password: "your_password" }
);

// Option B: Initialize with an existing user session token or linking key
const client = new SecretVaultAdmin({
  baseUrl: "https://your-vault-host",
  sessionToken: "session_token_from_login", // or clientKey: "sv_..."
});

const profiles = await admin.listProfiles();
const users = await admin.listUsers();
```

---

## 3. Configuring Service Profiles in Web UI

Service Profiles define how SecretVault injects credentials when proxying requests to upstream services.

1. Open Web UI (`http://your-vault-host:3004/ui`) and navigate to **Service Profiles**.
2. Click **Create Service Profile**.
3. Configure target options:
   - **Profile Name**: e.g. `qbittorrent`, `openai`, `github`
   - **Target Upstream URL**: e.g. `https://api.example.com`; HTTPS is required by default. Non-admin users may register only origins in `SECRETVAULT_EGRESS_ALLOWLIST`; private-network HTTP targets require the explicit administrator-controlled private-network option.
   - **Auth Type**:
     - `bearer`: Injects `Authorization: Bearer <decrypted_secret>`
     - `basic`: Injects `Authorization: Basic <base64(user:pass)>`
     - `header`: Injects custom header (e.g. `X-API-Key: <decrypted_secret>`)
     - `cookie`: Injects custom authentication cookie
   - **Secret Name Mapping**: Select secret canonical names (e.g. `QBITTORRENT_PASS`).
   - **Proxy Policy**: API-created profiles may set `allowed_methods` and `allowed_path_prefixes`; requests outside those constraints are rejected. Private-network mode is administrator-controlled.

---

---

## 4. MCP Server Integrations (Zero-Leak Stdio & Reverse Proxy)

SecretVault provides two zero-leak integration patterns for Model Context Protocol (MCP) servers:

### Pattern A: Reverse-Proxy Remote HTTP MCP Servers

For remote HTTP/SSE MCP servers (e.g., `https://api.example.com/mcp/tool` requiring `Authorization: Bearer <API_KEY>`):

1. **Create Service Profile**: In Web UI, create a profile `example-service` with Target URL `https://api.example.com` and Auth Type `Bearer Token` mapped to secret `EXAMPLE_API_KEY`.
2. **Configure MCP JSON**: Point the URL to SecretVault's proxy endpoint (`/proxy/example-service/...`) and pass your linking key (`sv_...`):

```json
"example-remote-mcp": {
  "type": "http",
  "url": "https://vault.example.com/proxy/example-service/mcp/tool",
  "headers": {
    "Authorization": "Bearer sv_YOUR_LINKING_KEY"
  }
}
```
*The real API key is injected server-side by SecretVault and never exists on the local client machine.*

### Pattern B: Stdio MCP Servers via CLI Runner (`secretvault run`)

For third-party stdio MCP servers running locally via CLI (e.g., `@example/mcp-server`):

The CLI runner fetches the requested secret directly from SecretVault into system RAM when the process boots, injecting it into `process.env` without writing plaintext secrets to disk:

```json
"example-stdio-mcp": {
  "command": "secretvault",
  "args": [
    "run",
    "--secret", "EXAMPLE_API_KEY",
    "--",
    "npx", "-y", "@example/mcp-server"
  ],
  "env": {
    "SECRETVAULT_URL": "https://vault.example.com",
    "SECRETVAULT_CLIENT_KEY": "sv_YOUR_LINKING_KEY"
  }
}
```

### Security Guarantees
- 🔒 **Zero Plaintext Secrets on Disk**: Config files stored on disk contain only `SECRETVAULT_CLIENT_KEY` (`sv_...`).
- 🧠 **RAM-Only Secret Lifecycle**: Decrypted secrets reside exclusively in process RAM during execution.
- 🛡️ **No Arg Leakage**: Secrets are injected via environment variables (`process.env`), preventing exposure in `ps` or `/proc/<pid>/cmdline`.

---

## 5. SDK Deprecation Notice

> [!NOTE]
> **Legacy package deprecation**
> `@secretvault/bridge` remains only as a proxy compatibility adapter, and `@secretvault/sdk` is a migration alias. New integrations should use `@secretvault/client` for proxying and `@secretvault/admin` for management with scoped linking keys (`sv_...`).
