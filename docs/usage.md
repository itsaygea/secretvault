# SecretVault Documentation & Usage Index

SecretVault is a Bounded Egress Gateway and Secret Proxy system designed to safely inject credentials into upstream service requests while keeping raw credentials out of LLM contexts, prompt streams, and local configuration files.

---

## 📖 Documentation Index & Guides

| Guide | Description | Key Topics |
| :--- | :--- | :--- |
| 🖥️ **[CLI & Terminal Manager](cli.md)** | Terminal management & stdio execution | `secretvault`, `securevault`, `secretvault update`, `secretvault run`, `~/.secretvault/credential.json` |
| 🌐 **[Web UI & Admin Portal](webui.md)** | Browser management interface (`/ui`) | Service Profiles, Secret management, Passkey & TOTP step-up authentication, Audit logs |
| ⚡ **[MCP & AI Developer Tools](mcp.md)** | Model Context Protocol integrations | Antigravity IDE, Claude Code, Claude Desktop, OpenCode, Codex, Cursor, Streamable HTTP & SSE endpoints |
| 📦 **[SDKs & Client Libraries](sdk.md)** | App integration & script clients | `@secretvault/client`, `@secretvault/admin`, Python & Bash script credentials |
| 🛠️ **[Server Operations & Hosting](server.md)** | Server setup & deployment | Docker Compose, environment variables, health checks, master key rotation, break-glass recovery |
| 🚀 **[Self-Hosting Installation](install.md)** | Production deployment guide | PostgreSQL setup, Supabase connection, Caddy SSL termination |
| 🛡️ **[Security Architecture](security.md)** | Threat model & cipher design | AES-256-GCM authenticated encryption, HKDF key derivation, memory isolation |
| 🔧 **[Operations & Disaster Recovery](ops.md)** | Maintenance & backups | `pg_dump` database backups, HA PostgreSQL failover, container upgrades |

---

## ⚡ Quickstart Summaries

### 1. Terminal Manager CLI (`secretvault` / `securevault`)

```bash
# Launch interactive terminal manager
secretvault
# (or securevault)

# Auto-update CLI binaries
secretvault update

# Execute zero-leak stdio command
secretvault run --secret OPENAI_API_KEY -- my-command
```

For full details, see the **[CLI & Terminal Manager Guide](cli.md)**.

---

### 2. Connect Developer AI Tools

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
```

Automatically configures Antigravity IDE, Claude Code, Claude Desktop, OpenCode, Codex, and Cursor.

For full details, see the **[MCP & Developer Tools Guide](mcp.md)**.

---

### 3. Application Reverse Proxy (`@secretvault/client`)

```typescript
import { SecretVaultClient } from "@secretvault/client";

// Auto-loads ~/.secretvault/credential.json
const vault = new SecretVaultClient();

// Route requests through SecretVault proxy
const response = await vault.proxy("qbittorrent", "/api/v2/torrents/info");
```

For full details, see the **[SDKs & Client Libraries Guide](sdk.md)**.
