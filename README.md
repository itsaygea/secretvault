# SecretVault

> **Bounded Egress Gateway & Secret Proxy for AI Agents and Applications.**
> Safely inject credentials into approved upstream requests while keeping raw credentials out of LLM agent prompt contexts.

---

## Why SecretVault?

Traditional secret managers return raw plaintext API keys and database passwords to applications. When AI agents (such as Claude Code or custom LLM tools) handle raw secret values, those secrets inevitably leak into LLM context streams, prompt logs, and telemetry data.

**SecretVault enforces a Bounded Egress Gateway Model:**

- 🛡️ **Bounded Egress Gateway Claim**: MCP tools, agent SDKs, and REST API calls cannot retrieve raw secret plaintexts. AI agents receive masked previews (`sk-live-***1234`) or proxy reference tokens (`sv://...`).
- 🔄 **Server-Side Credential Proxy**: Agents route requests through SecretVault's reverse proxy (`/proxy/:service/*`), which decrypts and injects real credentials server-side directly into outbound HTTP headers.
- 🌐 **Upstream Response Trust Boundary**: SecretVault injects credentials into outbound requests, but response bodies returned by third-party services reside within the upstream service's trust boundary. Current mitigations include HTTPS-by-default destinations, private-network rejection, and canonical origin validation; transparent response-body sanitization and universal path/method policy are not claimed.
- 🔑 **AES-256-GCM Encryption**: All secrets are encrypted locally using AES-256-GCM before being saved to Supabase/PostgreSQL.
- 🔐 **Human-Only Step-Up Auth**: High-risk Web UI operations (such as revealing raw secrets to human operators) require hardware WebAuthn Passkeys or TOTP 2FA assertion.

---

## Architecture Diagram

```mermaid
graph TD
    User["👤 Human Operator (Browser Web UI)"] -->|"Step-Up Auth (Passkey/TOTP)"| WebUI["🌐 SecretVault Web UI (/ui)"]
    Claude["🤖 Claude Code / AI Agent"] -->|"Streamable HTTP / SSE"| MCP["⚡ SecretVault MCP Server (:3004)"]
    App["💻 Application / Agent Code"] -->|"proxy() with sv_... key"| Proxy["🔒 Credential Proxy (/proxy/*)"]

    MCP -->|"Masked Previews / References"| Claude
    Proxy -->|"Inject Decrypted Credential"| Upstream["☁️ Upstream Service (GitHub, OpenAI, etc.)"]

    WebUI -->|"Encrypted Blobs"| DB[("🗄️ Supabase PostgreSQL")]
    MCP -->|"Encrypted Blobs"| DB
    Proxy -->|"Read Encrypted Secret"| DB
```

---

---

## Quickstart & Setup

Connecting to SecretVault requires two sequential steps: **Deploying the SecretVault Server** (core infrastructure), followed by **Configuring Developer AI Tools** (connecting Antigravity IDE, Claude Code, etc.).

---

### Step 1: Deploy SecretVault Server (Required First)

Deploy the core SecretVault server (AES-256-GCM proxy + Web UI + MCP engine).

#### Option 1A: 1-Line Server Installer (Recommended)

Interactive installer that configures database connections, generates encryption keys, and provisions Docker Compose:

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
```

#### Option 1B: Manual Docker Compose Deployment

```bash
# 1. Clone repository & enter directory
git clone https://github.com/itsaygea/secretvault.git
cd secretvault

# 2. Prepare environment configuration
cp .env.example .env

# 3. Generate 32-byte master key & edit .env
openssl rand -hex 32
nano .env # Paste master key and database connection parameters

# 4. Restrict file permissions & launch stack
chmod 600 .env
docker compose up -d

# 5. Verify health check & access Web UI
curl http://localhost:3004/health/ready
# Open http://localhost:3004/ui in browser
```

---

### Step 2: Connect Developer AI Tools & Clients

Once your SecretVault server is running, connect your AI developer tools (**Antigravity IDE**, **Claude Code**, **Claude Desktop**, **OpenCode**, **Codex**):

#### Option 2A: Interactive Developer Client Setup Wizard

Automatically provisions linking keys and configures MCP settings across all detected developer tools:

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
```

*(Or launch directly via npx: `npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp setup`).*

#### Option 2B: Terminal Secret Manager CLI

Manage secrets directly from your terminal or SSH shell:

```bash
# Setup developer tool integrations
npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp setup

# Manage secrets via CLI
npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp secret list
npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp secret create
npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp secret rotate
npx --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp secret delete
```

> 📖 **Full Installation Guide**: See **[docs/install.md](docs/install.md)** for detailed server options, PostgreSQL migrations, and Caddy HTTPS setup.

---

## Documentation Index

- 🚀 **[Self-Host & Installation Guide](docs/install.md)** — Step-by-step AFFiNE-style Docker Compose deployment guide.
- 💻 **[Usage & Developer Integration Guide](docs/usage.md)** — Connecting Claude Code / Desktop MCP, using `@secretvault/client` and `@secretvault/admin`, and setting up Service Profiles.
- 📜 **[Versioned HTTP Contract](docs/openapi.json)** — OpenAPI 3.1 management/metadata schema and proxy contract surface.
- 🛡️ **[Security Architecture & Threat Model](docs/security.md)** — AES-256-GCM cipher details, Docker Secrets RAM-mount, and Passkey/TOTP step-up auth.
- 🔧 **[Operations & Troubleshooting](docs/ops.md)** — Database backups (`pg_dump`), disaster recovery, container upgrades, and break-glass CLI tools.

---

## Monorepo Layout

```
secretvault/
├── packages/
│   ├── shared/          # Crypto (AES-256-GCM), masking, types, naming helpers
│   ├── mcp-server/      # MCP server + REST API + Web UI + Proxy
│   ├── client/          # Proxy-only application client (@secretvault/client)
│   ├── admin/           # Management client (@secretvault/admin)
│   ├── bridge/          # Deprecated proxy compatibility adapter
│   └── sdk/             # Deprecated migration alias
├── supabase/migrations/ # PostgreSQL schema migrations (001 - 011)
├── docs/                # Public user guides (install, usage, security, ops)
├── Dockerfile           # Multi-stage production container build
└── docker-compose.yml   # Production Docker Compose distribution
```

---

## License

SecretVault is open-source software licensed under the **[MIT License](LICENSE)**.
