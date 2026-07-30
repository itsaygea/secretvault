# Self-Host SecretVault with Docker Compose

This guide walks you through deploying a production-ready SecretVault instance using Docker Compose.

> [!WARNING]
> **CRITICAL: BACK UP YOUR MASTER KEY**  
> SecretVault encrypts all stored credentials using your `SECRETVAULT_MASTER_KEY` with AES-256-GCM before writing to PostgreSQL.  
> If you lose your `SECRETVAULT_MASTER_KEY`, **all stored secrets become permanently unrecoverable**. Store a copy of your master key in a secure password manager during initial setup.

---

## Prerequisites

Before installing SecretVault, ensure you have:

- **Docker** 20.10+ & **Docker Compose** v2.0+ installed on your host server.
- **Supabase Instance**: Either a free [Supabase Cloud](https://supabase.com) project or a self-hosted Supabase PostgreSQL instance. You will need:
  - Supabase URL (`https://<project-ref>.supabase.co`)
  - Supabase Service Role Key (`eyJ...`)

---

## Step 1: Create a Project Directory

Create a dedicated directory on your server for SecretVault configuration and persistent volumes:

```bash
mkdir -p secretvault && cd secretvault
```

---

## Step 2: Deployment & Configuration Options

### Option A: Automated 1-Line Guided Installer (Recommended)

Deploy SecretVault with interactive guided prompts for master keys, admin passwords, and PostgreSQL connection settings:

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
```

---

### Option B: Pull the Published Registry Image (Recommended for Production)

Download the base Compose file, the distribution overlay, and the environment
template — **no source checkout or build required**. The distribution overlay
pulls a versioned, digest-pinnable image from the GitHub Container Registry.

```bash
mkdir -p secretvault && cd secretvault

# Compose files + environment template only (no source)
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/itsaygea/secretvault/main/docker-compose.yml
curl -fsSL -o docker-compose.dist.yml https://raw.githubusercontent.com/itsaygea/secretvault/main/docker-compose.dist.yml
curl -fsSL -o .env.example https://raw.githubusercontent.com/itsaygea/secretvault/main/.env.example

cp .env.example .env
```

Pin the exact image you want to run by setting these in `.env` (or your
shell). A digest pins immutable bytes and is immune to tag retagging:

```env
SECRETVAULT_IMAGE=ghcr.io/itsaygea/secretvault:v1.0.0
# strongly recommended — pin the digest too:
SECRETVAULT_DIGEST=sha256:<digest-from-the-release>
```

Then bring it up with the distribution overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.dist.yml up -d
```

The published image is multi-arch (`linux/amd64`, `linux/arm64`) and ships
with build provenance and SBOM attestations. Verify an image's attestation
with `gh attestation verify` against the package on GitHub.

> The previous "download individual files" path is gone: it downloaded a
> `docker-compose.yml` that specified `build: .` with no build context, so it
> could not actually run. Use this registry-image path instead, or Option C.

---

### Option C: Clone the Repository and Build

If you want to build from source (development, air-gapped, or custom patches):

```bash
git clone https://github.com/itsaygea/secretvault.git
cd secretvault
cp .env.example .env

# Build and run locally from the source tree
docker compose up -d --build
```

---

### Option D: Bundled Local PostgreSQL (Zero-Dependency 1-Click)

If you do **not** already have Supabase or an external PostgreSQL instance,
SecretVault can run entirely self-contained in Docker Compose: a bundled
`postgres:16-alpine` database plus a `postgrest/postgrest:v12.2.3` sidecar.
No external infrastructure, no manual SQL — the installer provisions
everything.

Run the installer and choose backend **1) Bundled Local PostgreSQL**:

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
```

In bundled mode the installer:

- Generates a strong `POSTGRES_PASSWORD`, a 32-byte `PGRST_JWT_SECRET`, and
  mints a `service_role` HS256 JWT for `SECRETVAULT_SUPABASE_SERVICE_KEY`
  (signed against that secret) — all in-process, no manual entry.
- Writes `.env` restricted to `0600` and loads both overlays:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.bundled.yml up -d
  ```

- Boots the stack in order — `postgres → migrate (one-shot) → postgrest →
  postgrest-proxy → secretvault-mcp` — and verifies `/health/live` then
  `/health/ready`.

The bundled stack provisions the PostgREST schema exposure described in
[Step 4](#postgrest--supabase-schema-exposure-required) automatically:
`bundled/postgres-init.sql` creates the `authenticator`/`anon`/`service_role`
roles and `auth.role()` on first boot, and the bundled overlay sets
`PGRST_DB_SCHEMAS=secretvault`, `PGRST_DB_ANON_ROLE=anon`, and legacy GUCs ON.
A small nginx proxy rewrites `/rest/v1/` → PostgREST so the app's
`@supabase/supabase-js` client reaches the local sidecar exactly as it would
Supabase Cloud. The bundled PostgreSQL port is never published to the host;
API access is gated by the per-install `PGRST_JWT_SECRET`.

> The bundled database is intended for single-node self-hosting (it stores
> data in the `secretvault_postgres_data` named volume). For HA Postgres or a
> managed database, use Option A/C with backend 2, or Supabase Cloud with
> backend 3.

---

## Step 3: Generate Master Key & Configure Environment

1. Generate a cryptographically secure 32-byte hex master encryption key:

   ```bash
   openssl rand -hex 32
   ```

   *Copy the 64-character output string.*

2. Edit your `.env` file (`nano .env` or `vim .env`):

   ```env
   # Master Encryption Key (64-char hex)
   SECRETVAULT_MASTER_KEY=paste_your_generated_64_char_hex_key_here

   # Supabase Backend Credentials
   SECRETVAULT_SUPABASE_URL=https://your-project.supabase.co
   SECRETVAULT_SUPABASE_SERVICE_KEY=your_supabase_service_role_key

   # Direct PostgreSQL connection used for automatic startup migrations
   SECRETVAULT_DATABASE_URL=postgresql://postgres:password@db.example.com:5432/postgres
   SECRETVAULT_DATABASE_SSL=true

   # Admin Bootstrap Password (used ONLY on first container boot)
   SECRETVAULT_UI_PASSWORD=ChangeMeOnFirstBoot123!

   # Exact public origins non-admin users may register as proxy destinations
   SECRETVAULT_EGRESS_ALLOWLIST=https://api.github.com,https://api.openai.com
   ```

   The container applies pending SQL files from `supabase/migrations/` before
   starting the HTTP server. For an existing database whose migrations were
   previously applied manually, set `SECRETVAULT_MIGRATIONS_BASELINE` to the
   last applied filename without `.sql` (for example,
   `011_audit_event_contract`) for the first startup only.

3. Restrict file permissions so only your user can read the environment configuration:

   ```bash
   chmod 600 .env
   ```

---

## Step 4: Verify Database Migration Access

No manual migration step is required for a fresh deployment. The container
applies the numbered SQL files in `supabase/migrations/` before it accepts
traffic, using `SECRETVAULT_DATABASE_URL`.

Confirm that the database URL's role can create schemas, tables, indexes,
policies, and the `secretvault.schema_migrations` history table. For an
existing database that was migrated manually, set
`SECRETVAULT_MIGRATIONS_BASELINE` as described in Step 3 before the first
startup migration.

### PostgREST / Supabase schema exposure (required)

SecretVault reads and writes every table as the **`service_role`** through
PostgREST (the Supabase REST API). For this to work, PostgREST must be
configured to expose the `secretvault` schema and the database must grant
`service_role` the privileges the application needs. Migration
`018_postgrest_grants.sql` establishes those grants and default privileges
automatically:

- `GRANT USAGE ON SCHEMA secretvault TO service_role`
- `SELECT, INSERT, UPDATE, DELETE` on every current table, plus
  `DEFAULT PRIVILEGES` so tables added by future migrations inherit access
- `REVOKE … FROM PUBLIC` so untrusted roles never read secretvault data even
  if a table ships without an RLS policy

What you must configure on the PostgREST side:

| Setting | Value |
| --- | --- |
| Exposed schemas (`db-schemas`) | `secretvault` |
| Anonymous role (`db-anon-role`) | `anon` (or any NOLOGIN role with **no** grants on secretvault) |
| JWT secret | the same secret Supabase uses to sign the service-role key |

On **Supabase Cloud** this is the default: the project's service role already
has access and `secretvault` is exposed once the migration runs. On
**self-hosted Supabase**, add `secretvault` to the `db-schemas` list in your
`docker-compose.yml` `postgrest` service and restart PostgREST so it reloads
the schema cache. **Never expose the `auth` schema** alongside `secretvault`.

CI proves this contract end to end: the integration stack runs real PostgREST
against real PostgreSQL and asserts `service_role` can read secretvault tables
while `anon` cannot (`ci/postgrest-permissions.mjs`).

> Using the **bundled** backend (Option D)? All of the above is provisioned
> automatically by `docker-compose.bundled.yml` — you do not need to configure
> a PostgREST instance separately.

---


## Step 5: Start the Container

Launch SecretVault in detached background mode:

```bash
# Option A (installer) or Option C (source build):
docker compose up -d

# Option B (registry image) — include the distribution overlay:
docker compose -f docker-compose.yml -f docker-compose.dist.yml up -d
```

Verify that the container is running and healthy:

```bash
docker ps --filter name=secretvault-mcp
```

---

## Step 6: Enabling HTTPS & TLS (Required for WebAuthn Passkeys)

> [!IMPORTANT]
> The bundled `docker-compose.yml` publishes the listener on the **host loopback only** (SV-020). External access requires one of the TLS-terminating setups below — do not expose the plaintext port directly. Modern web browsers (Chrome, Firefox, Safari) also enforce a strict rule: **Hardware Passkeys (WebAuthn / Touch ID / YubiKey) require a Secure Context (`https://` or `http://localhost`)**.
> If accessed over plain HTTP via an IP address, `navigator.credentials` will be disabled by your browser. Choose one of the 4 turn-key HTTPS setups below:

### Option A: Automatic Caddy ACME Let's Encrypt (1-Step Profile)

If you have a public domain pointing to your server IP, launch SecretVault with the Caddy profile:

1. Edit `.env` to set your domain and ACME email:
   ```env
   SECRETVAULT_DOMAIN=vault.yourdomain.com
   SECRETVAULT_ACME_EMAIL=admin@yourdomain.com
   ```
2. Launch with Caddy:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d
   ```
   *Caddy will automatically issue, manage, and renew Let's Encrypt TLS certificates on ports 80 & 443.*

### Option B: Tailscale MagicDNS / Netbird Overlay Mesh (Zero Public Ports)

If you run a private mesh network (Tailscale or Netbird), you can get instant HTTPS without exposing any public ports or configuring DNS:

```bash
tailscale serve --https=443 http://127.0.0.1:3004
```
*Tailscale provisions a valid Let's Encrypt TLS certificate for `https://<node>.<tailnet>.ts.net` instantly.*

By default the Compose mapping publishes port 3004 on the **host loopback
(`127.0.0.1`) only** (SV-020 / SV-AUD-001) — the listener is not reachable on
the host's LAN interfaces. To let clients connect directly through a Tailscale
or NetBird address, set `SECRETVAULT_PUBLISH_HOST=0.0.0.0` (and terminate TLS
first, or acknowledge external plaintext with the two override flags). The Caddy
overlay (`docker-compose.caddy.yml`) removes the app's host-side port 3004
entirely so Caddy is the sole externally reachable path; a loopback-only mapping
is likewise suitable when Tailscale Serve or another local reverse proxy is the
sole entry point.

### Option C: Nginx Proxy Manager (NPM), Cloudflare Tunnels, or Traefik

If you already use a reverse proxy:

- **Nginx Proxy Manager**: Add Proxy Host `vault.yourdomain.com` pointing to `http://secretvault-mcp:3004`. Enable **Websockets Support**, **Block Common Exploits**, and **SSL Force HTTPS**.
- **Cloudflare Tunnels (`cloudflared`)**: Add Public Hostname `vault.yourdomain.com` pointing to `http://localhost:3004`.
- **Traefik**: Add label `"traefik.http.services.secretvault.loadbalancer.server.port=3004"`.

### Option D: Native Custom TLS Certificates

Mount custom SSL certificates (`cert.pem`, `key.pem`) directly into SecretVault via environment variables:

```yaml
services:
  secretvault-mcp:
    environment:
      - SECRETVAULT_TLS_CERT=/etc/secretvault/certs/fullchain.pem
      - SECRETVAULT_TLS_KEY=/etc/secretvault/certs/privkey.pem
    volumes:
      - ./certs:/etc/secretvault/certs:ro
```

---

## Step 7: Validate & Complete Initial Setup

1. **Verify Health Endpoint**:
   ```bash
   curl http://localhost:3004/health/ready
   ```
   *Expected Output*: `{"status":"ok"}`

2. **Access Web UI**: Open `https://vault.yourdomain.com/ui` (loopback-only: `http://localhost:3004/ui`) in your browser. Use the HTTPS URL — the default deployment does not publish port 3004 on the host's network interfaces.
3. **Log In**: Authenticate using username `admin` and the password set in `SECRETVAULT_UI_PASSWORD`.
4. **Generate Linking Key**: Navigate to Security / Client Applications in the Web UI to generate your first linking key (`sv_...`) for Claude Code or developer applications.

---

## Next Steps

- **[Connect Claude Code / MCP & Developer SDK](usage.md)**
- **[Security Model & Hardening](security.md)**
- **[Backups & Maintenance](ops.md)**
