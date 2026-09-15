# SecretVault Server Operations & Hosting Guide

This guide covers self-hosting, environment configuration, database migrations, container management, master key rotation, and break-glass procedures for the SecretVault Server.

---

## 1. Server Deployment Options

SecretVault can be deployed using the automated 1-line server installer or via Docker Compose.

### Option A: 1-Line Server Installer (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
```
The installer prompts for your PostgreSQL connection string, auto-generates a 32-byte (64 hex) master encryption key, and starts the Docker Compose stack on port 3004.

### Server upgrades

For an existing source checkout, the safe updater backs up the environment,
project tree, and PostgreSQL before fetching an immutable release. It detects
bundled versus external/shared/HA PostgreSQL and verifies readiness after the
Compose rebuild:

```bash
cd /opt/secretvault
bash upgrade-server.sh --dry-run
bash upgrade-server.sh --yes
```

See [`docs/upgrade.md`](upgrade.md) for registry-image deployments and rollback
cautions. The updater refuses non-matching tracked local changes and never uses
`docker compose down -v`.

### Option B: Manual Docker Compose Deployment
```bash
git clone https://github.com/itsaygea/secretvault.git
cd secretvault
cp .env.example .env

# Generate 32-byte master encryption key
openssl rand -hex 32
nano .env # Edit SECRETVAULT_MASTER_KEY and SECRETVAULT_DATABASE_URL

chmod 600 .env
docker compose up -d --build
```

---

## 2. Server Environment Variables

| Variable | Description | Required | Example |
| :--- | :--- | :---: | :--- |
| `SECRETVAULT_MASTER_KEY` | 64-char hex (32-byte) master encryption key | Yes | `<64-hex-master-key>` |
| `SECRETVAULT_DATABASE_URL` | PostgreSQL connection string | Yes | `postgresql://<db-user>:<db-password>@<db-host>:5432/<db-name>` |
| `SECRETVAULT_SUPABASE_URL` | Supabase API instance URL | Yes | `https://supabase.example.com` |
| `SECRETVAULT_SUPABASE_SERVICE_KEY` | Supabase service role key | Yes | `<supabase-service-role-jwt>` |
| `SECRETVAULT_PGRST_JWT_SECRET` | PostgREST JWT secret used for internal tenant-scoped requests | Yes | `<postgrest-jwt-secret>` |
| `SECRETVAULT_UI_PASSWORD` | Password for initial admin user | Yes | `<initial-admin-password>` |
| `SECRETVAULT_ALLOWED_ORIGINS` | CORS origin allowlist | No | `https://vault.example.com,http://localhost:3004` |
| `SECRETVAULT_DATABASE_SSL` | Enable/disable SSL for DB connection | No | `false` |

---

## 3. Server Health Checks & Inspection

Check server container status and health endpoints:

```bash
# Container status
docker ps --filter name=secretvault-mcp

# Liveness health check
curl -s http://localhost:3004/health

# Readiness health check (verifies DB connection)
curl -s http://localhost:3004/health/ready

# View server container logs
docker logs secretvault-mcp --tail 50 -f
```

---

## 4. Master Key Rotation & Envelope Migrations

### Master Key Rotation (`rotate-master-key`)
To re-encrypt all stored secrets with a new 32-byte master encryption key:

```bash
docker exec -it secretvault-mcp secretvault-cli rotate-master-key --new-key <64_HEX_KEY>
```

### Envelope Migration (`migrate-envelopes`)
To auto-upgrade legacy `v1` ciphertext envelopes to context-bound `v2` envelopes:

```bash
docker exec -it secretvault-mcp secretvault-cli migrate-envelopes
```

---

## 5. Break-Glass Emergency Account Recovery

If administrator login credentials are lost or locked out, run the interactive break-glass helper directly inside the server container:

```bash
docker exec -it secretvault-mcp secretvault-break-glass
```

Follow the prompts to reset the admin password or issue a fresh one-time setup code.
