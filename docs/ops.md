# SecretVault Operations & Maintenance Guide

This guide details database backups, disaster recovery, container upgrades, and emergency recovery procedures.

---

## 1. Backup & Disaster Recovery

### Master Key Backup (CRITICAL)
Your `SECRETVAULT_MASTER_KEY` encrypts all secret blobs in PostgreSQL. Store this 64-character hex key in an offline physical vault or secure password manager (e.g., 1Password, Bitwarden).

### Database Backup
Perform regular PostgreSQL database dumps of the `secretvault` schema:

```bash
pg_dump -h <db-host> -U postgres -d postgres -n secretvault -F c -f secretvault_$(date +%F).dump
```

### Disaster Recovery Steps

1. Provision a fresh PostgreSQL database instance.
2. Restore database dump:
   ```bash
   pg_restore -h <db-host> -U postgres -d postgres secretvault_backup.dump
   ```
3. If the dump predates automatic migration history, set
   `SECRETVAULT_MIGRATIONS_BASELINE` to the last manually applied migration.
4. Start SecretVault providing the original `SECRETVAULT_MASTER_KEY` and
   `SECRETVAULT_DATABASE_URL`; pending migrations run before traffic is served.

The container runs pending migrations before accepting traffic. It records
checksums in `secretvault.schema_migrations`, takes a PostgreSQL
advisory lock to serialize concurrent starts, and stops startup on migration
failure or checksum drift. Keep `SECRETVAULT_DATABASE_URL` separate from the
Supabase API URL; it must be a direct PostgreSQL connection string.

> [!IMPORTANT]
> **PostgreSQL Direct Connection Topology (SV-021)**
> Direct connection URL: `postgresql://supabase_admin:<password>@db.example.com:5432/postgres`.
> TLS is **on with certificate verification on by default**. Pin a CA with
> `SECRETVAULT_DATABASE_SSL_CA_FILE` (path) or `SECRETVAULT_DATABASE_SSL_CA`
> (inline PEM), and override SNI/hostname with `SECRETVAULT_DATABASE_SSL_SERVERNAME`.
> Set `SECRETVAULT_DATABASE_SSL=false` only for a local plaintext instance.
> To disable verification against a private/dev database, set **both**
> `SECRETVAULT_DATABASE_SSL_INSECURE=1` and
> `SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM=I-know-this-is-insecure` — never on
> an untrusted network.

---

## 2. Emergency Break-Glass Password Reset

If you lose access to the admin account or lose your 2FA authenticator device,
perform an emergency password reset directly from the host terminal using the
`secretvault-break-glass` executable shipped inside the runtime image:

```bash
docker exec -e CONFIRM=1 secretvault-mcp secretvault-break-glass \
  --username admin --confirm --password 'NewSecurePassword123!'
```

To also wipe WebAuthn/TOTP factors (full recovery from a lost authenticator),
add `--reset-2fa`. The reset revokes every active session for the user so a
compromised session cannot survive.

Prefer reading the password from a file or stdin so it never lands in shell
history or `docker inspect`:

```bash
# from a file mounted into the container
docker exec secretvault-mcp secretvault-break-glass \
  --username admin --confirm --password-file /run/secrets/newpass

# or via stdin
docker exec -i secretvault-mcp secretvault-break-glass \
  --username admin --confirm --password-stdin < newpass.txt
```

The executable refuses to run without `--confirm` and requires exactly one
password source (`--password`, `--password-file`, or `--password-stdin`). It
needs no `npm` and no source checkout — only the `SECRETVAULT_SUPABASE_URL`
and `SECRETVAULT_SUPABASE_SERVICE_KEY` already present in the container
environment.

> [!NOTE]
> **Security Boundary**
> The break-glass tool is gated by Host OS root/sudo permissions (`docker
> exec`) plus its own `--confirm` flag. Every run inserts a high-severity
> audit event (`access_type: "emergency_cli_password_reset"`) and prints a
> `[break-glass]` confirmation to stdout, so recovery is attributable.

---

## 3. Container Upgrades

To upgrade SecretVault to the latest release, re-run the 1-liner installer (which preserves your existing `.env` and master key):

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
```

Or pull the latest changes and rebuild locally:

```bash
cd secretvault
git pull origin main
docker compose up -d --build
```

---

## 4. Diagnostics & Troubleshooting

### Proxy Upstream Timeout

The credential proxy aborts an upstream request after 30 seconds by default. Set
`SECRETVAULT_PROXY_TIMEOUT_MS` to a positive millisecond value when an upstream
service needs a different limit. Aborted requests return the standard
`UPSTREAM_CONNECTION_FAILED` error envelope and are recorded in the access log.

### Health Check
```bash
curl http://localhost:3004/health/ready
```

### Container Logs
```bash
docker logs secretvault-mcp --tail 100 -f
```

## 5. Security Scanning & Accepted Risk

CI and the scheduled `Security` workflow scan the runtime image, dependency
manifests/lockfile, configuration/IaC, and the repository for leaked secrets
using Trivy. Scans that find a fixable HIGH or CRITICAL vulnerability (or any
hard-coded secret) **fail CI** — they do not pass with a warning.

### Running scans locally

```bash
# Image scan (requires a built image)
docker build --tag secretvault-mcp:local .
trivy image --exit-code 1 --ignore-unfixed --severity CRITICAL,HIGH secretvault-mcp:local

# Repository scan (deps + config + secrets)
trivy fs --scanners vuln,misconfig,secret --severity CRITICAL,HIGH .
```

### Gate self-test

The gate configuration is verified without a live network scan:

```bash
node scripts/check-workflow-pins.mjs   # all actions pinned to commit SHAs
node scripts/test-trivy-gate.mjs       # gate exit-code, secret severity, register
```

Both run as part of `npm test`.

### Accepted-risk register

When a finding is deliberately accepted, record it in two places:

1. `.trivyignore` — the CVE/GHSA ID that Trivy should suppress.
2. `.github/trivy/accepted-risk.yml` — the full triage record.

Every suppression must declare **owner**, **rationale**, **scope**, and an
**expiration** date (YYYY-MM-DD). The gate self-test fails if a suppressed ID
is missing any of those fields, or if its expiration has passed. There are no
silent suppressions.

### Triage process

1. A scheduled or PR scan surfaces a finding.
2. The on-call operator (the `owner`) confirms the finding is real and not a
   false positive.
3. If a fix exists, patch it. If no fix is available or the finding is out of
   the reachable attack surface, add a `accepted-risk.yml` entry with all four
   fields and an expiration no more than 90 days out, then add the ID to
   `.trivyignore`.
4. The gate self-test enforces the annotation. Expired entries fail CI until
   re-reviewed.
5. Scanner databases refresh automatically in the scheduled workflow; run the
   workflow manually (`Actions → Security → Run workflow`) to pick up a fresh
   DB before an unscheduled triage.

### Reporting a vulnerability

See [`../SECURITY.md`](../SECURITY.md) for the private reporting path, response
SLA, supported versions, and coordinated disclosure policy.

