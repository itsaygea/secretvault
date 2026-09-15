# SecretVault Upgrade Guide

This guide upgrades an existing SecretVault deployment to the current release
without changing the encryption master key or deleting existing data.

## Before you upgrade

1. Schedule a short maintenance window. The container runs database migrations
   before it accepts traffic.
2. Back up both the database and the original `SECRETVAULT_MASTER_KEY`.
   Losing the master key makes encrypted secrets unrecoverable.

   ```bash
   # Run against the PostgreSQL database configured by your installation.
   pg_dump -h <db-host> -U <db-user> -d <db-name> -n secretvault \
     -F c -f secretvault_pre_upgrade_$(date +%F).dump
   cp .env .env.pre-upgrade.backup
   chmod 600 .env.pre-upgrade.backup
   ```

3. Do not generate a new master key during an application upgrade. Keep the
   existing `SECRETVAULT_MASTER_KEY` exactly as it is.

## Required configuration for this release

The current release enforces tenant isolation through PostgREST. Before
starting the new container, add the raw JWT signing secret used by PostgREST:

```env
SECRETVAULT_PGRST_JWT_SECRET=<the-existing-postgrest-jwt-secret>
```

Use the existing secret; do not generate a replacement during the upgrade.

- Supabase Cloud: use the project's API JWT secret from its settings.
- Self-hosted PostgREST: use the value configured as `PGRST_JWT_SECRET`.
- Bundled Compose: use the per-install value already generated in `.env`.
- Shared or HA PostgreSQL: the database endpoint may be a LAN VIP or pooler;
  keep using the existing `SECRETVAULT_DATABASE_URL` and take the backup from
  that endpoint. The PostgREST JWT secret still comes from the Supabase/
  PostgREST configuration, not from PostgreSQL.

This is a server-side secret. Keep it in `.env` or a secret manager, never in
the repository, client configuration, browser code, or commit history.

## Source checkout upgrade

### Automated server updater

For a normal source-checkout deployment, use the checked-in updater. It resolves
`main` to an immutable 40-character commit, refuses tracked local edits, backs
up `.env`, the project tree, PostgreSQL schema data, and database globals, then
rebuilds the currently active Compose topology and verifies readiness:

```bash
cd /opt/secretvault
bash upgrade-server.sh --dry-run
bash upgrade-server.sh --yes
```

The updater detects bundled PostgreSQL, external PostgreSQL (including shared or
HA PostgreSQL), and the Caddy overlay. It never enables the bundled overlay for
an external database. Untracked files are preserved unless the requested Git
release would overwrite one; tracked changes must be committed or stashed first.
Backups are written beside the deployment in a timestamped directory with a
`SHA256SUMS` manifest. The updater does not print `.env` or database values.

For an older checkout that does not yet contain the updater, fetch the script
from the repository and run it in dry-run mode first:

```bash
curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/upgrade-server.sh \
  | bash -s -- --dir /opt/secretvault --dry-run
```

For a fully pinned bootstrap, replace `main` in that URL with a verified
40-character commit and pass the same commit with `--ref <commit>`.

Registry-image deployments are intentionally not handled by this source updater;
use the registry-image procedure below so the image digest remains explicit.

From the directory containing the existing checkout:

```bash
git status --short
git fetch origin main
git pull --ff-only origin main
```

Review `.env` after the pull and confirm that the original master key,
database URL, Supabase credentials, and the new `SECRETVAULT_PGRST_JWT_SECRET`
are still present. Then rebuild and start the matching Compose mode.

Bundled local PostgreSQL (the default for new installs):

```bash
docker compose -f docker-compose.yml -f docker-compose.bundled.yml up -d --build
```

Existing external, shared, or HA PostgreSQL:

```bash
docker compose up -d --build
```

This external command is also the correct command for Supabase Cloud and
shared/HA PostgreSQL deployments. Do not use the bundled overlay unless this
installation owns the PostgreSQL container and its Compose volume.

The entrypoint runs the pending migrations before starting the server. Do not
run `docker compose down -v`; the `-v` option can delete the bundled database
volume.

## Registry-image upgrade

If the deployment uses `docker-compose.dist.yml`, update the image reference to
the desired release and preferably its immutable digest, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.dist.yml pull
docker compose -f docker-compose.yml -f docker-compose.dist.yml up -d
```

The image contains the migration files and runs them through the same startup
entrypoint. Keep the existing `.env` beside the Compose files.

## Migration history and older installations

The current release adds these forward-only migrations:

- `024_reinstate_tenant_isolation.sql` removes the broad service-role policies
  restored by migration 023 and restores the database tenant boundary.
- `025_rate_limit_stable_buckets.sql` keeps account/IP rate-limit buckets and
  cooldowns stable across fixed-window boundaries.
- `026_proxy_access_tokens.sql` creates the digest-only short-lived proxy-token
  table.
- `027_atomic_session_epoch_bump.sql` adds the atomic session-revocation RPC.
- `028_pre_auth_lookup_functions.sql` keeps pre-authentication lookups narrow;
  it does not restore global table access to `client_applications` or proxy
  tokens.
- `029_revoke_residual_service_role_privileges.sql` removes residual
  non-DML privileges from `service_role` on tenant tables.
- `030_remove_proxy_service_role_policy.sql` removes the obsolete proxy-token
  bootstrap policy after direct service-role privileges are gone.

If the installation already has `secretvault.schema_migrations`, leave
`SECRETVAULT_MIGRATIONS_BASELINE` unset. The runner will apply only migrations
that are missing and will stop on checksum drift.

If an old installation applied SQL manually and has no migration-history table,
set the baseline once to the last migration that was actually applied. For an
installation known to contain migrations 001 through 023:

```env
SECRETVAULT_MIGRATIONS_BASELINE=023_restore_service_role_grants
```

Remove the baseline setting after the first successful startup. Do not use
`023_restore_service_role_grants` unless migrations 001–023 are already present
in the database; otherwise use the actual last applied migration. When unsure,
stop before starting the new container and verify the schema from a database
backup or with the database administrator.

## Verify the upgrade

Check that migrations completed and the readiness endpoint is healthy:

```bash
docker logs secretvault-mcp --tail 100
curl -fsS http://127.0.0.1:3004/health/ready
```

The logs should show the pending migrations being applied and the schema being
up to date. Confirm that the Web UI loads, an existing user can sign in, and a
known secret remains available. For a proxy client, issue a token through
`POST /v1/client/token` or use the current `@secretvault/client`; it will
exchange the linking key for short-lived proxy access tokens automatically.

Existing linking keys remain valid. Existing proxy integrations that still send
a linking key continue to work during the compatibility window, but new client
code should use the short-lived token exchange. No master-key rotation or
ciphertext re-encryption is required for this upgrade.

## Rollback caution

The migrations are forward-only. After `024` is applied, an old application
image that does not mint the internal tenant JWT may not be able to use the
database safely. If the new image fails after migrations begin, keep the
database backup, inspect the migration error, and prefer fixing forward. A
rollback to the old image should be paired with restoring the pre-upgrade
database backup rather than deleting migration history or editing applied SQL.
