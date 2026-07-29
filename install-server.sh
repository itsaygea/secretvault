#!/usr/bin/env bash

# ==============================================================================
# SecretVault Server Installer & Deployment Setup Script
# Supports 1-line execution:
# curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-server.sh | bash
#
# Offers a 1-click bundled backend (local postgres:16-alpine + PostgREST, zero
# external infrastructure) alongside the existing external-PostgreSQL and
# Supabase Cloud options.
# ==============================================================================

set -eo pipefail

main() {
  # Attach stdin to TTY if available (required for curl | bash execution)
  if [ -t 0 ]; then
    : # Already running in TTY
  elif [ -e /dev/tty ]; then
    exec < /dev/tty 2>/dev/null || true
  fi

  # ANSI Color Definitions
  BOLD="\033[1m"
  GREEN="\033[1;32m"
  CYAN="\033[1;36m"
  YELLOW="\033[1;33m"
  RED="\033[1;31m"
  RESET="\033[0m"

  VERSION="v0.1.7"

  # Print Section Banner
  banner() {
    echo -e "${CYAN}"
    echo "════════════════════════════════════════════════════════════════════════"
    echo "       🔒 SecretVault Server Installer & Deployment Wizard (${VERSION})  "
    echo "════════════════════════════════════════════════════════════════════════"
    echo -e "${RESET}"
  }

# Helper to read with default value (prints result to stdout, no eval)
prompt_with_default() {
  local prompt="$1"
  local default_val="$2"
  local input
  if [ -n "$default_val" ]; then
    read -rp "$(echo -e "${BOLD}${prompt}${RESET} [${YELLOW}${default_val}${RESET}]: ")" input < /dev/tty
    echo "${input:-$default_val}"
  else
    read -rp "$(echo -e "${BOLD}${prompt}${RESET}: ")" input < /dev/tty
    echo "$input"
  fi
}

# Helper to read silent/hidden input (prints result to stdout, no eval)
prompt_password() {
  local prompt="$1"
  local input
  read -srp "$(echo -e "${BOLD}${prompt}${RESET}: ")" input < /dev/tty
  echo ""
  echo "$input"
}

# Percent-encode a string for safe use in URI components
url_encode() {
  local string="$1"
  local strlen=${#string}
  local encoded=""
  local pos c
  for ((pos = 0; pos < strlen; pos++)); do
    c="${string:$pos:1}"
    case "$c" in
      [-_.~a-zA-Z0-9]) encoded+="$c" ;;
      *) printf -v encoded '%s%%%02x' "$encoded" "'$c" ;;
    esac
  done
  printf '%s' "$encoded"
}

# Validate a numeric port is within 1-65535
validate_port() {
  local port="$1"
  case "$port" in
    ''|*[!0-9]*) return 1 ;;
    *) [ "$port" -ge 1 ] && [ "$port" -le 65535 ] ;;
  esac
}

# Validate a value is "true" or "false" (case-insensitive)
validate_boolean() {
  local val
  val=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  [ "$val" = "true" ] || [ "$val" = "false" ]
}

# Validate an HTTP(S) URL has a plausible scheme + host.
validate_url() {
  local url="$1"
  [[ "$url" =~ ^https?://[a-zA-Z0-9._-]+ ]]
}

# Generate a strong random alphanumeric secret (URL-safe, no padding).
# Uses openssl when available; falls back to /dev/urandom + base64.
generate_secret() {
  local bytes="${1:-24}"
  if command -v openssl &>/dev/null; then
    openssl rand -base64 "$bytes" | tr -d '=+/' | head -c "$((bytes * 2))"
  else
    head -c "$bytes" /dev/urandom | base64 | tr -d '=+/' | head -c "$((bytes * 2))"
  fi
}

# Mint an HS256 JWT carrying role=service_role, signed with the given secret.
# PostgREST accepts this as the SecretVault service key in bundled mode (the
# same convention ci/mint-jwt.mjs uses deterministically). Prints the JWT.
mint_service_role_jwt() {
  local secret="$1"
  local now exp iat
  # Fixed iat (2025-01-01) + far-future exp (2099-01-01) so the committed token
  # never expires during the install's lifetime, mirroring ci/mint-jwt.mjs.
  iat=1735689600
  exp=4070908800

  b64url() {
    # Strip padding, use URL-safe alphabet. Reads JSON from stdin.
    openssl base64 -A 2>/dev/null | tr '/+' '_-' | tr -d '='
  }

  local header payload signing_input sig
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"role":"service_role","iss":"secretvault-bundled","iat":%s,"exp":%s,"ref":"bundled"}' "$iat" "$exp" | b64url)
  signing_input="${header}.${payload}"
  sig=$(printf '%s' "$signing_input" | openssl dgst -sha256 -mac HMAC -macopt "key:${secret}" -binary 2>/dev/null | b64url)
  printf '%s.%s' "$signing_input" "$sig"
}

banner

# ------------------------------------------------------------------------------
# 1. Prerequisite Checks
# ------------------------------------------------------------------------------
echo -e "${BOLD}Checking system prerequisites...${RESET}"

if ! command -v docker &>/dev/null; then
  echo -e "${RED}Error: Docker is not installed or not in PATH.${RESET}" >&2
  exit 1
fi

DOCKER_COMPOSE_CMD=""
if docker compose version &>/dev/null; then
  DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE_CMD="docker-compose"
else
  echo -e "${RED}Error: Docker Compose (docker compose or docker-compose) is not installed.${RESET}" >&2
  exit 1
fi

if ! command -v openssl &>/dev/null; then
  echo -e "${RED}Error: OpenSSL is required for cryptographic key generation.${RESET}" >&2
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo -e "${RED}Error: curl is required for health check verification.${RESET}" >&2
  exit 1
fi

echo -e "${GREEN}✓ All prerequisites met (Docker, Docker Compose, OpenSSL, curl).${RESET}\n"

# ------------------------------------------------------------------------------
# 2. Repo Directory & Files Setup
# ------------------------------------------------------------------------------
REPO_URL="https://github.com/itsaygea/secretvault.git"

if [ ! -f "docker-compose.yml" ]; then
  echo -e "${YELLOW}Notice: docker-compose.yml not found in current directory (${PWD}).${RESET}"
  INSTALL_DIR=$(prompt_with_default "Directory to install SecretVault" "secretvault")

  if [ ! -d "$INSTALL_DIR" ]; then
    echo "Creating directory '$INSTALL_DIR' and fetching SecretVault repository..."
    if command -v git &>/dev/null; then
      git clone "$REPO_URL" "$INSTALL_DIR"
    else
      mkdir -p "$INSTALL_DIR"
      curl -fsSL https://github.com/itsaygea/secretvault/archive/refs/heads/main.tar.gz | tar -xz -C "$INSTALL_DIR" --strip-components=1
    fi
  fi
  cd "$INSTALL_DIR"
  echo -e "${GREEN}✓ Working directory set to ${PWD}.${RESET}\n"
fi

# ------------------------------------------------------------------------------
# 3. Check Existing Configuration (.env)
# ------------------------------------------------------------------------------
ENV_FILE=".env"
PRESERVE_MASTER_KEY=""
EXISTING_ADMIN_PASS=""

if [ -f "$ENV_FILE" ]; then
  echo -e "${YELLOW}Notice: Existing .env configuration file detected.${RESET}"

  if grep -q "^SECRETVAULT_MASTER_KEY=" "$ENV_FILE"; then
    EXISTING_KEY=$(grep "^SECRETVAULT_MASTER_KEY=" "$ENV_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    if [ -n "$EXISTING_KEY" ]; then
      PRESERVE_MASTER_KEY="$EXISTING_KEY"
      echo -e "${GREEN}✓ Preserving existing master key from .env file.${RESET}"
    fi
  fi

  if grep -q "^SECRETVAULT_UI_PASSWORD=" "$ENV_FILE"; then
    EXISTING_ADMIN_PASS=$(grep "^SECRETVAULT_UI_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
  fi

  read -rp "$(echo -e "${BOLD}Do you want to update configuration settings? [y/N]${RESET}: ")" UPDATE_CFG < /dev/tty
  if [[ ! "$UPDATE_CFG" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Proceeding directly to container startup...${RESET}"
    echo "Starting containers..."
    # Detect bundled mode from existing config so the right compose files load.
    COMPOSE_FILES=(-f docker-compose.yml)
    if grep -q "^POSTGRES_PASSWORD=" "$ENV_FILE"; then
      COMPOSE_FILES+=(-f docker-compose.bundled.yml)
    fi
    "$DOCKER_COMPOSE_CMD" "${COMPOSE_FILES[@]}" up -d

    echo -e "${BOLD}Waiting for SecretVault server health check...${RESET}"
    HEALTHY=false
    for i in {1..15}; do
      if curl -s http://localhost:3004/health/ready | grep -q '"status":"ok"'; then
        HEALTHY=true
        break
      fi
      sleep 2
    done

    if [ "$HEALTHY" = true ]; then
      echo -e "${GREEN}✓ SecretVault server is HEALTHY!${RESET}"
      exit 0
    else
      echo -e "${YELLOW}Warning: Container started but /health/ready endpoint did not respond OK within 30 seconds.${RESET}"
      exit 1
    fi
  fi
fi

# ------------------------------------------------------------------------------
# 4. Master Key Setup
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}--- Step 1: Master Encryption Key Setup ---${RESET}"
MASTER_KEY="$PRESERVE_MASTER_KEY"
NEWLY_GENERATED_MASTER_KEY=false

if [ -z "$MASTER_KEY" ]; then
  echo "The Master Key encrypts all stored secrets using AES-256-GCM."
  echo "1) Automatically generate a random 32-byte key (Recommended)"
  echo "2) Manually enter an existing 64-character hex master key"
  KEY_OPTION=$(prompt_with_default "Select option" "1")

  if [ "$KEY_OPTION" = "1" ]; then
    MASTER_KEY=$(openssl rand -hex 32)
    NEWLY_GENERATED_MASTER_KEY=true
  else
    MASTER_KEY=$(prompt_password "Enter 64-char hex Master Key")
    if [ ${#MASTER_KEY} -ne 64 ]; then
      echo -e "${RED}Error: Master Key must be exactly 64 hex characters (32 bytes).${RESET}" >&2
      exit 1
    fi
  fi
fi

if [ "$NEWLY_GENERATED_MASTER_KEY" = true ]; then
  echo -e "\n${RED}╔════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${RED}║  CRITICAL WARNING: MASTER ENCRYPTION KEY GENERATED                     ║${RESET}"
  echo -e "${RED}║  Copy and safely store this key in a secure password manager NOW:      ║${RESET}"
  echo -e "${RED}║                                                                        ║${RESET}"
  echo -e "${BOLD}   ${MASTER_KEY}${RESET}"
  echo -e "${RED}║                                                                        ║${RESET}"
  echo -e "${RED}║  WARNING: If lost, all encrypted secrets are PERMANENTLY lost!        ║${RESET}"
  echo -e "${RED}╚════════════════════════════════════════════════════════════════════════╝${RESET}\n"
fi

# ------------------------------------------------------------------------------
# 5. Database Backend Selection (Bundled / External Postgres / Supabase Cloud)
# ------------------------------------------------------------------------------
echo -e "${CYAN}--- Step 2: Database Backend ---${RESET}"
echo "Choose where SecretVault stores its data."
echo -e "  ${BOLD}1) Bundled Local PostgreSQL (Recommended)${RESET} — zero-dependency 1-click self-hosted"
echo "     (local postgres:16-alpine + PostgREST, runs entirely in Docker Compose)"
echo "  2) Existing PostgreSQL — Homelab, Neon, RDS, ElephantSQL, etc."
echo "  3) Supabase Cloud — Project URL + service_role key + direct connection URI"
BACKEND_OPTION=$(prompt_with_default "Select backend" "1")

# Mode flag drives .env contents + which compose files load later.
BUNDLED_MODE=false
COMPOSE_FILES=(-f docker-compose.yml)

case "$BACKEND_OPTION" in
  1)
    BUNDLED_MODE=true
    COMPOSE_FILES+=(-f docker-compose.bundled.yml)
    echo -e "${GREEN}✓ Bundled mode selected. Local PostgreSQL + PostgREST will be provisioned.${RESET}"

    # Auto-generate every credential the bundled stack needs. Nothing here is
    # operator-entered, so bundled mode is genuinely 1-click.
    echo -e "${BOLD}Generating bundled stack credentials...${RESET}"
    POSTGRES_DB="secretvault"
    POSTGRES_USER="secretvault"
    POSTGRES_PASSWORD=$(openssl rand -hex 24)
    # 32-byte JWT secret governs PostgREST API access; the app's service key is
    # an HS256 service_role JWT minted against this secret.
    PGRST_JWT_SECRET=$(openssl rand -hex 32)
    SECRETVAULT_SUPABASE_SERVICE_KEY=$(mint_service_role_jwt "$PGRST_JWT_SECRET")
    SECRETVAULT_SUPABASE_URL="http://postgrest-proxy:8000"
    DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}"
    DB_SSL="false"
    echo -e "${GREEN}✓ Postgres password, PostgREST JWT secret, and service key generated.${RESET}"
    ;;
  2)
    echo -e "${CYAN}--- Step 3: PostgreSQL Database URL ---${RESET}"
    echo "Direct PostgreSQL connection string used for schema migrations on startup."
    echo "1) Guided setup (Enter Host, Port, User, Password, DB Name)"
    echo "2) Enter full PostgreSQL connection URL"
    DB_OPTION=$(prompt_with_default "Select option" "1")

    if [ "$DB_OPTION" = "1" ]; then
      DB_HOST=$(prompt_with_default "PostgreSQL Host" "db.example.com")
      DB_PORT=$(prompt_with_default "PostgreSQL Port" "5432")
      while ! validate_port "$DB_PORT"; do
        echo -e "${RED}Error: Port must be a number between 1 and 65535.${RESET}" >&2
        DB_PORT=$(prompt_with_default "PostgreSQL Port" "5432")
      done
      DB_USER=$(prompt_with_default "PostgreSQL User" "supabase_admin")
      DB_PASS=$(prompt_password     "PostgreSQL Password")
      DB_NAME=$(prompt_with_default "PostgreSQL Database Name" "postgres")
      DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
      while ! validate_boolean "$DB_SSL"; do
        echo -e "${RED}Error: Must be 'true' or 'false'.${RESET}" >&2
        DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
      done

      encoded_user=$(url_encode "$DB_USER")
      encoded_pass=$(url_encode "$DB_PASS")
      encoded_db=$(url_encode "$DB_NAME")
      DATABASE_URL="postgresql://${encoded_user}:${encoded_pass}@${DB_HOST}:${DB_PORT}/${encoded_db}"
    else
      DATABASE_URL=$(prompt_password "Enter full PostgreSQL URL")
      DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
      while ! validate_boolean "$DB_SSL"; do
        echo -e "${RED}Error: Must be 'true' or 'false'.${RESET}" >&2
        DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
      done
    fi

    # External PostgreSQL still needs a PostgREST/Supabase REST endpoint for
    # runtime API queries (the app uses @supabase/supabase-js). If the operator
    # is pointing at a standalone PostgREST or a Supabase project behind the
    # same Postgres, capture it; otherwise default to the database host.
    echo -e "${CYAN}--- Step 4: PostgREST / Supabase REST endpoint ---${RESET}"
    echo "SECRETVAULT_SUPABASE_URL is the HTTPS Web / REST API endpoint (PostgREST)."
    echo "(For Supabase Cloud: https://your-project.supabase.co ; for self-hosted"
    echo " PostgREST pointing at the database above, enter its URL.)"
    SUPABASE_URL=$(prompt_with_default "PostgREST / Supabase REST URL" "https://supabase.example.com")
    while ! validate_url "$SUPABASE_URL"; do
      echo -e "${RED}Error: Must be a valid http(s) URL.${RESET}" >&2
      SUPABASE_URL=$(prompt_with_default "PostgREST / Supabase REST URL" "https://supabase.example.com")
    done
    echo -e "\nSECRETVAULT_SUPABASE_SERVICE_KEY is the administrative service_role JWT key."
    SUPABASE_SERVICE_KEY=$(prompt_password "Supabase Service Role Key")
    if [ -z "$SUPABASE_SERVICE_KEY" ]; then
      echo -e "${RED}Error: Supabase Service Role Key cannot be empty.${RESET}" >&2
      exit 1
    fi
    ;;
  3)
    echo -e "${CYAN}--- Step 3: Supabase Cloud Connectivity ---${RESET}"
    echo "SECRETVAULT_SUPABASE_URL is the HTTPS Web / REST API endpoint for your Supabase project."
    echo "(e.g., https://supabase.example.com or https://your-project.supabase.co)"
    SUPABASE_URL=$(prompt_with_default "Supabase API URL" "https://supabase.example.com")
    while ! validate_url "$SUPABASE_URL"; do
      echo -e "${RED}Error: Must be a valid http(s) URL.${RESET}" >&2
      SUPABASE_URL=$(prompt_with_default "Supabase API URL" "https://supabase.example.com")
    done

    echo -e "\nSECRETVAULT_SUPABASE_SERVICE_KEY is the administrative service_role JWT key."
    echo "(Found in Supabase Dashboard > Settings > API > service_role key)"
    SUPABASE_SERVICE_KEY=$(prompt_password "Supabase Service Role Key")
    if [ -z "$SUPABASE_SERVICE_KEY" ]; then
      echo -e "${RED}Error: Supabase Service Role Key cannot be empty.${RESET}" >&2
      exit 1
    fi

    echo -e "\n${CYAN}--- Step 4: Supabase Direct PostgreSQL Connection ---${RESET}"
    echo "Direct connection string for startup schema migrations (Supabase Dashboard"
    echo "> Settings > Database > Connection string, URI mode)."
    DATABASE_URL=$(prompt_password "Enter Supabase direct PostgreSQL URL")
    if [ -z "$DATABASE_URL" ]; then
      echo -e "${RED}Error: Database URL cannot be empty.${RESET}" >&2
      exit 1
    fi
    DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
    while ! validate_boolean "$DB_SSL"; do
      echo -e "${RED}Error: Must be 'true' or 'false'.${RESET}" >&2
      DB_SSL=$(prompt_with_default "Require SSL with certificate verification (true/false)" "true")
    done
    ;;
  *)
    echo -e "${RED}Error: Invalid backend option '${BACKEND_OPTION}'. Choose 1, 2, or 3.${RESET}" >&2
    exit 1
    ;;
esac

# ------------------------------------------------------------------------------
# 6. Admin Bootstrap Password
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}--- Step 5: Admin Bootstrap Password ---${RESET}"
echo "Initial admin password used on first startup to log into Web UI and API."
NEWLY_GENERATED_ADMIN_PASS=false

if [ -n "$EXISTING_ADMIN_PASS" ]; then
  ADMIN_PASS="$EXISTING_ADMIN_PASS"
  echo -e "${GREEN}✓ Keeping current admin password setting.${RESET}"
else
  echo "1) Automatically generate a strong random password (Recommended)"
  echo "2) Manually enter custom admin password"
  ADMIN_PASS_OPTION=$(prompt_with_default "Select option" "1")

  if [ "$ADMIN_PASS_OPTION" = "1" ]; then
    ADMIN_PASS=$(generate_secret 16)
    NEWLY_GENERATED_ADMIN_PASS=true
  else
    ADMIN_PASS=$(prompt_password "Enter Admin Password")
    if [ -z "$ADMIN_PASS" ]; then
      echo -e "${RED}Error: Admin Password cannot be empty.${RESET}" >&2
      exit 1
    fi
  fi
fi

if [ "$NEWLY_GENERATED_ADMIN_PASS" = true ]; then
  echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}║  INITIAL ADMIN PASSWORD GENERATED                                      ║${RESET}"
  echo -e "${GREEN}║  Copy this password for initial login to the Web UI / REST API:         ║${RESET}"
  echo -e "${GREEN}║                                                                        ║${RESET}"
  echo -e "${BOLD}   ${ADMIN_PASS}${RESET}"
  echo -e "${GREEN}║                                                                        ║${RESET}"
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════╝${RESET}\n"
fi

# ------------------------------------------------------------------------------
# 7. Optional Settings
# ------------------------------------------------------------------------------
echo -e "${CYAN}--- Step 6: Web UI & Proxy Options ---${RESET}"
echo -e "${CYAN}Allowed Origins (CORS): the final HTTPS URL(s) users reach the Web UI through"
echo -e "(e.g. behind Caddy / Nginx). Plaintext http://localhost is fine for local-only testing.${RESET}"
ALLOWED_ORIGINS=$(prompt_with_default "Allowed Origins (CORS)" "https://vault.example.com")

# ── Egress allowlist (SV-058) ──────────────────────────────────────────────
# The previous prompt implied an empty value meant unrestricted access, which
# is misleading: an empty allowlist means NON-admin users cannot create any
# proxy destination (every destination is rejected because no origin is
# permitted). Only administrators can override this and create any destination
# — including private-network destinations with a separate opt-in. Make the
# effective semantics explicit, recommend a default-deny (empty) choice, and
# confirm the resulting boundary.
echo ""
echo -e "${BOLD}Egress Proxy Allowlist${RESET}"
echo -e "${CYAN}SecretVault's reverse proxy sends credentials to upstream APIs. By default it"
echo -e "is default-deny: non-admin users can only create proxy destinations whose exact"
echo -e "HTTPS origin is listed here. An empty allowlist therefore means non-admin users"
echo -e "cannot create any destination until you (or an admin) adds one."
echo -e ""
echo -e "Administrators can ALWAYS create a destination regardless of this list, and can"
echo -e "additionally opt a destination into private-network mode (RFC1918 / loopback) —"
echo -e "treat admin-created destinations as an explicit override of this boundary.${RESET}"
echo -e "${BOLD}Enter a comma-separated list of exact HTTPS origins to permit for non-admins.${RESET}"
echo -e "${CYAN}Recommended: leave empty for a strict default-deny, then add origins as needed.${RESET}"
EGRESS_ALLOWLIST=$(prompt_with_default "Permitted non-admin origins (empty = default-deny)" "")

echo ""
echo -e "${BOLD}Resulting egress boundary:${RESET}"
if [ -n "$EGRESS_ALLOWLIST" ]; then
  echo -e "  ${GREEN}Non-admin users${RESET} may create destinations to: ${YELLOW}${EGRESS_ALLOWLIST}${RESET}"
else
  echo -e "  ${YELLOW}Default-deny:${RESET} non-admin users cannot create any proxy destination until an origin is added."
fi
echo -e "  ${GREEN}Administrators${RESET} may create any destination (override), incl. private-network with a per-profile opt-in."
read -rp "$(echo -e "${BOLD}Proceed with this egress boundary? [Y/n]${RESET}: ")" confirm_egress < /dev/tty
if [ "${confirm_egress:-Y}" != "Y" ] && [ "${confirm_egress:-Y}" != "y" ]; then
  echo -e "${YELLOW}Egress configuration aborted by operator. Re-run the installer to try again.${RESET}"
  exit 1
fi


# ------------------------------------------------------------------------------
# 8. Write .env File & Restrict Permissions (safe encoding, no shell expansion)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}Writing .env configuration file...${RESET}"

ENV_TMP="${ENV_FILE}.tmp"

# Backup existing .env if present
if [ -f "$ENV_FILE" ]; then
  ENV_BACKUP="${ENV_FILE}.backup"
  cp "$ENV_FILE" "$ENV_BACKUP"
  chmod 600 "$ENV_BACKUP"
  echo -e "${GREEN}✓ Existing .env backed up to .env.backup${RESET}"
fi

# Clean up temp file on exit
cleanup_env_tmp() {
  rm -f "$ENV_TMP"
}
trap cleanup_env_tmp EXIT

# Quote a value for safe .env insertion (single-quote, escape embedded quotes)
env_quote() {
  local val="$1"
  local escaped
  escaped="${val//\'/\'\\\'\'}"
  printf "'%s'" "$escaped"
}

# Set restrictive umask so temp file is created with 600-equivalent perms
umask 077

{
  printf '# ── SecretVault Master Encryption Key ─────────────────────────────────\n'
  printf "SECRETVAULT_MASTER_KEY=%s\n" "$(env_quote "$MASTER_KEY")"

  printf '\n'
  printf '# ── Supabase / PostgREST Connectivity ─────────────────────────────────\n'
  printf "SECRETVAULT_SUPABASE_URL=%s\n" "$(env_quote "$SUPABASE_URL")"
  printf "SECRETVAULT_SUPABASE_SERVICE_KEY=%s\n" "$(env_quote "$SECRETVAULT_SUPABASE_SERVICE_KEY")"
  printf "SECRETVAULT_DATABASE_URL=%s\n" "$(env_quote "$DATABASE_URL")"
  printf "SECRETVAULT_DATABASE_SSL=%s\n" "${DB_SSL:-true}"

  printf '\n'
  printf '# ── Admin Bootstrap Password ──────────────────────────────────────────\n'
  printf "SECRETVAULT_UI_PASSWORD=%s\n" "$(env_quote "$ADMIN_PASS")"

  printf '\n'
  printf '# ── CORS & Egress Allowlist ───────────────────────────────────────────\n'
  printf "SECRETVAULT_ALLOWED_ORIGINS=%s\n" "$(env_quote "$ALLOWED_ORIGINS")"
  printf "SECRETVAULT_EGRESS_ALLOWLIST=%s\n" "$(env_quote "$EGRESS_ALLOWLIST")"
  printf 'SECRETVAULT_PROXY_TIMEOUT_MS=30000\n'

  # Bundled-mode credentials. Present only when the operator chose the bundled
  # backend so docker-compose.bundled.yml can resolve its required variables.
  if [ "$BUNDLED_MODE" = true ]; then
    printf '\n'
    printf '# ── Bundled PostgreSQL + PostgREST (docker-compose.bundled.yml) ───────\n'
    printf "POSTGRES_DB=%s\n" "$(env_quote "$POSTGRES_DB")"
    printf "POSTGRES_USER=%s\n" "$(env_quote "$POSTGRES_USER")"
    printf "POSTGRES_PASSWORD=%s\n" "$(env_quote "$POSTGRES_PASSWORD")"
    printf "PGRST_JWT_SECRET=%s\n" "$(env_quote "$PGRST_JWT_SECRET")"
  fi
} > "$ENV_TMP"

# Atomic replace
mv "$ENV_TMP" "$ENV_FILE"
chmod 600 "$ENV_FILE"
echo -e "${GREEN}✓ .env file created with restricted permissions and safe encoding.${RESET}"

# ------------------------------------------------------------------------------
# 9. Start Container Service & Health Verification
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}Starting SecretVault Docker stack...${RESET}"
if [ "$BUNDLED_MODE" = true ]; then
  echo -e "${CYAN}(bundled mode: docker compose -f docker-compose.yml -f docker-compose.bundled.yml)${RESET}"
fi
"$DOCKER_COMPOSE_CMD" "${COMPOSE_FILES[@]}" up -d --build

echo -e "\n${BOLD}Verifying SecretVault health checks (/health/live then /health/ready)...${RESET}"
# Bundled mode boots postgres -> migrate -> postgrest -> proxy -> app, so the
# app can take meaningfully longer than the external-DB path to become ready.
# Poll /health/live first (process up), then /health/ready (DB reachable).
MAX_ATTEMPTS=40
HEALTHY=false
for i in $(seq 1 "$MAX_ATTEMPTS"); do
  if curl -fsS http://localhost:3004/health/ready 2>/dev/null | grep -q '"status":"ok"'; then
    HEALTHY=true
    break
  fi
  # Liveness is a cheap signal the container is at least serving HTTP.
  curl -fsS http://localhost:3004/health/live >/dev/null 2>&1 && \
    echo -e "  ${YELLOW}liveness OK, waiting for readiness (attempt ${i}/${MAX_ATTEMPTS})...${RESET}" || \
    echo -e "  ${YELLOW}waiting for container to start (attempt ${i}/${MAX_ATTEMPTS})...${RESET}"
  sleep 2
done

if [ "$HEALTHY" = true ]; then
  echo -e "\n${GREEN}========================================================================${RESET}"
  echo -e "${GREEN}       🎉 SECRETVAULT SERVER DEPLOYMENT COMPLETE & HEALTHY             ${RESET}"
  echo -e "${GREEN}========================================================================${RESET}"
  echo -e "  Server Status:  ${GREEN}HEALTHY (HTTP 200 OK)${RESET}"
  if [ "$BUNDLED_MODE" = true ]; then
    echo -e "  Backend:        ${GREEN}Bundled local PostgreSQL + PostgREST${RESET}"
  fi
  echo -e "  Server URL:     ${ALLOWED_ORIGINS%%,*}"
  echo -e "  Web UI:         ${ALLOWED_ORIGINS%%,*}/ui"
  echo -e "  REST API:       ${ALLOWED_ORIGINS%%,*}/api"
  echo -e "  (loopback: http://localhost:3004)"
  echo -e "------------------------------------------------------------------------"
  echo -e "${YELLOW}⚠  TLS REQUIRED FOR EXTERNAL ACCESS (SV-020):${RESET}"
  echo -e "  The listener is published on loopback only. Put a TLS-terminating reverse"
  echo -e "  proxy (Caddy / Nginx / Tailscale Serve) in front before exposing it on the"
  echo -e "  network — see docs/install.md. Never send passwords or setup codes over"
  echo -e "  externally reachable plaintext HTTP."
  echo -e "${YELLOW}IMPORTANT CREDENTIALS (SAVE/BACK UP THESE VALUES NOW):${RESET}"
  echo -e "  Master Encryption Key: ${BOLD}${MASTER_KEY}${RESET}"
  echo -e "  Initial Admin Password: ${BOLD}${ADMIN_PASS}${RESET}"
  echo -e "------------------------------------------------------------------------"
  echo -e "  ${CYAN}Next Step:${RESET} Run 'secretvault-mcp setup' on developer machines to"
  echo -e "             connect AI tools (Antigravity IDE, Claude Code, OpenCode)."
  echo -e "${GREEN}========================================================================${RESET}\n"
else
  echo -e "\n${RED}Error: SecretVault container started, but /health/ready check failed after $((MAX_ATTEMPTS * 2))s.${RESET}"
  echo "Check container logs using: $DOCKER_COMPOSE_CMD ${COMPOSE_FILES[*]} logs secretvault-mcp"
  exit 1
fi
}

main "$@"

