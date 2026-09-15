#!/usr/bin/env bash

# ==============================================================================
# SecretVault Server Safe Updater
#
# Updates an existing source-checkout deployment to an immutable GitHub commit.
# The updater:
#   - resolves main to a 40-character commit SHA when no ref is supplied;
#   - refuses tracked local changes and never uses reset --hard or down -v;
#   - backs up .env, the project tree, the secretvault schema, and PostgreSQL
#     globals before changing the checkout;
#   - detects bundled, external/shared/HA PostgreSQL, and Caddy Compose modes;
#   - runs the existing Compose stack's migrations and verifies readiness.
#
# Usage from an existing checkout:
#   bash upgrade-server.sh
#   bash upgrade-server.sh --yes --dir /opt/secretvault
#   SECRETVAULT_UPDATE_REF=<40-char-commit> bash upgrade-server.sh --yes
#
# Registry-image deployments are intentionally refused. Use the registry-image
# procedure in docs/upgrade.md because an application commit cannot safely be
# inferred from an arbitrary image digest.
# ==============================================================================

set -euo pipefail
umask 077

readonly UPDATE_REPOSITORY="itsaygea/secretvault"
readonly UPDATE_REPOSITORY_URL="https://github.com/${UPDATE_REPOSITORY}.git"
readonly UPDATE_API_URL="https://api.github.com/repos/${UPDATE_REPOSITORY}/commits/main"
readonly COMMIT_SHA_RE='^[0-9a-fA-F]{40}$'

APP_DIR="${SECRETVAULT_SERVER_DIR:-${SECRETVAULT_DEPLOY_DIR:-$PWD}}"
RELEASE_REF="${SECRETVAULT_UPDATE_REF:-${SECRETVAULT_RELEASE_TAG:-}}"
BACKUP_ROOT="${SECRETVAULT_BACKUP_DIR:-}"
COMPOSE_MODE="${SECRETVAULT_COMPOSE_MODE:-auto}"
DRY_RUN=false
ASSUME_YES=false

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

WORK_DIR=""
BACKUP_DIR=""
ENV_FILE=""
COMPOSE_BIN=()
COMPOSE_FILES=()
USE_BUNDLED=false
USE_CADDY=false
USE_DIST=false
TRACKED_DIRTY=false

die() {
  echo -e "${RED}Error: $*${RESET}" >&2
  exit 1
}

notice() {
  echo -e "${CYAN}$*${RESET}"
}

ok() {
  echo -e "${GREEN}✓ $*${RESET}"
}

warn() {
  echo -e "${YELLOW}Warning: $*${RESET}" >&2
}

usage() {
  cat <<'USAGE'
SecretVault server updater

Usage:
  upgrade-server.sh [options]

Options:
  --dir <path>       Existing SecretVault source checkout (default: current dir)
  --ref <sha>        Exact 40-character release commit; otherwise main is resolved
  --backup-dir <dir> Backup root (default: sibling <dir>-backups)
  --yes              Skip the final confirmation prompt
  --dry-run          Resolve and validate the update plan without changing files
  --help             Show this help

Environment:
  SECRETVAULT_UPDATE_REF       Exact 40-character commit SHA
  SECRETVAULT_COMPOSE_MODE     auto, external, bundled, caddy, bundled-caddy, or dist
  SECRETVAULT_BACKUP_DIR       Backup root override

The updater requires a Git checkout and never prints .env or database values.
Registry-image deployments must use the registry upgrade procedure instead.
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dir)
        [ "$#" -ge 2 ] || die "--dir requires a path"
        APP_DIR="$2"
        shift 2
        ;;
      --ref)
        [ "$#" -ge 2 ] || die "--ref requires a 40-character commit SHA"
        RELEASE_REF="$2"
        shift 2
        ;;
      --backup-dir)
        [ "$#" -ge 2 ] || die "--backup-dir requires a path"
        BACKUP_ROOT="$2"
        shift 2
        ;;
      --yes)
        ASSUME_YES=true
        shift
        ;;
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown option '$1' (use --help)"
        ;;
    esac
  done
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' was not found"
}

validate_app_dir() {
  [ -n "$APP_DIR" ] || die "deployment directory cannot be empty"
  case "$APP_DIR" in
    /|/root|/home|/var|/opt|/tmp)
      die "refusing to use a broad directory as the deployment root: $APP_DIR"
      ;;
  esac
  [ -d "$APP_DIR" ] || die "deployment directory does not exist: $APP_DIR"
  APP_DIR="$(cd -- "$APP_DIR" && pwd -P)"
  ENV_FILE="$APP_DIR/.env"
  [ -f "$APP_DIR/docker-compose.yml" ] || die "docker-compose.yml was not found in $APP_DIR"
  [ -f "$ENV_FILE" ] || die ".env was not found in $APP_DIR"
  [ ! -L "$ENV_FILE" ] || die ".env must not be a symbolic link"

  if [ -z "$BACKUP_ROOT" ]; then
    BACKUP_ROOT="${APP_DIR}-backups"
  fi
  BACKUP_ROOT="${BACKUP_ROOT%/}"
  case "$BACKUP_ROOT" in
    /|/root|/home|/var|/opt|/tmp)
      die "refusing to use a broad directory as the backup root: $BACKUP_ROOT"
      ;;
  esac
  case "$BACKUP_ROOT" in
    "$APP_DIR"|"$APP_DIR"/*)
      die "backup directory must be outside the deployment directory"
      ;;
  esac
}

read_env_value() {
  local key="$1"
  local line=""
  local value=""

  line="$(awk -v wanted="${key}=" 'index($0, wanted) == 1 { line = $0 } END { print line }' "$ENV_FILE")"
  [ -n "$line" ] || return 1
  value="${line#*=}"

  # install-server.sh writes single-quoted values. Strip only a matching pair;
  # never eval or source .env because it contains credential material.
  if [[ "$value" == \'*\' ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" == \"*\" ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

validate_commit() {
  [[ "$1" =~ $COMMIT_SHA_RE ]]
}

resolve_release_ref() {
  if [ -z "$RELEASE_REF" ]; then
    require_command curl
    local payload=""
    payload="$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --max-time 30 -H 'Accept: application/vnd.github+json' \
      -H 'User-Agent: secretvault-server-updater' "$UPDATE_API_URL")"
    RELEASE_REF="$(printf '%s' "$payload" \
      | grep -oE '"sha"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]{40}"' \
      | head -n 1 \
      | sed -E 's/.*"([0-9a-fA-F]{40})"/\1/' || true)"
  fi
  validate_commit "$RELEASE_REF" || die "release ref must be an exact 40-character commit SHA; mutable tags are refused"
  RELEASE_REF="$(printf '%s' "$RELEASE_REF" | tr '[:upper:]' '[:lower:]')"
}

select_compose_binary() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_BIN=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_BIN=(docker-compose)
  else
    die "Docker Compose was not found"
  fi
}

compose() {
  "${COMPOSE_BIN[@]}" --env-file "$ENV_FILE" "${COMPOSE_FILES[@]}" "$@"
}

detect_compose_mode() {
  local labels=""
  labels="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' \
    secretvault-mcp 2>/dev/null || true)"

  if [ "$COMPOSE_MODE" = "auto" ]; then
    USE_BUNDLED=false
    USE_CADDY=false
    USE_DIST=false
    if [[ "$labels" == *docker-compose.bundled.yml* ]] || \
       { [ -z "$labels" ] && grep -q '^POSTGRES_PASSWORD=' "$ENV_FILE" && grep -q '^PGRST_JWT_SECRET=' "$ENV_FILE"; }; then
      USE_BUNDLED=true
    fi
    [[ "$labels" == *docker-compose.caddy.yml* ]] && USE_CADDY=true
    [[ "$labels" == *docker-compose.dist.yml* ]] && USE_DIST=true
  else
    case "$COMPOSE_MODE" in
      external) ;;
      bundled) USE_BUNDLED=true ;;
      caddy) USE_CADDY=true ;;
      bundled-caddy) USE_BUNDLED=true; USE_CADDY=true ;;
      dist) USE_DIST=true ;;
      *) die "unsupported SECRETVAULT_COMPOSE_MODE '$COMPOSE_MODE'" ;;
    esac
  fi

  [ "$USE_DIST" = false ] || die "registry-image deployments are not handled by this source updater; use the registry-image procedure in docs/upgrade.md"

  COMPOSE_FILES=(-f "$APP_DIR/docker-compose.yml")
  if [ "$USE_BUNDLED" = true ]; then
    [ -f "$APP_DIR/docker-compose.bundled.yml" ] || die "bundled Compose overlay is missing"
    COMPOSE_FILES+=(-f "$APP_DIR/docker-compose.bundled.yml")
  fi
  if [ "$USE_CADDY" = true ]; then
    [ -f "$APP_DIR/docker-compose.caddy.yml" ] || die "Caddy Compose overlay is missing"
    COMPOSE_FILES+=(-f "$APP_DIR/docker-compose.caddy.yml")
  fi
}

check_git_state() {
  git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 || \
    die "$APP_DIR is not a Git checkout; the safe updater will not overwrite a non-Git deployment"
  require_command git
  [ -n "$(git -C "$APP_DIR" branch --show-current)" ] || \
    die "deployment checkout is detached; check it out on a release branch before upgrading"

  if ! git -C "$APP_DIR" diff --cached --quiet; then
    die "tracked changes are present in $APP_DIR; commit or stash them before upgrading"
  fi
  if ! git -C "$APP_DIR" diff --quiet; then
    TRACKED_DIRTY=true
    warn "tracked files differ from the current Git commit; the updater will only adopt them if they exactly match the requested release"
  fi

  local untracked_count=""
  untracked_count="$(git -C "$APP_DIR" status --porcelain --untracked-files=all | awk 'substr($0, 1, 2) == "??" { count++ } END { print count + 0 }')"
  if [ "$untracked_count" -gt 0 ]; then
    warn "$untracked_count untracked file(s) will be preserved; the Git update will stop if a release would overwrite one"
  fi
}

acquire_lock() {
  mkdir -p "$BACKUP_ROOT"
  chmod 700 "$BACKUP_ROOT"
  local lock_file="$BACKUP_ROOT/.server-upgrade.lock"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$lock_file"
    flock -n 9 || die "another SecretVault server update is already running"
  else
    die "flock is required to prevent concurrent server updates"
  fi
}

confirm_plan() {
  notice "SecretVault server update plan"
  echo "  Deployment: $APP_DIR"
  echo "  Release:    ${RELEASE_REF:0:12}…"
  if [ "$USE_BUNDLED" = true ]; then
    echo "  Database:   bundled PostgreSQL Compose service"
  else
    echo "  Database:   external PostgreSQL (including shared/HA deployments)"
  fi
  if [ "$USE_CADDY" = true ]; then
    echo "  TLS:        Caddy Compose overlay"
  fi
  echo "  Backup:     $BACKUP_ROOT"

  [ "$DRY_RUN" = true ] && return 0
  [ "$ASSUME_YES" = true ] && return 0

  if [ -e /dev/tty ]; then
    local answer=""
    read -r -p "Continue after creating the backup? [y/N] " answer < /dev/tty
    [[ "$answer" =~ ^[Yy]$ ]] || die "update cancelled"
  else
    die "non-interactive update requires --yes"
  fi
}

prepare_backup_dir() {
  local timestamp=""
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP_DIR="$BACKUP_ROOT/$timestamp"
  if [ -e "$BACKUP_DIR" ]; then
    BACKUP_DIR="${BACKUP_DIR}-$$"
  fi
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
}

backup_project() {
  notice "Creating deployment backup"
  cp -- "$ENV_FILE" "$BACKUP_DIR/.env"
  chmod 600 "$BACKUP_DIR/.env"

  tar -czf "$BACKUP_DIR/secretvault-project.tgz" \
    --exclude='./.git' \
    --exclude='./.env' \
    --exclude='./.env.*' \
    --exclude='./node_modules' \
    --exclude='./dist' \
    --exclude='*.key' \
    --exclude='*.dump' \
    --exclude='*.log' \
    -C "$APP_DIR" .
}

prepare_password_safe_dsn() {
  local url="$1"
  local user_prefix=""
  local encoded_password=""
  local authority=""
  PG_DSN="$url"
  unset PGPASSWORD

  # Remove the password from the process argument while passing it through the
  # environment accepted by libpq. URL-escaped @ characters remain safe here;
  # the first unescaped @ terminates the user-info component.
  if [[ "$url" =~ ^(postgres(ql)?://[^:/@]+):([^@]*)@(.*)$ ]]; then
    user_prefix="${BASH_REMATCH[1]}"
    encoded_password="${BASH_REMATCH[3]}"
    authority="${BASH_REMATCH[4]}"
    PGPASSWORD="$(url_decode_component "$encoded_password")"
    PG_DSN="${user_prefix}@${authority}"
    export PGPASSWORD
  fi
}

url_decode_component() {
  local encoded="$1"
  local decoded=""
  local index=0
  local char=""
  local hex=""
  local byte=""
  while [ "$index" -lt "${#encoded}" ]; do
    char="${encoded:index:1}"
    if [ "$char" = '%' ] && [ "$((index + 2))" -lt "${#encoded}" ]; then
      hex="${encoded:index+1:2}"
      if [[ "$hex" =~ ^[0-9a-fA-F]{2}$ ]]; then
        printf -v byte '%b' "\\x${hex}"
        decoded+="$byte"
        index=$((index + 3))
        continue
      fi
    fi
    decoded+="$char"
    index=$((index + 1))
  done
  printf '%s' "$decoded"
}

backup_database() {
  notice "Creating database backup"
  if [ "$USE_BUNDLED" = true ]; then
    local postgres_user="secretvault"
    local postgres_db="secretvault"
    postgres_user="$(read_env_value POSTGRES_USER || printf '%s' 'secretvault')"
    postgres_db="$(read_env_value POSTGRES_DB || printf '%s' 'secretvault')"
    compose ps -q postgres | grep -q . || die "bundled postgres service is not running; start the stack before upgrading"
    compose exec -T postgres pg_dump -U "$postgres_user" -d "$postgres_db" \
      --schema=secretvault --format=custom > "$BACKUP_DIR/secretvault.pg_dump"
    compose exec -T postgres pg_dumpall -U "$postgres_user" --globals-only > "$BACKUP_DIR/postgres-globals.sql"
  else
    require_command pg_dump
    require_command pg_dumpall
    local database_url=""
    database_url="$(read_env_value SECRETVAULT_DATABASE_URL || true)"
    [ -n "$database_url" ] || die "SECRETVAULT_DATABASE_URL is missing from .env"
    local PG_DSN=""
    prepare_password_safe_dsn "$database_url"
    pg_dump --dbname="$PG_DSN" --schema=secretvault --format=custom \
      --file="$BACKUP_DIR/secretvault.pg_dump"
    pg_dumpall --dbname="$PG_DSN" --globals-only > "$BACKUP_DIR/postgres-globals.sql"
    unset PGPASSWORD PG_DSN
  fi
}

write_backup_manifest() {
  printf 'created_utc=%s\nrelease=%s\ncompose_mode=%s\nbundled_postgres=%s\ncaddy_overlay=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RELEASE_REF" "$COMPOSE_MODE" \
    "$USE_BUNDLED" "$USE_CADDY" > "$BACKUP_DIR/metadata.txt"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$BACKUP_DIR" && sha256sum .env secretvault-project.tgz secretvault.pg_dump postgres-globals.sql metadata.txt > SHA256SUMS)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$BACKUP_DIR" && shasum -a 256 .env secretvault-project.tgz secretvault.pg_dump postgres-globals.sql metadata.txt > SHA256SUMS)
  else
    die "sha256sum or shasum is required to manifest the backup"
  fi
  chmod 600 "$BACKUP_DIR/SHA256SUMS" "$BACKUP_DIR/metadata.txt"
  ok "Backup complete: $BACKUP_DIR"
}

backup_all() {
  prepare_backup_dir
  backup_project
  backup_database
  write_backup_manifest
}

fetch_release() {
  notice "Fetching immutable release ${RELEASE_REF:0:12}…"
  GIT_TERMINAL_PROMPT=0 git -C "$APP_DIR" fetch --no-tags --depth 1 "$UPDATE_REPOSITORY_URL" "$RELEASE_REF"
  local fetched=""
  fetched="$(git -C "$APP_DIR" rev-parse FETCH_HEAD)"
  [ "$fetched" = "$RELEASE_REF" ] || die "fetched commit did not match the requested immutable release"
}

apply_release() {
  local branch=""
  branch="$(git -C "$APP_DIR" branch --show-current)"
  [ -n "$branch" ] || die "deployment checkout is detached; check it out on a release branch before upgrading"
  git -C "$APP_DIR" merge --ff-only --no-edit FETCH_HEAD
  local applied=""
  applied="$(git -C "$APP_DIR" rev-parse HEAD)"
  [ "$applied" = "$RELEASE_REF" ] || die "checkout did not advance to the requested release"
}

adopt_matching_release() {
  local target="$1"
  local branch=""
  local current=""
  branch="$(git -C "$APP_DIR" branch --show-current)"
  current="$(git -C "$APP_DIR" rev-parse HEAD)"

  if ! git -C "$APP_DIR" diff --quiet "$target" --; then
    die "tracked checkout differs from the requested release; refusing to overwrite local changes"
  fi

  # An untracked file with a path that the release now tracks would be
  # overwritten by a future checkout. Refuse that case instead of guessing
  # whether the file is disposable.
  while IFS= read -r -d '' path; do
    if git -C "$APP_DIR" cat-file -e "$target:$path" 2>/dev/null; then
      die "untracked file would conflict with the requested release: $path"
    fi
  done < <(git -C "$APP_DIR" ls-files --others --exclude-standard -z)

  # The working tree already contains the requested release (for example,
  # after a prior rsync deployment). Move only the branch ref and index; do not
  # rewrite any application file or remove any operator-owned untracked file.
  git -C "$APP_DIR" update-ref "refs/heads/$branch" "$target" "$current"
  git -C "$APP_DIR" read-tree "$target"
  git -C "$APP_DIR" diff --quiet "$target" -- || die "release adoption changed the tracked working tree unexpectedly"
  git -C "$APP_DIR" diff --cached --quiet || die "release adoption left staged changes unexpectedly"
  ok "adopted the already-deployed tracked files into the immutable Git release"
}

verify_compose_config() {
  compose config --quiet
}

wait_for_readiness() {
  notice "Waiting for SecretVault readiness"
  local attempts=60
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if compose exec -T secretvault-mcp wget -qO- http://127.0.0.1:3004/health/ready 2>/dev/null \
      | grep -q '"status":"ok"'; then
      ok "SecretVault is ready"
      return 0
    fi
    sleep 2
  done
  return 1
}

deploy_release() {
  notice "Applying the release with the existing Compose topology"
  verify_compose_config || die "updated Compose configuration is invalid; no container restart was attempted"
  compose up -d --build
  if ! wait_for_readiness; then
    echo -e "${RED}SecretVault did not become ready after 120 seconds.${RESET}" >&2
    echo "The database backup is at: $BACKUP_DIR" >&2
    echo "Do not restore an older application image across forward-only migrations without also restoring the database backup." >&2
    echo "Inspect with: docker compose ${COMPOSE_FILES[*]} logs secretvault-mcp" >&2
    return 1
  fi
}

cleanup() {
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR"
  fi
}

main() {
  parse_args "$@"
  trap cleanup EXIT

  require_command awk
  require_command date
  require_command docker
  require_command grep
  require_command sed
  require_command tar
  require_command tr

  validate_app_dir
  select_compose_binary
  detect_compose_mode
  check_git_state
  resolve_release_ref

  local current_commit=""
  current_commit="$(git -C "$APP_DIR" rev-parse HEAD)"
  if [ "$current_commit" = "$RELEASE_REF" ]; then
    ok "deployment is already at ${RELEASE_REF:0:12}…"
    exit 0
  fi

  verify_compose_config || die "current Compose configuration is invalid; no update was attempted"
  if [ "$DRY_RUN" = false ]; then
    acquire_lock
  fi
  confirm_plan
  if [ "$DRY_RUN" = true ]; then
    ok "dry run complete; no files or containers were changed"
    exit 0
  fi

  backup_all
  fetch_release
  if [ "$TRACKED_DIRTY" = true ]; then
    adopt_matching_release "$RELEASE_REF"
  else
    apply_release
  fi
  deploy_release

  echo -e "${GREEN}========================================================================${RESET}"
  echo -e "${GREEN}       SecretVault server update completed successfully                 ${RESET}"
  echo -e "${GREEN}========================================================================${RESET}"
  echo "  Release: ${RELEASE_REF}"
  echo "  Backup:  $BACKUP_DIR"
}

main "$@"
