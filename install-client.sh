#!/usr/bin/env bash

# ==============================================================================
# SecretVault Client Setup Wizard 1-Liner Script
# Supports:
# curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
#
# Supply-chain hardening (SV-AUD-012): for a verified install, export
#   SECRETVAULT_RELEASE_TAG=<git tag or 40-char commit SHA>
#   SECRETVAULT_TARBALL_SHA256=<sha256 of the tag's source tarball>
# The installer then fetches that immutable ref (never mutable `main`) and
# verifies the SHA-256 before building, failing closed on any mismatch.
# Without both values it falls back to `main` and prints a warning.
# ==============================================================================

set -euo pipefail

main() {
  # ANSI Colors
  CYAN="\033[1;36m"
  GREEN="\033[1;32m"
  YELLOW="\033[1;33m"
  RED="\033[1;31m"
  RESET="\033[0m"

  VERSION="v0.1.8"

  # SV-AUD-012: fail-closed SHA-256 verification (see install-server.sh).
  verify_sha256() {
    local file="$1"
    local expected="$2"
    if [ -z "$expected" ]; then
      echo -e "${RED}Integrity verification requested but no checksum was provided. Aborting (fail-closed).${RESET}" >&2
      exit 1
    fi
    if [ ! -f "$file" ]; then
      echo -e "${RED}Integrity verification failed: ${file} not found. Aborting (fail-closed).${RESET}" >&2
      exit 1
    fi
    local actual=""
    if command -v sha256sum &>/dev/null; then
      actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
      echo -e "${RED}No sha256sum/shasum available to verify artifact integrity. Aborting (fail-closed).${RESET}" >&2
      exit 1
    fi
    if [ "$actual" != "$expected" ]; then
      echo -e "${RED}Integrity verification FAILED for ${file}: expected ${expected}, got ${actual}. Aborting (fail-closed).${RESET}" >&2
      exit 1
    fi
    echo -e "${GREEN}✓ Integrity verified (sha256 ${actual:0:16}…).${RESET}"
  }

  echo -e "${CYAN}"
  echo "════════════════════════════════════════════════════════════════════════"
  echo "       ⚡ SecretVault Client Setup & Tool Configurator (${VERSION})      "
  echo "════════════════════════════════════════════════════════════════════════"
  echo -e "${RESET}"

  # 1. Verify Node.js & npx
  if ! command -v node &>/dev/null; then
    echo -e "${RED}Error: Node.js (version 18+) is required to run SecretVault Client Setup.${RESET}" >&2
    echo "Please install Node.js from https://nodejs.org or using your system package manager."
    exit 1
  fi

  if ! command -v npx &>/dev/null; then
    echo -e "${RED}Error: npx is required to launch SecretVault Client Setup.${RESET}" >&2
    exit 1
  fi

  echo -e "${GREEN}✓ Node.js $(node -v) detected.${RESET}\n"

  # 2. Launch Client Setup Wizard
  echo -e "${CYAN}Fetching SecretVault setup wizard...${RESET}\n"

  TMP_DIR=$(mktemp -d)
  cleanup() {
    rm -rf "$TMP_DIR"
  }
  trap cleanup EXIT

  # SV-AUD-012: prefer an immutable release ref over mutable `main`.
  RELEASE_REF="${SECRETVAULT_RELEASE_TAG:-main}"
  EXPECTED_SHA256="${SECRETVAULT_TARBALL_SHA256:-}"
  ARCHIVE_REF="$RELEASE_REF"
  if [ "$RELEASE_REF" = "main" ]; then
    ARCHIVE_REF="refs/heads/main"
  fi

  if [ "$RELEASE_REF" = "main" ]; then
    echo -e "${YELLOW}WARNING (SV-AUD-012): SECRETVAULT_RELEASE_TAG not set — fetching mutable 'main'. Set SECRETVAULT_RELEASE_TAG and SECRETVAULT_TARBALL_SHA256 for a verified, immutable install.${RESET}"
  else
    echo -e "${GREEN}Fetching immutable release ref '${RELEASE_REF}'.${RESET}"
  fi

  if command -v git &>/dev/null; then
    echo -e "${CYAN}Cloning repository...${RESET}"
    if printf '%s' "$RELEASE_REF" | grep -Eq '^[0-9a-f]{40}$'; then
      git clone --depth 1 https://github.com/itsaygea/secretvault.git "$TMP_DIR" &>/dev/null
      git -C "$TMP_DIR" fetch --depth 1 origin "$RELEASE_REF" &>/dev/null
      git -C "$TMP_DIR" checkout "$RELEASE_REF" &>/dev/null
    else
      git clone --depth 1 --branch "$RELEASE_REF" https://github.com/itsaygea/secretvault.git "$TMP_DIR" &>/dev/null
    fi
  else
    echo -e "${CYAN}Downloading repository archive...${RESET}"
    mkdir -p "$TMP_DIR"
    TARBALL="$(mktemp)"
    trap 'rm -f "$TARBALL"; rm -rf "$TMP_DIR"' EXIT
    curl -fsSL "https://github.com/itsaygea/secretvault/archive/${ARCHIVE_REF}.tar.gz" -o "$TARBALL"
    if [ -n "$EXPECTED_SHA256" ]; then
      verify_sha256 "$TARBALL" "$EXPECTED_SHA256"
    elif [ "$RELEASE_REF" != "main" ]; then
      echo -e "${RED}Immutable ref '${RELEASE_REF}' requested without SECRETVAULT_TARBALL_SHA256 — refusing to install unverified. Aborting (fail-closed).${RESET}" >&2
      exit 1
    fi
    tar -xz -C "$TMP_DIR" --strip-components=1 -f "$TARBALL"
    rm -f "$TARBALL"
  fi

  cd "$TMP_DIR"
  echo -e "${CYAN}Installing dependencies...${RESET}"
  npm ci --ignore-scripts &>/dev/null
  echo -e "${CYAN}Building packages...${RESET}"
  npm run build &>/dev/null

  echo -e "${CYAN}Installing SecretVault CLI binaries (secretvault, secretvault-cli, secretvault-mcp, securevault)...${RESET}"
  rm -f "$HOME/.local/bin/secretvault" "$HOME/.local/bin/secretvault-cli" "$HOME/.local/bin/secretvault-mcp" "$HOME/.local/bin/securevault" "$HOME/.local/bin/securevault-cli" &>/dev/null || true
  # SV-AUD-012: install is fail-closed — a failed CLI install must surface, not be swallowed.
  npm install -g ./packages/mcp-server --force &>/dev/null || npm install -g ./packages/mcp-server --prefix="$HOME/.local" --force &>/dev/null

  mkdir -p "$HOME/.local/bin"
  NODE_BIN_DIR="$(node -e 'console.log(require("path").dirname(process.execPath))' 2>/dev/null || true)"
  if [ -n "$NODE_BIN_DIR" ] && [ -x "$NODE_BIN_DIR/secretvault" ]; then
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault")" "$HOME/.local/bin/secretvault" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault-cli")" "$HOME/.local/bin/secretvault-cli" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault-mcp")" "$HOME/.local/bin/secretvault-mcp" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault")" "$HOME/.local/bin/securevault" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault-cli")" "$HOME/.local/bin/securevault-cli" 2>/dev/null || true
  fi

  if command -v secretvault &>/dev/null || [ -x "$HOME/.local/bin/secretvault" ]; then
    echo -e "${GREEN}✓ SecretVault CLI binaries ('secretvault', 'securevault') installed to PATH.${RESET}\n"
  fi

  echo -e "${GREEN}✓ Environment ready. Launching setup...${RESET}\n"
  if [ -e /dev/tty ]; then
    if command -v secretvault &>/dev/null; then
      secretvault setup "$@" < /dev/tty
    elif command -v secretvault-mcp &>/dev/null; then
      secretvault-mcp setup "$@" < /dev/tty
    else
      node packages/mcp-server/dist/index.js setup "$@" < /dev/tty
    fi
  else
    if command -v secretvault &>/dev/null; then
      secretvault setup "$@"
    elif command -v secretvault-mcp &>/dev/null; then
      secretvault-mcp setup "$@"
    else
      node packages/mcp-server/dist/index.js setup "$@"
    fi
  fi
}

main "$@"

