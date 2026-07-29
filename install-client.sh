#!/usr/bin/env bash

# ==============================================================================
# SecretVault Client Setup Wizard 1-Liner Script
# Supports:
# curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
# ==============================================================================

set -eo pipefail

# Attach stdin to TTY if available (required for curl | bash execution)
if [ -t 0 ]; then
  : # Running directly in terminal
elif [ -e /dev/tty ]; then
  exec < /dev/tty 2>/dev/null || true
fi

# ANSI Colors
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "════════════════════════════════════════════════════════════════════════"
echo "       ⚡ SecretVault Client Setup & Tool Configurator                   "
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

if command -v git &>/dev/null; then
  git clone --depth 1 https://github.com/itsaygea/secretvault.git "$TMP_DIR" &>/dev/null
else
  mkdir -p "$TMP_DIR"
  curl -fsSL https://github.com/itsaygea/secretvault/archive/refs/heads/main.tar.gz | tar -xz -C "$TMP_DIR" --strip-components=1 &>/dev/null
fi

cd "$TMP_DIR"
npm ci --ignore-scripts &>/dev/null
npm run build &>/dev/null

node packages/mcp-server/dist/index.js setup "$@"
