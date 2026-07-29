#!/usr/bin/env bash

# ==============================================================================
# SecretVault Client Setup Wizard 1-Liner Script
# Supports:
# curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
# ==============================================================================

set -eo pipefail

main() {
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

  VERSION="v0.1.4"

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

  if command -v git &>/dev/null; then
    echo -e "${CYAN}Cloning repository...${RESET}"
    git clone --depth 1 https://github.com/itsaygea/secretvault.git "$TMP_DIR" &>/dev/null
  else
    echo -e "${CYAN}Downloading repository archive...${RESET}"
    mkdir -p "$TMP_DIR"
    curl -fsSL https://github.com/itsaygea/secretvault/archive/refs/heads/main.tar.gz | tar -xz -C "$TMP_DIR" --strip-components=1 &>/dev/null
  fi

  cd "$TMP_DIR"
  echo -e "${CYAN}Installing dependencies...${RESET}"
  npm ci --ignore-scripts &>/dev/null
  echo -e "${CYAN}Building packages...${RESET}"
  npm run build &>/dev/null

  echo -e "${CYAN}Installing secretvault-mcp CLI binary...${RESET}"
  npm install -g . &>/dev/null || npm install -g . --prefix="$HOME/.local" &>/dev/null || true

  if command -v secretvault-mcp &>/dev/null; then
    echo -e "${GREEN}✓ secretvault-mcp CLI installed to PATH.${RESET}\n"
  elif [ -x "$HOME/.local/bin/secretvault-mcp" ]; then
    echo -e "${GREEN}✓ secretvault-mcp CLI installed to ~/.local/bin/secretvault-mcp.${RESET}"
    echo -e "${YELLOW}Note: Add ~/.local/bin to your PATH if not already present.${RESET}\n"
  fi

  echo -e "${GREEN}✓ Environment ready. Launching setup...${RESET}\n"
  if command -v secretvault-mcp &>/dev/null; then
    secretvault-mcp setup "$@"
  else
    node packages/mcp-server/dist/index.js setup "$@"
  fi
}

main "$@"

