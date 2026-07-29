#!/usr/bin/env bash

# ==============================================================================
# SecretVault Client Setup Wizard 1-Liner Script
# Supports:
# curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash
# ==============================================================================

main() {
  # ANSI Colors
  CYAN="\033[1;36m"
  GREEN="\033[1;32m"
  YELLOW="\033[1;33m"
  RED="\033[1;31m"
  RESET="\033[0m"

  VERSION="v0.1.8"

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

  echo -e "${CYAN}Installing SecretVault CLI binaries (secretvault, secretvault-cli, secretvault-mcp)...${RESET}"
  rm -f "$HOME/.local/bin/secretvault" "$HOME/.local/bin/secretvault-cli" "$HOME/.local/bin/secretvault-mcp" &>/dev/null || true
  npm install -g ./packages/mcp-server --force &>/dev/null || npm install -g ./packages/mcp-server --prefix="$HOME/.local" --force &>/dev/null || true

  mkdir -p "$HOME/.local/bin"
  NODE_BIN_DIR="$(node -e 'console.log(require("path").dirname(process.execPath))' 2>/dev/null || true)"
  if [ -n "$NODE_BIN_DIR" ] && [ -x "$NODE_BIN_DIR/secretvault" ]; then
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault")" "$HOME/.local/bin/secretvault" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault-cli")" "$HOME/.local/bin/secretvault-cli" 2>/dev/null || true
    ln -sf "$(realpath "$NODE_BIN_DIR/secretvault-mcp")" "$HOME/.local/bin/secretvault-mcp" 2>/dev/null || true
  fi

  if command -v secretvault &>/dev/null || [ -x "$HOME/.local/bin/secretvault" ]; then
    echo -e "${GREEN}✓ SecretVault CLI binaries ('secretvault', 'secretvault-cli', 'secretvault-mcp') installed to PATH.${RESET}\n"
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

