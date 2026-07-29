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
  exec < /dev/tty
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

# 2. Launch Client Setup Wizard from GitHub
echo -e "${CYAN}Launching SecretVault setup wizard...${RESET}\n"

# Execute setup directly via npx from GitHub repository
npx -y --package=git+https://github.com/itsaygea/secretvault.git secretvault-mcp setup
