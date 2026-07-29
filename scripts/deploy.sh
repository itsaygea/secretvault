#!/usr/bin/env bash
set -euo pipefail

: "${SECRETVAULT_DEPLOY_HOST:?Set SECRETVAULT_DEPLOY_HOST (for example, deploy@example-host)}"
: "${SECRETVAULT_DEPLOY_DIR:?Set SECRETVAULT_DEPLOY_DIR (for example, /opt/secretvault)}"

remote_path="${SECRETVAULT_DEPLOY_DIR%/}"

echo "=== SecretVault Production Deployment ==="
echo "1. Verifying local compilation across all workspace packages..."
npm run build -w @secretvault/shared && \
npm run build -w @secretvault/bridge && \
npm run build -w @secretvault/sdk && \
npm run build -w @secretvault/mcp-server

echo "2. Rsyncing project files to the configured remote Docker host..."
rsync -avz --exclude 'node_modules' --exclude 'dist' ./ "${SECRETVAULT_DEPLOY_HOST}:${remote_path}/"

echo "3. Building and restarting the Docker container..."
ssh "$SECRETVAULT_DEPLOY_HOST" "cd '$remote_path' && docker compose up -d --build"

echo "4. Verifying container status and health check..."
ssh "$SECRETVAULT_DEPLOY_HOST" "docker ps --filter name=secretvault-mcp && sleep 2 && curl -s http://localhost:3004/health/ready"

echo ""
echo "=== Deployment Complete ==="
