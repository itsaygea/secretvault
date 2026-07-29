#!/bin/sh
set -eu

node /app/packages/mcp-server/dist/migrate.js
exec "$@"
