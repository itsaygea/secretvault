FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /app

# Copy manifests first so dependency installation remains cacheable.
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/admin/package.json packages/admin/
COPY packages/bridge/package.json packages/bridge/
COPY packages/client/package.json packages/client/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY packages/sdk/package.json packages/sdk/
COPY packages/shared/package.json packages/shared/

RUN npm ci --ignore-scripts


COPY packages/ packages/
COPY supabase/migrations/ supabase/migrations/
COPY docs/openapi.json docs/openapi.json
COPY scripts/openapi-paths.json scripts/openapi-paths.json

RUN npm run build
RUN npm prune --omit=dev

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runtime

WORKDIR /app

# SV-AUD-001: the container binds its own interface (0.0.0.0) so a
# TLS-terminating reverse proxy on the Compose network can reach it, but the
# image NEVER bakes in the plaintext-external override. External exposure is
# governed entirely by the host-side publish mapping
# (SECRETVAULT_PUBLISH_HOST, see docker-compose.yml), which defaults to
# loopback. The runtime guard in transportSecurity.ts keys on that publish
# host, not on this in-container bind, so a legitimate container bind can
# never bypass the fail-closed check.
ENV NODE_ENV=production \
    PORT=3004 \
    SECRETVAULT_BIND_HOST=0.0.0.0

# Keep only the production dependency tree and the server/shared artifacts.
# The workspace symlink for @secretvault/shared resolves to the copied package.
COPY --from=build --chown=node:node /app/node_modules/ ./node_modules/
COPY --from=build --chown=node:node /app/packages/mcp-server/package.json packages/mcp-server/
COPY --from=build --chown=node:node /app/packages/mcp-server/dist/ packages/mcp-server/dist/
COPY --from=build --chown=node:node /app/packages/shared/package.json packages/shared/
COPY --from=build --chown=node:node /app/packages/shared/dist/ packages/shared/dist/
COPY --from=build --chown=node:node /app/supabase/migrations/ supabase/migrations/
COPY --from=build --chown=node:node /app/docs/openapi.json docs/openapi.json
COPY --chown=node:node docker/entrypoint.sh /usr/local/bin/secretvault-entrypoint
COPY --chown=node:node docker/break-glass.sh /usr/local/bin/secretvault-break-glass

RUN chmod 0555 /usr/local/bin/secretvault-entrypoint /usr/local/bin/secretvault-break-glass

# Remove inherited base-image npm toolchain to clear base OS/library vulnerability surface
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

USER node

EXPOSE 3004

# Provide an image-level readiness signal for non-Compose orchestrators as
# well as the Compose health check. The Node Alpine base includes BusyBox wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:3004/health/ready || exit 1

ENTRYPOINT ["/usr/local/bin/secretvault-entrypoint"]
CMD ["node", "packages/mcp-server/dist/index.js"]
