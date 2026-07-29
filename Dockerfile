FROM node:22-alpine AS build

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

FROM node:22-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3004 \
    SECRETVAULT_BIND_HOST=0.0.0.0 \
    SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL=1 \
    SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM=I-know-this-is-insecure

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

ENTRYPOINT ["/usr/local/bin/secretvault-entrypoint"]
CMD ["node", "packages/mcp-server/dist/index.js"]
