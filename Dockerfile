# Build stage: Chainguard Node with npm, running as the unprivileged node user.
FROM cgr.dev/chainguard/node:latest-dev@sha256:b9ed639e17936247866afb17a9a3ae7ae1da7d6419fd8d72266860d31a244afa AS builder
WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
# --ignore-scripts: the prepare script runs tsc, and the sources are not copied yet.
RUN npm ci --ignore-scripts

COPY --chown=node:node tsconfig.json ./
COPY --chown=node:node src ./src
RUN npm run build && npm prune --omit=dev && npm cache clean --force

# Runtime stage: minimal Chainguard Node (no shell, no npm), production dependencies only.
FROM cgr.dev/chainguard/node:latest@sha256:aaf2e52e7deb1f4e5e51461ec480516ddd9ed4559188866f131145f93dee0f44 AS runner
WORKDIR /app

# Copied files are root-owned, so the server can read but not modify them.
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/build ./build

ENV NODE_ENV=production
# Listen on all interfaces so a published port reaches the server. Publish it on
# localhost only (-p 127.0.0.1:3000:3000): the HTTP transport has no authentication.
ENV MCP_HOST=0.0.0.0
# The API key is supplied at runtime: docker run -e SHODAN_API_KEY=...
EXPOSE 3000

USER node
ENTRYPOINT ["/usr/bin/node", "build/index.js"]
