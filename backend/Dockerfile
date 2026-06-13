# syntax=docker/dockerfile:1
# Multi-stage build for the NestJS middleware. Native addons (argon2) are built
# on a glibc base and only the resulting binaries are carried into the runtime
# image, which runs as a non-root user.

# ---- builder: all deps + compile TypeScript ------------------------------------
FROM node:20-bookworm-slim AS builder
WORKDIR /app
# Toolchain so argon2 can build from source if a prebuilt binary isn't available.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json nest-cli.json ./
COPY src ./src
RUN npm run build            # → /app/dist

# ---- proddeps: production-only node_modules (native modules built for THIS base)
FROM node:20-bookworm-slim AS proddeps
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---- runtime: minimal, non-root ------------------------------------------------
FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# tini becomes PID 1: forwards SIGTERM (graceful worker shutdown via Nest's
# shutdown hooks) and reaps zombies.
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

# The argon2 .node was compiled in `proddeps` on the SAME node:20-bookworm-slim
# base, so it is ABI-compatible here. node_modules is production-only (no dev,
# no compilers).
COPY --from=proddeps --chown=node:node /app/node_modules ./node_modules
COPY --from=builder  --chown=node:node /app/dist        ./dist
COPY --chown=node:node package.json ./

# `node` (uid 1000) ships with the official image — run unprivileged.
USER node
EXPOSE 3000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/main.js"]
