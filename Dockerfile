######## Stage 1 — deps ########
# Build always on the host arch ($BUILDPLATFORM) — avoids QEMU SIGILL (exit 132)
# when npm/Node runs under emulated arm64. All runtime deps are pure JS, so
# node_modules are portable across amd64/arm64.
FROM --platform=$BUILDPLATFORM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then \
        npm ci --omit=dev --no-audit --no-fund; \
    else \
        npm install --omit=dev --no-audit --no-fund; \
    fi \
 && npm cache clean --force

######## Stage 2 — runtime ########
FROM node:20-alpine AS runtime

# Security updates + tini for correct PID 1 signal handling
RUN apk add --no-cache tini curl \
 && addgroup -g 1001 ladiosa \
 && adduser -D -u 1001 -G ladiosa -h /app ladiosa

WORKDIR /app

# Deps from previous stage
COPY --from=deps --chown=ladiosa:ladiosa /app/node_modules ./node_modules

# App sources (chown to non-root)
COPY --chown=ladiosa:ladiosa package.json server.js index.html ./
COPY --chown=ladiosa:ladiosa assets/ ./assets/
COPY --chown=ladiosa:ladiosa public/ ./public/

# Data directory (will be a bind-mount volume at runtime)
RUN mkdir -p /data/medias \
 && chown -R ladiosa:ladiosa /data

ENV NODE_ENV=production \
    DATA_DIR=/data \
    PORT=1106 \
    TRUST_PROXY="loopback, linklocal, uniquelocal" \
    ALLOWED_ORIGINS="" \
    PUBLIC_ORIGIN=""

VOLUME ["/data"]
EXPOSE 1106

USER ladiosa

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:1106/healthz || exit 1

ENTRYPOINT ["/sbin/tini","--"]
CMD ["node","server.js"]
