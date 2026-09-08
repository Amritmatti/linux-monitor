# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Vigil
#
# Two runtime dependencies: the Postgres driver, and ssh2 for the transport.
#
# ssh2 is used rather than shelling out to the openssh client for one specific
# reason: the openssh client can only take a private key from a file or an
# agent, and this product must never write a customer's private key to disk.
# ssh2 accepts it as a string, in memory, for the life of one connection.
#
# --omit=optional skips ssh2's `cpu-features` native binding, which is a
# micro-optimisation that would otherwise drag a C toolchain into the image.
# ssh2 falls back to its pure-JS crypto paths without it.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --omit=optional --no-audit --no-fund

FROM node:22-alpine
ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    DATA_DIR=/data

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY web ./web

# /data holds only the locally generated encryption key when one is not supplied
# from a secret manager. Everything else lives in Postgres.
RUN mkdir -p /data && chown -R node:node /data /app

USER node
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/index.mjs"]
