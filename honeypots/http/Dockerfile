# Build context: ./honeypots  (so the shared common/ module is available)
FROM node:22-alpine AS deps
WORKDIR /app/http
COPY http/package.json http/package-lock.json ./
# --ignore-scripts: no install hooks; ssh2's optional native addon isn't needed.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force && mkdir -p /data && chmod 700 /data

# Distroless runtime: no shell, no package manager, no wget/curl/nc. Even if the
# Node process were exploited, there are no tools to pivot with. Runs as the
# image's non-root user (uid 65532).
FROM gcr.io/distroless/nodejs22-debian12:nonroot
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/http/node_modules ./http/node_modules
COPY common ./common
COPY http/package.json ./http/package.json
COPY http/src ./http/src

WORKDIR /app/http
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3   CMD ["/nodejs/bin/node", "-e", "require('net').connect(Number(process.env.HTTP_HONEYPOT_PORT||8080),'127.0.0.1').on('connect',function(){this.destroy();process.exit(0)}).on('error',()=>process.exit(1))"]
CMD ["src/server.js"]
