# Build context: ./honeypots  (so the shared common/ module is available)
FROM node:26-alpine AS deps
WORKDIR /app/ssh
COPY ssh/package.json ssh/package-lock.json ./
# --ignore-scripts: no install hooks; ssh2's optional native addon isn't needed.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force && mkdir -p /data && chmod 700 /data

# Distroless runtime: no shell, no package manager, no wget/curl/nc. Even if the
# Node process were exploited, there are no tools to pivot with. Runs as the
# image's non-root user (uid 65532).
FROM gcr.io/distroless/nodejs22-debian12:nonroot
ENV NODE_ENV=production \
    SSH_HOST_KEY_PATH=/data/ssh_host_rsa_key
WORKDIR /app
COPY --from=deps /app/ssh/node_modules ./ssh/node_modules
COPY common ./common
COPY ssh/package.json ./ssh/package.json
COPY ssh/src ./ssh/src
# /data holds only the persistent host key (mount a volume here).
COPY --from=deps --chown=65532:65532 /data /data
WORKDIR /app/ssh
EXPOSE 2222
HEALTHCHECK --interval=30s --timeout=3s --retries=3   CMD ["/nodejs/bin/node", "-e", "require('net').connect(Number(process.env.SSH_HONEYPOT_PORT||2222),'127.0.0.1').on('connect',function(){this.destroy();process.exit(0)}).on('error',()=>process.exit(1))"]
CMD ["src/server.js"]
