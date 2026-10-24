# Build context: ./honeypots  (so the shared common/ module is available)
FROM node:22-alpine AS deps
WORKDIR /app/ssh
COPY ssh/package.json ssh/package-lock.json ./
# --ignore-scripts skips ssh2's optional native cpu-features build; pure JS is fine.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine
ENV NODE_ENV=production \
    SSH_HOST_KEY_PATH=/data/ssh_host_rsa_key
WORKDIR /app
COPY --chown=root:root common ./common
COPY --chown=root:root ssh/package.json ./ssh/package.json
COPY --chown=root:root ssh/src ./ssh/src
COPY --from=deps --chown=root:root /app/ssh/node_modules ./ssh/node_modules
# /data holds only the persistent host key (mount a volume here).
RUN mkdir -p /data && chown node:node /data && chmod 700 /data
WORKDIR /app/ssh
USER node
EXPOSE 2222
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "require('net').connect(process.env.SSH_HONEYPOT_PORT||2222,'127.0.0.1').on('connect',function(){this.destroy();process.exit(0)}).on('error',()=>process.exit(1))"
CMD ["node", "src/server.js"]
