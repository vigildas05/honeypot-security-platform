# Build context: ./honeypots  (so the shared common/ module is available)
FROM node:22-alpine AS deps
WORKDIR /app/http
COPY http/package.json http/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=root:root common ./common
COPY --chown=root:root http/package.json ./http/package.json
COPY --chown=root:root http/src ./http/src
COPY --from=deps --chown=root:root /app/http/node_modules ./http/node_modules
WORKDIR /app/http
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "require('net').connect(process.env.HTTP_HONEYPOT_PORT||8080,'127.0.0.1').on('connect',function(){this.destroy();process.exit(0)}).on('error',()=>process.exit(1))"
CMD ["node", "src/server.js"]
