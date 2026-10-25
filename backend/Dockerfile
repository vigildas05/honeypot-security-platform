FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=root:root package.json ./
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root src ./src
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
USER node
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${BACKEND_PORT:-${PORT:-8000}}/health" || exit 1
CMD ["node", "src/server.js"]
