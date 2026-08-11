# ── Stage 1: Install all dependencies ────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# ── Stage 2: Production image with only production dependencies ───────────────
FROM node:20-alpine AS final
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app .
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
  CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
