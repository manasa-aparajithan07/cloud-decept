# CloudDecept Dashboard - ARM64 compatible
FROM node:20-alpine AS builder

WORKDIR /app

# Build arguments for NEXT_PUBLIC_* compile-time variables
ARG NEXT_PUBLIC_BACKEND_URL
ARG NEXT_PUBLIC_COLLECTOR_URL
ARG NEXT_PUBLIC_THREAT_INTEL_URL
ARG NEXT_PUBLIC_ADAPTIVE_URL
ARG NEXT_PUBLIC_INTENT_URL

# Export as ENV so they're available during npm run build
ENV NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL
ENV NEXT_PUBLIC_COLLECTOR_URL=$NEXT_PUBLIC_COLLECTOR_URL
ENV NEXT_PUBLIC_THREAT_INTEL_URL=$NEXT_PUBLIC_THREAT_INTEL_URL
ENV NEXT_PUBLIC_ADAPTIVE_URL=$NEXT_PUBLIC_ADAPTIVE_URL
ENV NEXT_PUBLIC_INTENT_URL=$NEXT_PUBLIC_INTENT_URL

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Runtime stage
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Runtime environment variables for Next.js rewrites
# These must be set at runtime for rewrites to work
ARG NEXT_PUBLIC_BACKEND_URL
ARG NEXT_PUBLIC_COLLECTOR_URL
ARG NEXT_PUBLIC_THREAT_INTEL_URL
ARG NEXT_PUBLIC_ADAPTIVE_URL
ARG NEXT_PUBLIC_INTENT_URL

ENV NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL:-http://backend-api:8004}
ENV NEXT_PUBLIC_COLLECTOR_URL=${NEXT_PUBLIC_COLLECTOR_URL:-http://event-collector:8000}
ENV NEXT_PUBLIC_THREAT_INTEL_URL=${NEXT_PUBLIC_THREAT_INTEL_URL:-http://threat-intel:8005}
ENV NEXT_PUBLIC_ADAPTIVE_URL=${NEXT_PUBLIC_ADAPTIVE_URL:-http://adaptive-engine:8002}
ENV NEXT_PUBLIC_INTENT_URL=${NEXT_PUBLIC_INTENT_URL:-http://intent-engine:8001}
ENV BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL:-http://backend-api:8004}
ENV COLLECTOR_URL=${NEXT_PUBLIC_COLLECTOR_URL:-http://event-collector:8000}
ENV THREAT_INTEL_URL=${NEXT_PUBLIC_THREAT_INTEL_URL:-http://threat-intel:8005}
ENV ADAPTIVE_URL=${NEXT_PUBLIC_ADAPTIVE_URL:-http://adaptive-engine:8002}
ENV INTENT_URL=${NEXT_PUBLIC_INTENT_URL:-http://intent-engine:8001}

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"

CMD ["node", "server.js"]