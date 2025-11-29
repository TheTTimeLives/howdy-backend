FROM node:18-alpine AS base
WORKDIR /app
ENV NODE_ENV=production

FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev

FROM base AS build
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./tsconfig.json
COPY src ./src
COPY public ./public
RUN npm run build

FROM node:18-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5000
# Install only production deps
COPY --from=deps /app/node_modules ./node_modules
# Copy built dist and any static public assets
COPY --from=build /app/dist ./dist
COPY --from=build /app/public ./public
# Health check (optional)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD wget -qO- http://127.0.0.1:${PORT}/ || exit 1
EXPOSE 5000
CMD ["node", "dist/index.js"]


