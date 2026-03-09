FROM node:20-alpine AS base

WORKDIR /app

# Install Nmap and required NSE libraries/scripts
RUN apk add --no-cache nmap nmap-nselibs nmap-scripts

FROM base AS deps
COPY package.json package-lock.json* ./
RUN npm install

FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json* ./
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM base AS runner
ENV NODE_ENV=production
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY public ./public

# Data directories for DB and scan outputs
VOLUME ["/data"]
ENV DB_PATH=/data/db.sqlite
ENV SCAN_OUTPUT_DIR=/data/scans

EXPOSE 3000

CMD ["node", "dist/server.js"]

