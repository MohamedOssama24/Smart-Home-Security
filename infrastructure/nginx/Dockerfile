# Build context: repository root
#   docker build -f infrastructure/nginx/Dockerfile .
FROM node:24-alpine AS frontend
WORKDIR /app
COPY frontend/angular-dashboard/package.json frontend/angular-dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/angular-dashboard/ ./
RUN npx ng build --configuration production

FROM nginx:1.28-alpine
# openssl: only used to create a self-signed certificate in development (SHSC_TLS_SELF_SIGNED=true)
RUN apk add --no-cache openssl
COPY infrastructure/nginx/conf.d/ /etc/nginx/conf.d/
COPY infrastructure/nginx/snippets/ /etc/nginx/snippets/
COPY infrastructure/nginx/docker-entrypoint.d/ /docker-entrypoint.d/
RUN chmod +x /docker-entrypoint.d/*.sh
COPY --from=frontend /app/dist/angular-dashboard/browser/ /usr/share/nginx/html/
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1/nginx-health || exit 1
