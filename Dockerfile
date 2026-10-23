# ── Stage 1: Build React Dashboard ───────────────────────────────────────────
FROM node:22-alpine AS dashboard-builder

WORKDIR /dashboard
COPY Sentinel/apps/dashboard/package.json Sentinel/apps/dashboard/package-lock.json ./
RUN npm ci
COPY Sentinel/apps/dashboard/ ./
RUN npm run build

# ── Stage 2: Python Application Image ────────────────────────────────────────
FROM python:3.11-slim

# Container Security Environment Variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Install runtime dependencies including curl for HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgobject-2.0-0 \
        libharfbuzz0b \
        libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*

# Container security: Create non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install Python dependencies
COPY Sentinel/requirements.txt Sentinel/pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source & contracts
COPY --chown=appuser:appuser Sentinel/sentinel/ ./sentinel/
COPY --chown=appuser:appuser Sentinel/contracts/ ./contracts/
COPY --chown=appuser:appuser Sentinel/alembic.ini ./
COPY --chown=appuser:appuser Sentinel/alembic/ ./alembic/
COPY --chown=appuser:appuser Sentinel/docker/entrypoint.sh ./entrypoint.sh
COPY --chown=appuser:appuser mesh/ ./mesh/

# Copy compiled dashboard from stage 1
COPY --from=dashboard-builder --chown=appuser:appuser /dashboard/dist ./apps/dashboard/dist

# Install sentinel package in editable/wheel mode
RUN pip install --no-cache-dir -e .

# Runtime directories and entrypoint permissions
RUN mkdir -p /app/logs /app/data/artifacts && \
    sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
