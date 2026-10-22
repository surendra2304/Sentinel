#!/bin/bash
set -euo pipefail

# In a durable deployment, the API must not serve against an outdated schema.
if [ "${SENTINEL_STORAGE_BACKEND:-}" = "postgres" ]; then
    echo "[SENTINEL] Running database migrations (alembic upgrade head)..."
    alembic upgrade head
fi

exec uvicorn sentinel.apps.api.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --limit-concurrency "${SENTINEL_MAX_HTTP_CONCURRENCY:-256}"
