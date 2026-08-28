#!/bin/bash
set -e

# Run database migrations if postgres is reachable
if [ "$SENTINEL_STORAGE_BACKEND" = "postgres" ]; then
    echo "[SENTINEL] Running database migrations (alembic upgrade head)..."
    alembic upgrade head || echo "[SENTINEL] Database migration warning (will continue startup)..."
fi

exec uvicorn sentinel.apps.api.main:app --host 0.0.0.0 --port 8000 --workers 1