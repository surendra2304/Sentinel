# Deployment

## Local Docker Compose

The development Compose stack runs PostgreSQL, MinIO, the API, and the dashboard. The API is configured to use PostgreSQL and MinIO rather than silently falling back to process memory or local files. Database migrations run before the API starts; a migration error stops startup.

```bash
cp .env.example .env
# Set SENTINEL_DB_PASSWORD, SENTINEL_S3_ACCESS_KEY,
# SENTINEL_S3_SECRET_KEY, SENTINEL_AUDIT_SIGNING_KEY, and
# SENTINEL_CAPABILITY_SIGNING_KEY to unique local values.
docker compose up --build
```

The dashboard's browser requests are same-origin and its Nginx configuration proxies `/api/*` and `/health` to the `sentinel-api` service. Local dashboard tooling requires Node.js `^22.12.0 || ^24.0.0 || >=26.0.0` (Vitest 5 runtime requirement); the Docker and CI builders use Node 22. For Vite development outside Compose, start the API on port 8000 and run:

```bash
SENTINEL_API_PROXY_TARGET=http://127.0.0.1:8000 npm run dev --prefix apps/dashboard
```

`SENTINEL_API_PROXY_TARGET` is consumed by the Vite development server; browser code continues to use relative API paths.

## Production Compose

`docker-compose.production.yml` uses PostgreSQL, MinIO, a durable audit-log volume, required API/capability/audit signing keys, and fail-closed migrations. The API port is bound to host loopback (`127.0.0.1:8000`) intentionally. Place a separately managed, certificate-backed TLS reverse proxy in front of it before allowing remote operator access; this repository does not provision certificates or a public TLS edge.

The application currently runs orchestration and rate limiting in one API process. The Compose manifest does not advertise unimplemented Celery/Redis workers or horizontal API replicas. HTTP admission is bounded per process by `SENTINEL_MAX_HTTP_CONCURRENCY` (default 256); `/health` and `/ready` use a separate `SENTINEL_MAX_HEALTH_CONCURRENCY` budget (default 16). Requests beyond either budget receive HTTP 503 with `Retry-After: 1`, rather than being queued without bound. These are starting limits, not capacity guarantees; tune them from measured deployment load. They are not shared across processes or hosts. Agent work is separately bounded by `SENTINEL_MAX_AGENT_PROPOSALS_PER_TASK` (8), `SENTINEL_MAX_PLAN_STEPS_PER_ITERATION` (16), `SENTINEL_MAX_ACTIONS_PER_AGENT_PER_TASK` (32), `SENTINEL_MAX_AGENT_ANALYSIS_SECONDS` (15), and `SENTINEL_MAX_TASK_ITERATIONS` (10). These are safety ceilings, not throughput guarantees. See [GAPS.md](../GAPS.md) for distributed-work and scaling limits.

## Integrations and readiness

- Remote CLI control is disabled unless both `SENTINEL_API_URL` and `SENTINEL_API_KEY` are configured.
- Inference and Memora integrations require explicit service URLs as well as credentials; no source-coded Render URL is used as a fallback.
- Third-party reconnaissance enrichment is disabled by default. Explicitly authorize it in the task scope or pass the CLI opt-in only when target metadata may be shared externally.
- `/health` reports process liveness. `/ready` reports local dependency checks; in production, an in-memory storage backend is not considered durable or ready.

Container execution and live PostgreSQL migration behavior must be verified in the deployment environment. A local or SQLite test does not establish that Docker, PostgreSQL, MinIO, external TLS, or multi-instance operation is configured correctly.

## Local pressure test

`scripts/pressure_test_api.py` generates synthetic traffic only to `http://127.0.0.1:8000`; it has no target-URL option. Start a local API with a disposable test API key, set `SENTINEL_PRESSURE_TEST_API_KEY` to that same test key, then run:

```bash
SENTINEL_PRESSURE_TEST_API_KEY="$SENTINEL_API_KEY" \
  .venv/bin/python scripts/pressure_test_api.py \
  --health-count 5000 --api-count 1000 --concurrency 500
```

This is a loopback load exercise, not authorization to direct load at an external deployment. Results must be interpreted with the selected per-process caps, storage backend, worker count, and machine resources.
