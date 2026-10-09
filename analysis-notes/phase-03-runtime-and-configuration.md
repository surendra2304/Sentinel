# Phase 3 — Runtime, dependencies, settings, deployment configuration

## Dependency/runtime model

[FACT] `pyproject.toml` defines package `sentinel` version `0.1.0`, Python `>=3.11`, broad lower-bound-only dependencies (FastAPI/Uvicorn, Pydantic Settings, SQLAlchemy/asyncpg/Alembic, MinIO, httpx, Typer, report libraries, etc.) and optional `dev` test/lint/type tools. There is no Python lock/constraints file in the tracked root. The dashboard has its own npm lockfile; the root has `package-lock.json` without a tracked root `package.json`, while Docker and CI use `apps/dashboard/package-lock.json`.

[FACT] `docker/entrypoint.sh` runs `alembic upgrade head` only when `SENTINEL_STORAGE_BACKEND=postgres`, then starts one Uvicorn worker on `0.0.0.0:${PORT:-8000}` with the configured concurrency cap. `SENTINEL_API_HOST`/`SENTINEL_API_PORT` fields exist in settings but the entrypoint does not read them.

## Settings actually consumed

[FACT] `sentinel/config/settings.py` is a cached Pydantic Settings object with default `environment=development`, `debug=True`, `api_auth_required=False`, task storage `memory`, local artifact storage, 256 concurrent HTTP requests, 16 reserved health requests, 8 proposals/task, 16 plan steps/iteration, 32 actions/agent/task, 15-second agent analysis, 10 task iterations, and 50 global rate-limit RPS. Repository search shows the global RPS field is not used by the middleware; the middleware instead hard-codes 120 requests per 60 seconds (FRIDAY keys use 100/hour). Module flags are reported by the API/CLI, but no runtime gating uses `settings.modules` beyond display/readiness output.

[FACT] `.env.example` lists `SENTINEL_API_RATE_LIMIT`, `SENTINEL_FRIDAY_API_KEY`, `SENTINEL_LLM_*`, and `SENTINEL_AUDIT_LOG_FILE`; these names are not read by the current runtime. Audit settings use the `SENTINEL_AUDIT_` prefix and the field `log_file_path`, so the supported custom path key is `SENTINEL_AUDIT_LOG_FILE_PATH` (used in production Compose). `SENTINEL_AUDIT_ENABLE_HASH_CHAIN` is not consulted; `AuditLogger` always uses the hash-chain code. LLM variables do not instantiate `LLMPlanner` or an LLM provider in the task path.

[FACT] Relevant live names include `SENTINEL_ENVIRONMENT`, `SENTINEL_API_AUTH_REQUIRED`, `SENTINEL_API_KEY`, `SENTINEL_STORAGE_BACKEND`, `SENTINEL_DB_*`, `SENTINEL_S3_*`, `SENTINEL_AUDIT_SIGNING_KEY`/`SENTINEL_AUDIT_HMAC_KEY`, bounded-agent settings, `PORT`, `RENDER`, `INFERENCE_URL`/`INFERENCE_API_KEY`, `MEMORA_URL` plus `SENTINEL_MEMORA_EVENTS_*`, and `INTELX_URL`/`INTELX_API_KEY`. Render's `FRIDAY_URL`, `STRATEX_URL`, `FUTURIS_URL`, `CORTEX_URL`, `FORGE_URL` and several associated key names do not correspond to runtime consumers found in source search. `MEMORA_API_KEY` is not selected by `MemoraClient`; it chooses `<AGENT>_API_KEY` (for Sentinel, `SENTINEL_API_KEY`).

## Deployment profiles

[FACT] Development Compose runs PostgreSQL 16 and MinIO with named data volumes, but publishes DB 5432, MinIO API/console 9000/9001, API 8000 and dashboard 3000 to the host. Production Compose selects PostgreSQL task/evidence repositories, S3-compatible MinIO, requires API/capability/audit/database/S3 secrets, mounts audit storage and binds the API only to `127.0.0.1:8000`; it does not include a dashboard or TLS proxy.

[FACT] `render.yaml` selects a free Docker web service and explicitly selects in-memory task/repository storage and local object storage; it has no persistent disk or managed database declared. This sacrifices task/evidence durability across process replacement even though Postgres/MinIO are used in the Compose profile. Render variables advertise several ecosystem endpoints, but not every such integration is wired.

[FACT] The API module imports a global `EvidenceStore`; its constructor creates the selected artifact backend, opens/verifies the audit ledger, and, for MinIO, synchronously checks/creates the bucket. This runs during module import, before the FastAPI lifespan. The factory silently falls back to local filesystem storage if MinIO construction/bucket initialization raises. `LocalFileSystemStorage` creates `data/artifacts` on initialization. The API constructs the audit logger at startup; its constructor creates the parent log directory and verifies an existing ledger, while an absent JSONL ledger is not created until the first append. These are runtime side effects, not verification performed in this phase.

## Risks/uncertainty

[INFERENCE] Rebuilding Python images may resolve newer transitive and direct packages because dependencies are lower bounds rather than locked, so two builds from the same source can differ. Exact installed versions will be recorded in the verification phase.

[INFERENCE] A production operator who copies `.env.example` and sets only its documented custom audit path variable will not change the active path, though its default happens to match the example. A configured MinIO outage may silently redirect evidence to ephemeral local storage; the readiness endpoint does not establish that artifacts are on MinIO.

High confidence for settings, Compose/Render, and entrypoint source. Runtime services were not started in this phase.
