# Phase 9 — Operations, CI/CD, observability, and deployment reality

## Containers and profiles

[FACT] Root `Dockerfile` and `docker/Dockerfile.api` are multi-stage images: Node 22 builds the dashboard; Python 3.11 slim builds/installs the API; runtime installs WeasyPrint system libraries and runs as non-root `sentinel` on port 8000. Entrypoint runs Alembic only for `SENTINEL_STORAGE_BACKEND=postgres`, then one Uvicorn worker. `docker/Dockerfile.dashboard` builds the Vite SPA and runs a non-root Nginx image; `apps/dashboard/nginx.conf` proxies `/api/` and disables buffering for SSE.

[FACT] Development Compose publishes PostgreSQL, MinIO API/console, API and dashboard host ports and uses named DB/MinIO/audit volumes. Production Compose requires API, capability, audit, DB and S3 secrets; runs API on host loopback and expects a separately managed TLS reverse proxy; it has no dashboard/reverse-proxy service, backup job, or migration rollback mechanism. DB/MinIO remain private to the Compose network. No Docker/Compose command was run in this phase.

[FACT] The Kubernetes YAML declares a 3-replica `sentinel-api` Deployment and HPA targeting `sentinel-worker` (not declared), with no Service, Ingress, database/object store, env vars, Secret/ConfigMap, probes, or Pod security context. As written it falls back to memory storage and does not define a routable cluster service.

[FACT] Render YAML selects a free Docker web service, `/health`, memory repositories and local artifact storage; no persistent disk/database is declared. It sets a number of external integration URL/key names, some unused by the code. Root container image includes the dashboard bundle.

## CI and delivery

[FACT] `.github/workflows/ci.yml` triggers on pushes to `main`/`develop` and PRs to `main`; it has lint/type/diary/schema checks, unit tests (`tests/unit`), integration tests (`tests/integration`), two overlapping dashboard test/build jobs, Python `pip-audit`, TruffleHog secret scan, and Docker image build. The main CI unit/integration jobs do not directly run `tests/security/` or root `tests/test_prompt5_sentinel.py`; `deploy.yml` runs full `pytest` only on push to `main` after merge.

[FACT] CI's Docker job depends on unit, integration and dashboard-tests but not directly on the separate security-audit or secret-scan jobs. Branch-protection requirements are not present in the repository and therefore were not inferred. The TruffleHog action is referenced by mutable `@main`. The `deploy.yml` security step uses `pip-audit || true`; its final step only builds a local Docker image tagged `sentinel-api:latest` and does not push/deploy it, despite the workflow name.

## Operational signals and gaps

[FACT] `/health` is an unauthenticated process-liveness response and includes audit-chain count/durability labels; `/ready` checks local audit integrity, event-bus existence, a nonempty backend string and (only in production) that the backend name is `postgres`, but does not query database/object-store health. `/api/v1/health/ready` passes `persistence_ok=False` unconditionally and therefore reports 503. Compose/Render healthchecks use `/health`, not those readiness endpoints.

[FACT] Audit JSONL has no rotation/export/backup facility found in repository source. Production Compose mounts a named audit volume and PostgreSQL/MinIO volumes, but backup/restore jobs and retention policies are not in tracked deployment files. Kubernetes readiness/liveness probes and pod anti-affinity are absent.

[INFERENCE] A passing liveness probe does not imply task/evidence durability, S3 reachability, database connectivity, or security-readiness. Operators need external deployment policy/monitoring for those properties.

High confidence for checked-in configuration and route logic. No image build, orchestration startup, cloud deploy, or service connectivity was verified.

## Post-baseline CI security-test wiring (2026-10-07)

[FACT] The workflow now contains a dedicated `security-tests` job with the `testing` profile, memory repositories, local artifacts, and API auth disabled for the test runner. It executes `pytest tests/security/`; the Docker image job's `needs` now includes this job. Local PyYAML parsing confirmed the job and dependency, and the equivalent local command passed **123 tests** with one non-failing Starlette/httpx warning (`.github/workflows/ci.yml:76-95,184-186`). GitHub-hosted Actions and Docker image builds were not run, so hosted runner behavior remains unverified.
