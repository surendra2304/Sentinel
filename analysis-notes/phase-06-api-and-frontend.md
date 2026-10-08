# Phase 6 — HTTP API, SSE, browser dashboard, contract alignment

## API surface

[FACT] `sentinel/apps/api/main.py` builds a FastAPI app with task submit/list/get/cancel, approval list/decision, findings and task findings/evidence, risk summary, attack surface, task report and evidence bundle, task/FRIDAY SSE, FRIDAY delegation/posture/assets/schedule/results/cancel, global kill switch, security-gate review, FRIDAY research/context, readiness, incidents/quarantine/capability tokens, and inference proxy. It also serves health/root/docs and mounts a built dashboard when `apps/dashboard/dist/index.html` exists. Metrics are included from a router. Task list defaults to repository pagination, while the findings/evidence/approvals APIs do not expose paging parameters; dashboard fetches global lists.

[FACT] Dashboard source has seven routed pages in `App.tsx`: Overview, Tasks, Attack Surface, Findings, Risk, Reports, and Approvals, plus a fallback redirect. It uses a typed API client with relative `/api/v1` paths by default, a session-storage API key, fetch-based authenticated SSE, React Router, and static assets. The dashboard Nginx config proxies `/api/` to `sentinel-api:8000` with buffering disabled for streams; root API Docker image can instead serve the compiled SPA.

## Confirmed contract mismatch

[FACT] API `SubmitTaskRequest.scope` is required and `create_and_submit_task` rejects missing scope and synthetic authorization references. Dashboard `submitTask` sends only objective, targets, mode, and requested output. `TasksPage.handleCreateTask` calls it without scope; the client converts all non-2xx responses to `null`. Thus the built-in dashboard's “Launch New Task” request cannot pass server-side scope validation as currently wired, and the UI reports a generic authorization/target error rather than exposing the 422 body.

## Orphaned dashboard calls/pages

[FACT] `apps/dashboard/src/api/client.ts` calls `/api/v1/audit/logs`, `/policies`, `/operations/alerts`, `/operations/alerts/{id}`, `/operations/schedules`, `/operations/baselines/diffs`, and `/intelligence/attack-paths`; no matching route appears in the main FastAPI route set or included metrics router inspected. Fetch helpers generally swallow failures and return `[]`/`false`, so these functions can look like empty states rather than explicit “not implemented” errors. `OperationsPage` and `AuditPolicyPage` files exist but are not routed by `App.tsx`; `fetchAttackPaths` is not used by the routed Attack Surface page, which calls `/tasks/{id}/attack-surface`.

## Streaming/API identity notes

[FACT] Task SSE registers an in-memory queue by correlation ID and streams only events published after the connection, plus a connected event and pings. It does not replay the event bus's bounded history. Event queues have no max size; the bus and rate limiters are per process.

[FACT] `APIKeyAuthMiddleware` uses one configured `SENTINEL_API_KEY` (or `api_key` setting) with a constant-time compare when auth is enabled. In non-Render development it permits requests without a key by default. The dashboard retains that key in `sessionStorage` and sends it as `X-API-Key`; there is no per-user browser identity in the API client.

[FACT] FastAPI registers wildcard CORS with `allow_credentials=True`, then API-key and capacity middleware. If dashboard is placed on a separate origin via `VITE_API_URL`, browser preflight behavior should be explicitly verified; same-origin Vite/Nginx proxy is the configured default.

## Included-router coverage qualification

[FACT] The Phase 6 route scan initially focused on `main.py` and noted metrics-router inclusion without enumerating it. Follow-up read of `sentinel/api/metrics.py` found six included routes: posture trend, MTTR, finding velocity, coverage, predictive forecasts, and Prometheus. The first four and Prometheus return hard-coded example values; `/predictive-forecasts` calls the Futuris client and predictive workflow with hard-coded asset examples (`sentinel/api/metrics.py:8-100`; included at `sentinel/apps/api/main.py:1337`). Thus the orphaned-client claim was checked against both app routes and this sole included router; no other `include_router` call appears in `main.py`.

## Confidence

High for route declarations, TypeScript client paths, task-submit shape, page routing, and the included metrics router. The baseline browser/API flow was not exercised end-to-end; earlier dashboard lint/tests/build did not prove usability. Phase 12's capability and bridge trace is in `analysis-notes/phase-12-control-wiring.md`.

## Post-baseline dashboard correction (2026-10-07)

[FACT] The Tasks page now gathers caller-entered owner, written authorization reference, allowed target, explicit time window, methods, impact ceiling, rate limit and optional third-party-enrichment consent (unchecked by default); it submits the API's required `scope` object and displays the server validation detail. The API client now has a typed submission contract and throws on non-2xx responses (`apps/dashboard/src/pages/TasksPage.tsx:7-120, 189-305`; `apps/dashboard/src/api/client.ts:214-261`).

[FACT] Target type inference now handles IPv4 and IPv6 CIDRs before single IPs, including a regression for `2001:db8::/32` (`apps/dashboard/src/pages/TasksPage.tsx:7-18`; `apps/dashboard/src/test/TasksPage.test.tsx:13-20`). The current dashboard suite/lint/build outcomes are in the Phase 11 follow-up.

[FACT] Frontend tests mock `submitTask`; the independent API-to-report loopback test validates the submitted scope contract through FastAPI but does not drive a browser. A real browser-to-running-API acceptance flow remains unverified.

## Post-baseline lifecycle API edge pass (2026-10-07)

[FACT] Added API tests now reject expired, not-yet-active, and out-of-allowlist task requests before `_start_task_job` is called. A real FastAPI `TestClient` cancellation test holds the lifecycle worker on a controlled async event, cancels through `/api/v1/tasks/{id}/cancel`, verifies persisted `cancelled` state, and checks the local job handle is removed. A completed task cancellation now returns “already terminal” rather than falsely claiming it was halted. See `tests/integration/test_task_submission_e2e.py:173-268`.

[FACT] A route inventory test found two FastAPI `POST /api/v1/tasks/{task_id}/cancel` registrations; Starlette/FastAPI would match the earlier one and leave the later handler shadowed. The duplicate decorator was removed, while Friday/Sentinel aliases were kept. The alias handler now maps unknown task `KeyError` to 404 instead of leaking it as an unhandled server error. New tests assert one route and 404 for both missing-task aliases (`sentinel/apps/api/main.py:369-395,1088-1097`; `tests/integration/test_task_submission_e2e.py:271-292`).

[FACT] The loopback API-to-report test is stronger than the earlier smoke assertion: a deliberately header-light fixture produces a missing-security-headers finding; the test verifies it has same-task evidence references and that the finding is included in the generated report (`tests/integration/test_task_submission_e2e.py:142-171`). This confirms one deterministic heuristic observation and evidence/report wiring, not the finding's real-world severity or model precision/recall.
