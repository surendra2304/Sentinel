# Phase 13 — Quality model, test realism, and language checklists

> **Baseline boundary:** The observations in the checklist below describe the implementation and verification state at the initial review; several identified gaps were fixed in the dated post-baseline sections at the end. Read those later sections before treating an initial gap as current.

## Quality/tooling baseline

[FACT] `pyproject.toml` targets Python 3.11+, configures Ruff (E/F/W/I/B/UP/SIM, E501 ignored, 100-character configured line length), mypy with untyped definitions permitted, and pytest discovery under `tests/` with asyncio auto (`pyproject.toml:5-10, 67-88`). Python dependencies are lower-bound ranges rather than a lockfile (`pyproject.toml:23-59`). Dashboard scripts provide lint, type-check-plus-build, and Vitest commands; its package lock is separate (`apps/dashboard/package.json:6-15`).

[FACT] Phase 11 recorded a complete local pytest run with 321 tests collected and no failures; Ruff and both mypy modes passed; dashboard ESLint, 4 Vitest files/10 tests, and TypeScript+Vite build passed; generated schemas matched 8/8. Those are real verification results, but they only prove the exercised assertions/configuration. They do not prove target-discovery accuracy, end-user task usability, persistent deployment behavior, or security-control integration (see `analysis-notes/phase-11-verification-log.md`).

[FACT] Checked-in integration tests vary in realism. `tests/integration/test_master_e2e.py:1-12, 91-160` describes an in-process pipeline, but the test manually creates a `Task`, writes hand-authored evidence bytes, and ingests hand-authored observations before exercising correlation/report code; it does not submit through the API or run reconnaissance adapters. `tests/integration/test_orchestrator_e2e.py:23-104` starts a loopback HTTP server and executes the orchestrator directly, which is stronger action-path evidence, but bypasses API request parsing, task lifecycle submission, and dashboard interaction. `tests/integration/test_recon_module_e2e.py:20-175` similarly tests adapters and orchestrator against a local HTTP fixture. No external target was necessary for these tests.

[FACT] CI workflow analysis in Phase 9 shows the push/PR jobs exercise `tests/unit` and `tests/integration` but not the full `tests/security` directory or root `tests/test_prompt5_sentinel.py`; the deploy-named workflow runs full pytest only after a push to `main`. This means branch CI can be green without those separate security tests. No local branch-protection configuration was found.

## Python checklist

- [FACT] Packaging/runtime: Python >=3.11, API/CLI entry points exist, settings and deployment variables are documented imperfectly; direct dependencies are unlocked lower bounds.
- [FACT] Types/data: Pydantic domain/request schemas and mypy checks exist, but mypy does not require all function bodies to be typed; strict-ish `--check-untyped-defs` verification nevertheless passed in Phase 11.
- [FACT] Async/concurrency: FastAPI and async adapters are used; repository persistence contains synchronous MinIO calls in async methods (Phase 4); several state stores/rate limits/queues are per-process; Python fallback scanning is now capped at 256 ports and 32 concurrent checks per adapter instance, while Nmap/multi-process load and evidence/bundle accumulation remain uncharacterized (Phases 7/8).
- [FACT] Network: finite timeouts are common, but multiple outbound/target clients set `verify=False` (Phase 7, examples under `sentinel/modules/{web,recon,api_security}/adapters.py` and `sentinel/integrations/scanners/http_adapter.py`). Some endpoints transmit caller-supplied query/finding data when integrations are configured.
- [FACT] Process/filesystem: no `os.system`, `shell=True`, `eval`, or executable dynamic `exec` call was found in the project scan. Both subprocess APIs now share bounded streaming capture and retain only configured per-stream prefixes; `SafeProcessRunner` remains outside the default app execution path. The active scanner sandbox still inherits the environment and has no configured `CommandPolicy`, and child CPU/memory and Windows descendant cleanup are not covered by the output cap. Storage path traversal hardening is incomplete for caller-chosen keys, though current evidence keys are generated internally.
- [FACT] Persistence/audit: SQLAlchemy is used for core repositories, but selected ORM models are not written by the runtime; audit ledger integrity has known truncation/metadata gaps verified in Phase 11. Evidence metadata/manifest integrity requires hardening.
- [FACT] Testing: local-loopback adapter/orchestrator tests exist, but there is no demonstrated API->task->report round trip against the actual running app; the “master E2E” relies on synthetic fixtures. The latest full pytest outcome is therefore useful but not a functional acceptance test.

## TypeScript/React checklist

- [FACT] Dashboard is React/TypeScript with Vite, React Router, typed data interfaces and relative `/api/v1` paths by default (`apps/dashboard/package.json`, `apps/dashboard/src/api/client.ts`).
- [FACT] Scan found no `dangerouslySetInnerHTML`, `.innerHTML`, `eval`, or `localStorage` in dashboard source. Ordinary React text rendering is escaped; API credentials are stored in `sessionStorage`, which remains accessible to same-origin scripts.
- [FACT] `submitTask` in `apps/dashboard/src/api/client.ts` sends JSON but suppresses non-2xx response detail and returns `null`; the routed `TasksPage` calls it without the API-required `scope` object. This is a concrete functional UI/API mismatch, not a style issue.
- [FACT] Some dashboard data-fetch helpers convert HTTP failures to empty arrays/false, which can confuse “no data” with “API route unavailable” (Phase 6); client errors are generally not surfaced to the user.
- [FACT] The project builds/tests/lints locally per Phase 11. No browser-based acceptance test confirmed a real dashboard task submission, task progress, evidence, or report rendering.

## Quality conclusion

[INFERENCE] The suite provides substantial model/adapter/regression coverage and several local-target tests, but not a reliable quality signal for “agent works as a user would experience it.” The next verification layer must submit a task through the deployed app/API, observe its actual state transitions, verify adapter/evidence/report outcomes, then exercise cancellation/failure/unauthorized cases. External scans stay out of scope absent a verified allowlist.

High confidence for configuration/test source and the identified test execution boundaries; no static test coverage percentage is asserted from the baseline run.

## Post-baseline functional verification (2026-10-07)

[FACT] The former API-to-task-to-report gap has one actual local test now: a temporary `127.0.0.1` HTTP server, FastAPI `TestClient`, real lifecycle/planner/policy/adapters, evidence storage and report retrieval. The test asserts completed state, successful recorded actions including `http.observe`, nonempty evidence and a retrievable report. It does not assert a finding count/accuracy, drive a browser, cover cancellation/failure, or use a live target (`tests/integration/test_task_submission_e2e.py:52-127`).

[FACT] The dashboard now has a scope-submission form, explicit consent default-off, API error display, and tests for submitted fields/error recovery/IPv6-CIDR classification. The page tests use a mocked API client; this is not browser-to-running-API evidence (`apps/dashboard/src/test/TasksPage.test.tsx:13-81`).

[FACT] FRIDAY fail-closed scope/mode behavior, audit v2 metadata signing, and evidence manifest verification have focused regressions, as detailed in Phase 7. The prior full pytest run reported 331 passed; see the later Phase 11 continuation for the larger follow-up.

## Continued task-level acceptance and CI quality update (2026-10-07)

[FACT] The loopback API acceptance test now asserts one task reaches completed/100%, all recorded actions succeed including `http.observe`, an expected missing-security-headers finding is emitted, the finding references evidence owned by that task, and the generated report includes that finding. This is a stronger functional assertion than the earlier “findings endpoint responds” check, but it does not validate severity/precision beyond a fixture deliberately omitting headers (`tests/integration/test_task_submission_e2e.py:81-183`).

[FACT] Additional actual API tests reject expired, future, and out-of-scope scope without scheduling the worker; cancel a deliberately blocked in-flight lifecycle job and check persisted cancellation/job cleanup; validate completed-task cancellation wording; ensure only one regular cancellation route is registered; and assert missing integration-alias tasks return 404 (`tests/integration/test_task_submission_e2e.py:186-292`). The first run found inaccurate cancellation messages and duplicate cancel-route registration; both were fixed.

[FACT] Artifact storage tests were written red-first: all seven absolute/traversal/symlink cases failed against the baseline because `_resolve_path` accepted them; after the containment check they passed. Checks span store/read/exists/delete. This validates path containment, not race-free access against a concurrent symlink replacement (`tests/security/test_artifact_storage_paths.py`).

[FACT] A dedicated GitHub Actions security test job now executes `pytest tests/security/`; `docker-build` depends on it. Workflow YAML parsing passed and local-equivalent security testing passed **123 tests**. Hosted Actions itself has not run (`.github/workflows/ci.yml:76-95,184-186`). The previous complete Python suite passed 341 tests; the newest result, including a report-failure lifecycle regression, is recorded in Phase 11. Ruff, typed-definition Mypy, and 11 diary checks passed again after that fix; dashboard lint/14 tests/build were verified earlier and no dashboard source changed in the final pass. Tests remain a regression signal, not proof of real-world assessment accuracy or production readiness.

[FACT] A new red-first lifecycle test fault-injects a report-generation exception after the orchestrator returns `completed`. It reproduced a false successful terminal state, then passed after the worker began marking report-generation failure as `failed` and recording a `TASK_FAILED` audit event (`tests/unit/test_evidence_and_orchestrator_deep.py:188-246`; `sentinel/core/orchestrator/lifecycle.py:240-295`). This covers the failure path in-process, not an actual report store or deployment.
