# Phase 15 — Synthesis and first-change guidance

> **Baseline boundary:** The findings and ordered plan below record the state observed before follow-up source changes. Read the dated post-baseline outcome at the end for what was fixed, what was newly exercised, and what remains unresolved. The original baseline is retained to avoid rewriting history.

## Product reality

[FACT] Sentinel has a real Python/FastAPI task engine with scope validation, a policy engine, adapter registry, evidence and report subsystems, a browser dashboard, and a local-loopback orchestrator path. Its normal work is a sequential, heuristic-driven assessment workflow, not an always-on autonomous agent with a configured LLM. The optional LLM planner/provider and newer gateway/tenant/process/prompt controls are not wired into ordinary task execution.

[FACT] The most immediate user-visible blocker is the dashboard task form/API contract mismatch: task submission omits required scope. The most consequential trust-boundary defect is FRIDAY scope defaulting: incomplete authorization claims can become accepted task scope. Passing tests did not catch these because the dashboard test suite does not perform an end-to-end task submission, and an existing FRIDAY test encodes the unsafe behavior as success.

[FACT] The second class of concern is integrity/durability: audit metadata/truncation and evidence manifest metadata can evade current verification, while process-local task/security state does not support the declared replica count. These are evidenced code/probe outcomes, not hypothetical scan findings.

## Ordered first-change plan

1. **Make task authorization explicit at every ingress.** Remove synthetic FRIDAY owner/reference/window defaults; require a complete caller-supplied scope and reject it when absent/partial. Keep the normal API's current fail-closed contract. Clarify that a reference string is a claim until an external authorization authority is integrated.
2. **Restore a usable dashboard task flow.** Add mandatory owner, authorization reference, allowed target, active time window, method, impact, rate limit, and enrichment-consent inputs; send the exact API contract; surface API validation errors. Include tests proving the form cannot silently fabricate authorization and an API integration test that reaches the lifecycle with an explicit local scope.
3. **Exercise the actual app, not just helpers.** In a local-only profile, start an isolated loopback fixture and submit through the API (then browser UI); assert task state transitions, adapter selection, evidence bytes/hash, finding/report status, cancellation, expired/out-of-scope rejection, and no outbound dependency calls when consent is false. Record what is still mocked.
4. **Repair integrity primitives.** Bind all persisted audit metadata into the signed record and detect missing/truncated/sequence-gapped ledgers; verify the evidence manifest digest and reject tampered manifests. Add mutation tests and preserve an external checkpoint/anchor for deletion resistance.
5. **Make deployment behavior match code.** Either constrain deployment to one API process with durable backing or add shared job claims/leases, distributed cancellation/kill switch, tenant context, database health checks, Kubernetes Service/config/persistence, and safe rollout/backup behavior before advertising multi-replica operation.
6. **Integrate and validate advertised controls.** Decide the intended security boundary, then wire tenancy/capabilities/quarantine, ContextFirewall and bounded process execution at the real task/action boundaries. Do not use optional isolated classes as evidence of enforcement.
7. **Make intelligence modes explicit.** If LLM planning is supported, configure/inject it deliberately, validate role-specific schemas, preserve target/parameter semantics, gate outbound data by consent, and run record/replay plus adversarial untrusted-output tests; otherwise document it as optional/not active.

## Acceptance evidence required before claiming “works”

[FACT] A green unit suite alone is insufficient. A meaningful acceptance claim requires at least one actual API/UI submission through the real lifecycle against a controlled loopback fixture, observed task-state progression, task-bound evidence verified against stored bytes, report retrieval, expected behavior on invalid/expired/out-of-scope authorization, cancellation/failure exercise, and outbound-call assertions. Deployment readiness additionally requires real PostgreSQL/object-store/container/health checks, which were unavailable in this audit.

[FACT — baseline probe before policy fix] After the baseline pytest record, an isolated `TestClient` exercise submitted one authorized passive task against `127.0.0.1` through `POST /api/v1/tasks`: missing scope returned 422; valid scope returned 201; the task reached `completed`/100%; `/evidence`, `/findings`, and `/report` returned 200 with 3 evidence records, 3 findings, and a report ID. A second controlled task targeted a temporary HTTP fixture bound to 127.0.0.1 only, with third-party consent false. The app made 4 HTTP requests only to that loopback fixture; it returned evidence/findings/report, but task status was `partially_completed` at progress 100. Inspecting persisted task memory identified `http.observe` as blocked because `allowed_methods=['discovery','validation']` did not recognize the `http` prefix (`sentinel/core/policy/engine.py`, baseline lines 236-254). All other recorded planned actions succeeded. This is a historical runtime observation and was fixed after baseline; the tests wrote only inside temporary directories, with no public target or configured integration.

## Self-assessment

- **Evidence discipline:** high for static wiring, source-adjacent paths, repository counts, and recorded local commands. Significant factual claims should cite source paths/line numbers in the final report and use certainty labels.
- **Runtime confidence:** medium. The core flow has local-loopback test coverage, but the actual API-to-user/browser flow was not exercised by the completed baseline verification. The request to go beyond passing tests is valid.
- **Deployment confidence:** low. No container, external DB/object store, cloud, or orchestration deployment was run.
- **Security confidence:** high for the observed control-flow defects and tamper probes; severity/exploitability depends on deployment identity, allowed targets, and operating practices.
- **Performance confidence:** low beyond code-shape observations; no benchmark or load test was run.

[FACT] The analysis notes are retained phase by phase. No live external target, cloud account, or third-party service was used. Add-ons: none requested.

## Post-baseline status and current guidance (2026-10-07)

### Changes made and functional evidence

| Area | Change | What verification proves—and does not prove |
|---|---|---|
| Active local task execution | `discovery` now permits only the exact planned `http.observe` action; passive mode still denies it (`sentinel/core/policy/engine.py:236-260`). | The real API/lifecycle/orchestrator test completes an assessment against a temporary `127.0.0.1` HTTP server, verifies all recorded action outcomes succeeded including `http.observe`, observes evidence, and retrieves a report (`tests/integration/test_task_submission_e2e.py:52-127`). It does not prove finding accuracy or performance on real targets. |
| Dashboard task submission | Form gathers explicit scope and consent; client sends it and surfaces API errors; IPv6 CIDR inference fixed/tested (`apps/dashboard/src/pages/TasksPage.tsx:7-18, 64-120, 189-305`; `apps/dashboard/src/api/client.ts:214-261`). | 5 dashboard test files/14 tests, lint and production build pass. Tests mock HTTP; no browser connected to a running API. |
| FRIDAY trust boundary | Missing/partial scope rejected; no synthesized authorization; `assessment` stays assessment; unsupported forensics/monitoring mode rejected. Docs and JSON contract updated (`sentinel/apps/api/main.py:623-722`; `sentinel/integrations/friday/models.py:58-93`; `contracts/friday_delegation.schema.json`). | Route tests confirm rejection and mode storage; FRIDAY lifecycle tests disable the background worker. The reference is still a caller claim and is not verified with an authorization registry. |
| Audit integrity | New audit v2 signs sequence, timestamp, tenant and action metadata and enforces v2 sequence continuity; legacy v1 remains readable (`sentinel/audit/audit_logger.py:20-30, 100-150, 190-275`). | Mutation tests reject v2 metadata edits; a legacy chain verifies and can be extended. There is still no trusted head anchor, so deletion or valid-prefix truncation remains undetectable. |
| Evidence ZIP integrity | New v2 bundles authenticate a canonical manifest with the audit HMAC key and verify record count, paths, size, and artifact bytes (`sentinel/storage/evidence/store.py:227-376`). | Tests reject changed artifact bytes and a rehashed manifest with a stale/forged HMAC. Legacy v1 is checksum-only. The exported JSON manifest has a signature field but no corresponding public verification method in this code path. |

[FACT] These changes are evaluated by behavioral properties and direct observations, not LOC. The first follow-up full local run at that point was 331 tests; later runs superseded it, with the current outcome recorded in the Phase 11 continuation.

### Remaining highest-priority work

1. **Make authorization claims verifiable.** Bind task owner and reference to an authenticated human/tenant and a trusted authorization source (ticket/signature/asset inventory), instead of accepting caller strings as proof. Keep third-party data-sharing consent explicit.
2. **Make one-worker semantics real before scaling.** Add shared task leases/claims, idempotent checkpoint transitions, distributed cancellation/kill-switch propagation, tenant-bound repositories and truthful DB/object-store health; then repair the Kubernetes Service/worker/shared-storage configuration. Do not use the declared replica count as scale evidence.
3. **Anchor audit history externally.** Persist/compare a trusted last-sequence/hash checkpoint outside the ledger's failure domain; add rotation/retention/export, append efficiency and multi-process coordination. The current v2 fixes metadata alteration but not tail deletion or valid-prefix rollback.
4. **Close network execution gaps.** Add bounded scanner port limits and subprocess resource limits; replace unconditional TLS `verify=False` with explicit trust configuration; preserve opt-in support for local/self-signed fixtures only where required. Confirm redirect targets and external-data consent at every endpoint.
5. **Complete user-facing acceptance.** Add browser-to-running-API task creation, progress, cancellation, and error-state tests. API-level expired/future/out-of-scope rejection and controlled in-flight cancellation now have tests; exercise cancellation/failure during a real adapter action next. Add measured useful-finding precision/recall only against an explicitly authorized controlled corpus.
6. **Validate deployment with dependencies.** Run container/Compose, PostgreSQL, object store, health/readiness, migration and restart-recovery tests; none were available in this audit.

**First next change recommendation:** implement an explicit trusted identity/authorization-reference verification boundary, because the current form and FRIDAY guard now collect/reject scope shape correctly but cannot establish the truth of those claims. In parallel, do not deploy the existing multi-replica manifest as a safe execution topology until distributed work/cancellation state is implemented.

### Updated self-assessment

- **Evidence discipline:** high for repository inventory, static wiring and executed local commands; significant report claims cite inspected paths/lines. Historical Git conclusions remain low-confidence because the checkout is shallow.
- **Functional/runtime confidence:** medium. One controlled API-to-report task path completes with successful action outcomes; API scope/cancellation edges and report-failure handling have regression tests; dashboard logic and FRIDAY ingress have unit tests. No browser-to-live-app acceptance, real adapter-action interruption, public/live target validation, or measured finding quality is claimed.
- **Security confidence:** high for the specific fixed regressions and remaining static gaps; no live exploitation or authorization-source validation occurred.
- **Deployment and performance confidence:** low; containers, external DB/object storage, orchestration and sustained load were not run.

[FACT] Work stayed on `arena/f082f82e-sentinel`; no commit, push, PR, publish, external scan, or source upload was performed. Add-ons: none requested.

## Continued functional/security pass (2026-10-07)

The previous synthesis did not complete the user's requested functional follow-up. This continuation added behavior-driven tests and fixed defects observed by those tests rather than treating the report or green suite as the endpoint.

| Defect/coverage gap reproduced | Follow-up |
|---|---|
| Cancel API always said “execution halted successfully,” even for a completed task and for status responses that only reported the actual cancelled state. | Corrected message to distinguish a cancelled task from already-terminal completion/failure; tests assert both paths. |
| Two `POST /api/v1/tasks/{task_id}/cancel` registrations shadowed one another; FRIDAY/Sentinel alias cancellation raised uncaught `KeyError` on an unknown ID. | Removed duplicate regular route, kept aliases, mapped absent task IDs to 404; route-count and missing-alias tests pass. |
| Report-generation exceptions were logged and suppressed after orchestration completed, leaving tasks `completed` without a report. | Escalated report failure into the fail-closed task handler; the red-first regression verifies persisted `failed` status and a valid `TASK_FAILED` audit entry. It fault-injects in process and does not test an actual report backend outage. |
| The network scanner accepted unbounded/malformed port lists and issued all Python fallback probes concurrently. | Added 256-port validation, range/type checks, deduplication, and a shared 32-slot Python socket semaphore. Ten red-first cases reproduced input/concurrency gaps and pass after the fix; no throughput or cross-process claim is made. |
| `LocalFileSystemStorage` accepted `..`, Windows-style traversal/absolute paths and symlink escapes. | Added root-relative validation and resolved-path containment; red-first path tests reproduced acceptance, then passed after fix. Concurrent symlink-replacement races remain outside this implementation's assurance. |
| Existing API-to-report test did not assert useful output. | The local fixture intentionally omits defensive HTTP headers; normal task execution now has a tested missing-header observation that remains linked to same-task evidence and appears in the generated report. This is a deterministic fixture assertion, not corpus-level accuracy evidence. |
| PR CI omitted the separate security tests directory. | Added `security-tests` GitHub Actions job and made Docker image build depend on it; YAML parsed and the local equivalent passed 123 tests. Hosted Actions was not run. |

[FACT] Latest full Python result is **356 passed in 11.86 s** with one non-failing Starlette/httpx deprecation warning; the CI-equivalent security suite passed 125 tests in 3.81 s, Ruff passed repository-wide, typed-definition Mypy passed 166 source files, and diary validation passed. The subprocess-output regression measured 492,157 bytes of traced parent peak for 8 MiB per stream, compared with 33,599,049 bytes in an old-style local `communicate()` harness. Dashboard lint/14 tests/build passed earlier; dashboard source did not change. These local results do not establish browser, database/object-store, deployment, public-target, child-memory/CPU, or general finding-quality behavior.
