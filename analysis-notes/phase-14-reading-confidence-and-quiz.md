# Phase 14 — Reading/confidence log and comprehension quiz

## Coverage log: deep reads, samples, skips

- [FACT] Deep-read traces: API app and request models; normal task creation/lifecycle/recovery; default heuristic planner and orchestrator/executor; policy/scope checks; evidence/audit/report paths; dashboard submit form/API client/routes; primary settings and storage repository factories; capability/approval/gateway/tenancy modules; CI, Compose, Docker, Render and Kubernetes manifests.
- [FACT] Targeted family scans/samples: registered adapters and security-relevant network/process/path helpers; repository-wide symbol references for control wiring; TypeScript dangerous DOM/storage patterns; route/client path comparison; test organization and selected representative local/synthetic integration tests. This was not a line-by-line review of all 245 Python files, every adapter, or every test assertion.
- [FACT] Verification performed separately and recorded in Phase 11: 321 pytest tests; dashboard lint/10 tests/build; Ruff; mypy normal plus `--check-untyped-defs`; diary validator; 8 schema comparisons; package audits; local-only integrity/FRIDAY probes.
- [FACT] Explicitly skipped/unavailable: Docker/Compose/image build, PostgreSQL/MinIO integration, Kubernetes/Render deployment, TLS/reverse-proxy behavior, cloud service connectivity, live third-party enrichment, external targets, sustained load/chaos tests, and browser UI acceptance against a running deployment. The source does not contain an authorized asset list for a production scan.

## Claim confidence scale

- **High**: directly counted tracked files or observed in source; command exit/output is recorded with the exact invocation in Phase 11.
- **Medium**: behavior inferred from connected code paths, or risks dependent on deployment topology/real traffic. Such claims are explicitly marked `[INFERENCE]`.
- **Low / unresolved**: claims that would require unavailable services, full Git history, a browser-driven deployed session, or customer-specific operating assumptions. These are marked as unknown, not filled in.

## High-confidence conclusions

[FACT] The default agent runtime is a sequential in-process task lifecycle using the heuristic planner, policy engine, adapters, evidence, and reporting. The optional LLM planner/provider and several recently added security controls are not wired into that normal task path (`analysis-notes/phase-02-source-structure.md`, `phase-05-core-execution-and-policy.md`, `phase-12-control-wiring.md`).

[FACT] The dashboard's task form omits a required authorization scope, and `submitTask` swallows response detail (`analysis-notes/phase-06-api-and-frontend.md`, `phase-13-quality-and-checklists.md`).

[FACT] FRIDAY delegation can synthesize owner/reference/time/methods for omitted or partial scopes, and normal scope claims are not checked against an external authorization authority (`analysis-notes/phase-07-security-and-trust-boundaries.md`; local probe in `phase-11-verification-log.md`).

[FACT] Independent local pytest, lint/type/build/audit/schema checks passed as recorded, but did not prove use of live target systems or deployed services (`analysis-notes/phase-11-verification-log.md`).

## Comprehension quiz (answer key included)

1. What planner/provider configuration drives ordinary tasks by default?
2. What scope values must a normal API task include, and does Sentinel prove that the cited authorization exists?
3. Why is the FRIDAY delegation path a scope-integrity exception?
4. Why can the dashboard “Launch New Task” form fail despite valid credentials?
5. Which security-control implementation actually gates normal adapter execution: `ActionRouter` or `ExecutionEngine`/`PolicyEngine`?
6. What did the local test named “master E2E” really exercise, and what did the loopback orchestrator test add?
7. Which fields can be altered in persisted audit JSONL without invalidating the current chain check, and what does the check say after ledger deletion?
8. Does evidence-bundle verification recompute `manifest_sha256`?
9. Why is the 3-replica Kubernetes declaration not evidence of horizontally safe task execution?
10. What does a passing full pytest run establish here, and what does it not establish?

### Answer key

1. `HeuristicPlanner` is the normal task planner. The `IntelligenceRouter` is heuristic-only by default; `LLMPlanner`/`LLMProvider` are not instantiated in that task path.
2. Owner, non-synthetic written authorization reference, active start/end time window, allowed methods, maximum impact, positive rate limit, and target binding. Sentinel validates shape and declarations but does not verify a trusted external ticket/signature or the truth of the owner's claim.
3. It fills absent/partial owner/reference/time/method/impact data with defaults such as `friday`/`FRIDAY_DIRECTIVE` and then sends the task through lifecycle; existing tests assert such delegation succeeds.
4. The UI sends objective/target/mode but no `scope`; the API schema requires it. The client also converts non-2xx errors into `null`, hiding the server's explanation.
5. `ExecutionEngine` calls `PolicyEngine` and the adapter registry. `ActionRouter` is a separate abstraction used by bridge classes, not the normal task path.
6. “Master E2E” manually creates a task, records hand-authored evidence, and ingests synthetic observations before testing intelligence/reporting. The loopback orchestrator test starts an HTTP fixture and calls the orchestrator directly, but still bypasses API submission and dashboard flow.
7. `seq`, `timestamp`, `tenant_id`, and `action_id` are omitted from the signed payload; deleting the ledger or truncating a valid tail is not detected. Local probe results are recorded in Phase 11.
8. No. The verifier checks listed artifact bytes but does not compare a recomputed manifest digest to the stored `manifest_sha256`.
9. Task/recovery state and kill-switch/job maps are process-local; the manifest omits Service, shared storage and worker definition/claims. Multiple replicas would not coordinate execution as written.
10. It establishes the current automated assertions complete successfully in the test environment. It does not establish that the agent can accept a real user task through the UI, produce useful findings against a live authorized target, survive production services/restarts, or enforce every disconnected control.

## Limitations

[FACT] The repository history is shallow/grafted to one visible merge commit, so historical project quality/churn cannot be established. No external standard/service was used to certify the app. No performance measurements or live scan accuracy claims are made.

## Post-baseline corrections for current-state reading (2026-10-07)

The original quiz answers describe the audited source baseline. Apply these corrections when reading the current checkout:

- **Q3:** FRIDAY no longer creates owner/reference/window/method/impact/rate defaults. Missing or partial scope is rejected, and `assessment` maps to `TaskMode.ASSESSMENT`; `policy_context` remains advisory. The caller's owner/reference is still not externally authenticated.
- **Q4:** the dashboard now submits explicit scope and shows API validation errors; IPv6 CIDR classification is covered. Component tests use a mocked client, so a real browser/API session remains unverified.
- **Q7:** v2 audit entries authenticate sequence, timestamp, tenant and action ID and reject gaps. Legacy v1 entries have their old weaker signature shape. Missing-ledger or valid-prefix truncation remains undetectable without an external head anchor.
- **Q6:** the later API-to-report test now asserts a real loopback task completes, produces a missing-security-headers finding linked to same-task evidence, and includes it in the report; separate API tests cover invalid scope and cancellation. This still does not validate browser UX or findings against a corpus.
- **Q8:** v2 ZIP verification recomputes the canonical manifest checksum and checks its HMAC signature, plus artifact size/hash. Legacy v1 manifests are checksum-checked only and are not authenticated.
- **Q10:** the latest full local run is 356 passed with one Starlette/httpx deprecation warning. It proves those local assertions only. Public/live target, browser-driven acceptance, production stores, deployments, and broad finding accuracy remain untested.

[FACT] Continued reading also found/fixed inaccurate cancellation responses, duplicate cancellation route registration, uncaught missing-task cancellation aliases, and local artifact path traversal/symlink escapes; the new security regression suite is now wired into CI and locally passed 123 tests. The review still used targeted family scans/samples rather than a line-by-line audit of every adapter/test.
