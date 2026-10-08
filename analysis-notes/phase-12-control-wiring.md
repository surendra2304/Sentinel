# Phase 12 — Security-control wiring and capability boundaries

## Runtime integration trace

[FACT] The task execution path constructs `ExecutionEngine`, whose imports and constructor wire `PolicyEngine`, `ToolAdapterRegistry`, evidence storage, and `AuditLogger` (`sentinel/core/orchestrator/executor.py:16-90, 95-116`). Each action calls `self.policy.evaluate_action(...)` and then looks up/runs the registered adapter (`sentinel/core/orchestrator/executor.py:136-219`). A full tracked-Python search found no `ActionRouter` construction in the API/task execution path.

[FACT] `ActionRouter` is imported by three ecosystem bridge classes. FRIDAY and Inference bridges only call `router.authorize`; the Forge bridge calls `router.execute_once` (`sentinel/integrations/ecosystem/friday_bridge.py:6-17`, `inference_bridge.py:6-17`, `forge_bridge.py:6-17`). The bridges are not imported by `sentinel/apps/api/main.py`, lifecycle, or the normal executor. Thus the router's “mandatory gateway” module docstring describes the intended abstraction, not the default assessment runtime.

[FACT] The capability issuer is instantiated conditionally in `main.py` when the configured signing key is sufficiently long, and exposed through issue/verify endpoints (`sentinel/apps/api/main.py:1173-1178, 1296-1332`). Those endpoints take `actor_id`, `tenant_id`, actions, resources, and token from request bodies; the API middleware uses one service API key rather than binding those fields to a verified human/tenant identity (`sentinel/apps/api/middleware.py`, `main.py:1296-1332`). The HMAC implementation verifies token signature, expiry, actor/tenant string equality, and action/resource membership (`sentinel/core/auth/capabilities.py:76-118`), but the normal `ExecutionEngine` does not consult it.

## Orphaned/incomplete controls

[FACT] `TenantManager` is a process-local dictionary mapping plaintext API-key strings to tenant IDs, with simple usage counters (`sentinel/core/tenancy.py:30-61`). Repository search found no runtime consumer outside its definition. The API middleware does not resolve tenant identity through it; tasks and primary evidence/findings repositories have no authenticated tenant context (see Phase 4).

[FACT] The incident and quarantine managers are in-memory collections (`sentinel/core/incident/incident_manager.py:23-40`, `quarantine_manager.py:17-41`). `QuarantineManager.is_quarantined` is called only by its API query endpoint; no policy engine, lifecycle, or executor checks quarantine before task/action execution (`sentinel/apps/api/main.py:1282-1286`; repository-wide symbol search). Incident listing/containment likewise reads process-local state.

[FACT] `SafeProcessRunner` is referenced only by its own module and tests; `SafePath` is referenced only by its own module and tests. `ExecutionEngine` instead uses the older scanner `SubprocessSandbox` path (Phase 7). The process runner receives an `env` object from its caller, and truncates after `communicate()` buffers complete stdout/stderr (`sentinel/core/sandbox/process_runner.py:27-84`); it is not the execution boundary for all adapters. `SafePath` resolves candidates and checks containment (`sentinel/core/security/path_guard.py:17-55`) but is not used by `LocalFileSystemStorage`.

[FACT] `ContextFirewall.prepare` scans and redacts supplied text but returns findings without a blocking decision (`sentinel/intelligence/firewall/prompt_guard.py:17-25`). Search found test references but no use in the default task/LLM path. The intelligence router is offline heuristic-only by default, and no default task planner instantiates `LLMPlanner` (Phases 2/3).

## Gateway implementation caveats

[FACT] `ActionRouter.authorize` verifies a capability only when both a token and issuer are present; it does not require a token. It passes only `targets[0]` (or `"*"` when no target exists) to capability resource verification (`sentinel/core/gateway/router.py:40-50`). Its optional nonce consumer is not supplied at this call site. These caveats affect this standalone abstraction; the normal executor does not use it.

[FACT] `ApprovalManager.consume` performs a `get_approval`, checks APPROVED, then separately writes CONSUMED; `SentinelPersistence.save_approval` is `INSERT OR REPLACE`, not a compare-and-swap update (`sentinel/core/auth/approvals.py:48-64`, `sentinel/storage/persistence/durable_store.py:83-115`). The single-use guarantee in the docstring is therefore not shown to be atomic under concurrent consumers. No concurrent race test was found.

[INFERENCE] The best description is “multiple security-control implementations coexist, with uneven integration,” not “the app consistently enforces every advertised control.” New critical runtime controls should be integrated at the `ExecutionEngine`/policy/lifecycle boundaries and tested through a real task flow, rather than validated only as isolated classes.

## Evidence and confidence

High confidence for static import/reference connectivity and code shape. The test suite contains isolated tests for capability tokens, quarantine, incidents, path handling, subprocess runner, approvals, scanners, and bridges, but those tests do not establish that controls gate actual assessment execution. This phase made no network requests or task submissions.
