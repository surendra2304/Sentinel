# Phase 5 — Task lifecycle, planner, policy, execution, evidence and agent flow

## Normal API task path

[FACT] `POST /api/v1/tasks` validates a request shape then calls `TaskLifecycleManager.create_and_submit_task`. Lifecycle requires an explicit scope with non-empty owner, authorization reference, active bounded window, allowed methods, maximum impact and positive rate limit; `ScopeResolver.validate_scope` checks scope declarations and each requested target is matched against the allowlist before task storage. It persists task metadata, appends `TASK_CREATED`, publishes in-process task events, and starts an `asyncio` job.

[FACT] The lifecycle job transitions submitted tasks to planning, constructs `AutonomousOrchestrator`, runs the plan, generates a technical report, then saves final state. It pauses on `AWAITING_APPROVAL`. The lifespan calls `recover_tasks_on_startup`, which can resume persisted checkpoints and fails a task closed if an in-flight action makes replay ambiguous.

## Default plan and action loop

[FACT] Default `HeuristicPlanner` baseline plans DNS enumeration, subdomain enumeration and IP intelligence for domain-like targets; it adds OSINT for every non-passive mode. DNS/subdomain actions carry `passive_only` when mode is `PASSIVE_RECON`; third-party-consent flag is copied from scope. Passive mode terminates after baseline. Other task modes continue to HTTP observation/technology fingerprint and then a Python-fallback TCP service scan on `[parsed_port, 80, 443, 8080, 8443, 18890]`. Static plan agent names are only `recon_agent`, `web_security_agent`, and `network_agent` (`sentinel/core/planner/heuristic.py`).

[FACT] The orchestrator persists the whole remaining plan before executing it and marks each action in-flight in the checkpoint before the executor can contact a target. It evaluates each action through `PolicyEngine`, then registered `ToolAdapter`, stores raw output as evidence and routes successful action evidence to the corresponding agent. Agent analysis has a 15-second configured timeout. The orchestrator verifies observation task IDs and every observation evidence ID against evidence actually supplied to the agent before accepting observations as findings.

[FACT] Handoffs are limited by a per-task proposal budget, require registered target-agent capability, a nonempty in-scope target, matching task ID, report-level evidence IDs present in the available evidence set, and duplicate/conflict checks. The action is then re-executed through the normal policy/executor path; it is not a direct execution bypass. The cited evidence list is at report level, not cryptographically/semantically bound to each proposed action and target.

## Policy boundaries and limitations

[FACT] `PolicyEngine.evaluate_action` checks global/task kill switch, third-party enrichment consent, active scope time, maximum impact, passive-mode action allowlist and adapter flags, every action target, optional policy action/module allowlists, allowed method categories, intensity, credential rules, human approval, offensive-action restrictions, and task/target rate windows. Action and module allowlists are checked only when nonempty; default `Policy` has empty lists, so those particular checks impose no additional restriction by default. Scope target/method/impact boundaries still apply.

[FACT] `PolicyEngine` treats action names containing `exploit`, `attack`, `payload`, `bruteforce`, `takeover`, or `destructive` as offensive. Offensive actions require `offensive_actions_enabled` and a listed exploitation method; high/critical impact or explicit `requires_approval` triggers the approval record flow. The policy engine's rate windows and approvals are held in process memory unless an injected repository is used for approvals.

[FACT] `ExecutionEngine` runs adapters under a per-process semaphore (default 25) and retries a non-success result or exception up to two times with exponential sleep. It records even failed/aborted adapter output as evidence. Most adapters are called directly in-process; the `SubprocessSandbox` is only referenced by the network scanner adapter (static source search), not a universal process/container sandbox.

## Observed boundaries / caveats

[FACT] Planner distinguishes `PASSIVE_RECON` from every other `TaskMode`; `FORENSICS` and `MONITORING` do not have separate phase implementations in the default planner. Their active behavior is constrained only by the supplied scope/method policy.

[INFERENCE] Because `run_task` receives one in-memory `Task` snapshot, and the orchestrator checks `task.status`/local settings rather than reloading persisted status between actions, a cancellation handled by another API process can update the repository without stopping the worker process. This becomes a practical risk in a multi-replica topology and is detailed later.

[INFERENCE] After each successful action, the orchestrator queries all evidence for the task, reads every artifact, decodes it to text and passes the full collection to the agent. Repeating this after many actions can re-read and retain the growing evidence set repeatedly; no aggregate evidence-byte cap was found in this path. This is a performance/resource risk, not a measured load result.

High confidence for static control-flow facts. No real targets or network services were contacted.

## Post-baseline task-flow correction (2026-10-07)

[FACT] A local active assessment had reached `partially_completed` at 100% because its explicitly allowed `discovery` method did not cover the planner's exact `http.observe` action. The policy matcher now allows only that exact action under `discovery` (not a broad `http.*` exception); passive-mode restrictions remain independent. See `sentinel/core/policy/engine.py:236-260` and the regression in `tests/security/test_scope_enforcement_regressions.py:132-165`.

[FACT] A new API-to-report integration test runs a task against a temporary loopback HTTP fixture. After the policy correction it asserts terminal `completed`/100%, every recorded action successful including `http.observe`, persisted evidence, and retrievable report. It uses no public target or third-party enrichment (`tests/integration/test_task_submission_e2e.py:52-127`). This demonstrates one bounded local task path, not general assessment accuracy, live-target effectiveness, cancellation coverage, or deployment durability.

## Report-failure status correction (2026-10-07)

[FACT] A red-first lifecycle test injected an exception from report generation after a mocked orchestrator returned `completed`. The pre-fix worker logged and suppressed the exception, then persisted the task as `completed` without a report. It now escalates report-generation failure into the existing fail-closed lifecycle path, which persists `failed` and writes a `TASK_FAILED` audit event. The test checks persisted status and audit-chain integrity (`tests/unit/test_evidence_and_orchestrator_deep.py:188-246`; `sentinel/core/orchestrator/lifecycle.py:240-295`). This is a fault-injected unit test; no real report storage backend or deployment failure was exercised.

## Network scanner request bounds (2026-10-08)

[FACT] The network scanner now rejects non-list inputs, empty lists, booleans/floats, values outside 1–65535, and more than 256 requested ports; duplicate ports are deduplicated. Python socket fallback checks use a shared 32-slot semaphore per adapter instance. Red-first tests reproduced accepted invalid/oversized input and a peak of 32 simultaneous fake connections when configured for 3; after the fix, ten new validation/concurrency test cases pass. A separate existing adapter test also passed with a loopback fixture (`tests/unit/test_network_scanner_bounds.py:24-107`; `sentinel/integrations/scanners/network_adapter.py:18-127`). No public target or production load was used. Nmap receives the port-count cap but its internal socket scheduling was not benchmarked.
