# Phase 8 — Performance, resource bounds, and scale characteristics

> **Baseline boundary:** The resource observations describe the initial review; the dated scanner follow-up below supersedes the initial port-list/concurrency finding for the Python fallback.

## Bounded mechanisms present

[FACT] Settings bound HTTP concurrency (256 default, Uvicorn limit matches), reserve 16 health slots in custom middleware, cap agent proposals (8/task), plan steps (16/iteration), per-agent actions (32/task), analysis timeout (15 s), and task iterations (10). Executor has a per-process semaphore of 25. Working-memory serialization is capped at 2 MB and execution trace at 1,000 entries. Event history is capped at 10,000 entries. HTTP adapter calls often set finite timeouts.

## Unbounded or multiplicative paths

[FACT — baseline issues, mitigated in follow-up] Initially, `NetworkScannerAdapter` accepted an unbounded caller-supplied port list and created one coroutine per port. It now accepts only integer ports in 1–65535, caps each list at 256 and deduplicates repeats. The Python fallback shares a 32-slot semaphore across socket checks per adapter instance. Nmap also receives the 256-port cap; process concurrency there still relies on the executor gate. Both subprocess APIs also replaced post-`communicate()` truncation with bounded streaming capture: stdout/stderr are drained concurrently while only their separately configured prefixes are retained. This bounds parent-side output retention, not child CPU/memory or aggregate cross-process work.

[FACT] After each successful action, orchestrator retrieves all task evidence and reads every raw artifact into a list of decoded strings before calling the agent. This repeats as evidence accumulates. Evidence ZIP creation loads all task artifacts into a dictionary and then an in-memory `BytesIO` archive using `ZIP_STORED`; JSON export decodes raw bytes into replacement-text strings. No total evidence-byte/count export cap was found. API findings/evidence/approvals lists have no paging inputs; task list has a repository default limit of 100.

[FACT] Each audit append loads every nonblank audit line into a list to recover the last entry, so a log with N entries incurs O(N) reading per append and O(N²) cumulative scanning. Event SSE queues are unbounded. HTTP rate-limit maps and in-memory task/evidence/finding/risk state have no global cap/retention; idle per-identity rate windows are purged only when that same identifier is used again.

[FACT] PostgreSQL pool defaults to 20 + 10 overflow per process; Kubernetes HPA advertises up to ten replicas. No pool-sizing/connection-budget alignment is declared in the manifests. Memory/event/risk/job data are process-local.

[FACT] `FridayDelegationRequest.time_budget_seconds` is not consumed by the delegation path; priority influences only the returned estimated-duration string. `resource_constraints` is consumed only for a rate-limit value. Thus these input fields are not task deadline/cancellation enforcement.

## Operational assessment

[INFERENCE] Large evidence collections can cause repeated artifact I/O, event-queue growth, and large peak memory during ZIP export. The Python scanner cap limits per-instance socket concurrency, but multiple worker processes and Nmap internals may still amplify total connections; neither is characterized under load. These are code-shape capacity risks, not measured production incidents.

[FACT] No benchmark or load-test harness was identified in tracked files. Test suites are functional/regression suites, not a performance characterization. No performance numbers are claimed in the final report.

Confidence high for code paths and configured bounds; low for real throughput/latency because no load test or deployment was run.

## Network scanner request bounds (2026-10-08)

[FACT] Red-first tests first demonstrated that invalid/empty/oversized port lists passed validation and that two scans opened 32 concurrent fake connections despite a test cap of 3. The adapter now validates list shape/range/count, deduplicates repeats, and shares a semaphore across scans on the same adapter instance. Ten new unit cases cover malformed, empty, out-of-range, bool/float, over-cap inputs, valid range endpoints, and aggregate concurrency (`tests/unit/test_network_scanner_bounds.py:24-107`). The direct concurrency harness monkeypatches `asyncio.open_connection` and performs no network I/O; an existing adapter integration test passed against a loopback fixture. Full test suite passed 352 tests. This validates bounds logic, not production throughput, Nmap's internal behavior, or cross-process aggregate load.

## Subprocess output retention (2026-10-08)

[FACT] `SubprocessSandbox` and the standalone `SafeProcessRunner` now share an asynchronous reader that retains a bounded prefix per stream and continues draining excess bytes. A local child emitted 8 MiB to each pipe: with a 4 KiB cap, parent Python-traced peak was **492,157 bytes** and each result was 4,133 bytes including its marker; a local old-style `Popen.communicate()` harness peaked at 33,599,049 traced bytes for 16,777,216 returned bytes. Targeted tests cover both runners’ markers, exact-cap behavior, timeout, and sandbox cancellation cleanup. The capture cap does not limit the child’s own allocations, output-generation CPU, or cross-process aggregate load. See [Phase 11](phase-11-verification-log.md) for exact commands and results.
