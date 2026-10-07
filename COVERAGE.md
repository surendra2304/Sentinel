# Sentinel Test Coverage Snapshot

**Measured:** 2026-10-07
**Command:** `SENTINEL_ENVIRONMENT=production .venv/bin/pytest --cov=sentinel --cov-report=term-missing -q -W error::pytest.PytestUnhandledThreadExceptionWarning`
**Environment:** Linux, Python 3.11.2

## Result

The complete pytest suite passed with unhandled-thread warnings promoted to errors. The warning-strict coverage run reported:

```text
TOTAL                                                      10322   1765    83%
```

FastAPI's test client emitted a Starlette deprecation warning for using `httpx` with `starlette.testclient`. A separate older coverage-instrumented run intermittently emitted a `PytestUnhandledThreadExceptionWarning` from an `aiosqlite` worker (`RuntimeError: Event loop is closed`), attributed by pytest to `test_approval_double_consumption_prevented`. It did not reproduce in the 2026-10-07 warning-strict coverage run. Its source remains unknown; do not declare it fixed.

## Selected module measurements

| Module | Statement coverage |
|---|---:|
| `sentinel/apps/api/main.py` | 73% |
| `sentinel/apps/api/middleware.py` | 89% |
| `sentinel/core/agents/api_agent.py` | 98% |
| `sentinel/core/agents/cloud_agent.py` | 97% |
| `sentinel/core/agents/device_agents.py` | 75% |
| `sentinel/core/agents/dfir_agents.py` | 86% |
| `sentinel/core/agents/endpoint_agent.py` | 83% |
| `sentinel/core/agents/intel_agents.py` | 93% |
| `sentinel/core/agents/network_agent.py` | 79% |
| `sentinel/core/agents/recon_agent.py` | 97% |
| `sentinel/core/agents/security_intelligence_agent.py` | 76% |
| `sentinel/core/agents/web_agent.py` | 73% |
| `sentinel/core/orchestrator/coordination.py` | 88% |
| `sentinel/core/orchestrator/orchestrator.py` | 76% |
| `sentinel/core/orchestrator/lifecycle.py` | 82% |
| `sentinel/core/planner/heuristic.py` | 93% |
| `sentinel/core/memory/working_memory.py` | 90% |
| `sentinel/core/policy/engine.py` | 90% |
| `sentinel/storage/repositories/postgres.py` | 81% |

## Interpretation and limits

- 83% statement coverage measures executed Python statements, not correctness, absence of vulnerabilities, scenario completeness, or production readiness.
- Local tests exercise a bounded recon-to-network handoff and checkpoint recovery, but do not prove useful peer review, conflict resolution from independent reports, distributed operation, or real-world agent behavior. The remaining limits are recorded in `GAPS.md` and `AUDIT_REPORT.md`.
- The Postgres repository's local SQLite-backed tests do not replace a live PostgreSQL/MinIO migration, persistence, restart, and outage test. Container verification remains **CONFIGURED-BUT-UNVERIFIED** because Docker and the service binaries were unavailable in this workspace.
- This replaces an older Windows/Python coverage transcript; historical percentages from that transcript should not be treated as current results.
