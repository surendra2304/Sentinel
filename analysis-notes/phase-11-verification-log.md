# Phase 11 — Independent local verification log

Verification commands were run in `/home/user/Sentinel` on `arena/f082f82e-sentinel`; each result applies to the working-tree source at that point, and no source was edited while an individual command was running. The audit signing key was a deterministic test-only key from `tests/conftest.py` or a temporary probe; no deployment credentials were read or printed. Before initial pytest, `logs/audit.jsonl`, `data/artifacts/`, and `.env` were confirmed absent. External integration variables and `RENDER` were unset for pytest; default storage was memory/local. Test-created `data/artifacts/` and pip-created `sentinel.egg-info/` were removed after the initial run because both were absent before verification. No external security target was contacted.

## Commands and observed outcomes

| Command | Outcome |
|---|---|
| `python -m venv .venv && .venv/bin/python -m pip install --disable-pip-version-check --no-input -e '.[dev]'` | Exit 0. Installed declared Python project/dev dependencies into ignored `.venv`; resolved FastAPI 0.142.2, Starlette 1.7.0, Pydantic 2.13.5, SQLAlchemy 2.1.3, pytest 9.1.1, Ruff 0.16.10, mypy 2.4.0 and others. No source lockfile was created. |
| `.venv/bin/python verify_diary.py` | Exit 0; all 11 dated diary files passed the line/bullet-count rules. |
| `.venv/bin/ruff check .` | Exit 0; `All checks passed!` |
| `.venv/bin/mypy sentinel` | Exit 0; `Success: no issues found in 164 source files`; emits notes that untyped function bodies are not checked by default. |
| `.venv/bin/mypy --check-untyped-defs sentinel scripts/pressure_test_api.py` | Exit 0; `Success: no issues found in 165 source files`. |
| `env -u RENDER -u SENTINEL_API_KEY -u SENTINEL_API_URL -u INTELX_URL -u INTELX_API_KEY -u INFERENCE_URL -u INFERENCE_API_KEY -u MEMORA_URL -u MEMORA_API_KEY -u SENTINEL_MEMORA_EVENTS_ENABLED -u SENTINEL_FRIDAY_API_KEY SENTINEL_ENVIRONMENT=testing SENTINEL_STORAGE_BACKEND=memory SENTINEL_S3_BACKEND=local SENTINEL_API_AUTH_REQUIRED=false .venv/bin/pytest -q -W error::pytest.PytestUnhandledThreadExceptionWarning --tb=short` | Exit 0; progress reached 100%; no failures/errors. One `StarletteDeprecationWarning`: `httpx` with `starlette.testclient` is deprecated; pytest suggests installing `httpx2`. The quiet invocation did not print a final pass count. |
| Same environment, `.venv/bin/pytest --collect-only -o addopts=` | Exit 0; `321 tests collected in 0.93s`. The full run displayed progress for each collection segment through 100%, so 321 tests ran. |
| `npm ci --no-audit --no-fund` in `apps/dashboard` | Exit 0; added 398 packages. Warnings: `whatwg-encoding@3.1.1` deprecated; `eslint@9.39.5` no longer supported. |
| `npm run lint` (dashboard) | Exit 0. |
| `npm test` (dashboard) | Exit 0; 4 test files, 10 tests passed. Vitest 5.0.3 emitted a jsdom-per-file performance suggestion, not a failure. |
| `npm run build` (dashboard) | Exit 0; `tsc` passed, Vite 6.4.4 transformed 1,609 modules and built `dist/` successfully (JS 264.77 kB, CSS 50.81 kB before gzip). |
| `npm audit --audit-level=low` (dashboard) | Exit 0; `found 0 vulnerabilities`. This queried the npm registry vulnerability data; no project source was uploaded. |
| Initial `.venv/bin/pip-audit --skip-editable` | Exit 1; found 20 advisories in the venv bootstrap `pip 23.0.1` and `setuptools 66.1.1`; editable `sentinel` was explicitly skipped. |
| `.venv/bin/python -m pip install --upgrade pip setuptools && .venv/bin/pip-audit --skip-editable` | Exit 0 after upgrading only the ignored venv to `pip 26.2.1` and `setuptools 84.0.0`; output `No known vulnerabilities found`; editable Sentinel remains skipped. |
| Isolated schema generation/comparison using `scripts/generate_schemas.py` from a temporary directory | Corrected Python harness exited 0: generator exit 0, all eight generated JSON schemas byte-matched checked-in files, `mismatches=0`. An earlier shell wrapper printed the same eight MATCH results but returned 1; the isolated Python harness replaced that unreliable wrapper result. No tracked contract file was written. |
| Local temporary audit/evidence/FRIDAY probe, run with `cwd` in a `TemporaryDirectory` | Exit 0. Changing persisted audit `seq`, `timestamp`, `tenant_id`, and `action_id` still yielded `verify_integrity=True`; deleting the ledger also yielded `True`. Altering the ZIP manifest's finding map after its stored hash still yielded verifier `True`. Calling FRIDAY delegate with target `authorized.invalid`, `mode=authorized_assessment`, no scope, and a stubbed lifecycle returned `submitted` with `FRIDAY_DIRECTIVE` and owner `nexus`. This was an isolated local code-path probe; no target resolution/network request or task execution was started. |

## Not run / not established

[FACT] Docker, docker-compose, `psql`, and `minio` were unavailable in PATH at the precheck; no Docker image build, Compose startup, PostgreSQL/MinIO migration, Nginx parse, Render/Kubernetes deploy, TLS check, or live integration was run. No production readiness or capacity claim is made.

[FACT] `npm audit` and `pip-audit` contacted only their package/vulnerability registries to resolve dependency advisories; no repository source was sent. No live scan target was used. The root repository's tracked files remained unchanged; only this audit's `analysis-notes/` files are untracked deliverables at this point. `.venv`, `node_modules`, Vite build output and test caches are ignored/excluded workspace artifacts.

## Follow-up verification after functional/security changes (2026-10-07)

This section is deliberately separate from the baseline above: the application and tests were changed after the original 321-test audit. Commands were run on `arena/f082f82e-sentinel` with production API keys/URLs, `RENDER`, IntelX, inference, Memora and FRIDAY integration variables unset; `SENTINEL_ENVIRONMENT=testing`, in-memory repositories, local artifact storage, and API auth disabled only for local tests. No public target or configured integration was contacted.

| Command / exercise | Outcome |
|---|---|
| Targeted pytest covering v2 audit integrity, evidence-bundle tamper checks, FRIDAY missing/partial scope and mode checks, policy regressions, local API-to-report execution, FRIDAY integration and local concurrent submissions | Exit 0; 33 passed; one non-failing Starlette/httpx deprecation warning. The FRIDAY lifecycle tests stubbed `_start_task_job`, so they verify ingress/storage/mode mapping rather than run a FRIDAY scan. |
| Full suite: `pytest -o addopts= -q -W error::pytest.PytestUnhandledThreadExceptionWarning --tb=short` under the environment above | Exit 0; **331 passed** in 10.72 s. One non-failing `StarletteDeprecationWarning` about using `httpx` with `starlette.testclient`; no thread-exception warnings. This is an automated regression result, not a claim of live-target accuracy. |
| `.venv/bin/ruff check .` | Exit 0; `All checks passed!`. |
| `.venv/bin/mypy --check-untyped-defs sentinel scripts/pressure_test_api.py` | Exit 0; `Success: no issues found in 165 source files`. |
| Dashboard `npm run lint && npm test -- --reporter=dot && npm run build` | Exit 0; ESLint clean, **5 test files / 14 tests passed**, TypeScript check passed, Vite built 1,609 modules (JS 270.61 kB; CSS 51.08 kB before gzip). Tests mock the API client; no browser session against a running API was performed. |
| Schema generation in a temporary directory and byte-comparison of the eight generated core schemas; Ajv validation of `contracts/friday_delegation.schema.json` | Exit 0; 8/8 checked-in core schemas byte-matched. Ajv accepted a complete local-scope sample and rejected the same request without scope. No generated core contract file was overwritten. |
| `.venv/bin/python verify_diary.py` | Exit 0; all 11 dated diary entries passed the repository's line/bullet-count checks. |
| `git diff --check` | Exit 0; no whitespace errors. |
| Loopback-only API-to-report test `tests/integration/test_task_submission_e2e.py` | Real `TestClient` submission through lifecycle, planner, policy, adapter, evidence/findings endpoints and report retrieval against a temporary HTTP server bound to `127.0.0.1`. Asserted `completed` at 100%, all recorded actions successful including `http.observe`, nonempty evidence, and a retrievable report. The fixture receives only localhost requests; third-party enrichment is false. The test checks the findings endpoint status but does not assert nonempty findings or finding accuracy. |
| Audit/evidence mutation probes in added regression tests | New v2 audit records reject changes to `seq`, `timestamp`, `tenant_id` and `action_id`; legacy v1 audit records can still be verified and extended. Evidence v2 checks canonical manifest hash, HMAC signature and artifact bytes/size; a modified artifact and a forged-but-rehashed manifest are both rejected. |

[FACT] The full test run created ignored `data/artifacts/` fixtures; these and the untracked `sentinel.egg-info/` install artifact were removed afterward. `logs/audit.jsonl` and `.env` remained absent. The report and `analysis-notes/` are intentional audit deliverables. No commit, push, publication, deployment, live scan, Docker build, PostgreSQL/MinIO connection or browser acceptance test was performed.

## Intermediate verification after FRIDAY contract and report edits (2026-10-07)

The FRIDAY schema and audit-note edit postdated the earlier follow-up test run, so core checks were rerun against the then-current source tree. The later continuation section below supersedes these full-suite outcomes. The environment/scope restrictions above applied.

| Command | Observed outcome |
|---|---|
| Full pytest with the same local-only environment: `pytest -o addopts= -q -W error::pytest.PytestUnhandledThreadExceptionWarning --tb=short` | Exit 0; **331 passed, 1 non-failing StarletteDeprecationWarning, in 10.27 s**. |
| `.venv/bin/ruff check .` | Exit 0; all checks passed. |
| `.venv/bin/mypy --check-untyped-defs sentinel scripts/pressure_test_api.py` | Exit 0; no issues in 165 source files. |
| `.venv/bin/python verify_diary.py` | Exit 0; all 11 dated diary entries passed. |
| Dashboard `npm run lint && npm test -- --reporter=dot && npm run build` | Exit 0; lint clean, **5 files / 14 tests passed**, TypeScript check passed, Vite built 1,609 modules (JS 270.61 kB; CSS 51.08 kB before gzip). |
| `git diff --check` | Exit 0; no whitespace errors in the then-current diff. It was run again after the final note/report edits before delivery. |
| Report citation/link audit | Exit 0; all **157** Markdown links resolve in the repository/workspace and every explicit `#L...` anchor is within its cited file. This checks link existence/range, not whether every cited span alone proves the associated prose. |

[FACT] The then-current tree passed the full test/lint/type/dashboard checks after the schema update. That test rerun recreated ignored `data/artifacts/`; after confirming `git ls-files -- data/artifacts` returned no tracked files, that test-generated directory was removed at that stage. The FRIDAY schema semantic sample remains the Ajv result recorded above; no new Python `jsonschema` dependency was installed. Later verification and cleanup are recorded below.

## Continued functional/security verification after user correction (2026-10-07)

The user explicitly clarified that the report plus a smoke task did not finish the requested functional work. A new pass added API-level lifecycle edge tests, found two cancellation API defects, and independently hardened local artifact path resolution. Every target in this pass was a literal `127.0.0.1` fixture or a request rejected before scheduling; production/integration variables were unset.

| Exercise | Observed result |
|---|---|
| Initial API acceptance test after adding terminal/in-flight cancellation message assertions | **2 failed, 1 passed**. Both failures showed the endpoint always said “execution halted successfully,” including when the task was already `completed` and in the cancelled response. Fixed the response to say “already terminal” for completed/failed/blocked/partial tasks and “is cancelled” for cancelled tasks. |
| API task lifecycle suite after fixes: `tests/integration/test_task_submission_e2e.py` | **4 passed**. Covers a full loopback API task, completed status/100%/successful action outcomes, expected missing-header finding, same-task evidence references and report inclusion; expired/not-yet-active/out-of-scope requests return 422 without scheduling; a blocked worker can be cancelled through API and its handle is removed; unique cancellation routes and unknown-task 404s for aliases. |
| Route ambiguity regression | Red-first test found **two** `POST /api/v1/tasks/{task_id}/cancel` route registrations. Removed the shadowed duplicate; kept the FRIDAY/Sentinel aliases and converted missing alias tasks to 404. The final route test passes. |
| Initial artifact path adversarial tests | **7 failed** against old storage because traversal, absolute keys, Windows-style keys, and a symlink escape were accepted instead of raising. After adding relative-key validation and realpath containment, all seven cases pass. Expanded checks exercise store, read, exists, and delete. |
| `pytest tests/security/` in the CI-equivalent local profile | **123 passed**, one non-failing Starlette/httpx deprecation warning. |
| Full pytest with local test environment and external service variables unset | **341 passed** in **10.83 s**, one non-failing Starlette/httpx deprecation warning; no thread-exception warnings. |
| Re-run of the CI security job command `pytest tests/security/` after final test strengthening | **123 passed** in 2.70 s; one non-failing Starlette/httpx deprecation warning. |
| `.venv/bin/ruff check .`; typed-def Mypy on `sentinel scripts/pressure_test_api.py`; diary validator | Ruff passed; Mypy reported no issues in **165 source files**; all 11 diary checks passed. |
| Dashboard `npm ci`, lint, tests, build | `npm ci` passed (deprecation notices for transitive `whatwg-encoding` and ESLint package); lint clean, **5 files / 14 tests passed**, TypeScript check clean, Vite built 1,609 modules (JS 270.61 kB, CSS 51.08 kB before gzip). |
| CI workflow check | PyYAML parsed the workflow; `security-tests` is present and in `docker-build.needs`. A local-equivalent `pytest tests/security/` passed. Hosted GitHub Actions execution was not attempted. |

[FACT] The full suite and dashboard checks did not use public targets, third-party services, credentials, Docker, PostgreSQL, MinIO, or a browser. The loopback header observation is an expected low-severity configuration signal from a controlled fixture; no real-world finding-quality claim is made. Tests regenerated ignored `data/artifacts/` contents and pip generated untracked `sentinel.egg-info/`; both were absent before this verification phase and were removed again after the final test runs. `git diff --check` and the report link/anchor audit were rerun after the final report/note edits.

## Verification after lifecycle report-failure fix (2026-10-07)

| Check | Result |
|---|---|
| Red-first report-failure regression | Before the fix, injected report-generation failure left the persisted task as `completed`; the failing output demonstrated the false terminal state. After escalation to the fail-closed task handler, the regression checks `failed`, a `TASK_FAILED` audit entry, and audit-chain integrity. The full `tests/unit/test_evidence_and_orchestrator_deep.py` module passed **10 tests**. |
| Full local Python suite with external service variables unset | **342 passed in 10.14 s**; one non-failing Starlette/httpx deprecation warning; no thread-exception warnings. |
| Current CI-equivalent security suite | **123 passed in 2.71 s**; one non-failing Starlette/httpx deprecation warning. |
| `.venv/bin/ruff check .` | Passed: `All checks passed!`. |
| `.venv/bin/mypy --check-untyped-defs sentinel scripts/pressure_test_api.py` | Passed: no issues in **165 source files**. |
| `.venv/bin/python verify_diary.py` | Passed all 11 dated diary count/bullet checks. |
| Dashboard lint/tests/build | Prior verified result remains **5 files / 14 tests**, lint clean, TypeScript check and production build passed; no dashboard source changed during this final Python lifecycle fix. |
| Final report links and diff hygiene | **180** local Markdown links and **161** explicit line anchors were checked across 17 files; no missing paths or out-of-range anchors. `git diff --check` passed after the final documentation edit. This verifies link existence/ranges, not that each cited span proves the associated claim. |

The test-fault injection is local and does not simulate a real file/object store outage. No public or external target, deployment credential, Docker build, database/object store, browser session, GitHub Actions run, or production deployment was used. The new failure behavior still needs user-facing/API acceptance around failed report retrieval and external persistence in a future scoped test.

## Final verification after network scanner bounds (2026-10-08)

| Check | Result |
|---|---|
| Red-first scanner bounds suite | Before the fix, **9 of 10** new cases failed: invalid/oversized port inputs were accepted and two simultaneous scans reached 32 concurrent fake connects rather than the test cap of 3. After adding validation, the 256-port cap and a shared 32-slot Python socket semaphore, all ten new cases passed. An existing adapter execution test against a loopback fixture also passed; total targeted result: **11 passed**. The concurrency test monkeypatches `asyncio.open_connection` and performs no network I/O. |
| Full local Python suite with integration credentials unset | **352 passed in 11.66 s**; one non-failing Starlette/httpx deprecation warning; no thread-exception warnings. |
| Current CI-equivalent security suite | **123 passed in 3.14 s**; one non-failing Starlette/httpx deprecation warning. |
| `.venv/bin/ruff check .` | Passed: `All checks passed!`. |
| `.venv/bin/mypy --check-untyped-defs sentinel scripts/pressure_test_api.py` | Passed: no issues in **165 source files**. |
| `.venv/bin/python verify_diary.py` | Passed all 11 dated diary count/bullet checks. |
| Dashboard lint/tests/build | Previously passed: lint clean, **5 files / 14 tests**, TypeScript check and production build. No dashboard source changed in the scanner pass. |
| Full dependency environment | Recreated ignored `.venv` from `.[dev]` because it had not persisted across tool sessions; latest full run resolved FastAPI 0.143.0 and Starlette 1.7.0. The project does not pin these dependencies. |
| Final report links and diff hygiene | **185** local Markdown links and **166** explicit line anchors checked across 17 files; no missing paths or out-of-range anchors. Markdown trailing-whitespace check passed. `git diff --check` passed after the final report/note edit. This verifies link existence/ranges, not that each cited span proves its associated claim. Test-generated `data/artifacts/` and `sentinel.egg-info/` were removed again. |

The scanner test does not measure real throughput, Nmap internal scheduling, or aggregate concurrency across processes. The port count cap applies before both Nmap and Python fallback; the Python socket semaphore is shared per adapter instance. No external target, public target, or configured integration service was contacted.
