# Phase 2 — Source structure and implementation map

## Quantified source snapshot

[FACT] Static `git ls-files` + Python AST walk found 361 tracked files; 164 Python files under `sentinel/` contain 18,273 nonblank lines, 352 class definitions, and 904 function definitions (314 async). `tests/` contains 71 tracked files, 70 Python files, 9,813 nonblank Python lines, 27 test/helper classes, and 427 function definitions (170 async). `alembic/` has 7 files (5 Python, 415 nonblank Python lines); `scripts/` has 4 Python files and 306 nonblank lines. AST counts include nested definitions and test helpers and are inventory metrics, not quality scores.

[FACT] Dashboard source is 21 tracked files under `apps/dashboard/src` (within 30 total under `apps/`); technology includes React/TypeScript, Vite, Tailwind, Zustand, and TanStack Query as declared in its package manifest. Core backend packages are `sentinel/core/{agents,events,gateway,intelligence,memory,models,orchestrator,planner,policy}`, with implementation packages for API, CLI, integrations, modules, storage, reporting, risk and audit.

## Runtime ownership boundaries

[FACT] The production API app is assembled in `sentinel/apps/api/main.py`. It imports the singleton `lifecycle_manager`, task and evidence repositories, audit logger, event bus, API-key middleware, rate/concurrency middleware, and router modules. The CLI lives in `sentinel/apps/cli/main.py`; the browser app is a separate Vite bundle in `apps/dashboard/`.

[FACT] `sentinel/core/orchestrator/lifecycle.py` owns task admission, in-process jobs, execution, approval pause/resumption, checkpoint persistence and startup recovery. `sentinel/core/orchestrator/orchestrator.py` creates the deterministic planner/executor/coordinator chain. `sentinel/core/policy/engine.py` evaluates action policy. `sentinel/core/gateway/router.py` defines a separate `ActionRouter` integration abstraction; the search found only bridge imports for it, not API task execution wiring.

[FACT] `sentinel/core/planner/heuristic.py` is the default task planner; `sentinel/core/planner/llm_planner.py` exists but is not instantiated by runtime search. `sentinel/core/intelligence/router.py` builds an offline heuristic provider by default. The provider interface and optional LLM implementation are separate from the default task planner path.

## Source map confidence

High for the counted files, AST definitions, package ownership, and static wiring inspected. Counts are based on the tracked snapshot; untracked audit notes are excluded. This phase did not import or execute product code.
