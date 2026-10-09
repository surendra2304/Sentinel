# Phase 10 — History, documentation, conventions, and drift

## History limits

[FACT] Local Git is shallow/grafted with one visible commit (`d991a5a`, merge message from `arena/01a10cc4-sentinel`); no earlier parent objects are available. The current branch is `arena/f082f82e-sentinel`. `AUDIT_REPORT.md` records branch `arena/01a10cc4-sentinel` and a verification date of 2026-10-07, so that record is not evidence that commands were run on this current working branch. I will independently run safe local verification and label it separately.

[FACT] Eleven dated diary entries span 2026-08-28 through 2026-09-15. The root `SENTINEL_DIARY.md` aggregates historical feature/test claims. `verify_diary.py` checks only each diary file's total line count and number of bullets under `## Daily Summary`; it does not validate technical claims, commands, test outcomes, or source-code agreement.

## Documentation alignment observations

[FACT] README labels intended functions such as complete 10-domain support, optional LLM planner/provider, operations scheduling/alerts, graph views, four report types with evidence manifests, full programmatic access, and secrets never logged/serialized. Source review found material caveats: default planner uses three agents, `LLMPlanner` is not runtime-instantiated, several dashboard operations/audit routes have no API endpoint, only seven dashboard pages are routed, report `evidence_manifest_hash` remains empty, and redaction is key-name based rather than a guarantee against all secret/PII content. README's autonomy-boundary paragraph is appropriately cautious about single-process sequential work.

[FACT] `docs/architecture.md` starts its Mermaid diagram with a bare `mermaid` word rather than a fenced ` ```mermaid ` block; the diagram is not a standard fenced Markdown Mermaid block. It depicts a `TaskGateway`, LLM planner, broad intelligence/report pipeline, Operations services, and `/approvals/{id}/approve` signature flow that do not match current runtime wiring (the API uses `/approvals/{id}/decide`, no signature field). It also says Task status `PENDING`, content-addressed artifacts, and policy default-deny allowlists, while current code uses `SUBMITTED`, task/evidence IDs for artifact keys, and skips empty action/module allowlists.

[FACT] `GAPS.md` and the diary state stronger feature/sandbox/graph/test claims than checked-in wiring supports in places. For example, the attack surface page renders data fields rather than a Cytoscape/Canvas renderer; Nmap is the only optional external scanner binary referenced by the default network adapter; a generic `SubprocessSandbox` is not the execution path for every adapter. `docs/contracts.md` is empty. `VERIFICATION.md` uses Windows `file:///d:/Sentinel/...` links and broadly marks blueprint criteria `VERIFIED`; it is a component/test map, not proof of current runtime or deployment.

[FACT] `AUDIT_REPORT.md` and `COVERAGE.md` contain detailed prior test/build/audit/load observations dated 2026-10-07, including 83% coverage and unavailable Docker/Postgres/MinIO. Those are repository-authored records from the preceding branch; they will be treated as historical claims until independently reproduced in this checkout.

## Conventions / release metadata

[FACT] Python style is Ruff with 100-character configured line length (E501 ignored) and mypy configured for Python 3.11; pytest uses `tests/`, strict markers, asyncio auto. Dashboard scripts define lint/test/build and Node engine constraints. Dependencies are lower-bounded in Python and lockfile-based in the dashboard. README/pyproject claim Apache 2.0, but no LICENSE file is tracked; README links to an untracked `CONTRIBUTING.md`.

High confidence for locally inspected documentation and shallow Git metadata. Historical diaries are recorded as claims, not independently verified chronology.

## Post-baseline contract correction (2026-10-07)

[FACT] `docs/friday-integration.md` now describes `policy_context` as advisory and shows a complete time-bounded scope; `contracts/friday_delegation.schema.json` now requires either `scope` or `scope_override`, a target, the full explicit scope fields, and the supported mode set. `FridayPolicyContext.authorization_reference` no longer has the synthetic `FRIDAY_DIRECTIVE` default (`sentinel/integrations/friday/models.py:58-67`; `docs/friday-integration.md:9-46`; `contracts/friday_delegation.schema.json`). The schema was JSON-parsed; this run did not use a JSON Schema validator package.
