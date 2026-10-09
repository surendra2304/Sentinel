# Phase 1 — Repository map, stated purpose, and documentation boundary

## Inventory snapshot

[FACT] `git ls-files` reports 361 tracked files. Top-level tracked counts: `sentinel/` 183, `tests/` 71, `apps/` 30, `contracts/` 21, root 20, `diary/` 11, `alembic/` 7, `docs/` 8, `docker/` 3, `.github/` 2, `scripts/` 4, `k8s/` 1. Extension totals include 245 Python files, 34 JSON, 29 Markdown, 15 TSX, 11 YAML, 6 TS, 4 YML, plus JS, shell, CSS, HTML, Mako, TOML, INI, and extensionless files. The tracked code-like set (`*.py`, `*.ts`, `*.tsx`, `*.js`, `*.jsx`, `*.sh`) is 36,442 lines including tests and scripts. The more inclusive Phase 0 text inventory was 50,621 lines. These are separate counting scopes.

[FACT — baseline snapshot] The current branch is `arena/f082f82e-sentinel`; at the start of this phase, only Phase 0 notes were untracked and no application source edits had been made. Follow-up code/test changes are documented separately in the Phase 11/15 addenda; do not treat this baseline sentence as current working-tree status.

## Purpose and interface map

[FACT] README describes a Python/FastAPI security-assessment service, Typer CLI, React/TypeScript dashboard, security modules/adapters, task lifecycle and policy controls, evidence store, reports, FRIDAY integration, and offline/optional intelligence (`README.md`). The actual main packages are `sentinel/apps/{api,cli}`, `sentinel/core`, `sentinel/modules`, `sentinel/integrations`, `sentinel/storage`, `sentinel/intelligence`, `sentinel/audit`, plus `apps/dashboard/src`.

[FACT] The tracked documentation set includes `README.md`, architecture, deployment, authorization/policy, module-development, FRIDAY, intelligence-provider, and empty contracts documentation. `docs/contracts.md` is zero bytes. README links to `CONTRIBUTING.md`, but no such file is tracked; no LICENSE, SECURITY, or CODE_OF_CONDUCT file is tracked (Phase 0 inventory).

## Trust boundary for repository claims

[FACT] README says task submission requires explicit owner, written authorization, target scope, impact ceiling and bounded time window, and says third-party enrichment defaults off. This statement is checked against both the normal task gateway and FRIDAY path later; it is not accepted as proof.

[FACT] `docs/architecture.md` and README contain component/data-flow claims that are not fully aligned with runtime wiring. Detailed differences and source evidence are captured in later phases. The README's Apache-2.0 classifier is not accompanied by a tracked license file (`pyproject.toml`; Phase 0 file inventory).

## Source-history constraint

[FACT] Git metadata is shallow/grafted at the sole locally visible commit; its recorded parents are absent. No project age, contribution count, churn, or release chronology can be inferred. The diary is documentation, not a substitute for full Git history (`analysis-notes/phase-00-ground-truth.md`).

## Confidence

High for tracked-file counts, package boundaries, and read documentation; medium for interpreting README intent; low for historical claims beyond the shallow commit.
