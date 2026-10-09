# Phase 0 — Ground truth & orientation

## Environment and commands

Repository root is `/home/user/Sentinel`, checked out on `arena/f082f82e-sentinel`; initial `git status --short --branch` was clean. No source changes had been made when these notes were started. Inventory commands: `git ls-files`, `find` excluding `.git` and common generated directories, `wc -l`, `du -sh`, `file`, and Git metadata commands.

## Measured inventory

- [FACT] 361 files are tracked (`git ls-files | wc -l`); 361 regular files were found outside `.git` (no untracked generated tree was present at inventory time).
- [FACT] The checkout occupies 2.7 MB excluding `.git`, and `find ... | wc -l` reports 50,621 total text/file lines (all tracked file types, including schemas, lockfiles, tests, docs and configs; not a pure source LOC measure).
- [FACT] Python is the largest language by file count: 245 `.py` files, 34,065 lines. JSON: 34 files / 10,911 lines; Markdown: 29 / 1,818; TSX: 15 / 1,719; TypeScript: 6 / 579. Other tracked types include YAML, YML, JS, TOML, shell, CSS, HTML, INI, Mako, and extensionless files. Approximately 36.5k lines are code-like Python/TypeScript/JavaScript/shell, but this estimate includes tests and generated/contract code.
- [FACT] No symlinks or binary-looking tracked files were identified by the `find`/`file` pass. Hidden regular files include `.dockerignore`, `.env.example`, `.gitignore`; `.github/` is also hidden. No `.env` or `node_modules` directory is present. `.gitignore` excludes local environments, build output, databases, logs, and real `.env` files while allowing `.env.example` (`.gitignore`).
- [FACT] Root areas: `alembic/`, `apps/`, `contracts/`, `diary/`, `docker/`, `docs/`, `k8s/`, `scripts/`, `sentinel/`, `tests/`, and `.github/`; there are also project-level docs, container/deployment files, a Python CLI script, and JSON artifacts. [HYPOTHESIS] `sentinel/` is application/library code; `tests/` is its test suite; `apps/dashboard/` is the separate browser UI; `contracts/` contains wire/schema contracts; `alembic/` holds database migrations; `docker/`/`k8s/`/Render files describe deployment; `diary/` and top-level audit/verification docs record engineering history. Later phases validate these hypotheses.

## Git metadata boundary

- [FACT] HEAD is `d991a5acbee890211e66539c547fd9e32c328143`, dated `2026-10-07T13:57:40+05:30`, subject `Merge pull request #1 from surendra2304/arena/01a10cc4-sentinel` (Git log / `git show`).
- [FACT] `.git/shallow` contains this HEAD; it is shown as grafted. `git rev-list --count HEAD` sees one commit; only local branches `arena/f082f82e-sentinel` and `main`, remote-tracking `origin/main`, and no tags were listed. The visible merge object names parent SHAs `947b3f009750792abe14b2030a39cb88ad460846` and `a8140a72f147ace241f5eef54993e21656f2aeb7`, but their history is absent from this shallow checkout.
- [INFERENCE] True project age, lifetime commit count, activity cadence, author concentration, churn, and tag/release timeline cannot be estimated from this shallow clone. The one visible commit is not a reliable project-history sample. Full history would be required; no attempt was made to fetch it.

## Meta-file and documentation read log

- Read `README.md`, `AUDIT_REPORT.md`, `COVERAGE.md`, `GAPS.md`, `SENTINEL_DIARY.md`, `SYSTEM_MANIFEST.md`, `VERIFICATION.md`, all tracked `docs/*.md`, and both `.github/workflows/*.yml` (each is summarized in later phase notes where relevant).
- [FACT] No `LICENSE*`, `CONTRIBUTING*`, `CODE_OF_CONDUCT*`, or `SECURITY*` file is tracked, despite README's link to `CONTRIBUTING.md` (`README.md`); `docs/contracts.md` exists but is empty (0 bytes).
- [FACT] The README documents a Docker Compose + PostgreSQL + MinIO quickstart, CLI/API/dashboard, authorization boundary, and directs contributors to `CONTRIBUTING.md` (`README.md`). The source/deployment claims are cross-checked in later phases rather than accepted as proof.
- [FACT] Existing documentation itself draws a verification boundary: `GAPS.md`, `AUDIT_REPORT.md`, and `COVERAGE.md` explicitly distinguish local test evidence from live deployment/production validation.

## Initial items to verify in later phases

- [HYPOTHESIS] `render.yaml` and `k8s/deployments.yaml` may describe topologies inconsistent with the one-process Compose application; inspect code and manifests together.
- [HYPOTHESIS] The docs may be stale in their API/component claims; route and startup inventory will be derived from executable source.
- [HYPOTHESIS] The root package lock and nested dashboard package lock may have different roles; inspect manifests.
- [HYPOTHESIS] The diaries may contain development-history claims that should not be treated as Git history or runtime verification.
