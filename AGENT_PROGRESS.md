# Agent Progress — Sentinel

**Updated:** 2026-10-08 (Asia/Calcutta)<br>
**Branch:** `arena/f082f82e-sentinel`<br>
**Baseline commit:** `d991a5acbee890211e66539c547fd9e32c328143`<br>
**Latest checkpoint:** `674d270` is committed and pushed on this branch.<br>
**State:** Steps 6–8 are complete; step 9 is in progress. This is not a completion claim.

## Current step

**[~] 9 — Bound task-event SSE queues without stalling publishers.** Source inspection confirms `InMemoryEventBus.publish` awaits `put()` into unbounded per-correlation queues; both task and FRIDAY streams consume those queues and unregister in `finally`. The global 10,000-event history is not replayed by either route. Candidate policy: cap each queue, emit an explicit overflow signal when old live updates must be discarded, preserve a terminal task event under overflow, and test both stream mappings plus cleanup. Do not silently lose terminal events; all tests local.

## Checklist

1. **[x] Recover repository state.** Checked branch/log/status/diff. The only visible commit is the baseline merge; prior implementation, report, phase notes, and regression tests were uncommitted. `AGENT_PROGRESS.md` was missing and has been rebuilt.
2. **[x] Complete the repository analysis and Phases 0–15 evidence notes.** `REPO_ANALYSIS.md` and `analysis-notes/phase-00` through `phase-15` are present. Baseline observations are distinguished from follow-up fixes and remaining uncertainty.
3. **[x] Implement and verify the pre-existing functional/security follow-up.** The working-tree patch includes explicit FRIDAY scope enforcement, dashboard scope/error flow, narrow `http.observe` policy correction, audit/evidence integrity fixes, cancellation/API fixes, local artifact-key containment, API-to-report loopback acceptance, and a CI security-test job.
4. **[x] Fix report-failure task status.** A red-first test reproduced `completed` being persisted when report generation threw. The lifecycle now persists `failed` and records `TASK_FAILED`. The unit module passed 10 tests; the prior full suite passed 342.
5. **[x] Bound scanner port inputs and Python-fallback sockets.** Rejects malformed/empty/out-of-range lists and more than 256 ports, deduplicates repeats, and caps shared Python socket checks at 32 per adapter instance. Red-first tests exposed 9 failures including a 32-vs-3 concurrency breach; targeted suite passed 11 including the loopback adapter test. Full Python suite now passes **352 in 11.66 s**, security suite **123 in 3.14 s**, Ruff, Mypy (165 source files), and all diary checks pass.
6. **[x] Bound output in both subprocess runners.** Replaced unbounded `communicate()` capture with one shared asynchronous reader that retains at most each configured stdout/stderr prefix while draining both pipes. Preserved per-stream markers, return shapes, timeout messages, and the standalone truncation flag; cancellation/timeout now reap the local child and signal a dedicated process group on POSIX. Preserved `SafeProcessRunner`’s 1-second POSIX SIGTERM grace before SIGKILL, verified with a SIGTERM-ignoring local child. The 8 MiB-per-stream regression held traced parent allocations to **492,157 bytes**; equivalent old `communicate()` capture peaked at **33,599,049 bytes**. Targeted suite: **13 passed**.
7. **[x] Final verification/evidence update.** Full pytest **356 passed in 11.86 s**; security suite **125 passed in 3.81 s**; Ruff, Mypy (166 source files), and all 11 diary checks passed. Final report audit checked **191 links / 170 line anchors across 17 files**, with no invalid targets and zero Markdown trailing whitespace; staged `git diff --check` passed. Removed only verified untracked `data/artifacts/` test fixtures; `sentinel.egg-info/` and `logs/audit.jsonl` were absent.
8. **[x] Commit and push the verified subprocess-boundary item.** Commit `674d270` is on `arena/f082f82e-sentinel` and was pushed to `origin`; no other branch was used. Continue recording future verified items with the same fixed-branch rule.
9. **[~] Bound in-memory task-event queues.** `publish` fills unbounded per-correlation queues; two SSE routes read them and only unregister on generator teardown; event history is capped but is not replayed. Validate a bounded, explicit overflow signal that preserves terminal events and does not block publishers. Add local regression tests for queue size, terminal preservation, SSE mapping, and cleanup.

## Latest verification after step 6 (2026-10-08)

- Full local Python suite: **356 passed in 11.86 s**, one non-failing Starlette/httpx deprecation warning; no thread-exception warnings.
- CI-equivalent security suite: **125 passed in 3.81 s**, same warning.
- Ruff passed repository-wide; typed-definition Mypy passed on **166 source files**; all 11 diary checks passed.
- Targeted sandbox/execution/process-runner tests: **13 passed**. They cover both output markers, exact-cap behavior, zero-timeout mapping, timeout escalation, injection-safe argv, and local cancellation cleanup.
- Memory regression: child emitted 8 MiB on each stream; new sandbox retained 4 KiB per stream plus markers with **492,157 bytes** traced parent peak. An old-style local `Popen.communicate()` harness returned 16 MiB and peaked at **33,599,049 bytes**.
- Dashboard lint, **14 tests**, and production build passed in the previous verification pass; dashboard source has not changed.
- Final Markdown audit: **191** local links / **170** line anchors across 17 report/note files; zero invalid references and zero trailing whitespace. `git diff --cached --check` passed; verified generated task artifacts were removed.

## Boundaries / remaining unknowns

No browser-to-running-API acceptance, real report-store outage, actual adapter-action interruption, trusted authorization-source validation, public target, Docker deployment, PostgreSQL/MinIO connection, production environment, or GitHub-hosted Actions run has been performed. Nmap internal scheduling and cross-process load remain uncharacterized. Passing tests are evidence for their assertions, not proof of completeness or zero defects.
