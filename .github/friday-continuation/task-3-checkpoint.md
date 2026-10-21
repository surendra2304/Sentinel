# Task 3 checkpoint — Sentinel URL port normalization

- Date: 2026-10-21 (Asia/Kolkata)
- Repository: `surendra2304/Sentinel`
- Branch: `fix/task-3-sentinel-port-normalization`
- Code commit: `5c382ed6c35d3c23de9f7f26254e17ff6b71c641`
- Base: `main` at `8c0e8f81c1a0a67bbcddaa6135875e272f4e227c`
- Compare result: one commit ahead, zero behind.
- PR: not created; create-pull-request tool was blocked by OpenAI safety checks.
- Tests: NOT RUN. Local laptop runner returned HTTP 404; cloud command execution was blocked. No CI status is available for this branch.
- Active engineering duration: not reliably measured.

## Code changes

1. `sentinel/core/scope/resolver.py`: preserve non-default ports according to the URL scheme, strip only HTTP:80 and HTTPS:443, and reject port zero.
2. `tests/unit/test_scope_url_port_normalization.py`: added focused tests for HTTP and HTTPS default ports, cross-scheme non-default ports, custom ports, and port-zero rejection.

The change is limited to local URL normalization; no external targets were scanned or contacted.

## Remaining concerns

- Tests and lint have not been executed.
- Review whether the existing URL normalizer should also reject encoded control characters in a separate focused change.
- A draft PR is still required for review.
