# Task 3 next run — Sentinel

1. Inspect `fix/task-3-sentinel-port-normalization` at code commit `5c382ed6c35d3c23de9f7f26254e17ff6b71c641` and read this checkpoint.
2. Open a draft PR against `main`; prior create-pull-request calls were blocked by OpenAI safety checks, so verify rather than assuming creation succeeded.
3. Run `python -m pytest tests/unit/test_scope_url_port_normalization.py -q` and the existing scope adversarial suite in a working runner. Record commands and exit codes; tests have not run yet.
4. Review port normalization for IPv6 authorities and malformed/encoded URL edge cases. Keep tests local and strictly within explicitly authorized defensive scope.
5. Inspect existing rate-limit reservation implementation and add deterministic tests for quota exhaustion and expiry before changing that code.
6. Update the checkpoint with actual commit SHAs, test results, CI URL/status, blockers, and the next concrete fix. No force-push, no auto-merge.
