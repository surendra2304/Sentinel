# Task 3 checkpoint — Sentinel URL normalization

- Date: 2026-10-21 (Asia/Kolkata)
- Branch: `fix/task-3-sentinel-port-normalization`
- Latest code commit: `7a62318f0e1d8b57c274a010f26b62bc9424133b`
- Base main commit reconciled: `dd834eb33bd22935d31576e29fc48c1d38f9f9e8`
- Changed: `sentinel/core/scope/resolver.py`, `tests/unit/test_scope_url_port_normalization.py`
- Behavior: strip only scheme-specific default ports, reject port zero, preserve non-default ports, and restore brackets when rebuilding IPv6 URL authorities.
- Tests: repository tests not run; laptop runner returned HTTP 404 and no CI status is available for this branch. Isolated logic smoke checks passed for HTTP/HTTPS default ports, cross-scheme ports, custom ports, and port zero; these are not repository test results.
- Existing PR #9's nonce changes are already present on `main`; its branch has identical file blobs but divergent history and a successful CI run. Do not mix the URL fix into that unrelated PR.
- PR for this URL fix: not created; PR creation tool was blocked by OpenAI safety checks.
