# Task 3 next run — Sentinel

1. Inspect `fix/task-3-sentinel-port-normalization` at `7a62318f0e1d8b57c274a010f26b62bc9424133b` and read the checkpoint.
2. Run `python -m pytest tests/unit/test_scope_url_port_normalization.py -q` plus the existing scope adversarial tests. Tests have not run on this branch.
3. Verify IPv6 brackets, scheme-specific defaults, port-zero rejection, and custom ports; inspect CI if a review path is available.
4. Keep the URL change separate from unrelated PR #9. After tests pass, add deterministic rate-window expiry tests.
