"""Sentinel Fail-Closed Security Readiness Health Check."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HealthReport:
    ok: bool
    checks: dict[str, bool]
    generated_at: float


class FailClosedHealth:
    def check(
        self,
        *,
        audit_ok: bool,
        persistence_ok: bool,
        signing_key_ok: bool,
        policy_loaded: bool,
    ) -> HealthReport:
        checks = {
            "audit_integrity": audit_ok,
            "persistence": persistence_ok,
            "signing_key": signing_key_ok,
            "policy": policy_loaded,
        }
        return HealthReport(all(checks.values()), checks, time.time())
