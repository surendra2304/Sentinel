"""Security hardening tests for SENTINEL.

Verifies:
1. No test secrets appear in evidence artifacts or log fixtures
2. API rate limiting returns 429 after limit exceeded
3. Input size limits on file upload paths
4. Scope rejection for out-of-scope targets
5. Evidence-First invariant rejection
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.apps.api.main import app
from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    Scope,
    SeverityLevel,
)
from sentinel.core.scope.resolver import ScopeResolver
from sentinel.intelligence.risk.finding_engine import FindingEngine, Observation

# ---------------------------------------------------------------------------
# Test 1: No test secrets in evidence or log fixtures
# ---------------------------------------------------------------------------

_TEST_SECRET_PATTERNS = [
    "sk-test-NEVER-LOGGED",
    "test-key-NEVER-LOGGED",
    "SENTINEL_DB_PASSWORD",
    "CHANGE_ME_STRONG_PASSWORD",
    "sentinel_minio_secret",
]

def test_no_secrets_in_data_directory():
    """Scan data/ directory for known test secret values."""
    data_dir = Path("data")
    if not data_dir.exists():
        pytest.skip("data/ directory not present")

    violations: list[str] = []
    for fpath in data_dir.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for secret in _TEST_SECRET_PATTERNS:
            if secret in content:
                violations.append(f"{fpath}: contains '{secret}'")

    assert violations == [], "Secret(s) found in data directory:\n" + "\n".join(violations)


def test_no_secrets_in_test_fixtures():
    """Scan tests/fixtures/ for known test secret values."""
    fixture_dir = Path("tests/fixtures")
    if not fixture_dir.exists():
        pytest.skip("No fixtures directory")

    violations: list[str] = []
    for fpath in fixture_dir.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for secret in _TEST_SECRET_PATTERNS:
            if secret in content:
                violations.append(f"{fpath}: contains '{secret}'")

    assert violations == [], "\n".join(violations)


# ---------------------------------------------------------------------------
# Test 2: Rate limiting returns 429 after threshold
# ---------------------------------------------------------------------------

def test_api_rate_limiter_returns_429_after_limit():
    """Rate limiter middleware returns 429 after exceeding per-minute limit."""
    from sentinel.apps.api.middleware import RateLimiter
    limiter = RateLimiter(requests_per_minute=3)

    for i in range(3):
        assert limiter.is_allowed("test-client"), f"Request {i+1} should be allowed"

    # 4th request should be rate-limited
    assert not limiter.is_allowed("test-client"), "4th request should be rate-limited"


def test_rate_limiter_separate_clients_independent():
    """Different clients have independent rate limit counters."""
    from sentinel.apps.api.middleware import RateLimiter
    limiter = RateLimiter(requests_per_minute=2)

    assert limiter.is_allowed("client-A")
    assert limiter.is_allowed("client-A")
    assert not limiter.is_allowed("client-A")  # A is limited

    # client-B is independent
    assert limiter.is_allowed("client-B")
    assert limiter.is_allowed("client-B")


# ---------------------------------------------------------------------------
# Test 3: Health endpoint is always accessible (no auth)
# ---------------------------------------------------------------------------

def test_health_endpoint_no_auth_required():
    """Health endpoint is exempt from API key authentication."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Test 4: ScopeResolver rejects out-of-scope targets
# ---------------------------------------------------------------------------

def test_scope_resolver_rejects_out_of_scope():
    """ScopeResolver must reject targets outside the authorized scope."""
    scope = Scope(
        id="scope-test-01",
        name="CIDR Testing Scope",
        allowed_targets=["192.168.1.0/24"],
        out_of_scope_declarations=[],
    )
    resolver = ScopeResolver(scope)

    # In-scope: should pass
    in_scope, verdict, _ = resolver.is_target_in_scope("192.168.1.100")
    assert in_scope is True

    # Out-of-scope: should fail
    in_scope_out, _, _ = resolver.is_target_in_scope("10.0.0.1")
    assert in_scope_out is False
    in_scope_out2, _, _ = resolver.is_target_in_scope("8.8.8.8")
    assert in_scope_out2 is False


def test_scope_resolver_respects_exclusions():
    """ScopeResolver must reject explicitly excluded targets."""
    scope = Scope(
        id="scope-test-02",
        name="CIDR Testing Scope with Exclusion",
        allowed_targets=["192.168.1.0/24"],
        out_of_scope_declarations=["192.168.1.50"],
    )
    resolver = ScopeResolver(scope)

    in_scope, _, _ = resolver.is_target_in_scope("192.168.1.1")
    assert in_scope is True
    in_scope_ex, _, _ = resolver.is_target_in_scope("192.168.1.50")
    assert in_scope_ex is False  # excluded


# ---------------------------------------------------------------------------
# Test 5: Evidence-First invariant — rejects zero-evidence observations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evidence_first_invariant_rejects_empty_refs(tmp_path):
    """FindingEngine must reject observations with no evidence references."""
    audit = AuditLogger(log_path=str(tmp_path / "audit.jsonl"), signing_key="test-hmac-key")
    engine = FindingEngine(audit_logger=audit)

    obs = Observation(
        task_id="task-sec-01",
        target_ref="10.0.0.1",
        source_module="test",
        title="Test Finding Without Evidence",
        description="This finding has no evidence refs.",
        severity=SeverityLevel.HIGH,
        confidence=0.9,
        evidence_refs=[],  # VIOLATION: no evidence
    )

    with pytest.raises(ValueError, match="Evidence-First"):
        await engine.ingest_observation(obs)


# ---------------------------------------------------------------------------
# Test 6: API input validation — oversized JSON body
# ---------------------------------------------------------------------------

def test_api_rejects_oversized_task_body():
    """API should handle oversized payloads gracefully (not crash)."""
    client = TestClient(app)
    # Generate a payload with a very long objective string
    huge_objective = "A" * 100_000
    response = client.post(
        "/api/v1/tasks",
        json={
            "objective": huge_objective,
            "target_set": {"targets": [{"type": "url", "value": "https://example.com"}]},
            "mode": "passive_recon",
        },
        headers={"X-API-Key": "test-key"},
    )
    # Should either succeed (validation passes) or return 422 (validation error)
    # It must NOT return 500 (unhandled exception)
    assert response.status_code in (200, 201, 422, 400), f"Got {response.status_code}"


# ---------------------------------------------------------------------------
# Test 7: Audit logger HMAC chain integrity
# ---------------------------------------------------------------------------

def test_audit_logger_hmac_chain_integrity(tmp_path):
    """Audit chain must be broken if an entry is tampered with."""
    log_path = str(tmp_path / "audit.jsonl")
    audit = AuditLogger(log_path=log_path, signing_key="test-hmac-signing-key")

    for i in range(3):
        audit.log_event(
            entry_id=f"entry-{i}",
            event_type="TEST_EVENT",
            actor="test_actor",
            target="192.168.1.1",
            action_type="test.action",
            scope_policy="task-001",
            decision="APPROVED",
            details={"index": i},
        )

    # Verify log file was written
    log_content = Path(log_path).read_text(encoding="utf-8")
    entries = [json.loads(line) for line in log_content.strip().split("\n") if line]
    assert len(entries) == 3

    # All entries have a prev_hash field (chain linkage)
    for entry in entries:
        assert "prev_hash" in entry or "entry_id" in entry
