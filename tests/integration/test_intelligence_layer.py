"""Integration tests for SENTINEL Intelligence Layer Abstraction (Phase 8).

Tests:
1. HeuristicProvider full task run - all roles, no LLM, schema-valid outputs
2. LLMPlanner against mocked endpoint - schema enforcement and plan reconstruction
3. Fallback chain when LLM fails (500) - heuristic result returned
4. Quality review flags planted weak finding (no evidence refs)
"""

import json

import httpx
import pytest
import respx

from sentinel.core.intelligence.heuristic_provider import HeuristicProvider, heuristic_provider
from sentinel.core.intelligence.interface import (
    IntelligenceRequest,
    IntelligenceRole,
)
from sentinel.core.intelligence.llm_provider import LLMProvider
from sentinel.core.intelligence.router import IntelligenceRouter
from sentinel.intelligence.evaluation.harness import EvaluationHarness, TaskContext

# ---------------------------------------------------------------------------
# Test 1: HeuristicProvider - full role coverage, no LLM
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heuristic_provider_all_roles():
    """All 7 intelligence roles return schema-valid structured output via HeuristicProvider."""
    provider = HeuristicProvider()

    # PLANNING
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.PLANNING,
        context={"task_id": "t-001", "targets": [{"type": "url", "value": "example.com"}]},
    ))
    assert result.ok
    assert "steps" in result.structured_output
    assert len(result.structured_output["steps"]) > 0
    assert result.provider_used == "heuristic"

    # CORRELATION
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.CORRELATION,
        context={"findings": [
            {"id": "f-1", "affected_assets": ["db.example.com"]},
            {"id": "f-2", "affected_assets": ["db.example.com"]},
        ]},
    ))
    assert result.ok
    assert "clusters" in result.structured_output
    # Two findings sharing same asset should cluster
    clusters = result.structured_output["clusters"]
    multi = [c for c in clusters if len(c["finding_ids"]) > 1]
    assert len(multi) >= 1

    # VULNERABILITY_REASONING
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.VULNERABILITY_REASONING,
        context={"cve_ids": ["CVE-2023-1234"], "cvss_score": 9.8, "exploit_available": True},
    ))
    assert result.ok
    out = result.structured_output
    assert out["remediation_priority"] == "immediate"
    assert out["exploit_maturity"] == "weaponized"

    # THREAT_INTELLIGENCE - IP
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.THREAT_INTELLIGENCE,
        context={"indicator": "198.51.100.1"},
    ))
    assert result.ok
    assert result.structured_output["ioc_type"] == "ip"

    # THREAT_INTELLIGENCE - CVE
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.THREAT_INTELLIGENCE,
        context={"indicator": "CVE-2024-9999"},
    ))
    assert result.ok
    assert result.structured_output["ioc_type"] == "cve"
    assert result.structured_output["verdict"] == "confirmed"

    # FORENSICS_REASONING
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.FORENSICS_REASONING,
        context={"timeline_events": [
            {"timestamp": "2024-01-01T10:00:00Z", "description": "login", "source": "auth.log"},
            {"timestamp": "2024-01-01T10:01:00Z", "description": "cmd.exe", "source": "sysmon",
             "event_type": "process_exec"},
        ]},
    ))
    assert result.ok
    assert "reconstructed_sequence" in result.structured_output
    assert len(result.structured_output["reconstructed_sequence"]) == 2

    # REPORT_SYNTHESIS
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.REPORT_SYNTHESIS,
        context={"task_objective": "Production web assessment", "total_findings": 5,
                 "critical_count": 2, "risk_score": 8.5},
    ))
    assert result.ok
    assert "executive_prose" in result.structured_output
    assert "critical" in result.structured_output["executive_prose"].lower()

    # QUALITY_REVIEW - no findings, trivially passes
    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.QUALITY_REVIEW,
        context={"findings": []},
    ))
    assert result.ok
    assert "reviewed_findings" in result.structured_output


# ---------------------------------------------------------------------------
# Test 2: LLMPlanner via mocked endpoint - schema enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_provider_mocked_endpoint():
    """LLMProvider parses a mocked JSON response and returns a valid IntelligenceResult."""
    mock_response = {
        "plan_id": "llm-plan-001",
        "task_id": "t-002",
        "steps": [
            {"agent": "recon_agent", "action_type": "dns.full_enum",
             "phase": "RECON_DNS", "justification": "Enumerate DNS records"},
            {"agent": "recon_agent", "action_type": "http.observe",
             "phase": "WEB_OBSERVE", "justification": "Observe HTTP surface"},
        ],
        "reasoning_trace": ["LLM planner: phase-based recon"],
        "is_terminal": False,
        "confidence_is_sufficient": False,
        "phases_covered": ["RECON_DNS", "WEB_OBSERVE"],
    }
    openai_response = {
        "choices": [{"message": {"content": json.dumps(mock_response)}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 80, "total_tokens": 180},
    }

    with respx.mock:
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json=openai_response)
        )
        provider = LLMProvider(
            base_url="https://api.openai.com/v1",
            api_key="test-key-NEVER-LOGGED",
        )
        result = await provider.request(IntelligenceRequest(
            role=IntelligenceRole.PLANNING,
            context={"task_id": "t-002", "targets": [{"type": "url", "value": "target.com"}]},
        ))

    assert result.ok
    assert result.provider_used == "llm:gpt-4o-mini"
    assert "steps" in result.structured_output
    assert len(result.structured_output["steps"]) == 2
    # Verify cost tracking
    assert result.token_usage.total_tokens == 180
    assert result.token_usage.cost_usd_stub > 0
    # Verify API key was NOT included in the structured output
    assert "test-key" not in json.dumps(result.structured_output)


# ---------------------------------------------------------------------------
# Test 3: Fallback chain - LLM 500 -> HeuristicProvider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fallback_chain_on_llm_failure():
    """Router falls back to HeuristicProvider when LLM returns a 500 error."""
    llm_provider = LLMProvider(
        base_url="https://api.openai.com/v1",
        api_key="sk-test-NEVER-LOGGED",
        max_retries=0,  # No retries for fast test
    )
    heuristic = HeuristicProvider()
    router = IntelligenceRouter(
        providers={"llm": llm_provider, "heuristic": heuristic},
        role_provider_map={IntelligenceRole.PLANNING: ["llm", "heuristic"]},
    )

    with respx.mock:
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(500, json={"error": "Internal Server Error"})
        )
        result = await router.request(IntelligenceRequest(
            role=IntelligenceRole.PLANNING,
            context={"task_id": "t-003", "targets": [{"type": "url", "value": "fallback.com"}]},
        ))

    # Should have fallen back and succeeded
    assert result.ok, f"Expected fallback to succeed, got error: {result.error}"
    assert result.provider_used == "heuristic"
    assert "steps" in result.structured_output


# ---------------------------------------------------------------------------
# Test 4: Quality review flags a planted weak finding (no evidence refs)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_quality_review_flags_weak_finding():
    """Quality review must flag a Critical finding with zero evidence references."""
    provider = HeuristicProvider()

    weak_finding = {
        "id": "find-weak-001",
        "severity": "critical",
        "title": "Remote Code Execution in Authentication Module",
        "cvss_score": 9.8,
        "evidence_refs": [],  # Planted weakness: no evidence
        "affected_assets": ["auth.example.com"],
        "target": "auth.example.com",
    }

    result = await provider.request(IntelligenceRequest(
        role=IntelligenceRole.QUALITY_REVIEW,
        context={"findings": [weak_finding]},
    ))

    assert result.ok
    reviewed = result.structured_output["reviewed_findings"]
    assert len(reviewed) == 1
    review = reviewed[0]
    assert review["finding_id"] == "find-weak-001"
    assert review["verdict"] == "flag"
    assert review["confidence_adjustment"] < 0
    assert review["flag_reason"] is not None
    assert "evidence" in review["flag_reason"].lower()

    # Verify total_flagged counter
    assert result.structured_output["total_flagged"] == 1
    assert result.structured_output["overall_confidence"] < 1.0


# ---------------------------------------------------------------------------
# Test 5: EvaluationHarness record and replay
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evaluation_harness_record_replay(tmp_path):
    """EvaluationHarness records a context and replays it, scoring schema validity."""
    harness = EvaluationHarness(fixture_dir=tmp_path)

    ctx = TaskContext(
        task_id="eval-t-001",
        objective="Web application assessment",
        targets=[{"type": "url", "value": "webapp.example.com"}],
        expected_plan_phases=["RECON_DNS", "WEB_OBSERVE"],
    )
    fixture_path = harness.record(ctx, name="test-fixture.json")
    assert fixture_path.exists()

    eval_result = await harness.replay(
        fixture_path,
        provider=heuristic_provider,
        role=IntelligenceRole.PLANNING,
    )

    assert eval_result.schema_valid
    assert eval_result.plan_sanity_score >= 0.5  # at least half expected phases present
    assert eval_result.provider_name == "heuristic"
    assert eval_result.error is None


# ---------------------------------------------------------------------------
# Test 6: Default router uses heuristic, singleton importable
# ---------------------------------------------------------------------------

def test_default_router_importable():
    """intelligence_router singleton imports correctly and uses heuristic chain."""
    from sentinel.core.intelligence.router import intelligence_router
    assert intelligence_router.provider_name == "router"
    assert not intelligence_router.has_llm_for_role(IntelligenceRole.PLANNING)
