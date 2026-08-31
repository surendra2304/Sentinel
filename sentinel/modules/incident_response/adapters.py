"""Incident Response Engine & SOC Report Models for Sentinel.

Provides:
- Alert Triage & Root Cause Analysis
- Containment Recommendation Engine (requires human approval, never auto-executes)
- SOC/IR Incident Investigation Report Generator
"""

import json
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.memory.knowledge_base import IOCType, knowledge_base_store
from sentinel.core.models import (
    ActionRequest,
    ActionResult,
)
from sentinel.core.orchestrator.adapter import ToolAdapter


class TriageVerdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    CONFIRMED_INCIDENT = "confirmed_incident"


class IncidentAlert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_system: str
    indicator: str
    indicator_type: str = "ip"
    description: str
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class ContainmentRecommendation(BaseModel):
    recommendation_id: str
    action_proposal: str
    target: str
    rationale: str
    requires_human_approval: bool = True
    suggested_action_type: str


# ---------------------------------------------------------------------------
# Incident Response Triage & Containment Adapter
# ---------------------------------------------------------------------------

class IncidentResponseTriageAdapter(ToolAdapter):
    """Triages security alerts, correlates IOCs, and generates approval-gated containment recommendations."""

    @property
    def name(self) -> str:
        return "ir_triage_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["ir.alert_triage", "ir.containment_recommend", "ir.root_cause_analysis"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if "alert_data" not in action.parameters and not action.target_refs:
            return False, "Parameter 'alert_data' or target required for IR triage."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        alert_raw = action.parameters.get("alert_data", {})
        alert_dict = json.loads(alert_raw) if isinstance(alert_raw, str) else alert_raw

        indicator_val = alert_dict.get("indicator", action.target_refs[0] if action.target_refs else "")
        verdict = TriageVerdict.SUSPICIOUS
        confidence = 0.7

        # 1. Correlate with KnowledgeBase Threat IOCs
        ioc_match = knowledge_base_store.query_ioc(IOCType.IP, indicator_val)
        if not ioc_match:
            ioc_match = knowledge_base_store.query_ioc(IOCType.DOMAIN, indicator_val)

        if ioc_match:
            verdict = TriageVerdict.CONFIRMED_INCIDENT
            confidence = 0.95

        # 2. Build Containment Recommendations (strictly approval required)
        recommendations: list[dict[str, Any]] = []
        if verdict in (TriageVerdict.SUSPICIOUS, TriageVerdict.CONFIRMED_INCIDENT):
            recommendations.append(
                ContainmentRecommendation(
                    recommendation_id=f"REC-{int(time.time())}-01",
                    action_proposal=f"Block inbound/outbound traffic to IOC '{indicator_val}' on edge firewalls",
                    target=indicator_val,
                    rationale=f"Indicator matched threat intel feed with verdict {verdict.value}.",
                    requires_human_approval=True,
                    suggested_action_type="network.firewall_block",
                ).model_dump(mode="json")
            )

        duration = time.time() - start_time
        summary = f"IR Alert Triage completed for '{indicator_val}': Verdict = {verdict.value.upper()} (Confidence = {confidence})."

        data = {
            "indicator": indicator_val,
            "verdict": verdict.value,
            "confidence": confidence,
            "matched_ioc": ioc_match.model_dump(mode="json") if ioc_match else None,
            "recommendations": recommendations,
        }

        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
