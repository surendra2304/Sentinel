"""FRIDAY Integration Contract Models and Summarizer Service.

Provides:
1. FridayDelegationRequest & FridayDelegationResponse models.
2. FridayResultPayload conforming to friday_result.schema.json.
3. Deterministic Human-Readable Summarizer (LLM-independent).
4. Blocked action tracking so FRIDAY always knows what Sentinel refused to do.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, SeverityLevel, Task


class FridayCapability(StrEnum):
    SECURITY_ASSESSMENT = "sentinel.security_assessment"
    RECONNAISSANCE = "sentinel.reconnaissance"
    INCIDENT_INVESTIGATION = "sentinel.incident_investigation"


class FridayRequestedOutput(StrEnum):
    TECHNICAL_AND_EXECUTIVE = "technical_and_executive"
    SUMMARY = "summary"
    DETAILED_REPORT = "detailed_report"
    ALERT = "alert"
    REMEDIATION_PLAN = "remediation_plan"


class FridayTargetPayload(BaseModel):
    type: str
    value: str


class FridayPolicyContext(BaseModel):
    environment: str = "production"
    authorization_reference: str = "FRIDAY_DIRECTIVE"
    constraints: dict[str, Any] = Field(default_factory=dict)


class FridayDelegationRequest(BaseModel):
    capability: FridayCapability
    objective: str
    targets: list[FridayTargetPayload]
    mode: str = "assessment"
    requested_output: FridayRequestedOutput = FridayRequestedOutput.TECHNICAL_AND_EXECUTIVE
    policy_context: FridayPolicyContext = Field(default_factory=FridayPolicyContext)
    time_budget_seconds: int | None = None
    resource_constraints: dict[str, Any] = Field(default_factory=dict)


class FridayDelegationResponse(BaseModel):
    delegation_id: str
    task_id: str
    status: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    stream_url: str


class BlockedActionRecord(BaseModel):
    action_type: str
    target: str
    reason: str
    policy_dimension: str = "scope_or_approval"


class FridayResultPayload(BaseModel):
    delegation_id: str
    task_id: str
    task_status: str
    progress_percentage: float
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    blocked_actions: list[BlockedActionRecord] = Field(default_factory=list)
    remediation_recommendations: list[dict[str, Any]] = Field(default_factory=list)
    report_artifacts: dict[str, str] = Field(default_factory=dict)
    human_summary: str


class FridaySummarizer:
    """Generates concise, deterministic handoff summaries for FRIDAY."""

    @classmethod
    def generate_summary(
        cls,
        task: Task,
        findings: list[Finding],
        blocked: list[BlockedActionRecord],
    ) -> str:
        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)

        if task.status.value == "complete":
            status_text = "successfully concluded"
        elif task.status.value == "executing":
            status_text = f"actively executing ({task.progress_percentage}% complete)"
        else:
            status_text = f"halted with status '{task.status.value}'"

        summary = (
            f"Sentinel security assessment for '{task.objective}' has {status_text}. "
            f"Evaluated {len(task.target_set.targets)} target(s) and identified {len(findings)} verified finding(s) "
            f"({crit} Critical, {high} High)."
        )

        if blocked:
            summary += f" Sentinel governance blocked {len(blocked)} elevated action(s) due to policy guardrails."

        if crit > 0:
            top_crit = next(f for f in findings if f.severity == SeverityLevel.CRITICAL)
            summary += f" Immediate attention required: {top_crit.title} on {top_crit.target_ref}."

        return summary
