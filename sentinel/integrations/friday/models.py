"""FRIDAY Integration Contract Models, Enhanced Delegation, and Summarizer Service.

Provides:
1. Extended FridayDelegationRequest & FridayDelegationResponse models.
2. FridaySecurityPostureResponse, FridayAssetInventoryResponse, and FridayScheduleRequest models.
3. FridaySSEEvent types: task_started, phase_changed, finding_detected, approval_required, task_completed, task_failed.
4. Deterministic Human-Readable Summarizer (LLM-independent).
5. Blocked action & blocked target tracking.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, SeverityLevel, Task


class FridayPriority(StrEnum):
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class FridaySourceSystem(StrEnum):
    NEXUS = "nexus"
    FORGE = "forge"
    TRADING_BOT = "trading_bot"
    OTHER = "other"


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
    type: str = "domain"
    value: str


class FridayContext(BaseModel):
    asset_type: str = "web_application"
    source_system: str = "nexus"  # nexus | forge | trading_bot | other
    related_incident_id: str | None = None


class FridayPolicyContext(BaseModel):
    environment: str = "production"
    authorization_reference: str = "FRIDAY_DIRECTIVE"
    constraints: dict[str, Any] = Field(default_factory=dict)


class FridayDelegationRequest(BaseModel):
    """Extended delegation request contract from FRIDAY."""
    friday_request_id: str = Field(default_factory=lambda: f"fri-req-{int(datetime.now(UTC).timestamp())}")
    target: FridayTargetPayload | str | None = None
    targets: list[FridayTargetPayload] = Field(default_factory=list)
    mode: str = "assessment"
    scope_override: dict[str, Any] | None = None
    priority: FridayPriority = FridayPriority.NORMAL
    context: FridayContext = Field(default_factory=FridayContext)
    webhook_url: str | None = None
    capability: FridayCapability = FridayCapability.SECURITY_ASSESSMENT
    objective: str = "Autonomous Security Assessment"
    requested_output: FridayRequestedOutput = FridayRequestedOutput.TECHNICAL_AND_EXECUTIVE
    policy_context: FridayPolicyContext = Field(default_factory=FridayPolicyContext)
    time_budget_seconds: int | None = None
    resource_constraints: dict[str, Any] = Field(default_factory=dict)


class BlockedTargetRecord(BaseModel):
    target: str
    reason: str
    policy_dimension: str = "scope"


class FridayDelegationResponse(BaseModel):
    """Enhanced response contract returned to FRIDAY."""
    sentinel_task_id: str
    task_id: str  # Backwards-compatibility alias
    delegation_id: str
    friday_request_id: str
    status: str
    initial_phase: str = "RECONNAISSANCE"
    estimated_duration: str = "5-10 minutes"
    blocked_targets: list[BlockedTargetRecord] = Field(default_factory=list)
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


class FridaySSEEvent(BaseModel):
    event_type: str  # task_started | phase_changed | finding_detected | approval_required | task_completed | task_failed
    task_id: str
    phase: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finding: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    reason: str | None = None
    summary: str | None = None


class OpenFindingsBySeverity(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class FridaySecurityPostureResponse(BaseModel):
    overall_posture_score: float  # 0-100 (100 = perfect/no findings)
    per_domain_scores: dict[str, float] = Field(default_factory=dict)
    open_findings_by_severity: OpenFindingsBySeverity = Field(default_factory=OpenFindingsBySeverity)
    most_critical_finding: dict[str, Any] | None = None
    last_scan_times: dict[str, str] = Field(default_factory=dict)
    trend: str = "stable"  # improving | stable | degrading


class FridayAssetInventoryItem(BaseModel):
    target: str
    asset_type: str
    status: str  # secure | vulnerable | critical | unscanned
    open_finding_count: int = 0
    last_assessed_at: str | None = None


class FridayAssetInventoryResponse(BaseModel):
    total_assets: int
    assets: list[FridayAssetInventoryItem]


class FridayScheduleFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class FridayScheduleNotifyOn(StrEnum):
    CRITICAL_ONLY = "critical_only"
    ALL_FINDINGS = "all_findings"
    COMPLETION = "completion"


class FridayScheduleRequest(BaseModel):
    target: FridayTargetPayload | str
    frequency: FridayScheduleFrequency = FridayScheduleFrequency.DAILY
    mode: str = "assessment"
    notify_on: FridayScheduleNotifyOn = FridayScheduleNotifyOn.ALL_FINDINGS


class FridayScheduleResponse(BaseModel):
    schedule_id: str
    target: str
    frequency: str
    mode: str
    notify_on: str
    status: str = "active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FridaySummarizer:
    """Generates concise, deterministic handoff summaries for FRIDAY with zero LLM required."""

    @classmethod
    def generate_summary(
        cls,
        task: Task,
        findings: list[Finding],
        blocked: list[BlockedActionRecord],
    ) -> str:
        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

        if task.status.value == "complete":
            status_text = "successfully concluded"
        elif task.status.value == "executing":
            status_text = f"actively executing ({task.progress_percentage}% complete)"
        else:
            status_text = f"halted with status '{task.status.value}'"

        summary = (
            f"Sentinel security assessment for '{task.objective}' has {status_text}. "
            f"Evaluated {len(task.target_set.targets)} target(s) and identified {len(findings)} verified finding(s) "
            f"(Critical: {crit}, High: {high}, Medium: {med}, Low: {low})."
        )

        if blocked:
            summary += f" Sentinel governance blocked {len(blocked)} action(s) due to policy/scope guardrails:"
            for b in blocked:
                summary += f" [{b.action_type} on {b.target} - {b.reason} ({b.policy_dimension})]"

        if crit > 0 or high > 0:
            top_findings = [f for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
            top = top_findings[0]
            summary += f" Top Risk: {top.title} on {top.target_ref}."
            rem_text = top.remediation or "Apply security hardening best practices and verify with Sentinel re-tests."
            summary += f" Remediation Pointer: {rem_text}"

        return summary