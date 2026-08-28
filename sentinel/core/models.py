"""Core domain models for Sentinel — typed Pydantic v2 schemas.

Provides shared vocabulary for Target, TargetSet, Scope, Policy, Task,
ActionRequest, ActionResult, Evidence, Finding, Risk, and Event.
"""

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TargetType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    HOST = "host"
    DEVICE = "device"
    WIRELESS_NETWORK = "wireless_network"
    CLOUD_ACCOUNT = "cloud_account"
    MOBILE_APP = "mobile_app"
    FILE = "file"
    OTHER = "other"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnvironmentLabel(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    EXTERNAL = "external"


class AuthorizationType(StrEnum):
    OWNED = "owned"
    WRITTEN_CONSENT = "written_consent"
    BUG_BOUNTY = "bug_bounty"
    AUTHORIZED_ENGAGEMENT = "authorized_engagement"
    UNAUTHORIZED = "unauthorized"


class TaskMode(StrEnum):
    PASSIVE_RECON = "passive_recon"
    ASSESSMENT = "assessment"
    AUTHORIZED_ASSESSMENT = "authorized_assessment"
    FORENSICS = "forensics"
    MONITORING = "monitoring"


class TaskStatus(StrEnum):
    SUBMITTED = "submitted"
    PLANNING = "planning"
    EXECUTING = "executing"
    AWAITING_APPROVAL = "awaiting_approval"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


VALID_TASK_TRANSITIONS: dict[TaskStatus, list[TaskStatus]] = {
    TaskStatus.SUBMITTED: [TaskStatus.PLANNING, TaskStatus.CANCELLED, TaskStatus.FAILED],
    TaskStatus.PLANNING: [TaskStatus.EXECUTING, TaskStatus.AWAITING_APPROVAL, TaskStatus.CANCELLED, TaskStatus.FAILED],
    TaskStatus.EXECUTING: [TaskStatus.AWAITING_APPROVAL, TaskStatus.REPORTING, TaskStatus.FAILED, TaskStatus.CANCELLED],
    TaskStatus.AWAITING_APPROVAL: [TaskStatus.EXECUTING, TaskStatus.CANCELLED, TaskStatus.FAILED],
    TaskStatus.REPORTING: [TaskStatus.COMPLETE, TaskStatus.FAILED],
    TaskStatus.COMPLETE: [],
    TaskStatus.FAILED: [],
    TaskStatus.CANCELLED: [],
}


class ImpactLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class SeverityLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    REVIEW_REQUIRED = "review_required"  # Flagged by quality review


class RiskTier(StrEnum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(StrEnum):
    TASK = "task"
    ACTION = "action"
    EVIDENCE = "evidence"
    FINDING = "finding"
    ALERT = "alert"
    STATUS = "status"


# ---------------------------------------------------------------------------
# 1. Target & TargetSet
# ---------------------------------------------------------------------------

class TargetMetadata(BaseModel):
    """Asset context metadata."""
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    environment: EnvironmentLabel = EnvironmentLabel.PRODUCTION
    owner: str | None = None
    description: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class Target(BaseModel):
    """Target entity model with normalization."""
    schema_version: str = SCHEMA_VERSION
    id: str
    type: TargetType
    value: str
    resolved_ips: list[str] = Field(default_factory=list)
    parent_asset_id: str | None = None
    metadata: TargetMetadata = Field(default_factory=TargetMetadata)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Target value must not be empty.")
        return clean

    @model_validator(mode="after")
    def normalize_and_validate_type(self) -> "Target":
        val = self.value.strip()
        if self.type == TargetType.IP:
            try:
                ipaddress.ip_address(val)
            except ValueError as err:
                raise ValueError(f"Invalid IP address format: {val}") from err
        elif self.type == TargetType.CIDR:
            try:
                net = ipaddress.ip_network(val, strict=False)
                self.value = str(net)
            except ValueError as err:
                raise ValueError(f"Invalid CIDR format: {val}") from err
        elif self.type == TargetType.URL and not (val.startswith("http://") or val.startswith("https://")):
            raise ValueError(f"URL target must start with http:// or https://: {val}")
        return self


class TargetSet(BaseModel):
    """Collection of targets with task-level context."""
    schema_version: str = SCHEMA_VERSION
    id: str
    name: str
    description: str | None = None
    targets: list[Target] = Field(default_factory=list)
    context_notes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# 2. Scope & Policy
# ---------------------------------------------------------------------------

class AuthorizationMetadata(BaseModel):
    """Authorization context and legal boundaries."""
    authorization_type: AuthorizationType = AuthorizationType.OWNED
    reference_ticket_id: str | None = None
    authorized_by: str | None = None
    expiry: datetime | None = None


class Scope(BaseModel):
    """Scope boundaries, target allowlists, and restrictions."""
    schema_version: str = SCHEMA_VERSION
    id: str
    name: str
    allowed_targets: list[str] = Field(default_factory=list)
    in_scope_declarations: list[str] = Field(default_factory=list)
    out_of_scope_declarations: list[str] = Field(default_factory=list)
    environment: EnvironmentLabel = EnvironmentLabel.PRODUCTION
    authorization: AuthorizationMetadata = Field(default_factory=AuthorizationMetadata)
    max_intensity: int = Field(default=5, ge=1, le=10)
    offensive_actions_enabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Policy(BaseModel):
    """Security rules, module restrictions, and guardrail constraints."""
    schema_version: str = SCHEMA_VERSION
    id: str
    name: str
    allowed_module_classes: list[str] = Field(default_factory=list)
    allowed_action_classes: list[str] = Field(default_factory=list)
    rate_limit_rps: int = Field(default=50, ge=1, le=1000)
    max_intensity: int = Field(default=5, ge=1, le=10)
    credential_handling_rules: dict[str, Any] = Field(default_factory=dict)
    require_approval_for_offensive: bool = True
    kill_switch_active: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# 3. Task
# ---------------------------------------------------------------------------

class Task(BaseModel):
    """Top-level Sentinel security task state machine."""
    schema_version: str = SCHEMA_VERSION
    id: str
    objective: str
    target_set: TargetSet
    scope: Scope
    policy: Policy
    mode: TaskMode = TaskMode.ASSESSMENT
    status: TaskStatus = TaskStatus.SUBMITTED
    requested_output_type: str = "comprehensive_report"
    progress_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    correlation_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def transition_to(self, new_status: TaskStatus) -> None:
        """Validate and apply task status state machine transition."""
        allowed = VALID_TASK_TRANSITIONS.get(self.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid status transition from {self.status.value} to {new_status.value}."
            )
        self.status = new_status
        self.updated_at = datetime.now(UTC)
        if new_status in (TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.CANCELLED):
            self.completed_at = datetime.now(UTC)


# ---------------------------------------------------------------------------
# 4. ActionRequest & ActionResult
# ---------------------------------------------------------------------------

class ActionRequest(BaseModel):
    """Structured, typed action execution request."""
    schema_version: str = SCHEMA_VERSION
    id: str
    task_id: str
    agent: str
    action_type: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    target_refs: list[str] = Field(default_factory=list)
    expected_impact_level: ImpactLevel = ImpactLevel.LOW
    requires_approval: bool = False
    status: ActionStatus = ActionStatus.PENDING_APPROVAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.:]+$", v):
            raise ValueError(f"Action type contains invalid characters: {v}")
        return v


class ActionResult(BaseModel):
    """Structured execution result of an ActionRequest."""
    schema_version: str = SCHEMA_VERSION
    action_id: str
    task_id: str
    success: bool
    output_summary: str
    raw_output_uri: str | None = None
    duration_seconds: float = Field(ge=0.0)
    error_info: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# 5. Evidence & Finding
# ---------------------------------------------------------------------------

class ChainOfCustodyEvent(BaseModel):
    """Handled event in evidence lifecycle."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str
    action: str
    notes: str | None = None


class Evidence(BaseModel):
    """Raw evidence artifact with cryptographic integrity."""
    schema_version: str = SCHEMA_VERSION
    id: str
    task_id: str
    target_ref: str
    source_agent: str
    source_module: str
    source_tool: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    artifact_storage_key: str
    content_type: str
    sha256_hash: str
    size_bytes: int = 0
    integrity_metadata: dict[str, Any] = Field(default_factory=dict)
    collected_by: str
    chain_of_custody: list[ChainOfCustodyEvent] = Field(default_factory=list)
    context_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("Invalid SHA-256 hash format (must be 64 hex characters).")
        return v.lower()

    def log_access(self, actor: str, reason: str = "") -> None:
        """Log read/access event in chain of custody."""
        self.chain_of_custody.append(
            ChainOfCustodyEvent(
                timestamp=datetime.now(UTC),
                actor=actor,
                action="ACCESS",
                notes=reason,
            )
        )


class Finding(BaseModel):
    """Security finding strictly anchored to raw evidence artifacts."""
    schema_version: str = SCHEMA_VERSION
    id: str
    task_id: str
    title: str
    description: str
    target_ref: str
    severity: SeverityLevel
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    exploitability_context: str | None = None
    impact: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    related_cwes: list[str] = Field(default_factory=list)
    remediation: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("evidence_refs")
    @classmethod
    def require_evidence_anchor(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Evidence-First violation: Every finding must reference at least one evidence artifact.")
        return v


# ---------------------------------------------------------------------------
# 6. Risk & Event
# ---------------------------------------------------------------------------

class Risk(BaseModel):
    """Contextual risk score model combining severity, asset criticality, exposure, exploitability, and confidence."""
    schema_version: str = SCHEMA_VERSION
    id: str
    finding_id: str
    task_id: str
    severity: SeverityLevel
    asset_criticality: AssetCriticality
    exposure_score: float = Field(default=1.0, ge=0.0, le=1.0)
    exploitability_score: float = Field(default=1.0, ge=0.0, le=1.0)
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    computed_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_tier: RiskTier = RiskTier.LOW
    rationale: str = ""

    @model_validator(mode="after")
    def calculate_risk(self) -> "Risk":
        severity_weights = {
            SeverityLevel.INFO: 5.0,
            SeverityLevel.LOW: 20.0,
            SeverityLevel.MEDIUM: 45.0,
            SeverityLevel.HIGH: 75.0,
            SeverityLevel.CRITICAL: 100.0,
        }
        criticality_multipliers = {
            AssetCriticality.LOW: 0.6,
            AssetCriticality.MEDIUM: 0.8,
            AssetCriticality.HIGH: 1.0,
            AssetCriticality.CRITICAL: 1.2,
        }

        base = severity_weights.get(self.severity, 20.0)
        crit = criticality_multipliers.get(self.asset_criticality, 1.0)

        # Raw score = base * crit * (0.4 + 0.3*exposure + 0.3*exploitability) * confidence
        factor = 0.4 + (0.3 * self.exposure_score) + (0.3 * self.exploitability_score)
        raw = base * crit * factor * self.confidence_score
        score = min(100.0, max(0.0, round(raw, 2)))
        self.computed_risk_score = score

        if score < 15.0:
            self.risk_tier = RiskTier.MINIMAL
        elif score < 40.0:
            self.risk_tier = RiskTier.LOW
        elif score < 70.0:
            self.risk_tier = RiskTier.MEDIUM
        elif score < 90.0:
            self.risk_tier = RiskTier.HIGH
        else:
            self.risk_tier = RiskTier.CRITICAL
        return self


class Event(BaseModel):
    """Typed event envelope for asynchronous event bus dispatch."""
    schema_version: str = SCHEMA_VERSION
    event_id: str
    event_type: EventType
    topic: str
    source: str
    payload: dict[str, Any]
    correlation_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
