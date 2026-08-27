"""Contracts for core Sentinel abstractions: Task, Action, Scope, Evidence, Finding, Risk, and Policy."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SeverityLevel(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class TargetAsset(BaseModel):
    """Target representation with explicit ownership & authorization tags."""
    target_id: str
    identifier: str  # e.g., IP, CIDR, domain, URL, container ID, cloud ARN
    asset_type: str  # e.g., IP_ADDRESS, DOMAIN, WEB_URL, CLOUD_RESOURCE
    authorized: bool = False
    authorization_reference: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class ScopeDefinition(BaseModel):
    """Scope boundaries and policy restrictions."""
    scope_id: str
    name: str
    allowed_targets: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    max_intensity: int = Field(default=5, ge=1, le=10)
    allowed_modules: list[str] = Field(default_factory=list)
    offensive_actions_enabled: bool = False


class ActionRequest(BaseModel):
    """Typed execution request governed by Scope and Policy engines."""
    action_id: str
    task_id: str
    module_name: str
    tool_adapter: str
    target: TargetAsset
    parameters: dict[str, Any] = Field(default_factory=dict)
    is_offensive: bool = False
    intensity: int = 1
    status: ActionStatus = ActionStatus.PENDING_APPROVAL
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class EvidenceArtifact(BaseModel):
    """Raw artifact with cryptographic verification hashes."""
    evidence_id: str
    action_id: str
    source_tool: str
    target_asset: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    storage_uri: str
    sha256_hash: str
    mime_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Security finding strictly anchored to raw evidence artifacts."""
    finding_id: str
    task_id: str
    title: str
    description: str
    severity: SeverityLevel
    target_asset: str
    module_source: str
    evidence_refs: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)
    remediation_guidance: str | None = None
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class RiskAssessment(BaseModel):
    """Contextual business and technical risk metric calculation."""
    assessment_id: str
    finding_id: str
    cvss_base_score: float = 0.0
    epss_score: float = 0.0
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    calculated_risk_score: float = 0.0
    business_context: str = ""


class TaskContract(BaseModel):
    """Top-level Sentinel Task definition."""
    task_id: str
    title: str
    scope: ScopeDefinition
    status: str = "PENDING"
    correlation_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
