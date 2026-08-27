"""SQLAlchemy 2.0 Async ORM Models for Sentinel Core Domain Entities."""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base declarative class for Sentinel database entities."""
    pass


# Association table for TargetSet <-> Target (Many-to-Many)
targetset_targets = Table(
    "sentinel_targetset_targets",
    Base.metadata,
    Column("targetset_id", String(64), ForeignKey("sentinel_targetsets.id", ondelete="CASCADE"), primary_key=True),
    Column("target_id", String(64), ForeignKey("sentinel_targets.id", ondelete="CASCADE"), primary_key=True),
)


class TargetModel(Base):
    __tablename__ = "sentinel_targets"

    id = Column(String(64), primary_key=True, index=True)
    type = Column(String(32), nullable=False, index=True)  # domain, ip, cidr, url, etc.
    value = Column(String(512), nullable=False, index=True)
    resolved_ips = Column(JSON, default=list, nullable=False)
    parent_asset_id = Column(String(64), nullable=True)
    criticality = Column(String(32), default="medium", nullable=False)
    environment = Column(String(32), default="production", nullable=False)
    owner = Column(String(128), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class TargetSetModel(Base):
    __tablename__ = "sentinel_targetsets"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    context_notes = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    targets = relationship("TargetModel", secondary=targetset_targets, backref="target_sets")


class ScopeModel(Base):
    __tablename__ = "sentinel_scopes"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    allowed_targets = Column(JSON, default=list, nullable=False)
    in_scope_declarations = Column(JSON, default=list, nullable=False)
    out_of_scope_declarations = Column(JSON, default=list, nullable=False)
    environment = Column(String(32), default="production", nullable=False)
    authorization_type = Column(String(64), default="owned", nullable=False)
    reference_ticket_id = Column(String(128), nullable=True)
    authorized_by = Column(String(128), nullable=True)
    expiry = Column(DateTime(timezone=True), nullable=True)
    max_intensity = Column(Float, default=5.0, nullable=False)
    offensive_actions_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class PolicyModel(Base):
    __tablename__ = "sentinel_policies"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    allowed_module_classes = Column(JSON, default=list, nullable=False)
    allowed_action_classes = Column(JSON, default=list, nullable=False)
    rate_limit_rps = Column(Float, default=50.0, nullable=False)
    max_intensity = Column(Float, default=5.0, nullable=False)
    credential_handling_rules = Column(JSON, default=dict, nullable=False)
    require_approval_for_offensive = Column(Boolean, default=True, nullable=False)
    kill_switch_active = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class TaskModel(Base):
    __tablename__ = "sentinel_tasks"

    id = Column(String(64), primary_key=True, index=True)
    objective = Column(Text, nullable=False)
    target_set_id = Column(String(64), ForeignKey("sentinel_targetsets.id"), nullable=False)
    scope_id = Column(String(64), ForeignKey("sentinel_scopes.id"), nullable=False)
    policy_id = Column(String(64), ForeignKey("sentinel_policies.id"), nullable=False)
    mode = Column(String(64), default="assessment", nullable=False)
    status = Column(String(32), default="submitted", index=True, nullable=False)
    requested_output_type = Column(String(64), default="comprehensive_report", nullable=False)
    progress_percentage = Column(Float, default=0.0, nullable=False)
    correlation_id = Column(String(64), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    target_set = relationship("TargetSetModel", backref="tasks")
    scope = relationship("ScopeModel", backref="tasks")
    policy = relationship("PolicyModel", backref="tasks")


class ActionRequestModel(Base):
    __tablename__ = "sentinel_action_requests"

    id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    agent = Column(String(128), nullable=False)
    action_type = Column(String(128), index=True, nullable=False)
    parameters = Column(JSON, default=dict, nullable=False)
    target_refs = Column(JSON, default=list, nullable=False)
    expected_impact_level = Column(String(32), default="low", nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="pending_approval", index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class ActionResultModel(Base):
    __tablename__ = "sentinel_action_results"

    action_id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    success = Column(Boolean, nullable=False)
    output_summary = Column(Text, nullable=False)
    raw_output_uri = Column(String(512), nullable=True)
    duration_seconds = Column(Float, nullable=False)
    error_info = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class EvidenceModel(Base):
    __tablename__ = "sentinel_evidence"

    id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    target_ref = Column(String(512), index=True, nullable=False)
    source_agent = Column(String(128), nullable=False)
    source_module = Column(String(128), index=True, nullable=False)
    source_tool = Column(String(128), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    artifact_storage_key = Column(String(512), nullable=False)
    content_type = Column(String(128), nullable=False)
    sha256_hash = Column(String(64), index=True, nullable=False)
    integrity_metadata = Column(JSON, default=dict, nullable=False)
    collected_by = Column(String(128), nullable=False)
    chain_of_custody = Column(JSON, default=list, nullable=False)
    context_metadata = Column(JSON, default=dict, nullable=False)


class FindingModel(Base):
    __tablename__ = "sentinel_findings"

    id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    target_ref = Column(String(512), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    exploitability_context = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    evidence_refs = Column(JSON, default=list, nullable=False)
    related_cves = Column(JSON, default=list, nullable=False)
    related_cwes = Column(JSON, default=list, nullable=False)
    remediation = Column(Text, nullable=True)
    status = Column(String(32), default="open", index=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class RiskModel(Base):
    __tablename__ = "sentinel_risks"

    id = Column(String(64), primary_key=True, index=True)
    finding_id = Column(String(64), ForeignKey("sentinel_findings.id", ondelete="CASCADE"), index=True, nullable=False)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    severity = Column(String(32), nullable=False)
    asset_criticality = Column(String(32), nullable=False)
    exposure_score = Column(Float, default=1.0, nullable=False)
    exploitability_score = Column(Float, default=1.0, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    computed_risk_score = Column(Float, default=0.0, index=True, nullable=False)
    risk_tier = Column(String(32), index=True, nullable=False)
    rationale = Column(Text, default="", nullable=False)


class EventModel(Base):
    __tablename__ = "sentinel_events"

    event_id = Column(String(64), primary_key=True, index=True)
    event_type = Column(String(64), index=True, nullable=False)
    topic = Column(String(128), index=True, nullable=False)
    source = Column(String(128), nullable=False)
    payload = Column(JSON, default=dict, nullable=False)
    correlation_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class AuditLogRecord(Base):
    __tablename__ = "sentinel_audit_logs"

    entry_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    event_type = Column(String(128), index=True, nullable=False)
    actor = Column(String(128), index=True, nullable=False)
    target = Column(String(256), nullable=True)
    action_type = Column(String(128), index=True, nullable=False)
    scope_policy = Column(String(128), nullable=False)
    decision = Column(String(64), index=True, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    previous_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)
    signature = Column(String(256), nullable=False)
    verified = Column(Boolean, default=True)
