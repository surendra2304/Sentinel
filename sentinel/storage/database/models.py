"""SQLAlchemy 2.0 Async ORM Models for Sentinel Core Domain Entities.

Oracle (23.26 / Autonomous Database) is the durable target:

* ``JSONDocument`` stores JSON as ``json.dumps`` text in a CLOB. Oracle's implicit
  empty-string-is-NULL rule makes the native ``JSON``/``VARCHAR2`` types
  paper-thin for optional payloads, and a CLOB round-trips any size.
* ``TextOrEmpty`` is a TEXT/CLOB column whose empty string is persisted as NULL
  (Oracle cannot store ``''``) and read back as ``''``.
* ``TaskModel.mode`` maps to the ``task_mode`` column: ``MODE`` is an Oracle
  reserved word and cannot be used as an unquoted identifier.
"""

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    event,
    inspect,
)
from sqlalchemy.dialects.oracle import CLOB
from sqlalchemy.orm import DeclarativeBase, Session, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Base declarative class for Sentinel database entities."""
    pass


def _load_clob(value: Any) -> Any:
    """Materialise a CLOB/LOB object (oracledb returns LOB handles for large data)."""
    if hasattr(value, "read"):
        try:
            return value.read()
        except Exception:  # pragma: no cover - driver specific failures
            return str(value)
    return value


class JSONDocument(TypeDecorator):
    """JSON payload stored as ``json.dumps`` text in a CLOB (TEXT elsewhere)."""

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[no-untyped-def]
        if dialect.name == "oracle":
            return dialect.type_descriptor(CLOB())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        return json.dumps(value, default=str)

    def process_result_value(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        value = _load_clob(value)
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        text = str(value).strip()
        if not text:
            return None
        return json.loads(text)


class TextOrEmpty(TypeDecorator):
    """TEXT/CLOB column where ``''`` is NULL (Oracle) and NULL reads back as ``''``."""

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[no-untyped-def]
        if dialect.name == "oracle":
            return dialect.type_descriptor(CLOB())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        text = str(value)
        # Oracle stores '' as NULL, so a NOT NULL column would reject it.
        return text if text != "" else None

    def process_result_value(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return ""
        value = _load_clob(value)
        return str(value)


@event.listens_for(Session, "before_flush")
def _oracle_normalise_empty_strings(session: Session, flush_context: Any, instances: Any) -> None:
    """Replace ``''`` with NULL for nullable text columns before an Oracle flush.

    Empty string is NULL in Oracle. Writing ``''`` into a nullable column would
    otherwise round-trip as NULL anyway, but doing the substitution explicitly
    keeps the unit of work consistent and avoids ORA-01400 on columns the caller
    left blank.
    """
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "oracle":
        return
    for obj in list(session.new) + list(session.dirty):
        try:
            mapper = inspect(obj).mapper
        except Exception:
            continue
        for attribute in mapper.column_attrs:
            column = attribute.columns[0]
            if not isinstance(column.type, (String, Text)) or isinstance(
                column.type, (JSONDocument, TextOrEmpty)
            ):
                continue
            if column.nullable is False:
                continue
            try:
                current = getattr(obj, attribute.key, None)
            except Exception:
                continue
            if isinstance(current, str) and current == "":
                setattr(obj, attribute.key, None)


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
    resolved_ips = Column(JSONDocument, default=list, nullable=False)
    parent_asset_id = Column(String(64), nullable=True)
    criticality = Column(String(32), default="medium", nullable=False)
    environment = Column(String(32), default="production", nullable=False)
    owner = Column(String(128), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(JSONDocument, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class TargetSetModel(Base):
    __tablename__ = "sentinel_targetsets"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    context_notes = Column(JSONDocument, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    targets = relationship("TargetModel", secondary=targetset_targets, backref="target_sets", lazy="selectin")


class ScopeModel(Base):
    __tablename__ = "sentinel_scopes"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    allowed_targets = Column(JSONDocument, default=list, nullable=False)
    in_scope_declarations = Column(JSONDocument, default=list, nullable=False)
    out_of_scope_declarations = Column(JSONDocument, default=list, nullable=False)
    environment = Column(String(32), default="production", nullable=False)
    authorization_type = Column(String(64), default="owned", nullable=False)
    reference_ticket_id = Column(String(128), nullable=True)
    authorized_by = Column(String(128), nullable=True)
    expiry = Column(DateTime(timezone=True), nullable=True)
    max_intensity = Column(Float, default=5.0, nullable=False)
    offensive_actions_enabled = Column(Boolean, default=False, nullable=False)
    # Preserve the complete current authorization contract, including fields that
    # are not represented by the legacy relational columns above.
    scope_contract = Column(JSONDocument, default=dict, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class PolicyModel(Base):
    __tablename__ = "sentinel_policies"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    allowed_module_classes = Column(JSONDocument, default=list, nullable=False)
    allowed_action_classes = Column(JSONDocument, default=list, nullable=False)
    rate_limit_rps = Column(Float, default=50.0, nullable=False)
    max_intensity = Column(Float, default=5.0, nullable=False)
    credential_handling_rules = Column(JSONDocument, default=dict, nullable=False)
    require_approval_for_offensive = Column(Boolean, default=True, nullable=False)
    kill_switch_active = Column(Boolean, default=False, nullable=False)
    policy_contract = Column(JSONDocument, default=dict, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class TaskModel(Base):
    __tablename__ = "sentinel_tasks"

    id = Column(String(64), primary_key=True, index=True)
    objective = Column(Text, nullable=False)
    target_set_id = Column(String(64), ForeignKey("sentinel_targetsets.id"), nullable=False)
    scope_id = Column(String(64), ForeignKey("sentinel_scopes.id"), nullable=False)
    policy_id = Column(String(64), ForeignKey("sentinel_policies.id"), nullable=False)
    # MODE is an Oracle reserved word, so the column is task_mode while the ORM
    # attribute (and every domain call site) stays ``mode``.
    mode = Column("task_mode", String(64), default="assessment", nullable=False)
    status = Column(String(32), default="submitted", index=True, nullable=False)
    requested_output_type = Column(String(64), default="comprehensive_report", nullable=False)
    progress_percentage = Column(Float, default=0.0, nullable=False)
    correlation_id = Column(String(64), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    target_set = relationship("TargetSetModel", backref="tasks", lazy="selectin")
    scope = relationship("ScopeModel", backref="tasks", lazy="selectin")
    policy = relationship("PolicyModel", backref="tasks", lazy="selectin")


class TaskCheckpointModel(Base):
    """Versioned, durable planner and working-memory checkpoint per task."""

    __tablename__ = "sentinel_task_checkpoints"

    task_id = Column(
        String(64),
        ForeignKey("sentinel_tasks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    version = Column(Integer, default=1, nullable=False)
    payload = Column(JSONDocument, default=dict, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class ActionRequestModel(Base):
    __tablename__ = "sentinel_action_requests"

    id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    agent = Column(String(128), nullable=False)
    action_type = Column(String(128), index=True, nullable=False)
    parameters = Column(JSONDocument, default=dict, nullable=False)
    target_refs = Column(JSONDocument, default=list, nullable=False)
    expected_impact_level = Column(String(32), default="low", nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="pending_approval", index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class ApprovalModel(Base):
    """Durable operator decision record bound to a single task action."""

    __tablename__ = "sentinel_approvals"

    approval_id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    action_id = Column(String(64), index=True, nullable=False)
    action_type = Column(String(128), nullable=False)
    target_refs = Column(JSONDocument, default=list, nullable=False)
    requested_by = Column(String(128), nullable=False)
    action_fingerprint = Column(String(64), nullable=True)
    status = Column(String(32), default="PENDING", index=True, nullable=False)
    justification_needed = Column(TextOrEmpty, nullable=True)
    justification_provided = Column(Text, nullable=True)
    approved_by = Column(String(128), nullable=True)
    authorization_reference = Column(String(256), nullable=True)
    requested_at = Column(DateTime(timezone=True), nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class ActionResultModel(Base):
    __tablename__ = "sentinel_action_results"

    action_id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    success = Column(Boolean, nullable=False)
    output_summary = Column(TextOrEmpty, nullable=True)
    raw_output_uri = Column(String(512), nullable=True)
    duration_seconds = Column(Float, nullable=False)
    error_info = Column(JSONDocument, nullable=True)
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
    integrity_metadata = Column(JSONDocument, default=dict, nullable=False)
    collected_by = Column(String(128), nullable=False)
    chain_of_custody = Column(JSONDocument, default=list, nullable=False)
    context_metadata = Column(JSONDocument, default=dict, nullable=False)


class FindingModel(Base):
    __tablename__ = "sentinel_findings"

    id = Column(String(64), primary_key=True, index=True)
    task_id = Column(String(64), ForeignKey("sentinel_tasks.id", ondelete="CASCADE"), index=True, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(TextOrEmpty, nullable=True)
    target_ref = Column(String(512), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    exploitability_context = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    evidence_refs = Column(JSONDocument, default=list, nullable=False)
    related_cves = Column(JSONDocument, default=list, nullable=False)
    related_cwes = Column(JSONDocument, default=list, nullable=False)
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
    rationale = Column(TextOrEmpty, default="", nullable=True)


class EventModel(Base):
    __tablename__ = "sentinel_events"

    event_id = Column(String(64), primary_key=True, index=True)
    event_type = Column(String(64), index=True, nullable=False)
    topic = Column(String(128), index=True, nullable=False)
    source = Column(String(128), nullable=False)
    payload = Column(JSONDocument, default=dict, nullable=False)
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
    details = Column(JSONDocument, default=dict, nullable=False)
    previous_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)
    signature = Column(String(256), nullable=False)
    verified = Column(Boolean, default=True)
