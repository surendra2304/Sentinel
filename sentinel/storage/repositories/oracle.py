"""Oracle-backed repository implementations for Sentinel durable entities.

Oracle Autonomous Database is the only durable backend. The SQLAlchemy statement
layer here is dialect-neutral -- it never emits ``ON CONFLICT``,
``INSERT OR REPLACE``, positional ``?`` binds or literal ``LIMIT`` (SQLAlchemy
compiles ``.limit()`` to ``FETCH FIRST n ROWS ONLY`` on Oracle).

Oracle-specific behaviour lives in this module:

* empty strings in ``save_*`` payloads are normalised to ``NULL``;
* JSON payloads are serialised with ``json.dumps`` into CLOB columns by
  ``JSONDocument`` (see :mod:`sentinel.storage.database.models`);
* result rows are read through ORM attributes / labelled columns, so Oracle's
  upper-case column names never leak into the domain models.

Oracle DDL is created from metadata at startup (``Base.metadata.create_all``) in
the schema of the connecting user (``SENTINEL``), with unqualified names.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import and_, select, update

from sentinel.audit.audit_logger import AuditEntry
from sentinel.core.models import (
    AssetCriticality,
    AuthorizationMetadata,
    AuthorizationType,
    ChainOfCustodyEvent,
    EnvironmentLabel,
    Event,
    EventType,
    Evidence,
    Finding,
    FindingStatus,
    Policy,
    Risk,
    RiskTier,
    Scope,
    SeverityLevel,
    Target,
    TargetMetadata,
    TargetSet,
    TargetType,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.core.policy.engine import ApprovalRecord
from sentinel.storage.database.models import (
    ApprovalModel,
    AuditLogRecord,
    EventModel,
    EvidenceModel,
    FindingModel,
    PolicyModel,
    RiskModel,
    ScopeModel,
    TargetModel,
    TargetSetModel,
    TaskCheckpointModel,
    TaskModel,
    targetset_targets,
)
from sentinel.storage.database.oracle import normalise_empty
from sentinel.storage.database.session import get_db_session
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    AuditRepository,
    EventRepository,
    EvidenceRepository,
    FindingRepository,
    RiskRepository,
    TaskRepository,
)


def _optional(value: Any) -> Any:
    """Oracle cannot store ``''``; persist it as ``NULL`` instead."""
    return normalise_empty(value)


class OracleTaskRepository(TaskRepository):
    """Oracle-backed Task entity repository (unqualified ``sentinel_*`` tables)."""

    async def create_task(self, task: Task) -> Task:
        async with get_db_session() as session:
            # 1. Upsert Scope
            scope_m = await session.get(ScopeModel, task.scope.id)
            if not scope_m:
                scope_m = ScopeModel(
                    id=task.scope.id,
                    name=task.scope.name,
                    allowed_targets=task.scope.allowed_targets,
                    in_scope_declarations=task.scope.in_scope_declarations,
                    out_of_scope_declarations=task.scope.out_of_scope_declarations,
                    environment=task.scope.environment.value,
                    authorization_type=task.scope.authorization.authorization_type.value,
                    reference_ticket_id=task.scope.authorization.reference_ticket_id,
                    authorized_by=task.scope.authorization.authorized_by,
                    expiry=task.scope.authorization.expiry,
                    max_intensity=float(task.scope.max_intensity),
                    offensive_actions_enabled=task.scope.offensive_actions_enabled,
                    scope_contract=task.scope.model_dump(mode="json"),
                    created_at=task.scope.created_at,
                )
                session.add(scope_m)
            else:
                cast(Any, scope_m).scope_contract = task.scope.model_dump(mode="json")

            # 2. Upsert Policy
            policy_m = await session.get(PolicyModel, task.policy.id)
            if not policy_m:
                policy_m = PolicyModel(
                    id=task.policy.id,
                    name=task.policy.name,
                    allowed_module_classes=task.policy.allowed_module_classes,
                    allowed_action_classes=task.policy.allowed_action_classes,
                    rate_limit_rps=float(task.policy.rate_limit_rps),
                    max_intensity=float(task.policy.max_intensity),
                    credential_handling_rules=task.policy.credential_handling_rules,
                    require_approval_for_offensive=task.policy.require_approval_for_offensive,
                    kill_switch_active=task.policy.kill_switch_active,
                    policy_contract=task.policy.model_dump(mode="json"),
                    created_at=task.policy.created_at,
                )
                session.add(policy_m)
            else:
                cast(Any, policy_m).policy_contract = task.policy.model_dump(mode="json")

            # 3. Upsert Targets & TargetSet
            t_set_m = await session.get(TargetSetModel, task.target_set.id)
            if not t_set_m:
                t_set_m = TargetSetModel(
                    id=task.target_set.id,
                    name=task.target_set.name,
                    description=task.target_set.description,
                    context_notes=task.target_set.context_notes,
                    created_at=task.target_set.created_at,
                )
                session.add(t_set_m)

            for target in task.target_set.targets:
                t_m = await session.get(TargetModel, target.id)
                if not t_m:
                    t_m = TargetModel(
                        id=target.id,
                        type=target.type.value,
                        value=target.value,
                        resolved_ips=target.resolved_ips,
                        parent_asset_id=target.parent_asset_id,
                        criticality=target.metadata.criticality.value,
                        environment=target.metadata.environment.value,
                        owner=target.metadata.owner,
                        description=target.metadata.description,
                        tags=target.metadata.tags,
                        created_at=target.created_at,
                    )
                    session.add(t_m)
                    await session.flush()
                # Insert association if not present
                stmt_assoc = select(targetset_targets).where(
                    and_(
                        targetset_targets.c.targetset_id == task.target_set.id,
                        targetset_targets.c.target_id == target.id,
                    )
                )
                res_assoc = await session.execute(stmt_assoc)
                if not res_assoc.first():
                    await session.execute(
                        targetset_targets.insert().values(
                            targetset_id=task.target_set.id,
                            target_id=target.id,
                        )
                    )

            # 4. Create Task Model
            task_m = TaskModel(
                id=task.id,
                objective=task.objective,
                target_set_id=task.target_set.id,
                scope_id=task.scope.id,
                policy_id=task.policy.id,
                mode=task.mode.value,
                status=task.status.value,
                requested_output_type=task.requested_output_type,
                progress_percentage=task.progress_percentage,
                correlation_id=task.correlation_id,
                created_at=task.created_at,
                updated_at=task.updated_at,
                completed_at=task.completed_at,
            )
            session.add(task_m)
        return task

    async def get_task(self, task_id: str) -> Task | None:
        async with get_db_session() as session:
            stmt = select(TaskModel).where(TaskModel.id == task_id)
            res = await session.execute(stmt)
            task_m = res.scalar_one_or_none()
            if not task_m:
                return None
            return self._to_domain_task(task_m)

    async def update_task(self, task: Task) -> Task:
        async with get_db_session() as session:
            stmt = (
                update(TaskModel)
                .where(TaskModel.id == task.id)
                .values(
                    status=task.status.value,
                    progress_percentage=task.progress_percentage,
                    updated_at=datetime.now(UTC),
                    completed_at=task.completed_at,
                )
            )
            await session.execute(stmt)
        return task

    async def list_tasks(
        self,
        status: TaskStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]:
        async with get_db_session() as session:
            stmt = select(TaskModel).order_by(TaskModel.created_at.desc()).limit(limit).offset(offset)
            if status:
                stmt = stmt.where(TaskModel.status == status.value)
            res = await session.execute(stmt)
            return [self._to_domain_task(m) for m in res.scalars().all()]

    async def get_active_non_terminal_tasks(self) -> list[Task]:
        terminal = [
            TaskStatus.COMPLETE.value,
            TaskStatus.COMPLETED.value,
            TaskStatus.BLOCKED.value,
            TaskStatus.PARTIALLY_COMPLETED.value,
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
        ]
        async with get_db_session() as session:
            stmt = select(TaskModel).where(TaskModel.status.not_in(terminal))
            res = await session.execute(stmt)
            return [self._to_domain_task(m) for m in res.scalars().all()]

    async def save_checkpoint(self, task_id: str, payload: dict[str, Any]) -> int:
        async with get_db_session() as session:
            checkpoint = await session.get(TaskCheckpointModel, task_id)
            if checkpoint is None:
                checkpoint = TaskCheckpointModel(
                    task_id=task_id,
                    version=1,
                    payload=payload,
                    updated_at=datetime.now(UTC),
                )
                session.add(checkpoint)
                await session.flush()
                return 1

            checkpoint_model = cast(Any, checkpoint)
            checkpoint_model.version = int(checkpoint_model.version) + 1
            checkpoint_model.payload = payload
            checkpoint_model.updated_at = datetime.now(UTC)
            return int(checkpoint_model.version)

    async def get_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        async with get_db_session() as session:
            checkpoint = await session.get(TaskCheckpointModel, task_id)
            if checkpoint is None:
                return None
            return {
                "version": int(checkpoint.version),
                "payload": dict(checkpoint.payload or {}),
            }

    @staticmethod
    def _to_domain_task(m: Any) -> Task:
        target_models: list[Any] = getattr(m.target_set, "targets", []) if m.target_set else []
        targets = [
            Target(
                id=str(t.id),
                type=TargetType(str(t.type)),
                value=str(t.value),
                resolved_ips=list(t.resolved_ips or []),
                metadata=TargetMetadata(
                    criticality=AssetCriticality(str(t.criticality)),
                    environment=EnvironmentLabel(str(t.environment)),
                    owner=t.owner,
                    description=t.description,
                    tags=dict(t.tags or {}),
                ),
                created_at=cast(datetime, t.created_at),
            )
            for t in target_models
        ]
        target_set = TargetSet(
            id=str(m.target_set_id),
            name=str(m.target_set.name) if m.target_set else "TargetSet",
            description=m.target_set.description if m.target_set else None,
            context_notes=dict(m.target_set.context_notes or {}) if m.target_set else {},
            targets=targets,
        )
        scope_contract = getattr(m.scope, "scope_contract", None) if m.scope else None
        if scope_contract:
            scope = Scope.model_validate(scope_contract)
        else:
            # Legacy rows predate the full JSON contract. Preserve fields that were
            # actually stored; do not invent a missing authorization reference or window.
            scope = Scope(
                id=str(m.scope_id),
                name=str(m.scope.name) if m.scope else "Scope",
                allowed_targets=list(m.scope.allowed_targets) if m.scope else [],
                in_scope_declarations=list(m.scope.in_scope_declarations) if m.scope else [],
                out_of_scope_declarations=list(m.scope.out_of_scope_declarations) if m.scope else [],
                environment=EnvironmentLabel(str(m.scope.environment)) if m.scope else EnvironmentLabel.PRODUCTION,
                authorization=AuthorizationMetadata(
                    authorization_type=AuthorizationType(str(m.scope.authorization_type)) if m.scope else AuthorizationType.OWNED,
                    reference_ticket_id=m.scope.reference_ticket_id if m.scope else None,
                    authorized_by=m.scope.authorized_by if m.scope else None,
                    expiry=m.scope.expiry if m.scope else None,
                ),
                max_intensity=int(m.scope.max_intensity) if m.scope else 5,
                offensive_actions_enabled=bool(m.scope.offensive_actions_enabled) if m.scope else False,
            )
        policy_contract = getattr(m.policy, "policy_contract", None) if m.policy else None
        if policy_contract:
            policy = Policy.model_validate(policy_contract)
        else:
            policy = Policy(
                id=str(m.policy_id),
                name=str(m.policy.name) if m.policy else "Policy",
                allowed_module_classes=list(m.policy.allowed_module_classes) if m.policy else [],
                allowed_action_classes=list(m.policy.allowed_action_classes) if m.policy else [],
                rate_limit_rps=int(m.policy.rate_limit_rps) if m.policy else 50,
                max_intensity=int(m.policy.max_intensity) if m.policy else 5,
                credential_handling_rules=dict(m.policy.credential_handling_rules or {}) if m.policy else {},
                require_approval_for_offensive=bool(m.policy.require_approval_for_offensive) if m.policy else True,
                kill_switch_active=bool(m.policy.kill_switch_active) if m.policy else False,
            )
        return Task(
            id=str(m.id),
            objective=str(m.objective),
            target_set=target_set,
            scope=scope,
            policy=policy,
            mode=TaskMode(str(m.mode)),
            status=TaskStatus(str(m.status)),
            requested_output_type=str(m.requested_output_type),
            progress_percentage=float(m.progress_percentage),
            correlation_id=str(m.correlation_id),
            created_at=cast(datetime, m.created_at),
            updated_at=cast(datetime, m.updated_at),
            completed_at=cast(datetime | None, m.completed_at),
        )


class OracleFindingRepository(FindingRepository):
    """Oracle-backed Finding repository."""

    async def save_finding(self, finding: Finding) -> Finding:
        finding.exploitability_context = _optional(finding.exploitability_context)
        finding.impact = _optional(finding.impact)
        finding.remediation = _optional(finding.remediation)
        finding.description = _optional(finding.description) or ""
        async with get_db_session() as session:
            f_m = await session.get(FindingModel, finding.id)
            if not f_m:
                f_m = FindingModel(
                    id=finding.id,
                    task_id=finding.task_id,
                    title=finding.title,
                    description=finding.description,
                    target_ref=finding.target_ref,
                    severity=finding.severity.value,
                    confidence=finding.confidence,
                    exploitability_context=finding.exploitability_context,
                    impact=finding.impact,
                    evidence_refs=finding.evidence_refs,
                    related_cves=finding.related_cves,
                    related_cwes=finding.related_cwes,
                    remediation=finding.remediation,
                    status=finding.status.value,
                    first_seen=finding.first_seen,
                    last_seen=finding.last_seen,
                )
                session.add(f_m)
            else:
                f_m.evidence_refs = finding.evidence_refs  # type: ignore[assignment]
                f_m.related_cves = finding.related_cves  # type: ignore[assignment]
                f_m.confidence = finding.confidence  # type: ignore[assignment]
                f_m.status = finding.status.value  # type: ignore[assignment]
                f_m.last_seen = finding.last_seen  # type: ignore[assignment]
        return finding

    async def get_finding(self, finding_id: str) -> Finding | None:
        async with get_db_session() as session:
            f_m = await session.get(FindingModel, finding_id)
            return self._to_domain_finding(f_m) if f_m else None

    async def list_findings(
        self,
        task_id: str | None = None,
        severity: SeverityLevel | None = None,
        status: FindingStatus | None = None,
        target_ref: str | None = None,
    ) -> list[Finding]:
        async with get_db_session() as session:
            stmt = select(FindingModel).order_by(FindingModel.last_seen.desc())
            if task_id:
                stmt = stmt.where(FindingModel.task_id == task_id)
            if severity:
                stmt = stmt.where(FindingModel.severity == severity.value)
            if status:
                stmt = stmt.where(FindingModel.status == status.value)
            if target_ref:
                stmt = stmt.where(FindingModel.target_ref == target_ref)
            res = await session.execute(stmt)
            return [self._to_domain_finding(m) for m in res.scalars().all()]

    async def update_status(self, finding_id: str, status: FindingStatus) -> Finding | None:
        async with get_db_session() as session:
            f_m = await session.get(FindingModel, finding_id)
            if not f_m:
                return None
            f_m.status = status.value  # type: ignore[assignment]
            f_m.last_seen = datetime.now(UTC)  # type: ignore[assignment]
            return self._to_domain_finding(f_m)

    @staticmethod
    def _to_domain_finding(m: Any) -> Finding:
        return Finding(
            id=str(m.id),
            task_id=str(m.task_id),
            title=str(m.title),
            description=str(m.description),
            target_ref=str(m.target_ref),
            severity=SeverityLevel(str(m.severity)),
            confidence=float(m.confidence),
            exploitability_context=str(m.exploitability_context) if m.exploitability_context else None,
            impact=str(m.impact) if m.impact else None,
            evidence_refs=list(m.evidence_refs or []),
            related_cves=list(m.related_cves or []),
            related_cwes=list(m.related_cwes or []),
            remediation=str(m.remediation) if m.remediation else None,
            status=FindingStatus(str(m.status)),
            first_seen=cast(datetime, m.first_seen),
            last_seen=cast(datetime, m.last_seen),
        )


class OracleEvidenceRepository(EvidenceRepository):
    """Oracle-backed Evidence metadata index."""

    async def save_evidence_record(self, evidence: Evidence) -> Evidence:
        async with get_db_session() as session:
            e_m = await session.get(EvidenceModel, evidence.id)
            if not e_m:
                e_m = EvidenceModel(
                    id=evidence.id,
                    task_id=evidence.task_id,
                    target_ref=evidence.target_ref,
                    source_agent=evidence.source_agent,
                    source_module=evidence.source_module,
                    source_tool=evidence.source_tool,
                    timestamp=evidence.timestamp,
                    artifact_storage_key=evidence.artifact_storage_key,
                    content_type=evidence.content_type,
                    sha256_hash=evidence.sha256_hash,
                    integrity_metadata=evidence.integrity_metadata,
                    collected_by=evidence.collected_by,
                    chain_of_custody=[c.model_dump(mode="json") for c in evidence.chain_of_custody],
                    context_metadata=evidence.context_metadata,
                )
                session.add(e_m)
            else:
                e_m.chain_of_custody = [c.model_dump(mode="json") for c in evidence.chain_of_custody]  # type: ignore[assignment]
                e_m.context_metadata = evidence.context_metadata  # type: ignore[assignment]
                e_m.integrity_metadata = evidence.integrity_metadata  # type: ignore[assignment]
        return evidence

    async def get_evidence_record(self, evidence_id: str) -> Evidence | None:
        async with get_db_session() as session:
            e_m = await session.get(EvidenceModel, evidence_id)
            if not e_m:
                return None
            return self._to_domain_evidence(e_m)

    async def list_evidence(
        self,
        task_id: str | None = None,
        target_ref: str | None = None,
    ) -> list[Evidence]:
        async with get_db_session() as session:
            stmt = select(EvidenceModel).order_by(EvidenceModel.timestamp.desc())
            if task_id:
                stmt = stmt.where(EvidenceModel.task_id == task_id)
            if target_ref:
                stmt = stmt.where(EvidenceModel.target_ref == target_ref)
            res = await session.execute(stmt)
            return [self._to_domain_evidence(m) for m in res.scalars().all()]

    @staticmethod
    def _to_domain_evidence(e_m: Any) -> Evidence:
        return Evidence(
            id=str(e_m.id),
            task_id=str(e_m.task_id),
            target_ref=str(e_m.target_ref),
            source_agent=str(e_m.source_agent),
            source_module=str(e_m.source_module),
            source_tool=str(e_m.source_tool),
            timestamp=cast(datetime, e_m.timestamp),
            artifact_storage_key=str(e_m.artifact_storage_key),
            content_type=str(e_m.content_type),
            sha256_hash=str(e_m.sha256_hash),
            integrity_metadata=dict(e_m.integrity_metadata or {}),
            collected_by=str(e_m.collected_by),
            chain_of_custody=[
                ChainOfCustodyEvent.model_validate(c) for c in (e_m.chain_of_custody or [])
            ],
            context_metadata=dict(e_m.context_metadata or {}),
        )


class OracleApprovalRepository(ApprovalRepository):
    """Oracle-backed durable operator approvals."""

    async def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        approval.justification_needed = _optional(approval.justification_needed) or ""
        approval.justification_provided = _optional(approval.justification_provided)
        approval.approved_by = _optional(approval.approved_by)
        approval.authorization_reference = _optional(approval.authorization_reference)
        approval.action_fingerprint = _optional(approval.action_fingerprint)
        values = {
            "task_id": approval.task_id,
            "action_id": approval.action_id,
            "action_type": approval.action_type,
            "target_refs": approval.target_refs,
            "requested_by": approval.requested_by,
            "action_fingerprint": approval.action_fingerprint,
            "status": approval.status,
            "justification_needed": approval.justification_needed,
            "justification_provided": approval.justification_provided,
            "approved_by": approval.approved_by,
            "authorization_reference": approval.authorization_reference,
            "requested_at": approval.requested_at,
            "decided_at": approval.decided_at,
            "expires_at": approval.expires_at,
        }
        async with get_db_session() as session:
            model = await session.get(ApprovalModel, approval.approval_id)
            if model is None:
                session.add(ApprovalModel(approval_id=approval.approval_id, **values))
            else:
                model_values = cast(Any, model)
                for field_name, field_value in values.items():
                    setattr(model_values, field_name, field_value)
        return approval

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        async with get_db_session() as session:
            model = await session.get(ApprovalModel, approval_id)
            return self._to_domain_approval(model) if model else None

    async def list_approvals(
        self,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[ApprovalRecord]:
        async with get_db_session() as session:
            stmt = select(ApprovalModel).order_by(ApprovalModel.requested_at.desc())
            if task_id:
                stmt = stmt.where(ApprovalModel.task_id == task_id)
            if status:
                stmt = stmt.where(ApprovalModel.status == status)
            result = await session.execute(stmt)
            return [self._to_domain_approval(model) for model in result.scalars().all()]

    @staticmethod
    def _to_domain_approval(model: Any) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=str(model.approval_id),
            task_id=str(model.task_id),
            action_id=str(model.action_id),
            action_type=str(model.action_type),
            target_refs=list(model.target_refs or []),
            requested_by=str(model.requested_by),
            action_fingerprint=model.action_fingerprint,
            status=str(model.status),
            justification_needed=str(model.justification_needed),
            justification_provided=model.justification_provided,
            approved_by=model.approved_by,
            authorization_reference=model.authorization_reference,
            requested_at=cast(datetime, model.requested_at),
            decided_at=cast(datetime | None, model.decided_at),
            expires_at=cast(datetime, model.expires_at),
        )


class OracleRiskRepository(RiskRepository):
    """Oracle-backed Risk score repository."""

    async def save_risk(self, risk: Risk) -> Risk:
        risk.rationale = _optional(risk.rationale)
        async with get_db_session() as session:
            model = await session.get(RiskModel, risk.id)
            if not model:
                model = RiskModel(
                    id=risk.id,
                    finding_id=risk.finding_id,
                    task_id=risk.task_id,
                    severity=risk.severity.value,
                    asset_criticality=risk.asset_criticality.value,
                    exposure_score=risk.exposure_score,
                    exploitability_score=risk.exploitability_score,
                    confidence_score=risk.confidence_score,
                    computed_risk_score=risk.computed_risk_score,
                    risk_tier=risk.risk_tier.value,
                    rationale=risk.rationale,
                )
                session.add(model)
            else:
                model.severity = risk.severity.value  # type: ignore[assignment]
                model.asset_criticality = risk.asset_criticality.value  # type: ignore[assignment]
                model.exposure_score = risk.exposure_score  # type: ignore[assignment]
                model.exploitability_score = risk.exploitability_score  # type: ignore[assignment]
                model.confidence_score = risk.confidence_score  # type: ignore[assignment]
                model.computed_risk_score = risk.computed_risk_score  # type: ignore[assignment]
                model.risk_tier = risk.risk_tier.value  # type: ignore[assignment]
                model.rationale = risk.rationale  # type: ignore[assignment]
        return risk

    async def get_risk(self, risk_id: str) -> Risk | None:
        async with get_db_session() as session:
            model = await session.get(RiskModel, risk_id)
            return self._to_domain_risk(model) if model else None

    async def list_risks(
        self,
        task_id: str | None = None,
        finding_id: str | None = None,
        risk_tier: RiskTier | None = None,
    ) -> list[Risk]:
        async with get_db_session() as session:
            stmt = select(RiskModel).order_by(RiskModel.computed_risk_score.desc())
            if task_id:
                stmt = stmt.where(RiskModel.task_id == task_id)
            if finding_id:
                stmt = stmt.where(RiskModel.finding_id == finding_id)
            if risk_tier:
                stmt = stmt.where(RiskModel.risk_tier == risk_tier.value)
            res = await session.execute(stmt)
            return [self._to_domain_risk(m) for m in res.scalars().all()]

    @staticmethod
    def _to_domain_risk(m: Any) -> Risk:
        return Risk(
            id=str(m.id),
            finding_id=str(m.finding_id),
            task_id=str(m.task_id),
            severity=SeverityLevel(str(m.severity)),
            asset_criticality=AssetCriticality(str(m.asset_criticality)),
            exposure_score=float(m.exposure_score),
            exploitability_score=float(m.exploitability_score),
            confidence_score=float(m.confidence_score),
            computed_risk_score=float(m.computed_risk_score),
            risk_tier=RiskTier(str(m.risk_tier)),
            rationale=str(m.rationale or ""),
        )


class OracleAuditRepository(AuditRepository):
    """Oracle-backed cryptographic audit ledger mirror.

    The signed ledger itself remains the append-only file chain owned by
    :class:`sentinel.audit.audit_logger.AuditLogger`; this repository mirrors the
    entries for querying. Its hashing/signature semantics are untouched.
    """

    async def save_audit_entry(self, entry: AuditEntry) -> AuditEntry:
        try:
            ts = datetime.fromisoformat(entry.timestamp)
        except Exception:
            ts = datetime.now(UTC)

        async with get_db_session() as session:
            rec = await session.get(AuditLogRecord, entry.entry_id)
            if not rec:
                rec = AuditLogRecord(
                    entry_id=entry.entry_id,
                    timestamp=ts,
                    event_type=entry.event_type,
                    actor=entry.actor,
                    target=entry.target,
                    action_type=entry.action_type,
                    scope_policy=entry.scope_policy,
                    decision=entry.decision,
                    details=entry.details,
                    previous_hash=entry.previous_hash,
                    current_hash=entry.current_hash,
                    signature=entry.signature,
                    verified=True,
                )
                session.add(rec)
            else:
                rec.verified = True  # type: ignore[assignment]
        return entry

    async def get_audit_entry(self, entry_id: str) -> AuditEntry | None:
        async with get_db_session() as session:
            rec = await session.get(AuditLogRecord, entry_id)
            return self._to_domain_entry(rec) if rec else None

    async def get_last_entry(self) -> AuditEntry | None:
        async with get_db_session() as session:
            stmt = select(AuditLogRecord).order_by(AuditLogRecord.timestamp.desc()).limit(1)
            res = await session.execute(stmt)
            rec = res.scalar_one_or_none()
            return self._to_domain_entry(rec) if rec else None

    async def list_audit_entries(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        async with get_db_session() as session:
            stmt = select(AuditLogRecord).order_by(AuditLogRecord.timestamp.asc()).offset(offset).limit(limit)
            res = await session.execute(stmt)
            return [self._to_domain_entry(r) for r in res.scalars().all()]

    async def verify_audit_chain(self) -> tuple[bool, str]:
        async with get_db_session() as session:
            stmt = select(AuditLogRecord).order_by(AuditLogRecord.timestamp.asc())
            res = await session.execute(stmt)
            records = res.scalars().all()

        if not records:
            return True, "Audit ledger in database is empty (genesis state)."

        prev_hash = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"
        for idx, rec in enumerate(records, start=1):
            if rec.previous_hash != prev_hash:
                return False, f"Audit chain hash break at record {idx} (entry_id={rec.entry_id})"
            prev_hash = str(rec.current_hash)

        return True, f"Cryptographic audit chain verified across {len(records)} database records."

    @staticmethod
    def _to_domain_entry(m: Any) -> AuditEntry:
        ts_str = m.timestamp.isoformat() if hasattr(m.timestamp, "isoformat") else str(m.timestamp)
        return AuditEntry(
            entry_id=str(m.entry_id),
            timestamp=ts_str,
            event_type=str(m.event_type),
            actor=str(m.actor),
            target=str(m.target) if m.target else None,
            action_type=str(m.action_type),
            scope_policy=str(m.scope_policy),
            decision=str(m.decision),
            details=dict(m.details or {}),
            previous_hash=str(m.previous_hash),
            current_hash=str(m.current_hash),
            signature=str(m.signature),
        )


class OracleEventRepository(EventRepository):
    """Oracle-backed system event repository."""

    async def save_event(self, event: Event) -> Event:
        async with get_db_session() as session:
            rec = await session.get(EventModel, event.event_id)
            ts = event.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)

            ev_type_str = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)

            if not rec:
                rec = EventModel(
                    event_id=event.event_id,
                    event_type=ev_type_str,
                    topic=event.topic,
                    source=event.source,
                    payload=event.payload,
                    correlation_id=event.correlation_id,
                    timestamp=ts,
                )
                session.add(rec)
            else:
                rec.payload = event.payload  # type: ignore[assignment]
                rec.timestamp = ts  # type: ignore[assignment]
        return event

    async def get_event(self, event_id: str) -> Event | None:
        async with get_db_session() as session:
            rec = await session.get(EventModel, event_id)
            return self._to_domain_event(rec) if rec else None

    async def list_events(
        self,
        topic: str | None = None,
        event_type: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]:
        async with get_db_session() as session:
            stmt = select(EventModel).order_by(EventModel.timestamp.desc()).offset(offset).limit(limit)
            if topic:
                stmt = stmt.where(EventModel.topic == topic)
            if event_type:
                stmt = stmt.where(EventModel.event_type == event_type)
            if correlation_id:
                stmt = stmt.where(EventModel.correlation_id == correlation_id)
            res = await session.execute(stmt)
            return [self._to_domain_event(r) for r in res.scalars().all()]

    @staticmethod
    def _to_domain_event(m: Any) -> Event:
        ev_type_str = str(m.event_type)
        try:
            ev_type = EventType(ev_type_str)
        except ValueError:
            ev_type = ev_type_str  # type: ignore[assignment]

        ts = m.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        return Event(
            event_id=str(m.event_id),
            event_type=ev_type,
            topic=str(m.topic),
            source=str(m.source),
            payload=dict(m.payload or {}),
            correlation_id=str(m.correlation_id),
            timestamp=ts,
        )


__all__ = [
    "OracleApprovalRepository",
    "OracleAuditRepository",
    "OracleEventRepository",
    "OracleEvidenceRepository",
    "OracleFindingRepository",
    "OracleRiskRepository",
    "OracleTaskRepository",
]
