"""SQLAlchemy Async Database Repository implementation for Sentinel."""

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import and_, select, update

from sentinel.core.models import (
    AssetCriticality,
    EnvironmentLabel,
    Evidence,
    Finding,
    FindingStatus,
    Policy,
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
    ActionRequestModel,
    EvidenceModel,
    FindingModel,
    PolicyModel,
    ScopeModel,
    TargetModel,
    TargetSetModel,
    TaskModel,
    targetset_targets,
)
from sentinel.storage.database.session import get_db_session
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    EvidenceRepository,
    FindingRepository,
    TaskRepository,
)


class PostgresTaskRepository(TaskRepository):
    """PostgreSQL-backed Task entity repository."""

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
                    created_at=task.scope.created_at,
                )
                session.add(scope_m)

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
                    created_at=task.policy.created_at,
                )
                session.add(policy_m)

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
        terminal = ["complete", "failed", "cancelled"]
        async with get_db_session() as session:
            stmt = select(TaskModel).where(TaskModel.status.not_in(terminal))
            res = await session.execute(stmt)
            return [self._to_domain_task(m) for m in res.scalars().all()]

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
            targets=targets,
        )
        scope = Scope(
            id=str(m.scope_id),
            name=str(m.scope.name) if m.scope else "Scope",
            allowed_targets=list(m.scope.allowed_targets) if m.scope else [],
            in_scope_declarations=list(m.scope.in_scope_declarations) if m.scope else [],
            out_of_scope_declarations=list(m.scope.out_of_scope_declarations) if m.scope else [],
            environment=EnvironmentLabel(str(m.scope.environment)) if m.scope else EnvironmentLabel.PRODUCTION,
        )
        policy = Policy(
            id=str(m.policy_id),
            name=str(m.policy.name) if m.policy else "Policy",
            allowed_module_classes=list(m.policy.allowed_module_classes) if m.policy else [],
            allowed_action_classes=list(m.policy.allowed_action_classes) if m.policy else [],
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


class PostgresFindingRepository(FindingRepository):
    """PostgreSQL-backed Finding repository."""

    async def save_finding(self, finding: Finding) -> Finding:
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


class PostgresEvidenceRepository(EvidenceRepository):
    """PostgreSQL-backed Evidence metadata index."""

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
                    integrity_metadata={},
                    collected_by=evidence.collected_by,
                    chain_of_custody=[c.model_dump(mode="json") for c in evidence.chain_of_custody],
                    context_metadata=evidence.context_metadata,
                )
                session.add(e_m)
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
            collected_by=str(e_m.collected_by),
            context_metadata=dict(e_m.context_metadata or {}),
        )


class PostgresApprovalRepository(ApprovalRepository):
    """PostgreSQL-backed Approval records repository."""

    async def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        async with get_db_session() as session:
            req_m = await session.get(ActionRequestModel, approval.approval_id)
            if not req_m:
                req_m = ActionRequestModel(
                    id=approval.approval_id,
                    task_id=approval.task_id,
                    agent=approval.requested_by,
                    action_type=approval.action_type,
                    parameters={"justification": approval.justification_needed},
                    target_refs=approval.target_refs,
                    expected_impact_level="high",
                    requires_approval=True,
                    status=approval.status,
                    created_at=approval.requested_at,
                )
                session.add(req_m)
            else:
                req_m.status = approval.status  # type: ignore[assignment]
        return approval

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        async with get_db_session() as session:
            req_m = await session.get(ActionRequestModel, approval_id)
            if not req_m:
                return None
            return self._to_domain_approval(req_m)

    async def list_approvals(
        self,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[ApprovalRecord]:
        async with get_db_session() as session:
            stmt = select(ActionRequestModel).order_by(ActionRequestModel.created_at.desc())
            if task_id:
                stmt = stmt.where(ActionRequestModel.task_id == task_id)
            if status:
                stmt = stmt.where(ActionRequestModel.status == status)
            res = await session.execute(stmt)
            return [self._to_domain_approval(m) for m in res.scalars().all()]

    @staticmethod
    def _to_domain_approval(req_m: Any) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=str(req_m.id),
            task_id=str(req_m.task_id),
            action_id=str(req_m.id),
            action_type=str(req_m.action_type),
            target_refs=list(req_m.target_refs or []),
            requested_by=str(req_m.agent),
            status=str(req_m.status),
            justification_needed=str(req_m.parameters.get("justification", "")) if req_m.parameters else "",
            requested_at=cast(datetime, req_m.created_at),
        )
