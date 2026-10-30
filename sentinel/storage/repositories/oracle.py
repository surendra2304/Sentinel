"""Oracle-backed repository implementations for Sentinel durable entities.

The SQLAlchemy statement layer in :mod:`sentinel.storage.repositories.postgres`
is dialect-neutral -- it never emits ``ON CONFLICT``, ``INSERT OR REPLACE``,
positional ``?`` binds or literal ``LIMIT`` (SQLAlchemy compiles ``.limit()`` to
``FETCH FIRST n ROWS ONLY`` on Oracle). The Oracle classes therefore inherit that
implementation and only add the Oracle-specific behaviour:

* empty strings in ``save_*`` payloads are normalised to ``NULL``;
* JSON payloads are serialised with ``json.dumps`` into CLOB columns by
  ``JSONDocument`` (see :mod:`sentinel.storage.database.models`);
* result rows are read through ORM attributes / labelled columns, so Oracle's
  upper-case column names never leak into the domain models.

Oracle DDL is created from metadata at startup (``Base.metadata.create_all``) in
the schema of the connecting user (``SENTINEL``), with unqualified names.
"""

from __future__ import annotations

from typing import Any

from sentinel.core.models import Evidence, Finding, Risk, Task
from sentinel.core.policy.engine import ApprovalRecord
from sentinel.storage.database.oracle import normalise_empty
from sentinel.storage.repositories.postgres import (
    PostgresApprovalRepository,
    PostgresAuditRepository,
    PostgresEventRepository,
    PostgresEvidenceRepository,
    PostgresFindingRepository,
    PostgresRiskRepository,
    PostgresTaskRepository,
)


def _optional(value: Any) -> Any:
    """Oracle cannot store ``''``; persist it as ``NULL`` instead."""
    return normalise_empty(value)


class OracleTaskRepository(PostgresTaskRepository):
    """Oracle-backed Task entity repository (unqualified ``sentinel_*`` tables)."""

    async def update_task(self, task: Task) -> Task:
        return await super().update_task(task)


class OracleFindingRepository(PostgresFindingRepository):
    """Oracle-backed Finding repository."""

    async def save_finding(self, finding: Finding) -> Finding:
        finding.exploitability_context = _optional(finding.exploitability_context)
        finding.impact = _optional(finding.impact)
        finding.remediation = _optional(finding.remediation)
        finding.description = _optional(finding.description) or ""
        return await super().save_finding(finding)


class OracleEvidenceRepository(PostgresEvidenceRepository):
    """Oracle-backed Evidence metadata index."""

    async def save_evidence_record(self, evidence: Evidence) -> Evidence:
        return await super().save_evidence_record(evidence)


class OracleApprovalRepository(PostgresApprovalRepository):
    """Oracle-backed durable operator approvals."""

    async def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        approval.justification_needed = _optional(approval.justification_needed) or ""
        approval.justification_provided = _optional(approval.justification_provided)
        approval.approved_by = _optional(approval.approved_by)
        approval.authorization_reference = _optional(approval.authorization_reference)
        approval.action_fingerprint = _optional(approval.action_fingerprint)
        return await super().save_approval(approval)


class OracleRiskRepository(PostgresRiskRepository):
    """Oracle-backed Risk score repository."""

    async def save_risk(self, risk: Risk) -> Risk:
        risk.rationale = _optional(risk.rationale)
        return await super().save_risk(risk)


class OracleAuditRepository(PostgresAuditRepository):
    """Oracle-backed cryptographic audit ledger mirror.

    The signed ledger itself remains the append-only file chain owned by
    :class:`sentinel.audit.audit_logger.AuditLogger`; this repository mirrors the
    entries for querying. Its hashing/signature semantics are untouched.
    """


class OracleEventRepository(PostgresEventRepository):
    """Oracle-backed system event repository."""


__all__ = [
    "OracleApprovalRepository",
    "OracleAuditRepository",
    "OracleEventRepository",
    "OracleEvidenceRepository",
    "OracleFindingRepository",
    "OracleRiskRepository",
    "OracleTaskRepository",
]
