"""Abstract Repository Interfaces for Sentinel Durable Entities."""

from abc import ABC, abstractmethod
from typing import Any

from sentinel.audit.audit_logger import AuditEntry
from sentinel.core.models import (
    Event,
    Evidence,
    Finding,
    FindingStatus,
    Risk,
    RiskTier,
    SeverityLevel,
    Task,
    TaskStatus,
)
from sentinel.core.policy.engine import ApprovalRecord


class TaskRepository(ABC):
    """Abstract interface for Task persistence."""

    @abstractmethod
    async def create_task(self, task: Task) -> Task: ...

    @abstractmethod
    async def get_task(self, task_id: str) -> Task | None: ...

    @abstractmethod
    async def update_task(self, task: Task) -> Task: ...

    @abstractmethod
    async def list_tasks(
        self,
        status: TaskStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]: ...

    @abstractmethod
    async def get_active_non_terminal_tasks(self) -> list[Task]: ...

    @abstractmethod
    async def save_checkpoint(self, task_id: str, payload: dict[str, Any]) -> int: ...

    @abstractmethod
    async def get_checkpoint(self, task_id: str) -> dict[str, Any] | None: ...


class FindingRepository(ABC):
    """Abstract interface for Security Findings persistence."""

    @abstractmethod
    async def save_finding(self, finding: Finding) -> Finding: ...

    @abstractmethod
    async def get_finding(self, finding_id: str) -> Finding | None: ...

    @abstractmethod
    async def list_findings(
        self,
        task_id: str | None = None,
        severity: SeverityLevel | None = None,
        status: FindingStatus | None = None,
        target_ref: str | None = None,
    ) -> list[Finding]: ...

    @abstractmethod
    async def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
    ) -> Finding | None: ...


class EvidenceRepository(ABC):
    """Abstract interface for Evidence index persistence."""

    @abstractmethod
    async def save_evidence_record(self, evidence: Evidence) -> Evidence: ...

    @abstractmethod
    async def get_evidence_record(self, evidence_id: str) -> Evidence | None: ...

    @abstractmethod
    async def list_evidence(
        self,
        task_id: str | None = None,
        target_ref: str | None = None,
    ) -> list[Evidence]: ...


class ApprovalRepository(ABC):
    """Abstract interface for Operator Approval persistence."""

    @abstractmethod
    async def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord: ...

    @abstractmethod
    async def get_approval(self, approval_id: str) -> ApprovalRecord | None: ...

    @abstractmethod
    async def list_approvals(
        self,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[ApprovalRecord]: ...


class RiskRepository(ABC):
    """Abstract interface for Risk score persistence."""

    @abstractmethod
    async def save_risk(self, risk: Risk) -> Risk: ...

    @abstractmethod
    async def get_risk(self, risk_id: str) -> Risk | None: ...

    @abstractmethod
    async def list_risks(
        self,
        task_id: str | None = None,
        finding_id: str | None = None,
        risk_tier: RiskTier | None = None,
    ) -> list[Risk]: ...


class AuditRepository(ABC):
    """Abstract interface for Cryptographic Audit Ledger persistence."""

    @abstractmethod
    async def save_audit_entry(self, entry: AuditEntry) -> AuditEntry: ...

    @abstractmethod
    async def get_audit_entry(self, entry_id: str) -> AuditEntry | None: ...

    @abstractmethod
    async def get_last_entry(self) -> AuditEntry | None: ...

    @abstractmethod
    async def list_audit_entries(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]: ...

    @abstractmethod
    async def verify_audit_chain(self) -> tuple[bool, str]: ...


class EventRepository(ABC):
    """Abstract interface for System Event persistence."""

    @abstractmethod
    async def save_event(self, event: Event) -> Event: ...

    @abstractmethod
    async def get_event(self, event_id: str) -> Event | None: ...

    @abstractmethod
    async def list_events(
        self,
        topic: str | None = None,
        event_type: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]: ...
