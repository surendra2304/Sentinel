"""Sentinel Central Security Gateway Models."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionKind(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    CREDENTIAL = "credential"
    SECURITY_SCAN = "security_scan"
    SYSTEM = "system"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class Actor:
    id: str
    kind: str = "agent"
    roles: tuple[str, ...] = ()
    tenant_id: str = "default"


@dataclass(frozen=True, slots=True)
class Resource:
    type: str
    identifier: str
    tenant_id: str = "default"
    sensitivity: RiskLevel = RiskLevel.LOW


@dataclass(frozen=True, slots=True)
class ActionRequest:
    id: str
    task_id: str
    actor: Actor
    kind: ActionKind
    action_type: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    targets: tuple[str, ...] = ()
    risk: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    idempotency_key: str | None = None
    capability_token: str | None = None
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def fingerprint(self) -> str:
        """Compute a deterministic SHA-256 fingerprint of the exact action parameters."""
        body = {
            "task_id": self.task_id,
            "actor": self.actor.id,
            "tenant": self.actor.tenant_id,
            "kind": self.kind.value,
            "action_type": self.action_type,
            "parameters": _stable(self.parameters),
            "targets": list(self.targets),
            "risk": self.risk.value,
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    reason: str
    action_id: str
    fingerprint: str
    evaluated_at: float = field(default_factory=time.time)
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class Approval:
    id: str
    fingerprint: str
    actor_id: str
    tenant_id: str
    action_type: str
    expires_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: RiskLevel
    title: str
    message: str
    source: str
    location: str | None = None
    confidence: float = 1.0
    redacted_evidence: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    seq: int
    ts: float
    event_type: str
    actor_id: str
    tenant_id: str
    action_id: str | None
    payload: Mapping[str, Any]
    previous_hash: str
    current_hash: str
    signature: str


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    action_id: str
    success: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    duration_ms: int = 0
    error: str | None = None
    replayed: bool = False


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_stable(v) for v in value)
    return value
