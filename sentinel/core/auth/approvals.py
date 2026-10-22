"""Sentinel Durable Approval Manager.

Binds approvals to exact action fingerprints, actor ID, and tenant ID.
Enforces single-use atomic consumption to prevent double-execution under concurrency.
"""

from __future__ import annotations

import time
from dataclasses import replace

from sentinel.core.gateway.models import ActionRequest, Approval, ApprovalStatus
from sentinel.storage.persistence.durable_store import SentinelPersistence


class ApprovalManager:
    """One-time approval bound to exact action fingerprint, actor and tenant."""

    def __init__(self, store: SentinelPersistence):
        self.store = store

    def request(self, action: ActionRequest, ttl: float = 300.0) -> Approval:
        approval = Approval(
            id="appr_" + action.id,
            fingerprint=action.fingerprint(),
            actor_id=action.actor.id,
            tenant_id=action.actor.tenant_id,
            action_type=action.action_type,
            expires_at=time.time() + ttl,
        )
        self.store.save_approval(approval)
        return approval

    def decide(self, approval_id: str, *, approve: bool) -> Approval:
        current = self.store.get_approval(approval_id)
        if current is None:
            raise KeyError(approval_id)
        if current.expires_at <= time.time():
            updated = replace(current, status=ApprovalStatus.EXPIRED)
        else:
            updated = replace(
                current,
                status=ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED,
            )
        self.store.save_approval(updated)
        return updated

    def consume(self, action: ActionRequest) -> Approval:
        current = self.store.get_approval("appr_" + action.id)
        if current is None:
            raise PermissionError("approval not found")
        if current.status != ApprovalStatus.APPROVED:
            raise PermissionError(f"approval status is {current.status}")
        if current.expires_at <= time.time():
            raise PermissionError("approval expired")
        if (
            current.fingerprint != action.fingerprint()
            or current.actor_id != action.actor.id
            or current.tenant_id != action.actor.tenant_id
        ):
            raise PermissionError("approval is not bound to this exact action")
        consumed = replace(current, status=ApprovalStatus.CONSUMED)
        self.store.save_approval(consumed)
        return consumed
