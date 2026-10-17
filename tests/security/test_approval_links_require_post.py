"""Human-in-the-loop approval links must be read-only on GET."""

import pytest
from fastapi import HTTPException

from sentinel.apps.api.main import (
    approve_action,
    deny_action,
    get_approval_confirmation,
    get_denial_confirmation,
)
from sentinel.gatekeeper.approval_dispatcher import ApprovalStatus, approval_dispatcher


@pytest.fixture
def pending_approval(monkeypatch):
    monkeypatch.setattr(approval_dispatcher, "_dispatch_notifications", lambda _pending: None)
    return approval_dispatcher.submit_approval(
        agent_name="TEST_AGENT",
        action="protected-test-action",
        details={"test": True},
    )


@pytest.mark.asyncio
async def test_approval_link_get_does_not_approve(pending_approval):
    page = await get_approval_confirmation(pending_approval.token)

    assert page.status_code == 200
    assert "Opening this link did not approve" in page.body.decode()
    assert pending_approval.status is ApprovalStatus.PENDING

    result = await approve_action(pending_approval.token)
    assert result["status"] == "APPROVED"
    assert pending_approval.status is ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_denial_link_get_does_not_deny(pending_approval):
    page = await get_denial_confirmation(pending_approval.token)

    assert page.status_code == 200
    assert "Opening this link did not deny" in page.body.decode()
    assert pending_approval.status is ApprovalStatus.PENDING

    result = await deny_action(pending_approval.token)
    assert result["status"] == "DENIED"
    assert pending_approval.status is ApprovalStatus.DENIED


@pytest.mark.asyncio
async def test_expired_approval_link_does_not_create_a_decision(pending_approval):
    pending_approval.expires_at = 0.0

    page = await get_approval_confirmation(pending_approval.token)

    assert page.status_code == 409
    assert pending_approval.status is ApprovalStatus.PENDING

    with pytest.raises(HTTPException) as exc:
        await approve_action(pending_approval.token)
    assert exc.value.status_code == 409
    assert pending_approval.status is ApprovalStatus.EXPIRED
