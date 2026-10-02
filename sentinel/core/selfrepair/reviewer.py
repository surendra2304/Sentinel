"""Sentinel review of a proposed self-repair patch.

Phase E1. Forge proposes a repair; Sentinel decides whether it is safe to hand to
the owner. Until now the recipient of that review had to take the reviewer's word
for it — a caller could simply *type* "sentinel" into a review endpoint and be
believed. This module removes that by making a review a signed artefact.

Design notes
------------
The signing scheme is deliberately the one already used by
``sentinel.audit.audit_logger.AuditLogger``:

    hash      = sha256(canonical_json(document_without_signature))
    signature = hmac_sha256(signing_key, hash)

Reusing the existing scheme means there is one signing convention in this
codebase, not two, and it means the review can be checked by anything that knows
the audit signing key.

The single-use property is **not** reimplemented. A review is bound to a
fingerprint and mints an approval through the existing
``sentinel.core.auth.approvals.ApprovalManager``, which already guarantees
fingerprint binding, expiry and atomic single-use consumption. This module only
produces the artefact; the consumption semantics stay in the component that
already owns them.

The reviewer is deliberately adversarial about its own verdict: it inspects the
proposed diff rather than trusting the rationale, and a patch that touches
credentials, auth or network egress is blocked regardless of how well it tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.auth.approvals import ApprovalManager
from sentinel.core.gateway.models import (
    ActionKind,
    ActionRequest,
    Actor,
    Approval,
    ApprovalStatus,
    RiskLevel,
)

#: Reviewer identity, matching the key FRIDAY's gate requires.
REVIEWER = "sentinel"

#: Same environment variables the audit logger already honours, so an operator
#: configures one key for the whole service.
_SIGNING_KEY_ENV = ("SENTINEL_AUDIT_HMAC_KEY", "SENTINEL_AUDIT_SIGNING_KEY")

#: Patterns that make a repair unreviewable-by-intent: whatever the tests say, a
#: patch that reaches for secrets or bypasses authorisation is not "clear".
_BLOCKING_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)\b(api[_-]?key|secret|password|token|private[_-]?key)\b\s*[:=]",
     "appears to hardcode a credential"),
    (r"(?i)\beval\s*\(", "uses eval"),
    (r"(?i)\bexec\s*\(", "uses exec"),
    (r"(?i)\bsubprocess\b|\bos\.system\b|\bshell\s*=\s*True\b", "shells out"),
    (r"(?i)\b(curl|wget)\b\s+http|requests\.(get|post)\s*\(\s*f?[\"']https?://",
     "adds outbound network access"),
    (r"(?i)\bchmod\s+777|0o777", "grants world-writable permissions"),
    (r"(?i)#\s*noqa|pytest\.skip|@unittest\.skip", "suppresses a check instead of fixing it"),
)


def canonical_json(payload: dict[str, Any]) -> str:
    """Byte-stable JSON, so both sides hash identical content."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def document_hash(document: dict[str, Any]) -> str:
    """SHA-256 over the canonical form of the document, excluding its signature."""
    body = {k: v for k, v in document.items() if k != "signature"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def sign_document(document: dict[str, Any], key: bytes) -> str:
    """HMAC-SHA256 over the document hash. Mirrors AuditLogger._sign_hash."""
    return hmac.new(key, document_hash(document).encode("utf-8"), hashlib.sha256).hexdigest()


def load_signing_key(explicit: str | None = None) -> bytes:
    if explicit:
        return explicit.encode("utf-8")
    for name in _SIGNING_KEY_ENV:
        value = os.environ.get(name)
        if value:
            return value.encode("utf-8")
    raise RuntimeError(
        "no self-repair signing key configured: set SENTINEL_AUDIT_HMAC_KEY or "
        "SENTINEL_AUDIT_SIGNING_KEY. Refusing to sign with a default key."
    )


@dataclass(frozen=True, slots=True)
class SignedReview:
    """A review that a recipient can verify without trusting the transport."""

    patch_fingerprint: str
    verdict: str
    reviewer: str
    approval_id: str
    findings: tuple[str, ...]
    checks_run: tuple[str, ...]
    issued_at: float
    nonce: str
    signature: str

    def to_document(self) -> dict[str, Any]:
        return {
            "patch_fingerprint": self.patch_fingerprint,
            "verdict": self.verdict,
            "reviewer": self.reviewer,
            "approval_id": self.approval_id,
            "findings": list(self.findings),
            "checks_run": list(self.checks_run),
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "signature": self.signature,
        }

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> SignedReview:
        return cls(
            patch_fingerprint=str(document["patch_fingerprint"]),
            verdict=str(document["verdict"]),
            reviewer=str(document["reviewer"]),
            approval_id=str(document["approval_id"]),
            findings=tuple(document.get("findings", ())),
            checks_run=tuple(document.get("checks_run", ())),
            issued_at=float(document["issued_at"]),
            nonce=str(document["nonce"]),
            signature=str(document["signature"]),
        )


@dataclass
class ReviewOutcome:
    """What the reviewer decided, and the artefacts that prove it.

    ``action`` is returned deliberately. The approval is bound to the fingerprint
    of that exact ActionRequest, and a consumer cannot reconstruct it by hand —
    any difference in risk, targets or parameters yields a different fingerprint
    and the consumption is refused. So the request travels with the outcome.
    """

    review: SignedReview
    approval: Approval | None
    action: ActionRequest
    blocked: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_document(self) -> dict[str, Any]:
        return {
            "review": self.review.to_document(),
            "blocked": self.blocked,
            "reasons": list(self.reasons),
        }


class SelfRepairReviewer:
    """Reviews a proposed patch and issues a signed, single-use verdict."""

    def __init__(
        self,
        approvals: ApprovalManager,
        signing_key: str | bytes | None = None,
        approval_ttl: float = 900.0,
    ) -> None:
        self.approvals = approvals
        if isinstance(signing_key, bytes):
            self._key = signing_key
        else:
            self._key = load_signing_key(signing_key)
        self.approval_ttl = approval_ttl

    # ── inspection ─────────────────────────────────────────────────────────
    @staticmethod
    def inspect(
        target_file: str,
        replacement_snippet: str,
        test_evidence: dict[str, Any] | None,
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        """Return (findings, reasons_to_block, checks_run).

        Inspection is on the *proposed* content, not the rationale: a patch that
        reads well and is dangerous is still dangerous.
        """
        findings: list[str] = []
        blockers: list[str] = []
        checks: list[str] = []

        checks.append("test_evidence_present")
        evidence = test_evidence if isinstance(test_evidence, dict) else {}
        if evidence.get("passed") is not True or not str(evidence.get("command", "")).strip():
            blockers.append("proposal carries no passing test command")
        else:
            findings.append(f"test evidence: {evidence.get('command')}")

        checks.append("no_hardcoded_credentials")
        for pattern, description in _BLOCKING_PATTERNS:
            if re.search(pattern, replacement_snippet):
                blockers.append(f"patch {description}")
        if not blockers:
            findings.append("no credential, exec, network or permission hazards in the diff")

        checks.append("target_file_declared")
        if not target_file.strip():
            blockers.append("patch names no target file")

        checks.append("patch_is_not_empty")
        if not replacement_snippet.strip():
            blockers.append("replacement snippet is empty")

        return tuple(findings), tuple(blockers), tuple(checks)

    # ── the signed verdict ─────────────────────────────────────────────────
    def review(
        self,
        *,
        patch_fingerprint: str,
        target_file: str,
        replacement_snippet: str,
        test_evidence: dict[str, Any] | None,
        action_id: str | None = None,
    ) -> ReviewOutcome:
        """Inspect the patch, mint a single-use approval, and sign the verdict.

        The approval is minted through the existing ApprovalManager and is bound
        to this exact patch fingerprint, so even a correctly signed review cannot
        be replayed against different code.
        """
        findings, blockers, checks = self.inspect(
            target_file=target_file,
            replacement_snippet=replacement_snippet,
            test_evidence=test_evidence,
        )
        blocked = bool(blockers)
        action_id = action_id or f"selfrepair_{uuid.uuid4().hex[:12]}"

        action = ActionRequest(
            id=action_id,
            task_id="self-repair",
            actor=Actor(id=REVIEWER),
            kind=ActionKind.WRITE,
            action_type="SELF_REPAIR_APPLY",
            # The fingerprint that binds the approval to this exact patch.
            parameters={"patch_fingerprint": patch_fingerprint, "target_file": target_file},
            targets=(target_file,),
            risk=RiskLevel.HIGH,
            requires_approval=True,
        )
        approval = self.approvals.request(action, ttl=self.approval_ttl)
        if not blocked:
            approval = self.approvals.decide(approval.id, approve=True)

        body = {
            "patch_fingerprint": patch_fingerprint,
            "verdict": "block" if blocked else "clear",
            "reviewer": REVIEWER,
            "approval_id": approval.id,
            "findings": list(findings),
            "checks_run": list(checks),
            "issued_at": time.time(),
            "nonce": uuid.uuid4().hex,
        }
        document = {**body, "signature": sign_document(body, self._key)}
        review = SignedReview.from_document(document)

        return ReviewOutcome(
            review=review, approval=approval, action=action, blocked=blocked, reasons=blockers
        )

    def consume_approval(self, action: ActionRequest) -> Approval:
        """Single-use consumption, delegated to the existing manager."""
        approval = self.approvals.consume(action)
        if approval.status is not ApprovalStatus.CONSUMED:  # pragma: no cover - defensive
            raise PermissionError("approval was not marked consumed")
        return approval


def verify_document(document: dict[str, Any], key: bytes) -> bool:
    """Constant-time signature check. The recipient's side of the contract."""
    expected = sign_document(document, key)
    return hmac.compare_digest(expected, str(document.get("signature", "")))


def resign(body: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Sign an arbitrary review body. Used by the sender and by tamper tests."""
    return {**body, "signature": sign_document(body, key)}
