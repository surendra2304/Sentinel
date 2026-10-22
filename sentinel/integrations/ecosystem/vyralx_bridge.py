"""VyralX Media and Distribution Security Bridge.

Enforces pre-publication safety gates, copyright license validation,
NSFW/harmful content prevention, and cryptographic veto authorization for VyralX.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger

# Restricted / prohibited content patterns
PROHIBITED_MEDIA_PATTERNS = [
    re.compile(r"\b(?:malware|ransomware|keylogger|exploit-kit|zero-day|rat)\b", re.IGNORECASE),
    re.compile(r"\b(?:nsfw|explicit|csam|doxx|hate-speech|harassment)\b", re.IGNORECASE),
    re.compile(r"\b(?:pirated|warez|cracked-software|torrent-leaks)\b", re.IGNORECASE),
]

VALID_LICENSES = {
    "proprietary_owned",
    "cc0",
    "cc_by",
    "cc_by_sa",
    "mit",
    "apache_2_0",
    "commercial_licensed",
    "fair_use_educational",
}


class MediaPublicationRequest(BaseModel):
    """Payload submitted by VyralX for pre-distribution inspection."""

    campaign_id: str
    asset_id: str
    asset_url: str
    mime_type: str
    title: str
    description: str = ""
    license_type: str = "proprietary_owned"
    target_channels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MediaAuditDecision(BaseModel):
    """Machine-readable security verdict returned to VyralX."""

    campaign_id: str
    asset_id: str
    is_approved: bool
    decision: str  # "APPROVED" | "VETOED"
    veto_reasons: list[str] = Field(default_factory=list)
    signature: str = ""
    timestamp: str = ""


class VyralXMediaPolicyGate:
    """Zero-Trust Media Safety and Rights Gatekeeper."""

    def __init__(self, signing_key: str | None = None) -> None:
        self.signing_key: str = str(
            signing_key or os.getenv("SENTINEL_AUDIT_SIGNING_KEY") or "sentinel-default-media-key"
        )

    def inspect_publication(self, request: MediaPublicationRequest) -> MediaAuditDecision:
        """Evaluate media submission; returns cryptographic pass/veto decision."""
        veto_reasons: list[str] = []

        # 1. License Check
        norm_license = request.license_type.strip().lower()
        if norm_license not in VALID_LICENSES:
            veto_reasons.append(
                f"Unauthorized or unverified license type '{request.license_type}'. "
                f"Allowed: {sorted(VALID_LICENSES)}"
            )

        # 2. Content Safety / Prohibited Patterns
        combined_text = f"{request.title} {request.description} {request.asset_url}"
        for pattern in PROHIBITED_MEDIA_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                veto_reasons.append(f"Content safety violation: Prohibited term '{match.group(0)}' detected.")

        # 3. Asset URL Safety Check (no loopback, no malicious TLDs)
        asset_url_lower = request.asset_url.lower().strip()
        if any(bad in asset_url_lower for bad in ["127.0.0.1", "localhost", "169.254.", "metadata.google"]):
            veto_reasons.append("Asset URL targets forbidden private/cloud metadata infrastructure.")

        # Determine Verdict
        is_approved = len(veto_reasons) == 0
        decision_str = "APPROVED" if is_approved else "VETOED"

        # Generate HMAC-SHA256 signature
        payload_to_sign = f"{request.campaign_id}:{request.asset_id}:{decision_str}:{len(veto_reasons)}"
        signature = hmac.new(
            self.signing_key.encode("utf-8"),
            payload_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Log decision into durable audit log
        audit_entry = audit_logger.log_event(
            event_type="VYRALX_MEDIA_AUDIT",
            actor="sentinel-vyralx-gate",
            target=f"{request.campaign_id}:{request.asset_id}",
            action_type="media_publication_gate",
            scope_policy="vyralx_content_safety_policy",
            decision=decision_str,
            details={
                "campaign_id": request.campaign_id,
                "asset_id": request.asset_id,
                "asset_url": request.asset_url,
                "license_type": request.license_type,
                "veto_reasons": veto_reasons,
                "is_approved": is_approved,
            },
        )

        return MediaAuditDecision(
            campaign_id=request.campaign_id,
            asset_id=request.asset_id,
            is_approved=is_approved,
            decision=decision_str,
            veto_reasons=veto_reasons,
            signature=signature,
            timestamp=audit_entry.timestamp,
        )
