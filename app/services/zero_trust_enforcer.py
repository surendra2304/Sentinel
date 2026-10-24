"""
Sentinel/app/services/zero_trust_enforcer.py — Sentinel Zero-Trust Policy Enforcement Engine.

Enforces zero-trust security policies: identity verification, device health
checks, micro-segmentation, continuous authentication, policy decisions, and
access revocation across the security mesh.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class IdentityContext:
    """An identity context for zero-trust verification."""
    identity_id: str
    user_id: str = ""
    device_id: str = ""
    session_id: str = ""
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    authentication_level: float = 0.0  # 0-1
    device_health: dict = field(default_factory=dict)
    risk_score: float = 0.0
    verified: bool = False
    timestamp: float = 0.0


@dataclass
class PolicyDecision:
    """A policy decision."""
    decision_id: str
    identity_id: str
    resource: str
    action: str  # read, write, execute, admin, deny
    decision: str  # allow, deny, challenge, revoke
    reason: str = ""
    policy_rules: list[str] = field(default_factory=list)
    risk_level: str = "low"
    timestamp: float = 0.0


@dataclass
class PolicyRule:
    """A zero-trust policy rule."""
    rule_id: str
    name: str
    description: str = ""
    resource_pattern: str = "*"
    action_type: str = "*"  # read, write, execute, admin
    identity_condition: dict = field(default_factory=dict)  # roles, groups, min_auth_level
    device_condition: dict = field(default_factory=dict)  # min_health_score, required_attributes
    decision: str = "allow"  # allow, deny, challenge
    priority: int = 100
    enabled: bool = True


@dataclass
class DeviceHealth:
    """Device health assessment."""
    device_id: str
    health_score: float = 0.0
    os_secure: bool = True
    encryption_enabled: bool = True
    antivirus_active: bool = True
    firewall_enabled: bool = True
    patch_level: str = "current"
    jailbroken_rooted: bool = False
    last_check: float = 0.0
    issues: list[str] = field(default_factory=list)


@dataclass
class AccessRequest:
    """An access request to evaluate."""
    request_id: str
    identity_id: str
    resource: str
    action: str
    context: dict = field(default_factory=dict)
    timestamp: float = 0.0
    decision: str = ""
    decision_id: str = ""


@dataclass
class MicroSegment:
    """A micro-segment for network isolation."""
    segment_id: str
    name: str
    description: str = ""
    rules: list[dict] = field(default_factory=list)  # [{direction, protocol, port, source, destination}]
    enabled: bool = True
    isolation_level: str = "strict"  # strict, moderate, permissive


@dataclass
class ContinuousAuthEvent:
    """A continuous authentication event."""
    event_id: str
    identity_id: str
    auth_method: str  # token, biometric, behavior, device, context
    result: str  # success, failure, challenge
    risk_delta: float = 0.0
    timestamp: float = 0.0
    details: str = ""


class ZeroTrustEnforcer:
    """Zero-trust policy enforcement engine."""

    def __init__(self):
        self._identities: dict[str, IdentityContext] = {}
        self._rules: dict[str, PolicyRule] = {}
        self._decisions: dict[str, PolicyDecision] = {}
        self._devices: dict[str, DeviceHealth] = {}
        self._segments: dict[str, MicroSegment] = {}
        self._auth_events: list[ContinuousAuthEvent] = []
        self._access_requests: dict[str, AccessRequest] = {}

        # Register default policy rules
        self._register_default_rules()

    def _register_default_rules(self):
        """Register default zero-trust policy rules."""
        rules = [
            ("admin_deny_unverified", "Admin Access Deny if Unverified", {"roles": ["admin"]}, {"min_auth_level": 0.9}, "deny", 10),
            ("high_risk_challenge", "Challenge High-Risk Access", {"risk_score": {"gte": 0.7}}, {}, "challenge", 20),
            ("device_health_required", "Require Device Health", {}, {"min_health_score": 0.6}, "challenge", 30),
            ("encryption_required", "Require Encryption", {}, {"encryption_enabled": True}, "deny", 50),
            ("default_allow_low_risk", "Allow Low-Risk Access", {}, {}, "allow", 100),
        ]

        for rid, name, id_cond, dev_cond, decision, priority in rules:
            rule = PolicyRule(
                rule_id=hashlib.md5(
                    f"rule:{rid}:{time.time()}".encode()
                ).hexdigest()[:12],
                name=name,
                description=f"Default rule: {name}",
                identity_condition=id_cond,
                device_condition=dev_cond,
                decision=decision,
                priority=priority,
            )
            self._rules[rule.rule_id] = rule

    def verify_identity(
        self,
        identity_id: str,
        user_id: str = "",
        device_id: str = "",
        session_id: str = "",
        roles: list[str] | None = None,
        authentication_level: float = 0.0,
    ) -> IdentityContext:
        """Verify an identity for zero-trust."""
        identity = IdentityContext(
            identity_id=hashlib.md5(
                f"identity:{identity_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            roles=roles or [],
            authentication_level=authentication_level,
            risk_score=1.0 - authentication_level,
            timestamp=time.time(),
        )

        # Check device health
        if device_id and device_id in self._devices:
            device = self._devices[device_id]
            identity.device_health = {
                "health_score": device.health_score,
                "os_secure": device.os_secure,
                "encryption_enabled": device.encryption_enabled,
            }

            # Adjust risk based on device health
            if device.health_score < 0.5:
                identity.risk_score = min(1.0, identity.risk_score + 0.3)
            if not device.encryption_enabled:
                identity.risk_score = min(1.0, identity.risk_score + 0.2)
            if device.jailbroken_rooted:
                identity.risk_score = min(1.0, identity.risk_score + 0.4)

        # Verify if risk is acceptable
        identity.verified = identity.risk_score < 0.5 and identity.authentication_level > 0.5

        self._identities[identity.identity_id] = identity
        return identity

    def register_device(
        self,
        device_id: str,
        os_secure: bool = True,
        encryption_enabled: bool = True,
        antivirus_active: bool = True,
        firewall_enabled: bool = True,
    ) -> DeviceHealth:
        """Register a device."""
        health = DeviceHealth(
            device_id=device_id,
            health_score=(
                os_secure * 0.3 +
                encryption_enabled * 0.2 +
                antivirus_active * 0.2 +
                firewall_enabled * 0.2 +
                0.1
            ),
            os_secure=os_secure,
            encryption_enabled=encryption_enabled,
            antivirus_active=antivirus_active,
            firewall_enabled=firewall_enabled,
            last_check=time.time(),
        )

        if not os_secure:
            health.issues.append("OS not secure")
        if not encryption_enabled:
            health.issues.append("Encryption not enabled")
        if not antivirus_active:
            health.issues.append("Antivirus not active")
        if not firewall_enabled:
            health.issues.append("Firewall not enabled")

        self._devices[device_id] = health
        return health

    def evaluate_access(
        self,
        identity_id: str,
        resource: str,
        action: str,
        context: dict | None = None,
    ) -> PolicyDecision:
        """Evaluate an access request against zero-trust policies."""
        identity = self._identities.get(identity_id)
        if not identity:
            raise HTTPException(404, f"Identity {identity_id} not found")

        # Evaluate rules in priority order
        sorted_rules = sorted(
            [r for r in self._rules.values() if r.enabled],
            key=lambda r: r.priority,
        )

        matched_rules = []
        decision = "allow"
        reason = "Default allow"

        for rule in sorted_rules:
            # Check if rule matches
            matches = True

            # Check identity conditions
            if rule.identity_condition:
                if "roles" in rule.identity_condition:
                    required_roles = rule.identity_condition["roles"]
                    if not any(role in identity.roles for role in required_roles):
                        matches = False

                if "risk_score" in rule.identity_condition:
                    cond = rule.identity_condition["risk_score"]
                    if "gte" in cond and identity.risk_score < cond["gte"]:
                        matches = False

                if "min_auth_level" in rule.identity_condition:
                    if identity.authentication_level < rule.identity_condition["min_auth_level"]:
                        matches = False

            # Check device conditions
            if rule.device_condition and identity.device_health:
                if "min_health_score" in rule.device_condition:
                    if identity.device_health.get("health_score", 0) < rule.device_condition["min_health_score"]:
                        matches = False

                if "encryption_enabled" in rule.device_condition:
                    if identity.device_health.get("encryption_enabled") != rule.device_condition["encryption_enabled"]:
                        matches = False

            if matches:
                matched_rules.append(rule.name)
                decision = rule.decision
                reason = rule.description

                if decision in ("deny", "challenge"):
                    break  # Stop at first matching deny/challenge

        # Determine risk level
        if identity.risk_score > 0.7:
            risk_level = "high"
        elif identity.risk_score > 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"

        if decision == "challenge" and identity.authentication_level > 0.7:
            decision = "allow"

        policy_decision = PolicyDecision(
            decision_id=hashlib.md5(
                f"decision:{identity_id}:{resource}:{action}:{time.time()}".encode()
            ).hexdigest()[:12],
            identity_id=identity_id,
            resource=resource,
            action=action,
            decision=decision,
            reason=reason,
            policy_rules=matched_rules,
            risk_level=risk_level,
            timestamp=time.time(),
        )

        self._decisions[policy_decision.decision_id] = policy_decision

        # Record access request
        request = AccessRequest(
            request_id=hashlib.md5(
                f"request:{identity_id}:{resource}:{time.time()}".encode()
            ).hexdigest()[:12],
            identity_id=identity_id,
            resource=resource,
            action=action,
            context=context or {},
            timestamp=time.time(),
            decision=decision,
            decision_id=policy_decision.decision_id,
        )
        self._access_requests[request.request_id] = request

        return policy_decision

    def continuous_authentication(
        self,
        identity_id: str,
        auth_method: str = "behavior",
    ) -> ContinuousAuthEvent:
        """Perform continuous authentication check."""
        identity = self._identities.get(identity_id)
        if not identity:
            raise HTTPException(404, f"Identity {identity_id} not found")

        # Simulate authentication result
        success = hashlib.md5(
            f"auth:{identity_id}:{auth_method}:{time.time()}".encode()
        ).hexdigest()[:1] < "8"  # 80% success rate

        risk_delta = 0.0
        if success:
            risk_delta = -0.05
        else:
            risk_delta = 0.1

        # Update identity risk
        identity.risk_score = max(0.0, min(1.0, identity.risk_score + risk_delta))

        event = ContinuousAuthEvent(
            event_id=hashlib.md5(
                f"auth_event:{identity_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            identity_id=identity_id,
            auth_method=auth_method,
            result="success" if success else "failure",
            risk_delta=risk_delta,
            timestamp=time.time(),
            details=f"Continuous {auth_method} authentication {'passed' if success else 'failed'}",
        )

        self._auth_events.append(event)
        return event

    def create_segment(
        self,
        name: str,
        description: str = "",
        isolation_level: str = "strict",
    ) -> MicroSegment:
        """Create a micro-segment."""
        segment = MicroSegment(
            segment_id=hashlib.md5(
                f"segment:{name}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            description=description,
            isolation_level=isolation_level,
            enabled=True,
        )
        self._segments[segment.segment_id] = segment
        return segment

    def revoke_access(self, identity_id: str, reason: str = "") -> dict:
        """Revoke access for an identity."""
        identity = self._identities.get(identity_id)
        if not identity:
            raise HTTPException(404, f"Identity {identity_id} not found")

        # Create revocation decision
        decision = PolicyDecision(
            decision_id=hashlib.md5(
                f"revoke:{identity_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            identity_id=identity_id,
            resource="*",
            action="*",
            decision="revoke",
            reason=reason or "Access revoked by policy",
            risk_level="high",
            timestamp=time.time(),
        )

        self._decisions[decision.decision_id] = decision

        return {"identity_id": identity_id, "status": "revoked", "reason": decision.reason}

    def get_report(self) -> dict:
        """Get zero-trust enforcement report."""
        total_decisions = len(self._decisions)
        allowed = sum(1 for d in self._decisions.values() if d.decision == "allow")
        denied = sum(1 for d in self._decisions.values() if d.decision == "deny")
        challenged = sum(1 for d in self._decisions.values() if d.decision == "challenge")
        revoked = sum(1 for d in self._decisions.values() if d.decision == "revoke")

        return {
            "total_identities": len(self._identities),
            "total_devices": len(self._devices),
            "total_rules": len(self._rules),
            "total_segments": len(self._segments),
            "total_decisions": total_decisions,
            "allowed": allowed,
            "denied": denied,
            "challenged": challenged,
            "revoked": revoked,
            "allow_rate": allowed / max(1, total_decisions),
            "avg_risk_score": sum(i.risk_score for i in self._identities.values()) / max(1, len(self._identities)),
            "auth_events": len(self._auth_events),
            "devices_healthy": sum(1 for d in self._devices.values() if d.health_score > 0.7),
        }


# Module-level singleton
zero_trust = ZeroTrustEnforcer()


# ── API Routes ──────────────────────────────────────────────────────────────


@router.post("/api/v1/sentinel/zt/identities/verify")
async def verify_identity(payload: dict):
    """Verify an identity for zero-trust."""
    identity = zero_trust.verify_identity(
        identity_id=payload["identity_id"],
        user_id=payload.get("user_id", ""),
        device_id=payload.get("device_id", ""),
        session_id=payload.get("session_id", ""),
        roles=payload.get("roles", []),
        authentication_level=payload.get("authentication_level", 0.0),
    )
    return {
        "identity_id": identity.identity_id,
        "verified": identity.verified,
        "risk_score": identity.risk_score,
        "authentication_level": identity.authentication_level,
    }


@router.post("/api/v1/sentinel/zt/devices/register")
async def register_device(payload: dict):
    """Register a device."""
    health = zero_trust.register_device(
        device_id=payload["device_id"],
        os_secure=payload.get("os_secure", True),
        encryption_enabled=payload.get("encryption_enabled", True),
        antivirus_active=payload.get("antivirus_active", True),
        firewall_enabled=payload.get("firewall_enabled", True),
    )
    return {"device_id": health.device_id, "health_score": health.health_score, "issues": health.issues}


@router.post("/api/v1/sentinel/zt/access/evaluate")
async def evaluate_access(payload: dict):
    """Evaluate an access request."""
    decision = zero_trust.evaluate_access(
        identity_id=payload["identity_id"],
        resource=payload["resource"],
        action=payload["action"],
        context=payload.get("context", {}),
    )
    return {
        "decision_id": decision.decision_id,
        "decision": decision.decision,
        "reason": decision.reason,
        "risk_level": decision.risk_level,
        "policy_rules": decision.policy_rules,
    }


@router.post("/api/v1/sentinel/zt/auth/continuous")
async def continuous_authentication(payload: dict):
    """Perform continuous authentication."""
    event = zero_trust.continuous_authentication(
        identity_id=payload["identity_id"],
        auth_method=payload.get("auth_method", "behavior"),
    )
    return {
        "event_id": event.event_id,
        "result": event.result,
        "risk_delta": event.risk_delta,
    }


@router.post("/api/v1/sentinel/zt/segments")
async def create_segment(payload: dict):
    """Create a micro-segment."""
    segment = zero_trust.create_segment(
        name=payload["name"],
        description=payload.get("description", ""),
        isolation_level=payload.get("isolation_level", "strict"),
    )
    return {"segment_id": segment.segment_id, "name": segment.name, "isolation_level": segment.isolation_level}


@router.post("/api/v1/sentinel/zt/identities/{identity_id}/revoke")
async def revoke_access(identity_id: str, payload: dict | None = None):
    """Revoke access for an identity."""
    reason = (payload or {}).get("reason", "")
    return zero_trust.revoke_access(identity_id, reason)


@router.get("/api/v1/sentinel/zt/report")
async def get_report():
    """Get zero-trust enforcement report."""
    return zero_trust.get_report()
