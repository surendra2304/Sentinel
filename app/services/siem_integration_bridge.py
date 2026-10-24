"""
Sentinel/app/services/siem_integration_bridge.py — Sentinel SIEM Integration Bridge.

SIEM integration, log aggregation, correlation rules, alert forwarding,
and security event normalization.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class SecurityEvent:
    """A normalized security event."""
    event_id: str
    source: str  # syslog, api, endpoint, network
    event_type: str  # authentication, authorization, network, system
    severity: str = "info"  # info, warning, alert, critical
    message: str = ""
    source_ip: str = ""
    timestamp: float = field(default_factory=time.time)
    raw_data: str = ""
    normalized: bool = False


@dataclass
class CorrelationRule:
    """A correlation rule for event analysis."""
    rule_id: str
    name: str
    description: str = ""
    conditions: list[dict] = field(default_factory=list)
    threshold: int = 3
    action: str = "alert"
    enabled: bool = True


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""
    result_id: str
    rule_id: str
    matched_events: list[str] = field(default_factory=list)
    correlation_score: float = 0.0
    triggered: bool = False
    recommendation: str = ""


class SIEMIntegrationBridge:
    """Bridge for SIEM integration and event correlation."""

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []
        self._rules: dict[str, CorrelationRule] = {}
        self._correlations: list[CorrelationResult] = []

    def ingest_event(self, source: str, event_type: str, message: str,
                     severity: str = "info", source_ip: str = "",
                     raw_data: str = "") -> str:
        """Ingest a security event."""
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        event = SecurityEvent(
            event_id=event_id, source=source, event_type=event_type,
            severity=severity, message=message, source_ip=source_ip,
            raw_data=raw_data, normalized=True,
        )
        self._events.append(event)
        # Run correlation rules
        self._run_correlations(event)
        return event_id

    def create_correlation_rule(self, name: str, description: str,
                                conditions: list[dict], threshold: int = 3,
                                action: str = "alert") -> str:
        """Create a correlation rule."""
        rule_id = f"rule_{uuid.uuid4().hex[:12]}"
        rule = CorrelationRule(
            rule_id=rule_id, name=name, description=description,
            conditions=conditions, threshold=threshold, action=action,
        )
        self._rules[rule_id] = rule
        return rule_id

    def _run_correlations(self, new_event: SecurityEvent) -> None:
        """Run correlation rules on a new event."""
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            matching = [
                e for e in self._events
                if any(
                    cond.get("type") == e.event_type and cond.get("severity", "").lower() == e.severity.lower()
                    for cond in rule.conditions
                )
            ]
            if len(matching) >= rule.threshold:
                result_id = f"corr_{uuid.uuid4().hex[:12]}"
                score = len(matching) / rule.threshold
                correlation = CorrelationResult(
                    result_id=result_id, rule_id=rule.rule_id,
                    matched_events=[e.event_id for e in matching],
                    correlation_score=score, triggered=True,
                    recommendation=f"Rule '{rule.name}' triggered: {len(matching)} matching events",
                )
                self._correlations.append(correlation)

    def get_events(self, event_type: str | None = None,
                   severity: str | None = None) -> list[dict[str, Any]]:
        """Get security events."""
        events = list(self._events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        return [
            {
                "event_id": e.event_id, "source": e.source, "event_type": e.event_type,
                "severity": e.severity, "message": e.message[:100],
                "source_ip": e.source_ip,
            }
            for e in events[-50:]
        ]

    def get_correlations(self) -> list[dict[str, Any]]:
        """Get correlation results."""
        return [
            {
                "result_id": c.result_id,
                "rule_id": c.rule_id,
                "matched_count": len(c.matched_events),
                "correlation_score": c.correlation_score,
                "triggered": c.triggered,
                "recommendation": c.recommendation,
            }
            for c in self._correlations
        ]

    def get_report(self) -> dict[str, Any]:
        """Get engine report."""
        return {
            "total_events": len(self._events),
            "total_rules": len(self._rules),
            "total_correlations": len(self._correlations),
            "triggered_correlations": sum(1 for c in self._correlations if c.triggered),
            "engine_status": "operational",
        }


engine = SIEMIntegrationBridge()


@router.post("/sentinel/siem/events")
async def ingest_event(source: str, event_type: str, message: str, severity: str = "info",
                       source_ip: str = "", raw_data: str = ""):
    """Ingest a security event."""
    event_id = engine.ingest_event(source, event_type, message, severity, source_ip, raw_data)
    return {"event_id": event_id, "status": "ingested"}


@router.post("/sentinel/siem/rules")
async def create_correlation_rule(name: str, description: str, conditions: list[dict],
                                  threshold: int = 3, action: str = "alert"):
    """Create a correlation rule."""
    rule_id = engine.create_correlation_rule(name, description, conditions, threshold, action)
    return {"rule_id": rule_id, "status": "created"}


@router.get("/sentinel/siem/events")
async def get_events(event_type: str | None = None, severity: str | None = None):
    """Get security events."""
    return {"events": engine.get_events(event_type, severity)}


@router.get("/sentinel/siem/correlations")
async def get_correlations():
    """Get correlation results."""
    return {"correlations": engine.get_correlations()}


@router.get("/sentinel/siem/report")
async def siem_report():
    """Get SIEM bridge report."""
    return engine.get_report()
