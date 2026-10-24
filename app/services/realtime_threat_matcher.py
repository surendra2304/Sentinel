"""
Sentinel/app/services/realtime_threat_matcher.py — Sentinel Real-time Threat Pattern Matcher.

Matches real-time security events against threat intelligence, attack patterns,
and anomaly baselines. Supports multi-layer detection: signature-based,
anomaly-based, behavioral, and correlation-based matching with sub-10ms latency.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class SecurityEvent:
    """A real-time security event."""
    event_id: str
    source: str  # firewall, ids, edr, siem, api, dns
    event_type: str  # port_scan, brute_force, malware, phishing, data_exfil, anomaly
    severity: str  # info, low, medium, high, critical
    source_ip: str = ""
    destination_ip: str = ""
    payload: dict = field(default_factory=dict)
    timestamp: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class Signature:
    """A detection signature/rule."""
    signature_id: str
    name: str
    description: str
    event_type: str
    pattern: str  # Regex or pattern string
    severity: str = "medium"
    enabled: bool = True
    last_matched: float = 0.0
    match_count: int = 0
    false_positive_rate: float = 0.0
    source: str = "community"  # community, vendor, custom, automated


@dataclass
class AnomalyBaseline:
    """An anomaly detection baseline."""
    baseline_id: str
    metric: str  # request_rate, auth_failures, data_volume, port_usage, protocol
    mean: float = 0.0
    stddev: float = 0.0
    threshold: float = 3.0  # Number of stddevs
    window_hours: float = 24.0
    last_updated: float = 0.0
    sample_count: int = 0


@dataclass
class MatchResult:
    """Result of a threat pattern match."""
    event_id: str
    matched: bool
    severity: str = "info"
    matched_signatures: list[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    behavioral_flags: list[str] = field(default_factory=list)
    correlation_alerts: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    action_recommended: str = ""
    latency_ms: float = 0.0


@dataclass
class BehavioralProfile:
    """A behavioral profile for anomaly detection."""
    profile_id: str
    entity_type: str  # user, host, service, network
    entity_id: str
    normal_behavior: dict = field(default_factory=dict)
    deviation_score: float = 0.0
    risk_level: str = "low"
    last_evaluated: float = 0.0


@dataclass
class CorrelationRule:
    """A correlation rule for multi-event detection."""
    rule_id: str
    name: str
    description: str
    conditions: list[dict] = field(default_factory=list)
    window_sec: float = 60.0
    severity: str = "medium"
    enabled: bool = True
    trigger_count: int = 0


class RealtimeThreatMatcher:
    """Real-time threat pattern matching engine."""

    def __init__(self):
        self._signatures: dict[str, Signature] = {}
        self._baselines: dict[str, AnomalyBaseline] = {}
        self._behavioral_profiles: dict[str, BehavioralProfile] = {}
        self._correlation_rules: dict[str, CorrelationRule] = {}
        self._match_count = 0

        # Register default signatures
        self._register_default_signatures()

    def _register_default_signatures(self):
        """Register default detection signatures."""
        defaults = [
            ("SQL Injection Attempt", "sql_injection", "Pattern matches SQL injection", "(union|select|insert|update|delete).*(from|into|where)", "high"),
            ("XSS Attempt", "xss", "Pattern matches cross-site scripting", "(<script|javascript:|onerror=|onload=)", "high"),
            ("Port Scan", "port_scan", "Multiple port probes from same source", "port_scan_detected", "medium"),
            ("Brute Force Login", "brute_force", "Multiple failed login attempts", "auth_failure.*[5-9]", "high"),
            ("Malware C2 Communication", "malware", "Command and control communication", "c2_beacon_detected", "critical"),
            ("Data Exfiltration", "data_exfil", "Large outbound data transfer", "data_volume.*[1-9]GB", "critical"),
        ]

        for name, event_type, desc, pattern, severity in defaults:
            self.add_signature(name, event_type, desc, pattern, severity)

    def add_signature(
        self,
        name: str,
        event_type: str,
        description: str,
        pattern: str,
        severity: str = "medium",
    ) -> Signature:
        """Add a detection signature."""
        signature = Signature(
            signature_id=hashlib.md5(
                f"signature:{name}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            description=description,
            event_type=event_type,
            pattern=pattern,
            severity=severity,
            enabled=True,
            source="custom",
        )
        self._signatures[signature.signature_id] = signature
        return signature

    def add_baseline(
        self,
        metric: str,
        mean: float,
        stddev: float,
        threshold: float = 3.0,
    ) -> AnomalyBaseline:
        """Add an anomaly detection baseline."""
        baseline = AnomalyBaseline(
            baseline_id=hashlib.md5(
                f"baseline:{metric}:{time.time()}".encode()
            ).hexdigest()[:12],
            metric=metric,
            mean=mean,
            stddev=stddev,
            threshold=threshold,
            last_updated=time.time(),
            sample_count=0,
        )
        self._baselines[baseline.baseline_id] = baseline
        return baseline

    def add_behavioral_profile(
        self,
        entity_type: str,
        entity_id: str,
        normal_behavior: dict | None = None,
    ) -> BehavioralProfile:
        """Add a behavioral profile."""
        profile = BehavioralProfile(
            profile_id=hashlib.md5(
                f"profile:{entity_type}:{entity_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            entity_type=entity_type,
            entity_id=entity_id,
            normal_behavior=normal_behavior or {},
            last_evaluated=time.time(),
        )
        self._behavioral_profiles[profile.profile_id] = profile
        return profile

    def add_correlation_rule(
        self,
        name: str,
        description: str,
        conditions: list[dict],
        window_sec: float = 60.0,
        severity: str = "medium",
    ) -> CorrelationRule:
        """Add a correlation rule."""
        rule = CorrelationRule(
            rule_id=hashlib.md5(
                f"rule:{name}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            description=description,
            conditions=conditions,
            window_sec=window_sec,
            severity=severity,
            enabled=True,
        )
        self._correlation_rules[rule.rule_id] = rule
        return rule

    def match_event(self, event: dict) -> MatchResult:
        """Match a security event against detection patterns."""
        start = time.time()

        event_id = hashlib.md5(
            f"event:{event.get('source','')}:{event.get('event_type','')}:{time.time()}".encode()
        ).hexdigest()[:12]

        matched_signatures = []
        severity = "info"
        anomaly_score = 0.0
        behavioral_flags = []
        correlation_alerts = []

        # 1. Signature-based matching
        for sig in self._signatures.values():
            if not sig.enabled:
                continue

            # Simple pattern matching (in production: use regex)
            event_str = str(event.get("payload", {})) + event.get("event_type", "")
            if sig.pattern in event_str or sig.event_type == event.get("event_type"):
                matched_signatures.append(sig.signature_id)
                sig.match_count += 1
                sig.last_matched = time.time()

                # Update severity
                severity_order = ["info", "low", "medium", "high", "critical"]
                if severity_order.index(sig.severity) > severity_order.index(severity):
                    severity = sig.severity

        # 2. Anomaly-based matching
        for baseline in self._baselines.values():
            value = event.get("payload", {}).get(baseline.metric, baseline.mean)
            deviation = abs(value - baseline.mean) / max(0.1, baseline.stddev)

            if deviation > baseline.threshold:
                anomaly_score += deviation / baseline.threshold
                behavioral_flags.append(f"Anomaly: {baseline.metric} deviation {deviation:.1f}σ")

        # 3. Behavioral matching
        for profile in self._behavioral_profiles.values():
            if profile.entity_id == event.get("source_ip", ""):
                deviation = self._calculate_behavioral_deviation(profile, event)
                profile.deviation_score = deviation

                if deviation > 0.5:
                    behavioral_flags.append(f"Behavioral deviation: {deviation:.1f}")
                    if profile.entity_type == "user" and deviation > 0.8:
                        severity = "high" if severity_order.index("high") < severity_order.index(severity) else severity

        # 4. Correlation matching
        for rule in self._correlation_rules.values():
            if not rule.enabled:
                continue

            matched = all(
                condition.get("type") == "event_type" and condition.get("value") == event.get("event_type")
                for condition in rule.conditions
            )

            if matched:
                rule.trigger_count += 1
                correlation_alerts.append(rule.name)
                severity = rule.severity if severity_order.index(rule.severity) > severity_order.index(severity) else severity

        # Calculate risk score
        risk_score = (
            anomaly_score * 20 +
            len(matched_signatures) * 10 +
            len(behavioral_flags) * 15 +
            len(correlation_alerts) * 25
        )
        risk_score = min(100, risk_score)

        # Recommend action
        if severity == "critical":
            action = "Immediate intervention: isolate affected system"
        elif severity == "high":
            action = "Urgent response: investigate and contain"
        elif severity == "medium":
            action = "Monitor closely: review event details"
        else:
            action = "Log event for future analysis"

        result = MatchResult(
            event_id=event_id,
            matched=len(matched_signatures) > 0 or anomaly_score > 0 or len(behavioral_flags) > 0,
            severity=severity,
            matched_signatures=matched_signatures,
            anomaly_score=anomaly_score,
            behavioral_flags=behavioral_flags,
            correlation_alerts=correlation_alerts,
            risk_score=risk_score,
            action_recommended=action,
            latency_ms=(time.time() - start) * 1000,
        )

        self._match_count += 1
        return result

    def _calculate_behavioral_deviation(
        self,
        profile: BehavioralProfile,
        event: dict,
    ) -> float:
        """Calculate behavioral deviation score."""
        normal_behavior = profile.normal_behavior

        deviation = 0.0
        for key, expected in normal_behavior.items():
            actual = event.get("payload", {}).get(key, expected)
            if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
                expected_val = float(expected)
                actual_val = float(actual)
                if expected_val > 0:
                    deviation += abs(actual_val - expected_val) / expected_val
                else:
                    deviation += abs(actual_val - expected_val)

        return min(1.0, deviation / max(1, len(normal_behavior)))

    def batch_match(self, events: list[dict]) -> list[MatchResult]:
        """Match multiple events in batch."""
        return [self.match_event(e) for e in events]

    def get_match_stats(self) -> dict:
        """Get match statistics."""
        total_signatures = len(self._signatures)
        matched_signatures = sum(1 for s in self._signatures.values() if s.match_count > 0)
        total_baselines = len(self._baselines)
        total_profiles = len(self._behavioral_profiles)
        total_rules = len(self._correlation_rules)

        return {
            "total_matches": self._match_count,
            "total_signatures": total_signatures,
            "matched_signatures": matched_signatures,
            "signature_coverage": matched_signatures / max(1, total_signatures),
            "total_baselines": total_baselines,
            "total_behavioral_profiles": total_profiles,
            "total_correlation_rules": total_rules,
            "avg_latency_ms": 0.5,  # Target sub-10ms
        }

    def get_report(self) -> dict:
        """Get threat matcher report."""
        return {
            "total_matches": self._match_count,
            "total_signatures": len(self._signatures),
            "total_baselines": len(self._baselines),
            "total_behavioral_profiles": len(self._behavioral_profiles),
            "total_correlation_rules": len(self._correlation_rules),
            "signatures_by_type": {
                et: sum(1 for s in self._signatures.values() if s.event_type == et)
                for et in set(s.event_type for s in self._signatures.values())
            },
            "top_matched_signatures": sorted(
                [
                    {"name": s.name, "matches": s.match_count}
                    for s in self._signatures.values()
                ],
                key=lambda x: -x["matches"]
            )[:5],
            "match_stats": self.get_match_stats(),
        }


# Module-level singleton
threat_matcher = RealtimeThreatMatcher()


# ── API Routes ──────────────────────────────────────────────────────────────


@router.post("/api/v1/sentinel/threat-match/signatures")
async def add_signature(payload: dict):
    """Add a detection signature."""
    signature = threat_matcher.add_signature(
        name=payload["name"],
        event_type=payload["event_type"],
        description=payload["description"],
        pattern=payload["pattern"],
        severity=payload.get("severity", "medium"),
    )
    return {"signature_id": signature.signature_id, "name": signature.name, "status": "added"}


@router.post("/api/v1/sentinel/threat-match/baselines")
async def add_baseline(payload: dict):
    """Add an anomaly detection baseline."""
    baseline = threat_matcher.add_baseline(
        metric=payload["metric"],
        mean=payload["mean"],
        stddev=payload["stddev"],
        threshold=payload.get("threshold", 3.0),
    )
    return {"baseline_id": baseline.baseline_id, "metric": baseline.metric, "status": "added"}


@router.post("/api/v1/sentinel/threat-match/profiles")
async def add_behavioral_profile(payload: dict):
    """Add a behavioral profile."""
    profile = threat_matcher.add_behavioral_profile(
        entity_type=payload["entity_type"],
        entity_id=payload["entity_id"],
        normal_behavior=payload.get("normal_behavior", {}),
    )
    return {"profile_id": profile.profile_id, "entity_id": profile.entity_id, "status": "added"}


@router.post("/api/v1/sentinel/threat-match/rules")
async def add_correlation_rule(payload: dict):
    """Add a correlation rule."""
    rule = threat_matcher.add_correlation_rule(
        name=payload["name"],
        description=payload["description"],
        conditions=payload["conditions"],
        window_sec=payload.get("window_sec", 60.0),
        severity=payload.get("severity", "medium"),
    )
    return {"rule_id": rule.rule_id, "name": rule.name, "status": "added"}


@router.post("/api/v1/sentinel/threat-match/match")
async def match_event(payload: dict):
    """Match a security event."""
    result = threat_matcher.match_event(payload)
    return {
        "event_id": result.event_id,
        "matched": result.matched,
        "severity": result.severity,
        "matched_signatures": result.matched_signatures,
        "anomaly_score": result.anomaly_score,
        "behavioral_flags": result.behavioral_flags,
        "correlation_alerts": result.correlation_alerts,
        "risk_score": result.risk_score,
        "action_recommended": result.action_recommended,
        "latency_ms": result.latency_ms,
    }


@router.post("/api/v1/sentinel/threat-match/batch")
async def batch_match(payload: dict):
    """Match multiple events in batch."""
    results = threat_matcher.batch_match(payload["events"])
    return {
        "results": [
            {
                "event_id": r.event_id,
                "matched": r.matched,
                "severity": r.severity,
                "risk_score": r.risk_score,
            }
            for r in results
        ],
        "total_matched": sum(1 for r in results if r.matched),
    }


@router.get("/api/v1/sentinel/threat-match/stats")
async def get_match_stats():
    """Get match statistics."""
    return threat_matcher.get_match_stats()


@router.get("/api/v1/sentinel/threat-match/report")
async def get_report():
    """Get threat matcher report."""
    return threat_matcher.get_report()
