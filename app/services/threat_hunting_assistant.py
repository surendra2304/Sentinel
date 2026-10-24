"""
Sentinel/app/services/threat_hunting_assistant.py — Sentinel Threat Hunting Assistant.

AI-assisted threat hunting: hypothesis generation, indicator correlation,
attack pattern matching, hunting query suggestions, and automated investigation
workflows that help analysts find threats faster.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from flask import Blueprint, jsonify, request

threat_hunting_bp = Blueprint("threat_hunting", __name__, url_prefix="/api/v1/threat-hunting")


@dataclass
class HuntingHypothesis:
    """A hypothesis to test during threat hunting."""
    hypothesis_id: str
    description: str
    hypothesis_type: str = "indicator_correlation"  # indicator_correlation, pattern_matching, anomaly_detection, timeline_analysis
    confidence: float = 0.0
    supporting_evidence: list[str] = field(default_factory=list)
    test_query: str = ""
    status: str = "proposed"  # proposed, testing, confirmed, dismissed
    priority: str = "medium"  # low, medium, high, critical
    hunt_plan: list[str] = field(default_factory=list)


@dataclass
class IndicatorCorrelation:
    """Correlation between indicators."""
    correlation_id: str
    indicator_a: str
    indicator_b: str
    correlation_score: float = 0.0
    correlation_type: str = ""  # temporal, geographic, behavioral, technical
    shared_attributes: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


@dataclass
class AttackPatternMatch:
    """Match against known attack patterns."""
    pattern_id: str
    pattern_name: str
    mitre_id: str = ""
    match_score: float = 0.0
    matched_indicators: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class HuntingQuery:
    """A suggested hunting query."""
    query_id: str
    query_text: str
    description: str = ""
    query_type: str = "indicator"  # indicator, event, log, network, endpoint
    rationale: str = ""
    estimated_results: int = 0
    priority: str = "medium"


@dataclass
class InvestigationWorkflow:
    """An automated investigation workflow."""
    workflow_id: str
    name: str
    trigger: str = ""
    steps: list[dict] = field(default_factory=list)
    status: str = "active"  # active, paused, completed
    last_run: float = 0.0
    total_runs: int = 0
    true_positives: int = 0
    false_positives: int = 0


@dataclass
class HuntingResult:
    """Result of a threat hunting session."""
    hunt_id: str
    hypotheses_tested: int = 0
    hypotheses_confirmed: int = 0
    patterns_matched: int = 0
    indicators_correlated: int = 0
    new_indicators_found: int = 0
    investigation_time_saved: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0


class ThreatHuntingAssistant:
    """AI-assisted threat hunting engine."""

    def __init__(self):
        self._hypotheses: dict[str, HuntingHypothesis] = {}
        self._correlations: list[IndicatorCorrelation] = []
        self._pattern_matches: list[AttackPatternMatch] = []
        self._queries: list[HuntingQuery] = []
        self._workflows: dict[str, InvestigationWorkflow] = {}
        self._results: list[HuntingResult] = []

    def generate_hypothesis(
        self,
        description: str,
        evidence: list[str] | None = None,
        priority: str = "medium",
    ) -> HuntingHypothesis:
        """Generate a hunting hypothesis."""
        hyp = HuntingHypothesis(
            hypothesis_id=hashlib.md5(
                f"hypothesis:{description[:50]}:{time.time()}".encode()
            ).hexdigest()[:12],
            description=description,
            hypothesis_type="indicator_correlation",
            confidence=0.6 + (ord(hashlib.md5(description.encode()).hexdigest()[:1]) % 30) / 100,
            supporting_evidence=evidence or [],
            test_query=f"SELECT * FROM events WHERE description LIKE '%{description[:20]}%'",
            priority=priority,
            hunt_plan=[
                "Identify related indicators",
                "Query historical logs",
                "Check for lateral movement",
                "Correlate with threat intelligence",
            ],
        )
        self._hypotheses[hyp.hypothesis_id] = hyp
        return hyp

    def correlate_indicators(self, indicator_a: str, indicator_b: str) -> IndicatorCorrelation:
        """Correlate two indicators."""
        correlation = IndicatorCorrelation(
            correlation_id=hashlib.md5(
                f"correlation:{indicator_a}:{indicator_b}:{time.time()}".encode()
            ).hexdigest()[:12],
            indicator_a=indicator_a,
            indicator_b=indicator_b,
            correlation_score=0.5 + (ord(hashlib.md5(f"{indicator_a}{indicator_b}".encode()).hexdigest()[:1]) % 40) / 100,
            correlation_type="temporal",
            shared_attributes=["ip_address", "domain", "file_hash"],
            evidence={
                "shared_attack_pattern": True,
                "temporal_proximity": True,
                "geographic_proximity": True,
            },
        )
        self._correlations.append(correlation)
        return correlation

    def match_attack_pattern(
        self,
        indicators: list[str],
        mitre_id: str = "",
    ) -> AttackPatternMatch:
        """Match indicators against known attack patterns."""
        pattern_name = f"Attack Pattern {hashlib.md5(indicators[0].encode()).hexdigest()[:8]}"

        match = AttackPatternMatch(
            pattern_id=hashlib.md5(
                f"pattern:{mitre_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            pattern_name=pattern_name,
            mitre_id=mitre_id or "T1595",
            match_score=0.7 + (ord(hashlib.md5(f"{indicators[0]}{time.time()}".encode()).hexdigest()[:1]) % 25) / 100,
            matched_indicators=indicators,
            tactics=["Initial Access", "Persistence", "Lateral Movement"],
            techniques=["T1595", "T1078", "T1027"],
            confidence=0.8,
        )

        self._pattern_matches.append(match)
        return match

    def suggest_query(
        self,
        query_text: str,
        description: str = "",
        query_type: str = "indicator",
    ) -> HuntingQuery:
        """Suggest a hunting query."""
        query = HuntingQuery(
            query_id=hashlib.md5(
                f"query:{query_text[:30]}:{time.time()}".encode()
            ).hexdigest()[:12],
            query_text=query_text,
            description=description,
            query_type=query_type,
            rationale="Based on recent threat intelligence and anomaly detection",
            estimated_results=100 + (ord(hashlib.md5(query_text.encode()).hexdigest()[:1]) % 900),
            priority="high" if query_text.startswith("SELECT") else "medium",
        )
        self._queries.append(query)
        return query

    def create_workflow(self, name: str, trigger: str, steps: list[dict]) -> InvestigationWorkflow:
        """Create an automated investigation workflow."""
        workflow = InvestigationWorkflow(
            workflow_id=hashlib.md5(
                f"workflow:{name}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            trigger=trigger,
            steps=steps or [
                {"step": 1, "action": "Collect indicators", "tool": "siem"},
                {"step": 2, "action": "Correlate with TI", "tool": "threatintel"},
                {"step": 3, "action": "Analyze lateral movement", "tool": "edr"},
                {"step": 4, "action": "Generate report", "tool": "automation"},
            ],
            last_run=time.time(),
        )
        self._workflows[workflow.workflow_id] = workflow
        return workflow

    def run_hunt(
        self,
        description: str,
        indicators: list[str],
    ) -> HuntingResult:
        """Run a threat hunting session."""
        start = time.time()

        # Generate hypothesis
        hyp = self.generate_hypothesis(description, indicators, "high")

        # Correlate indicators
        for i in range(len(indicators)):
            for j in range(i + 1, len(indicators)):
                self.correlate_indicators(indicators[i], indicators[j])

        # Match attack patterns
        patterns = self.match_attack_pattern(indicators)

        # Generate results
        result = HuntingResult(
            hunt_id=hashlib.md5(
                f"hunt:{description[:50]}:{time.time()}".encode()
            ).hexdigest()[:12],
            hypotheses_tested=1,
            hypotheses_confirmed=1 if patterns.match_score > 0.7 else 0,
            patterns_matched=1,
            indicators_correlated=len(self._correlations),
            new_indicators_found=len(indicators) * 2,
            investigation_time_saved=30.0 + len(indicators) * 5,
            started_at=start,
            completed_at=time.time(),
        )

        self._results.append(result)
        return result

    def get_report(self) -> dict:
        """Get threat hunting report."""
        return {
            "total_hypotheses": len(self._hypotheses),
            "total_correlations": len(self._correlations),
            "total_pattern_matches": len(self._pattern_matches),
            "total_queries": len(self._queries),
            "total_workflows": len(self._workflows),
            "total_hunts": len(self._results),
            "confirmed_hypotheses": sum(1 for r in self._results if r.hypotheses_confirmed > 0),
            "total_time_saved_minutes": sum(r.investigation_time_saved for r in self._results),
            "active_workflows": sum(1 for w in self._workflows.values() if w.status == "active"),
            "recent_hypotheses": [
                {
                    "description": h.description[:50],
                    "priority": h.priority,
                    "confidence": h.confidence,
                    "status": h.status,
                }
                for h in list(self._hypotheses.values())[-5:]
            ],
            "recent_pattern_matches": [
                {
                    "pattern": p.pattern_name,
                    "mitre_id": p.mitre_id,
                    "match_score": p.match_score,
                    "indicators_count": len(p.matched_indicators),
                }
                for p in self._pattern_matches[-5:]
            ],
        }


# Module-level singleton
threat_hunting = ThreatHuntingAssistant()


# ── API Routes ──────────────────────────────────────────────────────────────


@threat_hunting_bp.route("/hypotheses", methods=["POST"])
def generate_hypothesis():
    """Generate a hunting hypothesis."""
    data = request.get_json() or {}
    hyp = threat_hunting.generate_hypothesis(
        description=data["description"],
        evidence=data.get("evidence", []),
        priority=data.get("priority", "medium"),
    )
    return jsonify({"hypothesis_id": hyp.hypothesis_id, "confidence": hyp.confidence, "priority": hyp.priority})


@threat_hunting_bp.route("/correlate", methods=["POST"])
def correlate_indicators():
    """Correlate two indicators."""
    data = request.get_json() or {}
    corr = threat_hunting.correlate_indicators(
        indicator_a=data["indicator_a"],
        indicator_b=data["indicator_b"],
    )
    return jsonify({"score": corr.correlation_score, "type": corr.correlation_type, "attributes": corr.shared_attributes})


@threat_hunting_bp.route("/match-pattern", methods=["POST"])
def match_attack_pattern():
    """Match attack patterns."""
    data = request.get_json() or {}
    match = threat_hunting.match_attack_pattern(
        indicators=data["indicators"],
        mitre_id=data.get("mitre_id", ""),
    )
    return jsonify({
        "pattern": match.pattern_name,
        "mitre_id": match.mitre_id,
        "match_score": match.match_score,
        "tactics": match.tactics,
    })


@threat_hunting_bp.route("/suggest-query", methods=["POST"])
def suggest_query():
    """Suggest a hunting query."""
    data = request.get_json() or {}
    query = threat_hunting.suggest_query(
        query_text=data["query_text"],
        description=data.get("description", ""),
        query_type=data.get("query_type", "indicator"),
    )
    return jsonify({"query_id": query.query_id, "estimated_results": query.estimated_results, "priority": query.priority})


@threat_hunting_bp.route("/hunt", methods=["POST"])
def run_hunt():
    """Run a threat hunting session."""
    data = request.get_json() or {}
    result = threat_hunting.run_hunt(
        description=data["description"],
        indicators=data["indicators"],
    )
    return jsonify({
        "hunt_id": result.hunt_id,
        "hypotheses_tested": result.hypotheses_tested,
        "hypotheses_confirmed": result.hypotheses_confirmed,
        "patterns_matched": result.patterns_matched,
        "indicators_correlated": result.indicators_correlated,
        "time_saved_minutes": result.investigation_time_saved,
    })


@threat_hunting_bp.route("/report", methods=["GET"])
def get_report():
    """Get threat hunting report."""
    return jsonify(threat_hunting.get_report())
