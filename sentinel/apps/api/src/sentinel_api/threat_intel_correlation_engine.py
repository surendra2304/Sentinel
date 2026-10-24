"""
Sentinel/sentinel/apps/api/src/sentinel_api/threat_intel_correlation_engine.py — Sentinel Threat Intel Correlation Engine.

Cross-source threat intelligence correlation, IoC deduplication,
attack pattern matching, and intelligence confidence scoring.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class Indicator:
    """An intelligence indicator."""
    indicator_id: str
    value: str
    type: str = "ip"  # ip, domain, hash, email, url, vuln
    source: str = "internal"
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = 0.0


@dataclass
class CorrelationResult:
    """A correlation between indicators."""
    correlation_id: str
    source_indicator: str
    correlated_indicators: list[str] = field(default_factory=list)
    correlation_score: float = 0.0
    attack_pattern: str = ""
    confidence: float = 0.5


@dataclass
class IntelSummary:
    """An intelligence summary."""
    summary_id: str
    total_indicators: int = 0
    unique_indicators: int = 0
    avg_confidence: float = 0.0
    top_threats: list[str] = field(default_factory=list)
    correlations: int = 0
    generated_at: float = field(default_factory=time.time)


class ThreatIntelCorrelationEngine:
    """Engine for cross-source threat intelligence correlation."""

    def __init__(self) -> None:
        self._indicators: dict[str, Indicator] = {}
        self._correlations: list[CorrelationResult] = []
        self._summaries: list[IntelSummary] = []

    def add_indicator(self, value: str, itype: str = "ip", source: str = "internal",
                      confidence: float = 0.5, tags: list[str] | None = None) -> Indicator:
        """Add an intelligence indicator."""
        # Check for duplicates
        existing = next(
            (ind for ind in self._indicators.values() if ind.value == value and ind.type == itype),
            None,
        )
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            existing.last_seen = time.time()
            return existing

        indicator_id = f"ind_{uuid.uuid4().hex[:12]}"
        indicator = Indicator(
            indicator_id=indicator_id, value=value, type=itype,
            source=source, confidence=confidence, tags=tags or [],
        )
        indicator.last_seen = time.time()
        self._indicators[indicator_id] = indicator
        return indicator

    def correlate(self, indicator_id: str) -> CorrelationResult:
        """Correlate an indicator with others."""
        indicator = self._indicators.get(indicator_id)
        if not indicator:
            raise HTTPException(status_code=404, detail="Indicator not found")

        correlation_id = f"corr_{uuid.uuid4().hex[:12]}"
        result = CorrelationResult(
            correlation_id=correlation_id, source_indicator=indicator.value,
        )

        # Find correlated indicators (same tags or similar patterns)
        for other in self._indicators.values():
            if other.indicator_id == indicator_id:
                continue
            # Same tags
            tag_overlap = len(set(indicator.tags) & set(other.tags))
            if tag_overlap > 0:
                result.correlated_indicators.append(other.value)
                result.correlation_score = max(result.correlation_score, 0.3 + tag_overlap * 0.2)
            # Same type with similar values
            if other.type == indicator.type and indicator.value[:2] == other.value[:2]:
                result.correlated_indicators.append(other.value)
                result.correlation_score = max(result.correlation_score, 0.4)

        result.confidence = min(0.9, result.correlation_score)
        result.attack_pattern = "Multi-vector" if len(result.correlated_indicators) > 2 else "Single-vector"

        self._correlations.append(result)
        return result

    def generate_summary(self) -> IntelSummary:
        """Generate an intelligence summary."""
        summary_id = f"sum_{uuid.uuid4().hex[:12]}"
        summary = IntelSummary(summary_id=summary_id)
        summary.total_indicators = len(self._indicators)
        summary.unique_indicators = len(set(i.value for i in self._indicators.values()))
        summary.avg_confidence = sum(i.confidence for i in self._indicators.values()) / max(1, summary.total_indicators)
        summary.top_threats = [
            i.value for i in sorted(self._indicators.values(), key=lambda x: x.confidence, reverse=True)[:5]
        ]
        summary.correlations = len(self._correlations)

        self._summaries.append(summary)
        return summary

    def get_indicators(self, itype: str | None = None) -> list[dict[str, Any]]:
        """Get indicators."""
        indicators = list(self._indicators.values())
        if itype:
            indicators = [i for i in indicators if i.type == itype]
        return [
            {"value": i.value, "type": i.type, "source": i.source,
             "confidence": i.confidence, "tags": i.tags}
            for i in indicators
        ]

    def get_report(self) -> dict[str, Any]:
        """Get engine report."""
        return {
            "total_indicators": len(self._indicators),
            "total_correlations": len(self._correlations),
            "total_summaries": len(self._summaries),
            "engine_status": "operational",
        }


engine = ThreatIntelCorrelationEngine()


@router.post("/sentinel/correlation/indicators")
async def add_indicator(value: str, itype: str = "ip", source: str = "internal",
                        confidence: float = 0.5, tags: list[str] | None = None):
    """Add an intelligence indicator."""
    indicator = engine.add_indicator(value, itype, source, confidence, tags)
    return {"indicator_id": indicator.indicator_id, "value": indicator.value, "confidence": indicator.confidence}


@router.post("/sentinel/correlation/analyze")
async def correlate(indicator_id: str):
    """Correlate an indicator with others."""
    result = engine.correlate(indicator_id)
    return {
        "source": result.source_indicator,
        "correlated_count": len(result.correlated_indicators),
        "correlation_score": result.correlation_score,
        "attack_pattern": result.attack_pattern,
    }


@router.post("/sentinel/correlation/summary")
async def generate_summary():
    """Generate intelligence summary."""
    summary = engine.generate_summary()
    return {
        "summary_id": summary.summary_id,
        "total_indicators": summary.total_indicators,
        "unique_indicators": summary.unique_indicators,
        "avg_confidence": summary.avg_confidence,
        "correlations": summary.correlations,
    }


@router.get("/sentinel/correlation/indicators")
async def get_indicators(itype: str | None = None):
    """Get indicators."""
    return {"indicators": engine.get_indicators(itype)}


@router.get("/sentinel/correlation/report")
async def correlation_report():
    """Get correlation engine report."""
    return engine.get_report()
