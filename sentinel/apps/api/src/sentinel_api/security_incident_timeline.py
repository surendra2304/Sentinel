"""
Sentinel/sentinel/apps/api/src/sentinel_api/security_incident_timeline.py — Sentinel Security Incident Timeline.

Incident timeline reconstruction, attack chain visualization,
causal event correlation, and post-incident analysis.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class TimelineEvent:
    """An event in the incident timeline."""
    event_id: str
    timestamp: float
    event_type: str = "alert"  # alert, indicator, action, observation, detection
    description: str = ""
    severity: str = "medium"
    actor: str = ""
    related_events: list[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """An attack chain in the timeline."""
    chain_id: str
    description: str
    steps: list[str] = field(default_factory=list)
    entry_point: str = ""
    objective: str = ""
    status: str = "active"  # active, blocked, completed


@dataclass
class TimelineAnalysis:
    """Analysis of an incident timeline."""
    analysis_id: str
    incident_id: str
    total_events: int = 0
    attack_chains: list[str] = field(default_factory=list)
    root_cause: str = ""
    time_to_detection: float = 0.0
    time_to_response: float = 0.0
    insights: list[str] = field(default_factory=list)


class SecurityIncidentTimeline:
    """Engine for incident timeline reconstruction."""

    def __init__(self) -> None:
        self._events: dict[str, TimelineEvent] = {}
        self._chains: dict[str, AttackChain] = {}
        self._analyses: list[TimelineAnalysis] = []

    def add_event(self, timestamp: float, event_type: str, description: str,
                  severity: str = "medium", actor: str = "",
                  related: list[str] | None = None) -> TimelineEvent:
        """Add an event to the timeline."""
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        event = TimelineEvent(
            event_id=event_id, timestamp=timestamp, event_type=event_type,
            description=description, severity=severity, actor=actor,
            related_events=related or [],
        )
        self._events[event_id] = event
        return event

    def add_attack_chain(self, description: str, steps: list[str],
                         entry_point: str = "", objective: str = "") -> AttackChain:
        """Add an attack chain."""
        chain_id = f"chain_{uuid.uuid4().hex[:12]}"
        chain = AttackChain(
            chain_id=chain_id, description=description,
            steps=steps, entry_point=entry_point, objective=objective,
        )
        self._chains[chain_id] = chain
        return chain

    def block_chain(self, chain_id: str) -> AttackChain:
        """Block an attack chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            raise HTTPException(status_code=404, detail="Chain not found")
        chain.status = "blocked"
        return chain

    def analyze_timeline(self, incident_id: str) -> TimelineAnalysis:
        """Analyze an incident timeline."""
        analysis_id = f"ana_{uuid.uuid4().hex[:12]}"
        analysis = TimelineAnalysis(analysis_id=analysis_id, incident_id=incident_id)
        analysis.total_events = len(self._events)
        analysis.attack_chains = [c.chain_id for c in self._chains.values()]

        if self._events:
            first_event = min(self._events.values(), key=lambda e: e.timestamp)
            last_event = max(self._events.values(), key=lambda e: e.timestamp)
            analysis.time_to_detection = last_event.timestamp - first_event.timestamp

            # Find root cause (first critical event)
            critical = [e for e in self._events.values() if e.severity == "critical"]
            if critical:
                analysis.root_cause = min(critical, key=lambda e: e.timestamp).description[:80]
            else:
                analysis.root_cause = "No critical event identified"

        analysis.insights = [
            f"Incident lasted {analysis.time_to_detection:.0f} seconds",
            f"Detected {analysis.total_events} events",
            f"Identified {len(analysis.attack_chains)} attack chains",
            f"Root cause: {analysis.root_cause}",
        ]

        self._analyses.append(analysis)
        return analysis

    def get_events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        """Get timeline events."""
        events = list(self._events.values())
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        events.sort(key=lambda e: e.timestamp)
        return [
            {"timestamp": e.timestamp, "type": e.event_type,
             "description": e.description[:80], "severity": e.severity,
             "actor": e.actor}
            for e in events
        ]

    def get_chains(self) -> list[dict[str, Any]]:
        """Get attack chains."""
        return [
            {"description": c.description[:80], "steps": len(c.steps),
             "entry_point": c.entry_point, "status": c.status}
            for c in self._chains.values()
        ]

    def get_report(self) -> dict[str, Any]:
        """Get engine report."""
        return {
            "total_events": len(self._events),
            "total_chains": len(self._chains),
            "total_analyses": len(self._analyses),
            "blocked_chains": sum(1 for c in self._chains.values() if c.status == "blocked"),
            "engine_status": "operational",
        }


engine = SecurityIncidentTimeline()


@router.post("/sentinel/timeline/events")
async def add_event(timestamp: float, event_type: str, description: str,
                    severity: str = "medium", actor: str = "",
                    related: list[str] | None = None):
    """Add an event to the timeline."""
    event = engine.add_event(timestamp, event_type, description, severity, actor, related)
    return {"event_id": event.event_id, "type": event.event_type}


@router.post("/sentinel/timeline/chains")
async def add_attack_chain(description: str, steps: list[str],
                           entry_point: str = "", objective: str = ""):
    """Add an attack chain."""
    chain = engine.add_attack_chain(description, steps, entry_point, objective)
    return {"chain_id": chain.chain_id, "steps": len(chain.steps)}


@router.post("/sentinel/timeline/chains/{chain_id}/block")
async def block_chain(chain_id: str):
    """Block an attack chain."""
    chain = engine.block_chain(chain_id)
    return {"chain_id": chain_id, "status": "blocked"}


@router.post("/sentinel/timeline/analyze")
async def analyze_timeline(incident_id: str):
    """Analyze an incident timeline."""
    analysis = engine.analyze_timeline(incident_id)
    return {
        "analysis_id": analysis.analysis_id,
        "total_events": analysis.total_events,
        "attack_chains": analysis.attack_chains,
        "root_cause": analysis.root_cause,
        "time_to_detection": analysis.time_to_detection,
    }


@router.get("/sentinel/timeline/events")
async def get_events(event_type: str | None = None):
    """Get timeline events."""
    return {"events": engine.get_events(event_type)}


@router.get("/sentinel/timeline/chains")
async def get_chains():
    """Get attack chains."""
    return {"chains": engine.get_chains()}


@router.get("/sentinel/timeline/report")
async def timeline_report():
    """Get incident timeline report."""
    return engine.get_report()
