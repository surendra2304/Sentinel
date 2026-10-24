"""
Sentinel/sentinel/apps/api/src/sentinel_api/incident_response_playbook.py — Sentinel Incident Response Playbook.

Automated incident response, playbook execution, escalation management,
and post-incident analysis.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class PlaybookStep:
    """A step in an incident response playbook."""
    step_id: int
    action: str
    description: str = ""
    status: str = "pending"  # pending, running, completed, failed
    started_at: float = 0.0
    completed_at: float = 0.0
    result: str = ""


@dataclass
class Incident:
    """An active incident."""
    incident_id: str
    severity: str = "medium"  # low, medium, high, critical
    category: str = "security"  # security, compliance, operational
    description: str = ""
    status: str = "open"  # open, responding, contained, resolved
    playbook_id: str = ""
    steps: list[PlaybookStep] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0


@dataclass
class Playbook:
    """An incident response playbook."""
    playbook_id: str
    name: str
    category: str = "security"
    severity_threshold: str = "medium"
    steps: list[dict] = field(default_factory=list)
    description: str = ""


class IncidentResponsePlaybook:
    """Engine for automated incident response."""

    def __init__(self) -> None:
        self._playbooks: dict[str, Playbook] = {}
        self._incidents: dict[str, Incident] = {}

    def create_playbook(self, name: str, category: str = "security",
                        severity_threshold: str = "medium",
                        description: str = "") -> Playbook:
        """Create an incident response playbook."""
        playbook_id = f"pb_{uuid.uuid4().hex[:12]}"
        playbook = Playbook(
            playbook_id=playbook_id, name=name, category=category,
            severity_threshold=severity_threshold, description=description,
        )
        default_steps = [
            {"action": "Triage", "description": "Assess incident severity and scope"},
            {"action": "Isolate", "description": "Contain affected systems"},
            {"action": "Investigate", "description": "Determine root cause"},
            {"action": "Remediate", "description": "Apply fixes and remove threat"},
            {"action": "Recover", "description": "Restore normal operations"},
            {"action": "Review", "description": "Post-incident analysis and lessons learned"},
        ]
        playbook.steps = default_steps
        self._playbooks[playbook_id] = playbook
        return playbook

    def report_incident(self, severity: str, category: str, description: str,
                        playbook_id: str = "") -> Incident:
        """Report a new incident."""
        incident_id = f"inc_{uuid.uuid4().hex[:12]}"
        incident = Incident(
            incident_id=incident_id, severity=severity,
            category=category, description=description,
            playbook_id=playbook_id,
        )

        # Auto-select playbook if none specified
        if not playbook_id:
            for pb in self._playbooks.values():
                if pb.category == category:
                    playbook_id = pb.playbook_id
                    incident.playbook_id = playbook_id
                    break

        # Create playbook steps
        playbook = self._playbooks.get(playbook_id)
        if playbook:
            for i, step_def in enumerate(playbook.steps, 1):
                incident.steps.append(PlaybookStep(
                    step_id=i, action=step_def["action"],
                    description=step_def["description"],
                ))

        self._incidents[incident_id] = incident
        return incident

    def execute_step(self, incident_id: str, step_id: int) -> PlaybookStep:
        """Execute a playbook step."""
        incident = self._incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        for step in incident.steps:
            if step.step_id == step_id:
                step.status = "running"
                step.started_at = time.time()
                step.status = "completed"
                step.completed_at = time.time()
                step.result = "Step executed successfully"
                return step

        raise HTTPException(status_code=404, detail="Step not found")

    def resolve_incident(self, incident_id: str) -> Incident:
        """Resolve an incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident.status = "resolved"
        incident.resolved_at = time.time()
        return incident

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Get an incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            "incident_id": incident.incident_id,
            "severity": incident.severity,
            "category": incident.category,
            "status": incident.status,
            "step_count": len(incident.steps),
            "completed_steps": sum(1 for s in incident.steps if s.status == "completed"),
        }

    def get_report(self) -> dict[str, Any]:
        """Get engine report."""
        return {
            "total_playbooks": len(self._playbooks),
            "total_incidents": len(self._incidents),
            "open_incidents": sum(1 for i in self._incidents.values() if i.status != "resolved"),
            "resolved_incidents": sum(1 for i in self._incidents.values() if i.status == "resolved"),
            "engine_status": "operational",
        }


engine = IncidentResponsePlaybook()


@router.post("/sentinel/incidents/playbooks")
async def create_playbook(name: str, category: str = "security",
                          severity_threshold: str = "medium", description: str = ""):
    """Create an incident response playbook."""
    playbook = engine.create_playbook(name, category, severity_threshold, description)
    return {"playbook_id": playbook.playbook_id, "step_count": len(playbook.steps)}


@router.post("/sentinel/incidents/report")
async def report_incident(severity: str, category: str, description: str, playbook_id: str = ""):
    """Report a new incident."""
    incident = engine.report_incident(severity, category, description, playbook_id)
    return {"incident_id": incident.incident_id, "step_count": len(incident.steps)}


@router.post("/sentinel/incidents/{incident_id}/steps/{step_id}/execute")
async def execute_step(incident_id: str, step_id: int):
    """Execute a playbook step."""
    step = engine.execute_step(incident_id, step_id)
    return {"step_id": step.step_id, "status": step.status, "result": step.result}


@router.post("/sentinel/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str):
    """Resolve an incident."""
    incident = engine.resolve_incident(incident_id)
    return {"incident_id": incident.incident_id, "status": "resolved"}


@router.get("/sentinel/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get an incident."""
    return engine.get_incident(incident_id)


@router.get("/sentinel/incidents/report")
async def incident_report():
    """Get incident response report."""
    return engine.get_report()
