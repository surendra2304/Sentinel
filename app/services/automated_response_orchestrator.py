"""
Sentinel/app/services/automated_response_orchestrator.py — Sentinel Automated Response Orchestrator.

Orchestrates automated security responses: SOAR playbook execution, incident
response automation, containment actions, evidence collection, and response
coordination across tools and teams.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class Playbook:
    """A SOAR playbook."""
    playbook_id: str
    name: str
    description: str = ""
    trigger: str = ""  # alert_type, threshold, event
    conditions: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    enabled: bool = True
    created_at: float = 0.0


@dataclass
class ResponseAction:
    """A response action executed."""
    action_id: str
    playbook_id: str
    incident_id: str
    action_type: str = ""  # block, contain, isolate, notify, gather_evidence, escalate
    target: str = ""
    status: str = "pending"  # pending, executing, completed, failed
    result: str = ""
    executed_at: float = 0.0
    duration_ms: float = 0.0


@dataclass
class IncidentResponse:
    """An incident response plan."""
    response_id: str
    incident_id: str
    status: str = "initiated"  # initiated, containing, investigating, resolving, closed
    severity: str = "medium"
    assigned_team: str = ""
    playbooks_triggered: list[str] = field(default_factory=list)
    actions_executed: int = 0
    containment_achieved: bool = False
    started_at: float = 0.0
    resolved_at: float = 0.0


@dataclass
class ContainmentStep:
    """A containment step."""
    step_id: str
    response_id: str
    description: str = ""
    target: str = ""
    status: str = "pending"
    verified: bool = False
    completed_at: float = 0.0


@dataclass
class EvidenceBundle:
    """An evidence bundle collected during response."""
    bundle_id: str
    incident_id: str
    items: list[str] = field(default_factory=list)
    chain_of_custody: list[dict] = field(default_factory=list)
    collected_at: float = 0.0
    sealed: bool = False


@dataclass
class ResponseMetrics:
    """Response effectiveness metrics."""
    total_incidents: int = 0
    avg_time_to_containment_min: float = 0.0
    avg_time_to_resolution_min: float = 0.0
    containment_success_rate: float = 0.0
    playbook_success_rate: float = 0.0
    automation_coverage: float = 0.0


@dataclass
class ResponseReport:
    """Comprehensive response report."""
    report_id: str
    total_responses: int = 0
    contained_incidents: int = 0
    uncontained_incidents: int = 0
    avg_containment_time_min: float = 0.0
    avg_resolution_time_min: float = 0.0
    automation_rate: float = 0.0
    critical_incidents: int = 0


class AutomatedResponseOrchestrator:
    """Automated response orchestration engine."""

    def __init__(self):
        self._playbooks: dict[str, Playbook] = {}
        self._actions: list[ResponseAction] = []
        self._responses: dict[str, IncidentResponse] = {}
        self._containment: list[ContainmentStep] = []
        self._evidence: list[EvidenceBundle] = []
        self._metrics: ResponseMetrics = ResponseMetrics()
        self._reports: list[ResponseReport] = []

        # Create default playbooks
        self._create_default_playbooks()

    def _create_default_playbooks(self):
        """Create default SOAR playbooks."""
        playbooks = [
            ("Block Malicious IP", "alert:ip_reputation", ["is_malicious"], ["block_ip", "notify_team"]),
            ("Isolate Compromised Host", "alert:endpoint_compromise", ["compromise_confirmed"], ["isolate_host", "gather_evidence", "notify_team"]),
            ("Quarantine Phishing Email", "alert:phishing", ["email_flagged"], ["quarantine_email", "block_sender", "notify_user"]),
            ("Block Malicious Domain", "alert:domain_reputation", ["is_malicious"], ["block_domain", "notify_team"]),
        ]

        for name, trigger, conditions, actions in playbooks:
            self.create_playbook(name, trigger, conditions, actions)

    def create_playbook(
        self,
        name: str,
        trigger: str,
        conditions: list[str],
        actions: list[str],
    ) -> Playbook:
        """Create a SOAR playbook."""
        playbook = Playbook(
            playbook_id=hashlib.md5(
                f"playbook:{name}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            trigger=trigger,
            conditions=conditions,
            actions=actions,
            created_at=time.time(),
        )
        self._playbooks[playbook.playbook_id] = playbook
        return playbook

    def trigger_response(self, incident_id: str, severity: str, alert_type: str) -> IncidentResponse:
        """Trigger automated response to an incident."""
        response = IncidentResponse(
            response_id=hashlib.md5(
                f"response:{incident_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            incident_id=incident_id,
            status="initiated",
            severity=severity,
            started_at=time.time(),
        )

        self._responses[response.response_id] = response

        # Find matching playbooks
        for playbook in self._playbooks.values():
            if not playbook.enabled:
                continue
            if playbook.trigger == f"alert:{alert_type}" or playbook.trigger == alert_type:
                response.playbooks_triggered.append(playbook.playbook_id)

                # Execute actions
                for action_desc in playbook.actions:
                    action = ResponseAction(
                        action_id=hashlib.md5(
                            f"action:{playbook.playbook_id}:{incident_id}:{time.time()}".encode()
                        ).hexdigest()[:12],
                        playbook_id=playbook.playbook_id,
                        incident_id=incident_id,
                        action_type=action_desc,
                        status="executing",
                        executed_at=time.time(),
                    )

                    # Simulate action execution
                    action.status = "completed"
                    action.result = f"Successfully executed: {action_desc}"
                    action.duration_ms = 100.0 + (ord(hashlib.md5(action_desc.encode()).hexdigest()[:1]) % 500)

                    self._actions.append(action)
                    response.actions_executed += 1

        # Update metrics
        self._metrics.total_incidents += 1

        return response

    def add_containment_step(self, response_id: str, description: str, target: str = "") -> ContainmentStep:
        """Add a containment step."""
        step = ContainmentStep(
            step_id=hashlib.md5(
                f"step:{response_id}:{description[:30]}:{time.time()}".encode()
            ).hexdigest()[:12],
            response_id=response_id,
            description=description,
            target=target,
        )
        self._containment.append(step)
        return step

    def verify_containment(self, step_id: str) -> ContainmentStep:
        """Verify a containment step."""
        step = None
        for s in self._containment:
            if s.step_id == step_id:
                step = s
                break

        if not step:
            raise HTTPException(404, f"Step {step_id} not found")

        step.status = "completed"
        step.verified = True
        step.completed_at = time.time()

        # Update response
        response = self._responses.get(step.response_id)
        if response:
            all_verified = all(s.verified for s in self._containment if s.response_id == response.response_id)
            if all_verified:
                response.containment_achieved = True
                response.status = "resolving"

        return step

    def collect_evidence(self, incident_id: str, items: list[str]) -> EvidenceBundle:
        """Collect evidence bundle."""
        bundle = EvidenceBundle(
            bundle_id=hashlib.md5(
                f"evidence:{incident_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            incident_id=incident_id,
            items=items,
            collected_at=time.time(),
        )

        # Add chain of custody
        for item in items:
            bundle.chain_of_custody.append({
                "item": item,
                "collected_by": "automated",
                "timestamp": time.time(),
                "hash": hashlib.sha256(item.encode()).hexdigest()[:32],
            })

        self._evidence.append(bundle)
        return bundle

    def resolve_response(self, response_id: str) -> IncidentResponse:
        """Resolve an incident response."""
        response = self._responses.get(response_id)
        if not response:
            raise HTTPException(404, f"Response {response_id} not found")

        response.status = "closed"
        response.resolved_at = time.time()

        # Update metrics
        containment_time = (response.resolved_at - response.started_at) / 60
        self._metrics.avg_time_to_resolution_min = (
            self._metrics.avg_time_to_resolution_min * 0.9 + containment_time * 0.1
        )

        if response.containment_achieved:
            self._metrics.avg_time_to_containment_min = (
                self._metrics.avg_time_to_containment_min * 0.9 + containment_time * 0.1
            )
            self._metrics.containment_success_rate = (
                self._metrics.containment_success_rate * 0.9 + 1 * 0.1
            )

        return response

    def generate_report(self) -> ResponseReport:
        """Generate response report."""
        responses = list(self._responses.values())

        report = ResponseReport(
            report_id=hashlib.md5(
                f"report:{time.time()}".encode()
            ).hexdigest()[:12],
            total_responses=len(responses),
            contained_incidents=sum(1 for r in responses if r.containment_achieved),
            uncontained_incidents=sum(1 for r in responses if not r.containment_achieved),
            avg_containment_time_min=self._metrics.avg_time_to_containment_min,
            avg_resolution_time_min=self._metrics.avg_time_to_resolution_min,
            critical_incidents=sum(1 for r in responses if r.severity == "critical"),
        )

        report.automation_rate = (
            sum(len(r.playbooks_triggered) for r in responses) / max(1, len(responses))
        )

        self._reports.append(report)
        return report

    def get_report(self) -> dict:
        """Get response orchestrator report."""
        return {
            "total_playbooks": len(self._playbooks),
            "active_playbooks": sum(1 for p in self._playbooks.values() if p.enabled),
            "total_responses": len(self._responses),
            "total_actions": len(self._actions),
            "total_containment_steps": len(self._containment),
            "total_evidence_bundles": len(self._evidence),
            "total_reports": len(self._reports),
            "avg_time_to_containment_min": round(self._metrics.avg_time_to_containment_min, 1),
            "avg_time_to_resolution_min": round(self._metrics.avg_time_to_resolution_min, 1),
            "containment_success_rate": round(self._metrics.containment_success_rate, 3),
            "playbooks": [
                {"name": p.name, "trigger": p.trigger, "actions": len(p.actions), "enabled": p.enabled}
                for p in self._playbooks.values()
            ],
            "recent_responses": [
                {"incident": r.incident_id, "severity": r.severity, "status": r.status, "actions": r.actions_executed}
                for r in list(self._responses.values())[-10:]
            ],
            "recent_actions": [
                {"incident": a.incident_id, "action": a.action_type, "status": a.status, "duration_ms": a.duration_ms}
                for a in self._actions[-10:]
            ],
            "recent_reports": [
                {
                    "responses": r.total_responses,
                    "contained": r.contained_incidents,
                    "uncontained": r.uncontained_incidents,
                    "automation_rate": r.automation_rate,
                }
                for r in self._reports[-5:]
            ],
        }


response_orchestrator = AutomatedResponseOrchestrator()


@router.post("/api/v1/sentinel/response/playbooks")
async def create_playbook(payload: dict):
    """Create a SOAR playbook."""
    playbook = response_orchestrator.create_playbook(
        name=payload["name"],
        trigger=payload["trigger"],
        conditions=payload.get("conditions", []),
        actions=payload.get("actions", []),
    )
    return {"playbook_id": playbook.playbook_id, "name": playbook.name, "trigger": playbook.trigger}


@router.post("/api/v1/sentinel/response/trigger")
async def trigger_response(payload: dict):
    """Trigger automated response."""
    response = response_orchestrator.trigger_response(
        incident_id=payload["incident_id"],
        severity=payload["severity"],
        alert_type=payload["alert_type"],
    )
    return {
        "response_id": response.response_id,
        "incident_id": response.incident_id,
        "playbooks_triggered": len(response.playbooks_triggered),
        "actions_executed": response.actions_executed,
        "status": response.status,
    }


@router.post("/api/v1/sentinel/response/containment")
async def add_containment_step(payload: dict):
    """Add a containment step."""
    step = response_orchestrator.add_containment_step(
        response_id=payload["response_id"],
        description=payload["description"],
        target=payload.get("target", ""),
    )
    return {"step_id": step.step_id, "description": step.description, "status": step.status}


@router.post("/api/v1/sentinel/response/containment/{step_id}/verify")
async def verify_containment(step_id: str):
    """Verify a containment step."""
    step = response_orchestrator.verify_containment(step_id)
    return {"step_id": step.step_id, "verified": step.verified, "status": step.status}


@router.post("/api/v1/sentinel/response/evidence")
async def collect_evidence(payload: dict):
    """Collect evidence bundle."""
    bundle = response_orchestrator.collect_evidence(
        incident_id=payload["incident_id"],
        items=payload.get("items", []),
    )
    return {"bundle_id": bundle.bundle_id, "items": len(bundle.items), "sealed": bundle.sealed}


@router.post("/api/v1/sentinel/response/{response_id}/resolve")
async def resolve_response(response_id: str):
    """Resolve an incident response."""
    response = response_orchestrator.resolve_response(response_id)
    return {"response_id": response.response_id, "status": response.status, "resolved": response.resolved_at}


@router.get("/api/v1/sentinel/response/report")
async def get_report():
    """Get response orchestrator report."""
    return response_orchestrator.get_report()
