"""Incident Response & Quarantine REST API Routes."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel.core.gateway.models import RiskLevel
from sentinel.core.incident.incident_manager import Incident, IncidentManager
from sentinel.core.incident.quarantine_manager import (
    QuarantineCategory,
    QuarantineManager,
)

incident_router = APIRouter(tags=["Incident & Quarantine Management"])

# Global singletons
_quarantine_mgr = QuarantineManager()
_incident_mgr = IncidentManager(quarantine_manager=_quarantine_mgr)


class CreateIncidentRequest(BaseModel):
    id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    severity: str = "HIGH"
    reason: str = Field(..., min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)


class TriageIncidentRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1)
    notes: str = ""


class ContainIncidentRequest(BaseModel):
    auto_quarantine_subject: str | None = None
    quarantine_ttl_seconds: float = 3600.0


class CloseIncidentRequest(BaseModel):
    resolution_notes: str = ""


class EnforceQuarantineRequest(BaseModel):
    subject: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    ttl_seconds: float = 900.0
    category: str = "ip"
    initiator: str = "sentinel-api"
    incident_id: str | None = None


def _serialize_incident(inc: Incident) -> dict[str, Any]:
    return {
        "id": inc.id,
        "tenant_id": inc.tenant_id,
        "title": inc.title,
        "severity": inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
        "reason": inc.reason,
        "state": inc.state.value if hasattr(inc.state, "value") else str(inc.state),
        "contained": inc.contained,
        "created_at": inc.created_at,
        "contained_at": inc.contained_at,
        "closed_at": inc.closed_at,
        "assigned_to": inc.assigned_to,
        "sla_seconds": inc.sla_seconds,
        "is_sla_breached": inc.is_sla_breached,
        "time_to_contain": inc.time_to_contain,
        "containment_actions_taken": inc.containment_actions_taken,
        "evidence_refs": inc.evidence_refs,
        "attack_techniques": inc.metadata.get("attack_techniques", []),
        "attack_tactics": inc.metadata.get("attack_tactics", []),
        "playbook_steps": inc.metadata.get("playbook_steps", []),
        "metadata": inc.metadata,
    }


@incident_router.post("/v1/incidents")
@incident_router.post("/api/v1/incidents")
@incident_router.post("/api/v1/sentinel/incidents")
async def open_incident(req: CreateIncidentRequest) -> dict[str, Any]:
    """Open a new security incident with automated ATT&CK triage and playbook attachment."""
    try:
        sev = RiskLevel(req.severity.upper())
    except ValueError:
        sev = RiskLevel.HIGH

    inc = Incident(
        id=req.id,
        tenant_id=req.tenant_id,
        title=req.title,
        severity=sev,
        reason=req.reason,
        evidence_refs=req.evidence_refs,
    )

    # Auto-triage: map to ATT&CK techniques, tactics and generate playbook
    try:
        from app.services.cyber_skills_service import get_service
        service = get_service()
        triage_res = service.triage(
            req.title,
            [{
                "timestamp": str(inc.created_at),
                "description": f"{req.title}: {req.reason}",
                "technique": "",
                "host": "",
                "source": "incident_creation",
            }],
        )
        techs = triage_res.get("techniques", [])
        if not techs:
            techs = ["T1059", "T1078"]
        playbook_res = service.playbook(req.title, techs)
        steps = []
        for phase in playbook_res.get("phases", []):
            for s in phase.get("steps", []):
                steps.append(s)
        if not steps:
            steps = [{"phase": "containment", "action": "isolate host", "requires_approval": True}]

        inc.metadata["attack_techniques"] = techs
        inc.metadata["attack_tactics"] = triage_res.get("tactics", [])
        inc.metadata["playbook_steps"] = steps
        inc.metadata["triage_summary"] = triage_res
    except Exception:
        inc.metadata["attack_techniques"] = ["T1059", "T1078"]
        inc.metadata["playbook_steps"] = [{"phase": "containment", "action": "isolate host", "requires_approval": True}]

    opened = _incident_mgr.open(inc)
    return {"incident": _serialize_incident(opened)}


@incident_router.get("/v1/incidents")
@incident_router.get("/api/v1/incidents")
@incident_router.get("/api/v1/sentinel/incidents")
async def list_incidents(tenant_id: str | None = None, active_only: bool = True) -> dict[str, Any]:
    """List recorded security incidents."""
    if active_only and tenant_id:
        incidents = _incident_mgr.active(tenant_id)
    elif tenant_id:
        incidents = [i for i in _incident_mgr.incidents.values() if i.tenant_id == tenant_id]
    else:
        incidents = list(_incident_mgr.incidents.values())
        if active_only:
            incidents = [i for i in incidents if not i.contained]

    return {
        "count": len(incidents),
        "incidents": [_serialize_incident(i) for i in incidents],
    }


@incident_router.post("/v1/incidents/{incident_id}/triage")
@incident_router.post("/api/v1/incidents/{incident_id}/triage")
async def triage_incident(incident_id: str, req: TriageIncidentRequest) -> dict[str, Any]:
    """Assign incident and move to TRIAGED state."""
    inc = _incident_mgr.triage(incident_id, assigned_to=req.assigned_to, notes=req.notes)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    payload: dict[str, Any] = {"incident": _serialize_incident(inc)}
    # Security-skills crosswalk: severity, ATT&CK techniques/tactics and the
    # response skills that apply. Best-effort so triage never fails on it.
    try:
        from app.services.cyber_skills_service import get_service

        payload["crosswalk"] = get_service().triage(
            inc.title,
            [{
                "timestamp": str(getattr(inc, "opened_at", "") or ""),
                "description": f"{inc.title}: {inc.reason}",
                "technique": "",
                "host": "",
                "source": "incident",
            }],
        )
    except Exception as exc:  # pragma: no cover - optional enrichment
        payload["crosswalk"] = {"error": f"{type(exc).__name__}: {exc}"}
    return payload


@incident_router.post("/v1/incidents/{incident_id}/contain")
@incident_router.post("/api/v1/incidents/{incident_id}/contain")
async def contain_incident(incident_id: str, req: ContainIncidentRequest) -> dict[str, Any]:
    """Mark incident contained and optionally enforce automated subject quarantine."""
    inc = _incident_mgr.incidents.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    _incident_mgr.contain(
        incident_id=incident_id,
        auto_quarantine_subject=req.auto_quarantine_subject,
        quarantine_ttl=req.quarantine_ttl_seconds,
    )
    return {"incident": _serialize_incident(inc)}


@incident_router.post("/v1/incidents/{incident_id}/close")
@incident_router.post("/api/v1/incidents/{incident_id}/close")
async def close_incident(incident_id: str, req: CloseIncidentRequest) -> dict[str, Any]:
    """Mark incident closed and record resolution notes."""
    inc = _incident_mgr.close(incident_id, resolution_notes=req.resolution_notes)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {"incident": _serialize_incident(inc)}


@incident_router.get("/v1/incidents/metrics/mttc")
@incident_router.get("/api/v1/incidents/metrics/mttc")
async def get_incident_metrics(tenant_id: str | None = None) -> dict[str, Any]:
    """Retrieve Mean-Time-To-Contain (MTTC) and SLA breach metrics."""
    return {"metrics": _incident_mgr.get_mttr_metrics(tenant_id)}


@incident_router.get("/v1/quarantine")
@incident_router.get("/api/v1/quarantine")
async def list_quarantine(category: str | None = None) -> dict[str, Any]:
    """List active quarantined entities."""
    cat_enum: QuarantineCategory | None = None
    if category:
        with suppress(ValueError):
            cat_enum = QuarantineCategory(category.lower())

    items = _quarantine_mgr.list_active(category=cat_enum)
    return {"count": len(items), "quarantined_items": items}


@incident_router.post("/v1/quarantine")
@incident_router.post("/api/v1/quarantine")
async def enforce_quarantine(req: EnforceQuarantineRequest) -> dict[str, Any]:
    """Place a subject in quarantine."""
    try:
        cat = QuarantineCategory(req.category.lower())
    except ValueError:
        cat = QuarantineCategory.IP

    rec = _quarantine_mgr.put(
        subject=req.subject,
        reason=req.reason,
        ttl=req.ttl_seconds,
        category=cat,
        initiator=req.initiator,
        incident_id=req.incident_id,
    )
    return {
        "subject": rec.subject,
        "category": rec.category.value,
        "expires_at": rec.expires_at,
        "remaining_seconds": rec.remaining_seconds,
    }


@incident_router.delete("/v1/quarantine/{subject}")
@incident_router.delete("/api/v1/quarantine/{subject}")
async def lift_quarantine(subject: str) -> dict[str, Any]:
    """Lift quarantine for an active subject."""
    lifted = _quarantine_mgr.lift(subject)
    if not lifted:
        raise HTTPException(status_code=404, detail=f"Subject '{subject}' is not in quarantine.")
    return {"subject": subject, "lifted": True}
