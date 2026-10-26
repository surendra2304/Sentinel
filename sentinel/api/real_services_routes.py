"""
Sentinel — Real Services API Routes (Full)

Wires real_security_engine, real_advanced_security, real_cyber_skills,
and real_deep_security into the Sentinel API.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

real_services_router = APIRouter(tags=["Real Security Services"], prefix="/api/v1/real-services")


def _import_mods():
    mods: dict[str, Any] = {}
    try:
        from app.services.real_security_engine import (
            Threat, Vulnerability, SecurityPosture, Incident, SecurityEngine,
        )
        mods["security_engine"] = {
            "threat": Threat, "vulnerability": Vulnerability,
            "posture": SecurityPosture, "incident": Incident, "engine": SecurityEngine,
        }
    except Exception:
        pass
    try:
        from app.services.real_advanced_security import (
            SIEMIntegrationBridge, BehavioralAnomalyDetector,
        )
        mods["advanced_security"] = {
            "siem": SIEMIntegrationBridge, "behavior": BehavioralAnomalyDetector,
        }
    except Exception:
        pass
    try:
        from app.services.real_cyber_skills import (
            FrameworkMapping, SecuritySkill,
        )
        mods["cyber_skills"] = {
            "framework": FrameworkMapping, "skill": SecuritySkill,
        }
    except Exception:
        pass
    try:
        from app.services.real_deep_security import (
            VulnerabilityManagementSystem, ComplianceAuditTrail,
            IncidentResponsePlaybook,
        )
        mods["deep_security"] = {
            "vuln_mgmt": VulnerabilityManagementSystem, "compliance": ComplianceAuditTrail,
            "playbook": IncidentResponsePlaybook,
        }
    except Exception:
        pass
    return mods


_MODS: dict[str, Any] = {}


def get_mods():
    if not _MODS:
        _MODS.update(_import_mods())
    return _MODS


@real_services_router.get("/status")
def services_status():
    mods = get_mods()
    return {
        "status": "ok",
        "services": [
            {"name": name, "classes": sorted(m.keys()), "loaded": True}
            for name, m in mods.items()
        ],
    }


@real_services_router.post("/security-engine/scan")
def security_engine_scan(body: dict):
    mods = get_mods()
    if "security_engine" not in mods:
        raise HTTPException(503, "Security engine not available")
    engine = mods["security_engine"]["engine"]()
    result = engine.scan(body.get("data", {})) if hasattr(engine, "scan") else {"threats": []}
    return {"status": "ok", "result": result}


@real_services_router.post("/advanced-security/siem")
def advanced_security_siem(body: dict):
    mods = get_mods()
    if "advanced_security" not in mods:
        raise HTTPException(503, "Advanced security not available")
    siem = mods["advanced_security"]["siem"]()
    result = siem.correlate(body.get("events", [])) if hasattr(siem, "correlate") else {"events": []}
    return {"status": "ok", "result": result}


@real_services_router.post("/cyber-skills/check")
def cyber_skills_check(body: dict):
    mods = get_mods()
    if "cyber_skills" not in mods:
        raise HTTPException(503, "Cyber skills not available")
    skill = mods["cyber_skills"]["skill"]()
    result = skill.check(body.get("technique", "")) if hasattr(skill, "check") else {"covered": False}
    return {"status": "ok", "result": result}


@real_services_router.post("/deep-security/vuln")
def deep_security_vuln(body: dict):
    mods = get_mods()
    if "deep_security" not in mods:
        raise HTTPException(503, "Deep security not available")
    vms = mods["deep_security"]["vuln_mgmt"]()
    result = vms.scan(body.get("data", [])) if hasattr(vms, "scan") else {"findings": []}
    return {"status": "ok", "result": result}
