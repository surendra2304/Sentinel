"""
Sentinel/app/services/compliance_audit_trail.py — Sentinel Compliance Audit Trail Engine.

Tracks and manages compliance audit trails: regulatory change monitoring,
control assessments, audit evidence collection, compliance reporting, and
remediation tracking across the security mesh.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class RegulatoryFramework:
    """A regulatory framework."""
    framework_id: str
    name: str
    version: str = ""
    description: str = ""
    jurisdiction: str = "global"
    controls_count: int = 0
    last_updated: float = 0.0
    active: bool = True


@dataclass
class ComplianceControl:
    """A compliance control."""
    control_id: str
    framework_id: str
    control_number: str
    title: str
    description: str = ""
    category: str = ""  # access_control, audit, crypto, network, etc.
    status: str = "unverified"  # unverified, compliant, non_compliant, pending
    evidence: list[str] = field(default_factory=list)
    last_assessed: float = 0.0
    assessed_by: str = ""


@dataclass
class AuditEvent:
    """An audit event."""
    event_id: str
    control_id: str
    event_type: str  # assessment, evidence_collected, remediation, change, exception
    description: str
    timestamp: float
    assessor: str = ""
    severity: str = "info"
    details: dict = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """A compliance status report."""
    report_id: str
    framework_id: str
    generated_at: float
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    pending_controls: int
    compliance_percentage: float
    risk_level: str
    recommendations: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


@dataclass
class RemediationPlan:
    """A remediation plan for non-compliant controls."""
    plan_id: str
    control_id: str
    description: str
    actions: list[str] = field(default_factory=list)
    assignee: str = ""
    due_date: str = ""
    status: str = "pending"
    priority: str = "medium"
    created_at: float = 0.0


@dataclass
class EvidenceItem:
    """An evidence item for compliance."""
    evidence_id: str
    control_id: str
    description: str
    evidence_type: str  # screenshot, log, document, configuration, attestation
    source: str = ""
    collected_at: float = 0.0
    verified: bool = False
    verified_by: str = ""


class ComplianceAuditTrail:
    """Compliance audit trail engine."""

    def __init__(self):
        self._frameworks: dict[str, RegulatoryFramework] = {}
        self._controls: dict[str, ComplianceControl] = {}
        self._events: list[AuditEvent] = []
        self._reports: dict[str, ComplianceReport] = {}
        self._remediations: dict[str, RemediationPlan] = {}
        self._evidence: dict[str, EvidenceItem] = {}

    def register_framework(
        self,
        name: str,
        version: str = "",
        description: str = "",
        jurisdiction: str = "global",
        controls_count: int = 50,
    ) -> RegulatoryFramework:
        """Register a regulatory framework."""
        framework = RegulatoryFramework(
            framework_id=hashlib.md5(
                f"framework:{name}:{version}:{time.time()}".encode()
            ).hexdigest()[:12],
            name=name,
            version=version,
            description=description,
            jurisdiction=jurisdiction,
            controls_count=controls_count,
            last_updated=time.time(),
        )
        self._frameworks[framework.framework_id] = framework
        return framework

    def register_control(
        self,
        framework_id: str,
        control_number: str,
        title: str,
        description: str = "",
        category: str = "",
    ) -> ComplianceControl:
        """Register a compliance control."""
        control = ComplianceControl(
            control_id=hashlib.md5(
                f"control:{framework_id}:{control_number}:{time.time()}".encode()
            ).hexdigest()[:12],
            framework_id=framework_id,
            control_number=control_number,
            title=title,
            description=description,
            category=category,
        )
        self._controls[control.control_id] = control
        return control

    def assess_control(
        self,
        control_id: str,
        status: str,
        assessor: str,
        evidence: list[str] | None = None,
    ) -> dict:
        """Assess a compliance control."""
        control = self._controls.get(control_id)
        if not control:
            raise HTTPException(404, f"Control {control_id} not found")

        control.status = status
        control.last_assessed = time.time()
        control.assessed_by = assessor

        if evidence:
            control.evidence.extend(evidence)

        # Record audit event
        event = AuditEvent(
            event_id=hashlib.md5(
                f"event:{control_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            control_id=control_id,
            event_type="assessment",
            description=f"Control assessed as {status}",
            timestamp=time.time(),
            assessor=assessor,
            severity="info" if status == "compliant" else "warning",
            details={"status": status, "evidence_count": len(evidence or [])},
        )
        self._events.append(event)

        return {"control_id": control_id, "status": status, "assessed_by": assessor}

    def collect_evidence(
        self,
        control_id: str,
        description: str,
        evidence_type: str,
        source: str = "",
    ) -> EvidenceItem:
        """Collect evidence for a control."""
        evidence = EvidenceItem(
            evidence_id=hashlib.md5(
                f"evidence:{control_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            control_id=control_id,
            description=description,
            evidence_type=evidence_type,
            source=source,
            collected_at=time.time(),
        )
        self._evidence[evidence.evidence_id] = evidence

        # Add to control
        control = self._controls.get(control_id)
        if control:
            control.evidence.append(evidence.evidence_id)

        return evidence

    def generate_report(self, framework_id: str) -> ComplianceReport:
        """Generate compliance report for a framework."""
        framework = self._frameworks.get(framework_id)
        if not framework:
            raise HTTPException(404, f"Framework {framework_id} not found")

        controls = [c for c in self._controls.values() if c.framework_id == framework_id]
        compliant = sum(1 for c in controls if c.status == "compliant")
        non_compliant = sum(1 for c in controls if c.status == "non_compliant")
        pending = sum(1 for c in controls if c.status in ("unverified", "pending"))

        compliance_pct = compliant / max(1, len(controls)) * 100

        if compliance_pct > 80:
            risk_level = "low"
        elif compliance_pct > 50:
            risk_level = "medium"
        elif compliance_pct > 20:
            risk_level = "high"
        else:
            risk_level = "critical"

        recommendations = []
        if non_compliant > 0:
            recommendations.append(f"Remediate {non_compliant} non-compliant controls")
        if pending > 0:
            recommendations.append(f"Assess {pending} unverified controls")
        if compliance_pct < 50:
            recommendations.append("Prioritize compliance remediation")

        report = ComplianceReport(
            report_id=hashlib.md5(
                f"report:{framework_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            framework_id=framework_id,
            generated_at=time.time(),
            total_controls=len(controls),
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            pending_controls=pending,
            compliance_percentage=compliance_pct,
            risk_level=risk_level,
            recommendations=recommendations,
            findings=self._generate_findings(controls),
        )

        self._reports[report.report_id] = report
        return report

    def _generate_findings(self, controls: list[ComplianceControl]) -> list[str]:
        """Generate compliance findings."""
        findings = []

        for control in controls:
            if control.status == "non_compliant":
                findings.append(f"Control {control.control_number}: {control.title} is non-compliant")
            elif control.status == "unverified":
                findings.append(f"Control {control.control_number}: {control.title} needs assessment")

        return findings[:10]

    def create_remediation(
        self,
        control_id: str,
        description: str,
        actions: list[str],
        assignee: str = "",
        priority: str = "medium",
    ) -> RemediationPlan:
        """Create a remediation plan."""
        plan = RemediationPlan(
            plan_id=hashlib.md5(
                f"remediation:{control_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            control_id=control_id,
            description=description,
            actions=actions,
            assignee=assignee,
            priority=priority,
            created_at=time.time(),
        )

        self._remediations[plan.plan_id] = plan

        # Update control status
        control = self._controls.get(control_id)
        if control:
            control.status = "pending"

        return plan

    def get_report(self) -> dict:
        """Get compliance audit trail report."""
        return {
            "total_frameworks": len(self._frameworks),
            "total_controls": len(self._controls),
            "total_events": len(self._events),
            "total_reports": len(self._reports),
            "total_remediations": len(self._remediations),
            "total_evidence": len(self._evidence),
            "controls_by_status": {
                s: sum(1 for c in self._controls.values() if c.status == s)
                for s in ["compliant", "non_compliant", "unverified", "pending"]
            },
            "frameworks": [
                {
                    "name": f.name,
                    "version": f.version,
                    "jurisdiction": f.jurisdiction,
                    "controls": f.controls_count,
                    "active": f.active,
                }
                for f in self._frameworks.values()
            ],
        }


# Module-level singleton
compliance_trail = ComplianceAuditTrail()


# ── API Routes ──────────────────────────────────────────────────────────────


@router.post("/api/v1/sentinel/compliance/frameworks")
async def register_framework(payload: dict):
    """Register a regulatory framework."""
    framework = compliance_trail.register_framework(
        name=payload["name"],
        version=payload.get("version", ""),
        description=payload.get("description", ""),
        jurisdiction=payload.get("jurisdiction", "global"),
        controls_count=payload.get("controls_count", 50),
    )
    return {"framework_id": framework.framework_id, "name": framework.name, "controls": framework.controls_count}


@router.post("/api/v1/sentinel/compliance/frameworks/{framework_id}/controls")
async def register_control(framework_id: str, payload: dict):
    """Register a compliance control."""
    control = compliance_trail.register_control(
        framework_id=framework_id,
        control_number=payload["control_number"],
        title=payload["title"],
        description=payload.get("description", ""),
        category=payload.get("category", ""),
    )
    return {"control_id": control.control_id, "control_number": control.control_number, "title": control.title}


@router.post("/api/v1/sentinel/compliance/controls/{control_id}/assess")
async def assess_control(control_id: str, payload: dict):
    """Assess a compliance control."""
    result = compliance_trail.assess_control(
        control_id=control_id,
        status=payload["status"],
        assessor=payload["assessor"],
        evidence=payload.get("evidence", []),
    )
    return result


@router.post("/api/v1/sentinel/compliance/controls/{control_id}/evidence")
async def collect_evidence(control_id: str, payload: dict):
    """Collect evidence for a control."""
    evidence = compliance_trail.collect_evidence(
        control_id=control_id,
        description=payload["description"],
        evidence_type=payload["evidence_type"],
        source=payload.get("source", ""),
    )
    return {"evidence_id": evidence.evidence_id, "type": evidence.evidence_type, "verified": evidence.verified}


@router.post("/api/v1/sentinel/compliance/frameworks/{framework_id}/report")
async def generate_report(framework_id: str):
    """Generate compliance report."""
    report = compliance_trail.generate_report(framework_id)
    return {
        "report_id": report.report_id,
        "total_controls": report.total_controls,
        "compliant": report.compliant_controls,
        "non_compliant": report.non_compliant_controls,
        "pending": report.pending_controls,
        "compliance_percentage": report.compliance_percentage,
        "risk_level": report.risk_level,
        "recommendations": report.recommendations,
        "findings": report.findings,
    }


@router.post("/api/v1/sentinel/compliance/controls/{control_id}/remediation")
async def create_remediation(control_id: str, payload: dict):
    """Create a remediation plan."""
    plan = compliance_trail.create_remediation(
        control_id=control_id,
        description=payload["description"],
        actions=payload["actions"],
        assignee=payload.get("assignee", ""),
        priority=payload.get("priority", "medium"),
    )
    return {"plan_id": plan.plan_id, "control_id": plan.control_id, "status": plan.status, "priority": plan.priority}


@router.get("/api/v1/sentinel/compliance/report")
async def get_report():
    """Get compliance audit trail report."""
    return compliance_trail.get_report()
