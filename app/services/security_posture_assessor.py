"""
Sentinel/app/services/security_posture_assessor.py — Sentinel Security Posture Assessor.

Assess security posture across multiple domains: vulnerability management,
patch compliance, configuration drift, security controls effectiveness,
and posture scoring with improvement recommendations.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()


@dataclass
class VulnerabilityStatus:
    """Vulnerability management status."""
    total_vulns: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    avg_remediation_time_days: float = 0.0
    oldest_open_vuln_days: int = 0


@dataclass
class PatchCompliance:
    """Patch compliance status."""
    total_systems: int = 0
    patched_systems: int = 0
    compliance_rate: float = 0.0
    critical_patches_missed: int = 0
    avg_patch_age_days: float = 0.0


@dataclass
class ConfigDrift:
    """Configuration drift assessment."""
    total_checks: int = 0
    compliant_checks: int = 0
    drift_detected: int = 0
    critical_drift: int = 0
    compliance_rate: float = 0.0


@dataclass
class ControlStatus:
    """Security control effectiveness."""
    control_id: str
    control_name: str = ""
    domain: str = ""
    status: str = "active"  # active, monitoring, inactive, bypassed
    effectiveness: float = 0.0
    coverage: float = 0.0
    alerts_last_24h: int = 0


@dataclass
class PostureScore:
    """Overall security posture score."""
    overall_score: float = 0.0  # 0-100
    rating: str = "adequate"  # poor, fair, adequate, good, excellent
    vulnerability_score: float = 0.0
    patch_score: float = 0.0
    config_score: float = 0.0
    control_score: float = 0.0
    trend: str = "stable"  # improving, stable, declining


@dataclass
class ImprovementPlan:
    """Improvement recommendation plan."""
    plan_id: str
    area: str = ""
    recommendation: str = ""
    priority: str = "medium"  # low, medium, high, critical
    effort: str = "medium"  # low, medium, high
    expected_improvement: float = 0.0
    timeline: str = ""


@dataclass
class AssessmentHistory:
    """History of posture assessments."""
    total_assessments: int = 0
    avg_score: float = 0.0
    best_score: float = 0.0
    worst_score: float = 0.0
    trend: str = "stable"


class SecurityPostureAssessor:
    """Security posture assessment engine."""

    def __init__(self):
        self._vuln_status: VulnerabilityStatus = VulnerabilityStatus()
        self._patch: PatchCompliance = PatchCompliance()
        self._config: ConfigDrift = ConfigDrift()
        self._controls: dict[str, ControlStatus] = {}
        self._scores: list[PostureScore] = []
        self._plans: list[ImprovementPlan] = []
        self._history: AssessmentHistory = AssessmentHistory()

    def update_vulnerability_status(
        self,
        total: int, critical: int, high: int, medium: int, low: int,
        avg_remediation: float, oldest_open: int,
    ):
        """Update vulnerability status."""
        self._vuln_status = VulnerabilityStatus(
            total_vulns=total, critical=critical, high=high, medium=medium, low=low,
            avg_remediation_time_days=avg_remediation, oldest_open_vuln_days=oldest_open,
        )

    def update_patch_compliance(self, total_systems: int, patched: int, critical_missed: int, avg_age: float):
        """Update patch compliance."""
        self._patch = PatchCompliance(
            total_systems=total_systems,
            patched_systems=patched,
            compliance_rate=patched / max(1, total_systems),
            critical_patches_missed=critical_missed,
            avg_patch_age_days=avg_age,
        )

    def update_config_drift(self, total: int, compliant: int, critical_drift: int):
        """Update configuration drift."""
        self._config = ConfigDrift(
            total_checks=total,
            compliant_checks=compliant,
            drift_detected=total - compliant,
            critical_drift=critical_drift,
            compliance_rate=compliant / max(1, total),
        )

    def add_control(self, name: str, domain: str, effectiveness: float, coverage: float, alerts: int) -> ControlStatus:
        """Add a security control status."""
        control = ControlStatus(
            control_id=hashlib.md5(f"control:{name}:{time.time()}".encode()).hexdigest()[:12],
            control_name=name,
            domain=domain,
            status="active" if effectiveness > 0.5 else "monitoring",
            effectiveness=effectiveness,
            coverage=coverage,
            alerts_last_24h=alerts,
        )
        self._controls[control.control_id] = control
        return control

    def assess(self) -> PostureScore:
        """Assess overall security posture."""
        # Vulnerability score (higher is better)
        vuln_score = 100.0
        if self._vuln_status.total_vulns > 0:
            vuln_score -= (self._vuln_status.critical * 10 + self._vuln_status.high * 5)
            vuln_score -= min(20, self._vuln_status.oldest_open_vuln_days / 10)
        vuln_score = max(0, vuln_score)

        # Patch compliance score
        patch_score = self._patch.compliance_rate * 100
        patch_score -= self._patch.critical_patches_missed * 5
        patch_score = max(0, min(100, patch_score))

        # Configuration score
        config_score = self._config.compliance_rate * 100
        config_score -= self._config.critical_drift * 5
        config_score = max(0, min(100, config_score))

        # Control effectiveness score
        if self._controls:
            control_score = sum(c.effectiveness * c.coverage for c in self._controls.values()) / len(self._controls) * 100
        else:
            control_score = 50.0

        # Overall score
        overall = (vuln_score * 0.3 + patch_score * 0.25 + config_score * 0.25 + control_score * 0.2)

        rating = "excellent" if overall > 85 else "good" if overall > 70 else "adequate" if overall > 50 else "fair" if overall > 30 else "poor"

        # Trend
        if len(self._scores) >= 2:
            prev = self._scores[-1].overall_score
            trend = "improving" if overall > prev + 1 else "declining" if overall < prev - 1 else "stable"
        else:
            trend = "stable"

        score = PostureScore(
            overall_score=round(overall, 1),
            rating=rating,
            vulnerability_score=round(vuln_score, 1),
            patch_score=round(patch_score, 1),
            config_score=round(config_score, 1),
            control_score=round(control_score, 1),
            trend=trend,
        )

        self._scores.append(score)

        # Update history
        self._history.total_assessments += 1
        self._history.avg_score = (self._history.avg_score * 0.9 + overall * 0.1)
        self._history.best_score = max(self._history.best_score, overall)
        self._history.worst_score = min(self._history.worst_score if self._history.worst_score > 0 else overall, overall)

        return score

    def generate_improvement_plan(self, score: PostureScore) -> list[ImprovementPlan]:
        """Generate improvement recommendations."""
        plans = []

        if score.vulnerability_score < 70:
            plans.append(ImprovementPlan(
                plan_id=hashlib.md5(f"plan:vuln:{time.time()}".encode()).hexdigest()[:12],
                area="vulnerability_management",
                recommendation="Prioritize remediation of critical and high vulnerabilities",
                priority="critical",
                effort="high",
                expected_improvement=15.0,
                timeline="2-4 weeks",
            ))

        if score.patch_score < 70:
            plans.append(ImprovementPlan(
                plan_id=hashlib.md5(f"plan:patch:{time.time()}".encode()).hexdigest()[:12],
                area="patch_management",
                recommendation="Implement automated patch deployment for critical patches",
                priority="high",
                effort="medium",
                expected_improvement=10.0,
                timeline="1-2 weeks",
            ))

        if score.config_score < 70:
            plans.append(ImprovementPlan(
                plan_id=hashlib.md5(f"plan:config:{time.time()}".encode()).hexdigest()[:12],
                area="configuration_management",
                recommendation="Enforce configuration baselines with automated drift detection",
                priority="high",
                effort="medium",
                expected_improvement=10.0,
                timeline="2-3 weeks",
            ))

        if score.control_score < 70:
            plans.append(ImprovementPlan(
                plan_id=hashlib.md5(f"plan:control:{time.time()}".encode()).hexdigest()[:12],
                area="security_controls",
                recommendation="Review and enhance security control effectiveness and coverage",
                priority="medium",
                effort="high",
                expected_improvement=8.0,
                timeline="1-2 months",
            ))

        self._plans.extend(plans)
        return plans

    def get_report(self) -> dict:
        """Get security posture assessor report."""
        latest = self._scores[-1] if self._scores else PostureScore()

        return {
            "total_assessments": self._history.total_assessments,
            "latest_score": latest.overall_score,
            "latest_rating": latest.rating,
            "latest_trend": latest.trend,
            "vulnerability_status": {
                "total": self._vuln_status.total_vulns,
                "critical": self._vuln_status.critical,
                "high": self._vuln_status.high,
                "oldest_open_days": self._vuln_status.oldest_open_vuln_days,
            },
            "patch_compliance": {
                "compliance_rate": self._patch.compliance_rate,
                "critical_missed": self._patch.critical_patches_missed,
                "avg_patch_age_days": self._patch.avg_patch_age_days,
            },
            "config_drift": {
                "compliance_rate": self._config.compliance_rate,
                "drift_detected": self._config.drift_detected,
                "critical_drift": self._config.critical_drift,
            },
            "controls": [
                {"name": c.control_name, "domain": c.domain, "effectiveness": c.effectiveness, "coverage": c.coverage}
                for c in self._controls.values()
            ],
            "improvement_plans": [
                {"area": p.area, "priority": p.priority, "recommendation": p.recommendation[:60], "improvement": p.expected_improvement}
                for p in self._plans[-5:]
            ],
            "score_history": [
                {"score": s.overall_score, "rating": s.rating, "trend": s.trend}
                for s in self._scores[-10:]
            ],
            "nist_csf": self._csf_alignment(latest),
            "detection_coverage": self._detection_coverage(),
        }

    @staticmethod
    def _maturity(rate: float) -> int:
        """Normalise a compliance rate (ratio 0-1, 1-5 scale, or percentage 0-100) onto the 1-5 CSF scale."""
        value = float(rate or 0.0)
        if value <= 0.0:
            return 1
        if value <= 1.0:
            # Ratio: e.g. 0.8 -> 80% -> 4
            value *= 100.0
            return max(1, min(5, int(round(value / 20.0)) or 1))
        if value <= 5.0:
            # Already on 1-5 scale
            return max(1, min(5, int(round(value))))
        # Percentage (0-100): e.g. 80.0 -> 4
        return max(1, min(5, int(round(value / 20.0)) or 1))

    def _detection_coverage(self) -> dict:
        """Compute real-time detection coverage against active threat matcher rules."""
        try:
            from app.services.cyber_skills_service import get_service
            service = get_service()
        except Exception:
            return {"available": False}
        try:
            from app.services.realtime_threat_matcher import threat_matcher
            rules = []
            for sig_id, sig in getattr(threat_matcher, "_signatures", {}).items():
                cat = getattr(sig, "category", "") or ""
                techs = [cat] if cat.startswith("T") else []
                cat_lower = cat.lower()
                if "sql" in cat_lower or "injection" in cat_lower:
                    techs.append("T1190")
                elif "xss" in cat_lower:
                    techs.append("T1059")
                elif "port" in cat_lower or "scan" in cat_lower:
                    techs.append("T1046")
                elif "brute" in cat_lower:
                    techs.append("T1110")
                else:
                    techs.append("T1059")
                rules.append({
                    "id": sig_id,
                    "name": getattr(sig, "name", sig_id),
                    "techniques": techs,
                    "fidelity": 0.85 if getattr(sig, "severity", "") == "high" else 0.65,
                    "enabled": True,
                })
            eval_techniques = ["T1059", "T1190", "T1046", "T1110", "T1078", "T1566"]
            coverage_result = service.detection_coverage(eval_techniques, rules=rules)
            return {"available": True, "rules_count": len(rules), **coverage_result}
        except Exception as exc:  # pragma: no cover
            return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    def _csf_alignment(self, latest: "PostureScore") -> dict:
        """Map the posture score onto NIST CSF 2.0 functions via Sentinel's skills.

        1-5 maturity levels are derived from the live posture inputs so the same
        numbers drive both the internal score and the external framework view.
        """
        try:
            from app.services.cyber_skills_service import get_service
        except Exception:  # pragma: no cover - optional dependency
            return {"available": False}
        try:
            overall = float(getattr(latest, "overall_score", 0.0) or 0.0)
            maturity = max(1, min(5, int(round(overall / 20.0)) or 1))
            patch_rate = self._maturity(getattr(self._patch, "compliance_rate", 0.0))
            drift_rate = self._maturity(getattr(self._config, "compliance_rate", 0.0))
            controls = [
                {"category": "ID.AM", "maturity": maturity,
                 "owner": "asset-management", "evidence": ["posture assessor"]},
                {"category": "PR.PS", "maturity": patch_rate,
                 "owner": "platform", "evidence": ["patch compliance"]},
                {"category": "PR.IR", "maturity": drift_rate,
                 "owner": "platform", "evidence": ["config drift"]},
                {"category": "DE.CM", "maturity": maturity,
                 "owner": "soc", "evidence": ["control effectiveness"]},
            ]
            return {"available": True, **get_service().assess_csf(controls)}
        except Exception as exc:  # pragma: no cover - optional enrichment
            return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


posture_assessor = SecurityPostureAssessor()


@router.post("/api/v1/sentinel/posture/vulnerabilities")
async def update_vulnerability_status(payload: dict):
    """Update vulnerability status."""
    posture_assessor.update_vulnerability_status(
        total=payload["total"],
        critical=payload.get("critical", 0),
        high=payload.get("high", 0),
        medium=payload.get("medium", 0),
        low=payload.get("low", 0),
        avg_remediation=payload.get("avg_remediation_days", 30),
        oldest_open=payload.get("oldest_open_days", 0),
    )
    return {"updated": True}


@router.post("/api/v1/sentinel/posture/patches")
async def update_patch_compliance(payload: dict):
    """Update patch compliance."""
    posture_assessor.update_patch_compliance(
        total_systems=payload["total_systems"],
        patched=payload["patched_systems"],
        critical_missed=payload.get("critical_missed", 0),
        avg_age=payload.get("avg_patch_age_days", 0),
    )
    return {"updated": True}


@router.post("/api/v1/sentinel/posture/config")
async def update_config_drift(payload: dict):
    """Update configuration drift."""
    posture_assessor.update_config_drift(
        total=payload["total_checks"],
        compliant=payload["compliant_checks"],
        critical_drift=payload.get("critical_drift", 0),
    )
    return {"updated": True}


@router.post("/api/v1/sentinel/posture/assess")
async def assess():
    """Assess security posture."""
    score = posture_assessor.assess()
    return {
        "score": score.overall_score,
        "rating": score.rating,
        "trend": score.trend,
        "vulnerability_score": score.vulnerability_score,
        "patch_score": score.patch_score,
        "config_score": score.config_score,
        "control_score": score.control_score,
    }


@router.get("/api/v1/sentinel/posture/report")
async def get_report():
    """Get security posture assessor report."""
    return posture_assessor.get_report()
