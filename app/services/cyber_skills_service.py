"""
Sentinel/app/services/cyber_skills_service.py — Sentinel Security Skills Service.

Sentinel's triage, posture assessment and response orchestration now speak the
same language as the threat-intel world: MITRE ATT&CK techniques and tactics,
NIST CSF 2.0 categories, D3FEND controls, ATLAS/AI-RMF and F3 fraud tactics.

``CyberSkillsService`` is the adapter used by the running service:

* ``triage``            — turn incident evidence into techniques, tactics,
                          severity and matched response skills.
* ``playbook``          — phased containment/eradication/recovery plan.
* ``assess_csf``        — record control maturity and get prioritised gaps.
* ``detection_coverage`` — which ATT&CK techniques telemetry actually covers.
* ``authorise``         — rules-of-engagement check before offensive tooling.
* ``capabilities``      — catalogue coverage for the agent's capability card.

``router`` is mounted by ``Sentinel/sentinel/apps/api/main.py``;
``incident_routes.triage_incident`` calls ``triage`` so every triaged incident
carries its ATT&CK crosswalk, and ``security_posture_assessor.get_report``
adds the CSF function scores.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Iterable

_MODULE_PATH = Path(__file__).resolve().parent / "real_cyber_skills.py"

if "sentinel_cyber_skills" in sys.modules:
    cs = sys.modules["sentinel_cyber_skills"]
else:
    _spec = importlib.util.spec_from_file_location("sentinel_cyber_skills", _MODULE_PATH)
    cs = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    sys.modules["sentinel_cyber_skills"] = cs
    _spec.loader.exec_module(cs)  # type: ignore[union-attr]

try:  # pragma: no cover - only when FastAPI is installed
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel, Field

    _ROUTER_AVAILABLE = True
except Exception:  # pragma: no cover
    APIRouter = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    BaseModel = object  # type: ignore[assignment]

    def Field(*_args: Any, **_kwargs: Any) -> Any:  # type: ignore[misc]
        return None

    _ROUTER_AVAILABLE = False


class CyberSkillsService:
    """Security-skills facade used by Sentinel's API and incident pipeline."""

    def __init__(self, engine: Any | None = None) -> None:
        self.engine = engine or cs.CyberSkillsEngine()
        self.catalog = self.engine.catalog
        self.assessor = cs.NistCsfAssessor()

    # -- triage -----------------------------------------------------------
    def triage(self, title: str, events: Iterable[dict[str, Any]]) -> dict[str, Any]:
        prepared = [
            cs.IncidentEvent(
                timestamp=str(event.get("timestamp", "")),
                description=str(event.get("description", "")),
                technique=str(event.get("technique", "")),
                host=str(event.get("host", "")),
                source=str(event.get("source", "")),
            )
            for event in events
        ]
        if not prepared:
            raise ValueError("at least one incident event is required")
        report = cs.IncidentReport(title)
        for event in prepared:
            report.add_event(event)
        payload = report.build()
        payload["skills"] = [
            match["skill"] for match in self.recommend(payload["techniques"], limit=3)
        ]
        payload["markdown"] = report.render_markdown()
        return payload

    def recommend(self, techniques: Iterable[str], limit: int = 5) -> list[Any]:
        return cs.SkillRecommender(self.catalog).recommend(list(techniques), limit=limit)

    DESTRUCTIVE_ACTIONS: set[str] = {
        "isolate host", "isolate_host", "isolate-host",
        "block ip", "block_ip", "block-ip",
        "revoke credential", "revoke_credential", "revoke-credential", "revoke credentials",
        "quarantine", "kill_process", "wipe_host",
    }

    def playbook(self, title: str, techniques: Iterable[str], assets: int = 1
                 ) -> dict[str, Any]:
        techniques = [technique for technique in techniques if technique]
        if not techniques:
            raise ValueError("at least one technique is required")
        book = self.engine.playbook(title, techniques, assets=assets)
        for phase in book.get("phases", []):
            for step in phase.get("steps", []):
                action_text = str(step.get("action") or step.get("description") or "").lower()
                if any(d in action_text for d in self.DESTRUCTIVE_ACTIONS):
                    step["requires_approval"] = True
                    step["status"] = "pending_approval"
        return book

    def execute_playbook_action(
        self,
        action: str,
        target: str = "",
        engagement: str = "",
        approved: bool = False,
    ) -> dict[str, Any]:
        """Execute or gate a containment/remediation action."""
        action_clean = action.lower().strip()
        is_destructive = any(d in action_clean for d in self.DESTRUCTIVE_ACTIONS)

        if is_destructive and not approved:
            decision = self.authorise("action:" + action_clean, target=target, engagement=engagement)
            if not decision.get("authorized", False):
                return {
                    "action": action,
                    "target": target,
                    "status": "blocked_pending_approval",
                    "reason": "Destructive containment action requires human authorization",
                    "decision": decision,
                }

        import time
        return {
            "action": action,
            "target": target,
            "status": "executed",
            "timestamp": time.time(),
        }

    # -- posture ----------------------------------------------------------
    def assess_csf(self, controls: Iterable[dict[str, Any]], target: int = 3
                   ) -> dict[str, Any]:
        assessor = cs.NistCsfAssessor()
        recorded = 0
        for control in controls:
            try:
                assessor.assess(
                    str(control.get("category", "")),
                    int(control.get("maturity", 0)),
                    evidence=list(control.get("evidence", [])),
                    owner=str(control.get("owner", "")),
                )
                recorded += 1
            except ValueError:
                continue
        if recorded == 0:
            raise ValueError("no valid CSF categories supplied")
        return {
            "controls": recorded,
            "function_scores": assessor.function_scores(),
            "overall": assessor.overall(),
            "coverage": assessor.coverage(),
            "gaps": assessor.gaps(target=target)[:5],
            "actions": assessor.prioritized_actions(limit=5),
            "unassessed": len(assessor.unassessed()),
        }

    def detection_coverage(self, techniques: Iterable[str],
                           rules: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
        parsed = [
            cs.DetectionRule(
                rule_id=str(rule.get("id") or f"rule-{index}"),
                name=str(rule.get("name", "")),
                techniques=list(rule.get("techniques", [])),
                fidelity=float(rule.get("fidelity", 0.6)),
                enabled=bool(rule.get("enabled", True)),
            )
            for index, rule in enumerate(rules, start=1)
        ]
        engine = cs.DetectionCoverageEngine(parsed)
        payload = engine.evaluate(list(techniques)).as_dict()
        payload["recommendations"] = engine.recommendations(
            list(techniques), catalog=self.catalog, limit=5)
        return payload

    def coverage_report(self) -> dict[str, Any]:
        return self.catalog.coverage_report()

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        return [
            {"skill": match.skill.skill_id, "name": match.skill.name,
             "tier": match.skill.tier, "score": match.score,
             "reasons": list(match.reasons)}
            for match in self.catalog.search(query, limit=limit)
        ]

    # -- authorization ----------------------------------------------------
    def authorise(self, skill_id: str, target: str = "", engagement: str = "",
                  allowed_tiers: Iterable[str] = ("defensive",)) -> dict[str, Any]:
        scope = cs.AuthorizationScope(
            engagement=engagement,
            allowed_tiers=list(allowed_tiers),
        )
        skill = self.catalog.get(skill_id)
        decision = scope.check(skill or skill_id, target)
        return decision.as_dict()

    def capabilities(self) -> dict[str, Any]:
        report = self.catalog.coverage_report()
        return {
            "agent": "Sentinel",
            "capabilities": [
                "attack_mapping", "incident_triage", "incident_playbook",
                "csf_assessment", "detection_coverage", "security_skill_search",
                "fraud_mapping", "rules_of_engagement",
            ],
            "skills": report["skills"],
            "domains": report["domains"],
            "frameworks": report["frameworks"],
            "tactics_covered": len(report.get("tactics_covered", [])),
        }


_service: CyberSkillsService | None = None


def get_service() -> CyberSkillsService:
    global _service
    if _service is None:
        _service = CyberSkillsService()
    return _service


def reset_service(service: CyberSkillsService | None = None) -> CyberSkillsService:
    global _service
    _service = service or CyberSkillsService()
    return _service


# ── REST surface ──────────────────────────────────────────────────────────

if _ROUTER_AVAILABLE:

    class EventModel(BaseModel):  # type: ignore[misc]
        timestamp: str = ""
        description: str = Field(min_length=1)
        technique: str = ""
        host: str = ""
        source: str = "api"

    class TriageRequest(BaseModel):  # type: ignore[misc]
        title: str = Field(min_length=1)
        events: list[EventModel] = Field(min_length=1)

    class PlaybookRequest(BaseModel):  # type: ignore[misc]
        title: str = Field(min_length=1)
        techniques: list[str] = Field(min_length=1)
        assets: int = Field(default=1, ge=0, le=100000)

    class ControlModel(BaseModel):  # type: ignore[misc]
        category: str = Field(min_length=2)
        maturity: int = Field(ge=0, le=5)
        evidence: list[str] = Field(default_factory=list)
        owner: str = ""

    class CsfRequest(BaseModel):  # type: ignore[misc]
        controls: list[ControlModel] = Field(min_length=1)
        target: int = Field(default=3, ge=1, le=5)

    class RuleModel(BaseModel):  # type: ignore[misc]
        id: str = ""
        name: str = ""
        techniques: list[str] = Field(default_factory=list)
        fidelity: float = Field(default=0.6, ge=0.0, le=1.0)
        enabled: bool = True

    class CoverageRequest(BaseModel):  # type: ignore[misc]
        techniques: list[str] = Field(min_length=1)
        rules: list[RuleModel] = Field(default_factory=list)

    class AuthoriseRequest(BaseModel):  # type: ignore[misc]
        skill_id: str = Field(min_length=1)
        target: str = ""
        engagement: str = ""
        allowed_tiers: list[str] = Field(default_factory=lambda: ["defensive"])

    class ExecuteActionRequest(BaseModel):  # type: ignore[misc]
        action: str = Field(min_length=1)
        target: str = ""
        engagement: str = ""
        approved: bool = False

    router = APIRouter(prefix="/v1/cyber", tags=["Sentinel Security Skills"])

    @router.get("/capabilities")
    def capabilities() -> dict[str, Any]:
        return get_service().capabilities()

    @router.post("/triage")
    def triage(request: TriageRequest) -> dict[str, Any]:
        try:
            return get_service().triage(
                request.title, [event.model_dump() for event in request.events])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/playbook")
    def playbook(request: PlaybookRequest) -> dict[str, Any]:
        try:
            return get_service().playbook(request.title, request.techniques,
                                          assets=request.assets)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/action/execute")
    def execute_action(request: ExecuteActionRequest) -> dict[str, Any]:
        return get_service().execute_playbook_action(
            request.action,
            target=request.target,
            engagement=request.engagement,
            approved=request.approved,
        )

    @router.post("/csf/assess")
    def assess(request: CsfRequest) -> dict[str, Any]:
        try:
            return get_service().assess_csf(
                [control.model_dump() for control in request.controls], request.target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/detection/coverage")
    def coverage(request: CoverageRequest) -> dict[str, Any]:
        return get_service().detection_coverage(
            request.techniques, [rule.model_dump() for rule in request.rules])

    @router.get("/skills")
    def skills(query: str, limit: int = 5) -> dict[str, Any]:
        return {"query": query, "matches": get_service().search(query, limit)}

    @router.post("/authorise")
    def authorise(request: AuthoriseRequest) -> dict[str, Any]:
        return get_service().authorise(
            request.skill_id, request.target, request.engagement,
            request.allowed_tiers)

else:  # pragma: no cover
    router = None


__all__ = [
    "CyberSkillsService",
    "cs",
    "get_service",
    "reset_service",
    "router",
]
