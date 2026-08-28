"""HeuristicProvider - deterministic, offline IntelligenceProvider.

Wraps the existing heuristic/template-based engines so SENTINEL works
fully without any external model. This is the default and fallback provider.
"""

import time
from typing import Any

from sentinel.core.intelligence.interface import (
    IntelligenceProvider,
    IntelligenceRequest,
    IntelligenceResult,
    IntelligenceRole,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.intelligence.heuristic")


class HeuristicProvider(IntelligenceProvider):
    """Deterministic offline provider - zero external dependencies."""

    @property
    def provider_name(self) -> str:
        return "heuristic"

    async def request(self, req: IntelligenceRequest) -> IntelligenceResult:
        start = time.monotonic()
        try:
            output = await self._dispatch(req.role, req.context)
            return IntelligenceResult(
                role=req.role,
                provider_used=self.provider_name,
                structured_output=output,
                confidence=1.0,
                schema_valid=True,
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            logger.error("HeuristicProvider error", extra={"role": req.role, "error": str(exc)})
            return IntelligenceResult(
                role=req.role,
                provider_used=self.provider_name,
                error=str(exc),
                schema_valid=False,
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def _dispatch(self, role: IntelligenceRole, ctx: dict[str, Any]) -> dict[str, Any]:
        match role:
            case IntelligenceRole.PLANNING:
                return self._planning(ctx)
            case IntelligenceRole.CORRELATION:
                return self._correlation(ctx)
            case IntelligenceRole.VULNERABILITY_REASONING:
                return self._vulnerability_reasoning(ctx)
            case IntelligenceRole.THREAT_INTELLIGENCE:
                return self._threat_intelligence(ctx)
            case IntelligenceRole.FORENSICS_REASONING:
                return self._forensics_reasoning(ctx)
            case IntelligenceRole.REPORT_SYNTHESIS:
                return self._report_synthesis(ctx)
            case IntelligenceRole.QUALITY_REVIEW:
                return self._quality_review(ctx)
            case _:
                raise ValueError(f"Unknown role: {role}")

    def _planning(self, ctx: dict[str, Any]) -> dict[str, Any]:
        targets = ctx.get("targets", [])
        task_id = ctx.get("task_id", "unknown")
        steps: list[dict[str, Any]] = []
        phases: list[str] = []
        for t in targets:
            val = t if isinstance(t, str) else t.get("value", str(t))
            steps.append({"agent": "recon_agent", "action_type": "dns.full_enum",
                          "phase": "RECON_DNS", "justification": f"Baseline DNS for {val}"})
            steps.append({"agent": "recon_agent", "action_type": "http.observe",
                          "phase": "WEB_OBSERVE", "justification": f"HTTP surface for {val}"})
            phases.extend(["RECON_DNS", "WEB_OBSERVE"])
        return {
            "plan_id": f"hplan-{task_id[:8]}",
            "task_id": task_id,
            "steps": steps,
            "reasoning_trace": ["Heuristic planner: phase-based reconnaissance"],
            "is_terminal": len(steps) == 0,
            "confidence_is_sufficient": len(steps) == 0,
            "phases_covered": list(set(phases)),
        }

    def _correlation(self, ctx: dict[str, Any]) -> dict[str, Any]:
        findings = ctx.get("findings", [])
        clusters: list[dict[str, Any]] = []
        asset_map: dict[str, list[str]] = {}
        for f in findings:
            fid = f.get("id", "")
            for asset in f.get("affected_assets", []) or [f.get("target", "unknown")]:
                asset_map.setdefault(asset, []).append(fid)
        seen: set[str] = set()
        for asset, fids in asset_map.items():
            if len(fids) > 1:
                clusters.append({
                    "cluster_id": f"cluster-{asset[:20].replace('.', '-')}",
                    "finding_ids": fids,
                    "narrative": f"Multiple findings share asset '{asset}'.",
                    "shared_assets": [asset],
                })
                seen.update(fids)
        for f in findings:
            fid = f.get("id", "")
            if fid not in seen:
                clusters.append({"cluster_id": f"cluster-solo-{fid[:8]}",
                                  "finding_ids": [fid], "narrative": "Isolated finding.",
                                  "shared_assets": []})
        return {"clusters": clusters, "total_findings_correlated": len(findings)}

    def _vulnerability_reasoning(self, ctx: dict[str, Any]) -> dict[str, Any]:
        cve_ids = ctx.get("cve_ids", [])
        cvss_score = float(ctx.get("cvss_score", 0.0))
        has_exploit = ctx.get("exploit_available", False)
        if cvss_score >= 9.0:
            priority, maturity = "immediate", "weaponized" if has_exploit else "poc"
        elif cvss_score >= 7.0:
            priority, maturity = "high", "functional" if has_exploit else "theoretical"
        elif cvss_score >= 4.0:
            priority, maturity = "medium", "theoretical"
        else:
            priority, maturity = "low", "theoretical"
        return {
            "cve_ids": cve_ids,
            "exploitability_score": min(cvss_score / 10.0, 1.0),
            "exploit_maturity": maturity,
            "remediation_priority": priority,
            "reasoning": f"CVSS {cvss_score:.1f}: {priority} priority, maturity: {maturity}.",
        }

    def _threat_intelligence(self, ctx: dict[str, Any]) -> dict[str, Any]:
        import ipaddress
        import re
        indicator = ctx.get("indicator", "")
        ioc_type = "unknown"
        verdict = "unverified"
        kill_chain = "unknown"
        if re.match(r"^[0-9a-f]{32,64}$", indicator, re.I):
            ioc_type, verdict, kill_chain = "hash", "suspicious", "C2"
        else:
            try:
                ipaddress.ip_address(indicator)
                ioc_type, verdict, kill_chain = "ip", "suspicious", "delivery"
            except ValueError:
                if re.match(r"^[\w.-]+\.[a-z]{2,}$", indicator):
                    ioc_type, verdict, kill_chain = "domain", "suspicious", "C2"
                elif indicator.upper().startswith("CVE-"):
                    ioc_type, verdict, kill_chain = "cve", "confirmed", "exploitation"
        return {
            "ioc_type": ioc_type,
            "verdict": verdict,
            "confidence": 0.7 if verdict == "suspicious" else (1.0 if verdict == "confirmed" else 0.3),
            "threat_actor_hints": [],
            "kill_chain_phase": kill_chain,
        }

    def _forensics_reasoning(self, ctx: dict[str, Any]) -> dict[str, Any]:
        events = ctx.get("timeline_events", [])
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        anomalies = []
        for i in range(1, len(sorted_events)):
            prev, curr = sorted_events[i - 1], sorted_events[i]
            if prev.get("source") != curr.get("source") and curr.get("event_type") == "process_exec":
                anomalies.append(f"Lateral movement: {prev.get('source')} -> {curr.get('source')}")
        return {
            "reconstructed_sequence": [
                {"timestamp": e.get("timestamp", ""), "event": e.get("description", ""),
                 "source": e.get("source", ""), "confidence": 0.85}
                for e in sorted_events
            ],
            "anomalies": anomalies,
            "conclusion": ("Anomalies detected." if anomalies else "No significant anomalies."),
        }

    def _report_synthesis(self, ctx: dict[str, Any]) -> dict[str, Any]:
        objective = ctx.get("task_objective", "security assessment")
        finding_count = ctx.get("total_findings", 0)
        critical_count = ctx.get("critical_count", 0)
        risk_score = float(ctx.get("risk_score", 0.0))
        severity_label = "critical" if critical_count > 0 else ("elevated" if risk_score > 6 else "moderate")
        prose = (
            f"The assessment of '{objective}' identified {finding_count} finding(s), "
            f"reflecting an overall {severity_label} risk posture (score: {risk_score:.1f}/10). "
        )
        if critical_count > 0:
            prose += f"{critical_count} critical issue(s) require immediate remediation. "
        prose += "A phased remediation roadmap is provided in the technical section."
        return {
            "executive_prose": prose,
            "key_risk_statements": [
                f"{critical_count} critical finding(s)" if critical_count else "No critical findings",
                f"Overall risk score: {risk_score:.1f}/10",
            ],
            "remediation_roadmap_summary": "Immediate: Critical. 30 days: High. 90 days: Medium.",
        }

    def _quality_review(self, ctx: dict[str, Any]) -> dict[str, Any]:
        findings = ctx.get("findings", [])
        reviewed: list[dict[str, Any]] = []
        adjustments: list[float] = []
        for f in findings:
            fid = f.get("id", "")
            severity = str(f.get("severity", "low"))
            evidence_refs = f.get("evidence_refs", []) or f.get("evidence_references", []) or []
            cvss = float(f.get("cvss_score", 5.0) or 5.0)
            verdict = "pass"
            flag_reason: str | None = None
            confidence_adjustment = 0.0
            if len(evidence_refs) == 0:
                confidence_adjustment = -0.35
                verdict = "flag"
                flag_reason = "No evidence references - cannot be independently verified."
            elif severity == "critical" and cvss < 7.0:
                confidence_adjustment = -0.20
                verdict = "flag"
                flag_reason = f"Critical severity with CVSS {cvss:.1f} appears overclaimed."
            elif severity == "critical" and len(evidence_refs) == 1:
                confidence_adjustment = -0.10
                verdict = "weak"
                flag_reason = "Critical finding supported by only one evidence artifact."
            reviewed.append({
                "finding_id": fid,
                "verdict": verdict,
                "confidence_adjustment": confidence_adjustment,
                "flag_reason": flag_reason,
            })
            adjustments.append(confidence_adjustment)
        overall = max(0.0, min(1.0, 1.0 + sum(adjustments) / max(len(adjustments), 1)))
        return {
            "reviewed_findings": reviewed,
            "overall_confidence": overall,
            "total_flagged": sum(1 for r in reviewed if r["verdict"] == "flag"),
        }


heuristic_provider = HeuristicProvider()
