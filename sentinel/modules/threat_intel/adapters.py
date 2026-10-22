"""Tool adapter integrating Threat Intelligence into Sentinel's Orchestration Engine."""

from __future__ import annotations

import json
import time

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter
from sentinel.modules.threat_intel.ioc_extractor import extract_iocs
from sentinel.modules.threat_intel.models import IOCType
from sentinel.modules.threat_intel.reputation import ThreatIntelEngine


class ThreatIntelAdapter(ToolAdapter):
    """Adapter exposing Threat Intelligence capabilities to the Sentinel Task Orchestrator."""

    def __init__(self, engine: ThreatIntelEngine | None = None) -> None:
        self.engine = engine or ThreatIntelEngine()
        self.mitre_mapper = self.engine.mitre_mapper

    @property
    def name(self) -> str:
        return "threat_intel_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return [
            "threat_intel.extract_iocs",
            "threat_intel.map_mitre",
            "threat_intel.score_reputation",
            "threat_intel.analyze_threat",
        ]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if action.action_type == "threat_intel.score_reputation":
            if not action.parameters.get("indicator"):
                return False, "Parameter 'indicator' is required for reputation scoring."
        else:
            if not action.parameters.get("text") and not action.target_refs:
                return False, "Parameter 'text' or at least one target_ref is required."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        action_type = action.action_type
        params = action.parameters

        text = params.get("text") or ("\n".join(action.target_refs) if action.target_refs else "")

        if action_type == "threat_intel.extract_iocs":
            iocs = extract_iocs(text)
            data = {"extracted_iocs": [i.model_dump() for i in iocs], "count": len(iocs)}
            summary = f"Extracted {len(iocs)} indicators of compromise."

        elif action_type == "threat_intel.map_mitre":
            techniques = self.mitre_mapper.map_text(text)
            data = {
                "mitre_techniques": [t.model_dump() for t in techniques],
                "count": len(techniques),
            }
            summary = f"Mapped {len(techniques)} MITRE ATT&CK techniques from behavioral signals."

        elif action_type == "threat_intel.score_reputation":
            indicator = str(params.get("indicator", ""))
            ioc_type_str = str(params.get("ioc_type", "domain")).lower()
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                ioc_type = IOCType.DOMAIN

            rep = self.engine.score_indicator(indicator, ioc_type)
            data = {"reputation": rep.model_dump()}
            summary = f"Scored indicator {indicator}: {rep.score}/100 ({rep.risk_tier.value})."

        elif action_type == "threat_intel.analyze_threat":
            report = self.engine.analyze_text(text)
            data = report.model_dump()
            summary = report.summary

        else:
            duration = time.time() - start_time
            return (
                ActionResult(
                    action_id=action.id,
                    task_id=action.task_id,
                    success=False,
                    output_summary=f"Unknown capability: {action_type}",
                    duration_seconds=duration,
                    error_info={"error": f"Unsupported action type: {action_type}"},
                ),
                b"{}",
                "application/json",
            )

        duration = time.time() - start_time
        raw_bytes = json.dumps(data, default=str).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=duration,
        )
        return result, raw_bytes, "application/json"
