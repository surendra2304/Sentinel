"""Threat Context Enrichment using IntelX Research Client."""

from typing import Any
from sentinel.integrations.intelx_client import intelx_research_client, IntelXResearchResult


class ThreatContextEnricher:
    """Enriches Sentinel findings with deep threat actor and active exploitation intelligence."""

    @staticmethod
    async def enrich_finding_with_research(cve_or_finding_title: str, force: bool = False) -> dict[str, Any]:
        research: IntelXResearchResult = await intelx_research_client.submit_research(cve_or_finding_title, force=force)

        return {
            "exploitation_active": research.exploitation_active,
            "threat_actors": research.threat_actors,
            "patch_available": research.patch_available,
            "urgency_multiplier": research.urgency_multiplier,
            "citations": research.citations,
            "cached": research.cached,
        }


threat_context_enricher = ThreatContextEnricher()