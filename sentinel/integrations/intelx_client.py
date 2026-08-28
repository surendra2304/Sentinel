"""IntelX Threat Research Client and Cache Service."""

from datetime import UTC, datetime, timedelta
from typing import Any
from pydantic import BaseModel, Field


class IntelXResearchResult(BaseModel):
    query: str
    exploitation_active: bool = False
    threat_actors: list[str] = Field(default_factory=list)
    patch_available: bool = True
    urgency_multiplier: float = 1.0
    citations: list[str] = Field(default_factory=list)
    researched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False


class IntelXResearchClient:
    """Client for submitting deep security research questions and caching results."""

    def __init__(self, cache_days: int = 7):
        self.cache_ttl = timedelta(days=cache_days)
        self.cache: dict[str, IntelXResearchResult] = {}

    async def submit_research(self, query: str, force: bool = False) -> IntelXResearchResult:
        now = datetime.now(UTC)
        norm_query = query.strip().upper()

        if not force and norm_query in self.cache:
            entry = self.cache[norm_query]
            if now - entry.researched_at < self.cache_ttl:
                entry_copy = entry.model_copy()
                entry_copy.cached = True
                return entry_copy

        # Mock / Deterministic research result for IntelX questions
        is_active = "CVE-2024-" in norm_query or "LOG4SHELL" in norm_query or "CRITICAL" in norm_query
        actors = ["APT28", "Lazarus Group"] if is_active else []
        urgency = 2.0 if (is_active and "NO PATCH" in norm_query) else (1.5 if is_active else 1.0)
        citations = [
            f"IntelX Threat DB Reference for {norm_query}",
            "CISA Known Exploited Vulnerabilities Catalog",
        ]

        result = IntelXResearchResult(
            query=norm_query,
            exploitation_active=is_active,
            threat_actors=actors,
            patch_available=not ("NO PATCH" in norm_query),
            urgency_multiplier=urgency,
            citations=citations,
            researched_at=now,
            cached=False,
        )

        self.cache[norm_query] = result
        return result


intelx_research_client = IntelXResearchClient()