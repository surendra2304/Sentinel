"""IntelX Threat Research Client and Cache Service."""

from datetime import UTC, datetime, timedelta

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

        # Real research path: query the live IntelX knowledge base (verified claims corpus).
        result = await self._query_intelx_live(norm_query, now)
        if result is None:
            # Fallback ONLY when IntelX is unreachable: conservative heuristic estimate.
            result = self._heuristic_estimate(norm_query, now)

        self.cache[norm_query] = result
        return result

    async def _query_intelx_live(self, norm_query: str, now: datetime) -> IntelXResearchResult | None:
        """Query the real IntelX service knowledge base for verified security claims."""
        import os
        import re

        base_url = os.getenv("INTELX_URL", "").rstrip("/")
        api_key = os.getenv("INTELX_API_KEY", "")
        if not base_url:
            return None

        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", norm_query)
        question = (
            f"Exploitation status, threat actors, and patch availability for {cve_match.group(0)}"
            if cve_match
            else f"Exploitation status and patch availability for {norm_query}"
        )

        payload = {"q": question, "kinds": ["claim", "source"], "limit": 10}
        headers = {"Authorization": f"Bearer {api_key}", "X-API-KEY": api_key}
        candidates = [f"{base_url}/api/v1/knowledge/query", f"{base_url}/v1/knowledge/query"]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=8.0) as client:
                body = None
                for url in candidates:
                    try:
                        resp = await client.post(url, json=payload, headers=headers)
                        if resp.status_code == 200:
                            body = resp.json()
                            break
                    except Exception:
                        continue
                if body is None:
                    return None
        except Exception:
            return None

        claims = body.get("results") or body.get("claims") or []
        citations: list[str] = []
        exploit_signals = 0
        patch_signals = 0
        actor_names: set[str] = set()

        for item in claims:
            text_blob = " ".join(
                str(item.get(k, "")) for k in ("text", "quote", "summary", "title")
            ).lower()
            source_ref = item.get("source_title") or item.get("source_url") or "IntelX verified claim"
            if text_blob:
                citations.append(str(source_ref))
            if any(w in text_blob for w in ("actively exploited", "in the wild", "exploitation observed", "ransomware")):
                exploit_signals += 1
            if any(w in text_blob for w in ("no patch", "unpatched", "no fix available")):
                patch_signals -= 1
            elif any(w in text_blob for w in ("patch released", "patched", "fix available", "upgrade to")):
                patch_signals += 1
            m = re.findall(r"(apt\s?\d+|lazarus group|sandworm|fancy bear|lockbit|cl0p|advpci)", text_blob)
            actor_names.update(a.upper() for a in m)

        if not citations:
            # IntelX reachable but no verified claims — treat as no evidence (not fake data).
            return IntelXResearchResult(
                query=norm_query,
                exploitation_active=False,
                threat_actors=[],
                patch_available=True,
                urgency_multiplier=1.0,
                citations=["IntelX knowledge query returned no verified claims"],
                researched_at=now,
                cached=False,
            )

        return IntelXResearchResult(
            query=norm_query,
            exploitation_active=exploit_signals > 0,
            threat_actors=sorted(actor_names)[:5],
            patch_available=patch_signals >= 0,
            urgency_multiplier=2.0 if (exploit_signals > 0 and patch_signals < 0) else (1.5 if exploit_signals > 0 else 1.0),
            citations=citations[:5],
            researched_at=now,
            cached=False,
        )

    def _heuristic_estimate(self, norm_query: str, now: datetime) -> IntelXResearchResult:
        """Last-resort offline estimate, clearly flagged as heuristic."""
        is_active = "CVE-2024-" in norm_query or "LOG4SHELL" in norm_query or "CRITICAL" in norm_query
        actors = ["APT28", "Lazarus Group"] if is_active else []
        urgency = 2.0 if (is_active and "NO PATCH" in norm_query) else (1.5 if is_active else 1.0)
        return IntelXResearchResult(
            query=norm_query,
            exploitation_active=is_active,
            threat_actors=actors,
            patch_available="NO PATCH" not in norm_query,
            urgency_multiplier=urgency,
            citations=["Offline heuristic estimate — IntelX service unreachable"],
            researched_at=now,
            cached=False,
        )


intelx_research_client = IntelXResearchClient()
