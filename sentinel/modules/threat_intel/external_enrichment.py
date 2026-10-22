"""External Threat Intelligence & Vulnerability Enrichment Services.

Integrates Shodan, VirusTotal, and NVD (National Vulnerability Database) APIs
using configured API keys with caching, circuit breakers, and offline safety.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from sentinel.config.settings import get_settings
from sentinel.core.cache.ttl_lru_cache import TTLLRUCache

logger = logging.getLogger("sentinel.threat_intel.external")


class ExternalEnrichmentResult(BaseModel):
    """Normalized enrichment data from external intelligence providers."""

    provider: str
    target: str
    target_type: str  # ip | domain | hash | cve
    status: str  # SUCCESS | CACHED | SKIPPED | ERROR
    data: dict[str, Any] = Field(default_factory=dict)
    reputation_score: float = 0.0  # 0.0 (safe) to 1.0 (hostile)
    threat_verdict: str = "UNKNOWN"  # BENIGN | SUSPICIOUS | MALICIOUS | UNKNOWN
    error_message: str | None = None


class ExternalThreatIntelEnricher:
    """Orchestrator for Shodan, VirusTotal, and NVD lookups."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._cache: TTLLRUCache[str, ExternalEnrichmentResult] = TTLLRUCache(
            maxsize=2000, ttl_seconds=3600.0
        )

    # ── Shodan IP & Host Telemetry ──────────────────────────────────────────
    async def enrich_ip_shodan(self, ip: str, client: httpx.AsyncClient | None = None) -> ExternalEnrichmentResult:
        """Query Shodan for exposed ports, vulnerabilities, and services for an authorized IP."""
        cache_key = f"shodan:{ip}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        api_key = self.settings.shodan_api_key.get_secret_value()
        if not api_key:
            return ExternalEnrichmentResult(
                provider="shodan",
                target=ip,
                target_type="ip",
                status="SKIPPED",
                threat_verdict="UNKNOWN",
                error_message="Shodan API key is not configured.",
            )

        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            close_client = False
            if client is None:
                client = httpx.AsyncClient(timeout=8.0)
                close_client = True

            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = list(data.get("vulns", []))
                    score = min(1.0, (len(ports) * 0.05) + (len(vulns) * 0.25))
                    verdict = "MALICIOUS" if len(vulns) > 0 else ("SUSPICIOUS" if len(ports) > 5 else "BENIGN")

                    res = ExternalEnrichmentResult(
                        provider="shodan",
                        target=ip,
                        target_type="ip",
                        status="SUCCESS",
                        data={"ports": ports, "vulns": vulns, "org": data.get("org", ""), "os": data.get("os")},
                        reputation_score=round(score, 2),
                        threat_verdict=verdict,
                    )
                    self._cache.set(cache_key, res)
                    return res
                elif resp.status_code == 404:
                    res = ExternalEnrichmentResult(
                        provider="shodan",
                        target=ip,
                        target_type="ip",
                        status="SUCCESS",
                        data={"ports": [], "vulns": []},
                        reputation_score=0.0,
                        threat_verdict="BENIGN",
                    )
                    self._cache.set(cache_key, res)
                    return res
                else:
                    return ExternalEnrichmentResult(
                        provider="shodan",
                        target=ip,
                        target_type="ip",
                        status="ERROR",
                        error_message=f"Shodan returned HTTP {resp.status_code}: {resp.text[:100]}",
                    )
            finally:
                if close_client:
                    await client.aclose()
        except Exception as exc:
            logger.warning(f"Shodan enrichment failed for {ip}: {exc}")
            return ExternalEnrichmentResult(
                provider="shodan",
                target=ip,
                target_type="ip",
                status="ERROR",
                error_message=str(exc),
            )

    # ── VirusTotal Binary & Hash Reputation ──────────────────────────────────
    async def enrich_hash_virustotal(
        self, file_hash: str, client: httpx.AsyncClient | None = None
    ) -> ExternalEnrichmentResult:
        """Query VirusTotal v3 for file hash malware detection rates."""
        cache_key = f"vt:{file_hash.lower()}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        api_key = self.settings.virustotal_api_key.get_secret_value()
        if not api_key:
            return ExternalEnrichmentResult(
                provider="virustotal",
                target=file_hash,
                target_type="hash",
                status="SKIPPED",
                threat_verdict="UNKNOWN",
                error_message="VirusTotal API key is not configured.",
            )

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        try:
            close_client = False
            if client is None:
                client = httpx.AsyncClient(timeout=8.0)
                close_client = True

            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    payload = resp.json()
                    attr = payload.get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)
                    total = malicious + suspicious + undetected + harmless or 1

                    score = min(1.0, (malicious * 1.0 + suspicious * 0.5) / total)
                    verdict = "MALICIOUS" if malicious > 2 else ("SUSPICIOUS" if (malicious > 0 or suspicious > 2) else "BENIGN")

                    res = ExternalEnrichmentResult(
                        provider="virustotal",
                        target=file_hash,
                        target_type="hash",
                        status="SUCCESS",
                        data={
                            "malicious_count": malicious,
                            "suspicious_count": suspicious,
                            "stats": stats,
                            "meaningful_name": attr.get("meaningful_name", ""),
                        },
                        reputation_score=round(score, 2),
                        threat_verdict=verdict,
                    )
                    self._cache.set(cache_key, res)
                    return res
                elif resp.status_code == 404:
                    res = ExternalEnrichmentResult(
                        provider="virustotal",
                        target=file_hash,
                        target_type="hash",
                        status="SUCCESS",
                        data={"malicious_count": 0, "not_found": True},
                        reputation_score=0.0,
                        threat_verdict="UNKNOWN",
                    )
                    self._cache.set(cache_key, res)
                    return res
                else:
                    return ExternalEnrichmentResult(
                        provider="virustotal",
                        target=file_hash,
                        target_type="hash",
                        status="ERROR",
                        error_message=f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:100]}",
                    )
            finally:
                if close_client:
                    await client.aclose()
        except Exception as exc:
            logger.warning(f"VirusTotal enrichment failed for {file_hash}: {exc}")
            return ExternalEnrichmentResult(
                provider="virustotal",
                target=file_hash,
                target_type="hash",
                status="ERROR",
                error_message=str(exc),
            )

    # ── NVD CVE Vulnerability Enrichment ─────────────────────────────────────
    async def enrich_cve_nvd(self, cve_id: str, client: httpx.AsyncClient | None = None) -> ExternalEnrichmentResult:
        """Query NVD REST API 2.0 with authorized API key for official CVSS vectors & metrics."""
        clean_cve = cve_id.strip().upper()
        cache_key = f"nvd:{clean_cve}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        api_key = self.settings.nvd_api_key.get_secret_value()
        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={clean_cve}"
        try:
            close_client = False
            if client is None:
                client = httpx.AsyncClient(timeout=8.0)
                close_client = True

            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    payload = resp.json()
                    vulnerabilities = payload.get("vulnerabilities", [])
                    if not vulnerabilities:
                        res = ExternalEnrichmentResult(
                            provider="nvd",
                            target=clean_cve,
                            target_type="cve",
                            status="SUCCESS",
                            data={"found": False},
                            reputation_score=0.0,
                            threat_verdict="BENIGN",
                        )
                        self._cache.set(cache_key, res)
                        return res

                    cve_item = vulnerabilities[0].get("cve", {})
                    metrics = cve_item.get("metrics", {})
                    cvss_data: dict[str, Any] = {}
                    cvss_score = 0.0

                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))

                    descriptions = cve_item.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else ""

                    verdict = "MALICIOUS" if cvss_score >= 7.0 else ("SUSPICIOUS" if cvss_score >= 4.0 else "BENIGN")

                    res = ExternalEnrichmentResult(
                        provider="nvd",
                        target=clean_cve,
                        target_type="cve",
                        status="SUCCESS",
                        data={
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_data.get("vectorString", ""),
                            "description": desc_text[:300],
                            "published": cve_item.get("published"),
                        },
                        reputation_score=round(cvss_score / 10.0, 2),
                        threat_verdict=verdict,
                    )
                    self._cache.set(cache_key, res)
                    return res
                else:
                    return ExternalEnrichmentResult(
                        provider="nvd",
                        target=clean_cve,
                        target_type="cve",
                        status="ERROR",
                        error_message=f"NVD returned HTTP {resp.status_code}: {resp.text[:100]}",
                    )
            finally:
                if close_client:
                    await client.aclose()
        except Exception as exc:
            logger.warning(f"NVD enrichment failed for {clean_cve}: {exc}")
            return ExternalEnrichmentResult(
                provider="nvd",
                target=clean_cve,
                target_type="cve",
                status="ERROR",
                error_message=str(exc),
            )


external_threat_enricher = ExternalThreatIntelEnricher()
