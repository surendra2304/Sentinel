"""Sentinel Knowledge Layer & Threat Intelligence Models.

Persistent data models for:
- CVE Records (ID, description, CVSS score/vector, affected products/versions, KEV flag)
- CWE Records (ID, name, description)
- Technology Fingerprints & CPE Mappings
- Threat Indicators (IOCs: IP, Domain, Hash, URL with confidence & feed sources)
- Prior Assessment History
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from sentinel.core.models import SeverityLevel


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    URL = "url"


class CVERecord(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cwe_ids: list[str] = Field(default_factory=list)
    affected_product: str
    affected_version_ranges: list[str] = Field(default_factory=list)
    is_known_exploited: bool = False  # CISA KEV flag
    references: list[str] = Field(default_factory=list)
    published_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CWERecord(BaseModel):
    cwe_id: str
    name: str
    description: str


class ThreatIndicator(BaseModel):
    indicator_type: IOCType
    value: str
    context: str = ""
    source_feed: str
    confidence: float = 1.0
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


class KnowledgeBaseStore:
    """In-memory and persistent storage for CVEs, CWEs, and IOC indicators."""

    def __init__(self):
        self._cves: dict[str, CVERecord] = {}
        self._cwes: dict[str, CWERecord] = {}
        self._iocs: dict[str, ThreatIndicator] = {}

    def add_cve(self, cve: CVERecord) -> None:
        self._cves[cve.cve_id.upper()] = cve

    def get_cve(self, cve_id: str) -> CVERecord | None:
        return self._cves.get(cve_id.upper())

    def list_cves_for_product(self, product_name: str) -> list[CVERecord]:
        prod_clean = product_name.lower().strip()
        return [c for c in self._cves.values() if prod_clean in c.affected_product.lower()]

    def add_ioc(self, ioc: ThreatIndicator) -> None:
        key = f"{ioc.indicator_type.value}:{ioc.value.lower().strip()}"
        self._iocs[key] = ioc

    def query_ioc(self, indicator_type: IOCType, value: str) -> ThreatIndicator | None:
        key = f"{indicator_type.value}:{value.lower().strip()}"
        return self._iocs.get(key)


# Global Knowledge Base Store Singleton
knowledge_base_store = KnowledgeBaseStore()
