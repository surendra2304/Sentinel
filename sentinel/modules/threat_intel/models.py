"""Data models for Sentinel Threat Intelligence Module."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import RiskTier, SeverityLevel


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class IOCItem(BaseModel):
    """An individual extracted or normalized Indicator of Compromise."""

    value: str
    ioc_type: IOCType
    context: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    is_defanged: bool = False
    normalized_value: str = ""


class MitreTactic(BaseModel):
    """MITRE ATT&CK Tactic definition."""

    id: str
    name: str
    description: str


class MitreTechnique(BaseModel):
    """MITRE ATT&CK Technique definition and match evidence."""

    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    matched_patterns: list[str] = Field(default_factory=list)


class ThreatActor(BaseModel):
    """Known Advanced Persistent Threat (APT) or cybercrime group profile."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    origin: str = "Unknown"
    associated_techniques: list[str] = Field(default_factory=list)
    targeted_sectors: list[str] = Field(default_factory=list)
    active_years: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = ""


class ReputationScore(BaseModel):
    """Reputation evaluation for an indicator (IP, domain, hash, URL)."""

    indicator: str
    ioc_type: IOCType
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_tier: RiskTier = RiskTier.MINIMAL
    is_malicious: bool = False
    categories: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelReport(BaseModel):
    """Consolidated threat intelligence assessment."""

    iocs: list[IOCItem] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    actors: list[ThreatActor] = Field(default_factory=list)
    reputations: list[ReputationScore] = Field(default_factory=list)
    overall_threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    overall_risk_tier: RiskTier = RiskTier.MINIMAL
    summary: str = ""
