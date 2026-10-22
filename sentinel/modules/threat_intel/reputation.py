"""Multi-source reputation scoring and threat actor profiling engine."""

from __future__ import annotations

import time
from collections.abc import Sequence

from sentinel.core.models import RiskTier
from sentinel.modules.threat_intel.ioc_extractor import extract_iocs, is_valid_ipv4
from sentinel.modules.threat_intel.mitre_mapper import MitreMapper
from sentinel.modules.threat_intel.models import (
    IOCType,
    ReputationScore,
    ThreatActor,
    ThreatIntelReport,
)

# Known APT and Cybercrime Groups
KNOWN_THREAT_ACTORS: list[ThreatActor] = [
    ThreatActor(
        name="APT28",
        aliases=["Fancy Bear", "Sednit", "Strontium", "Sofacy"],
        origin="Russian Federation",
        associated_techniques=["T1190", "T1059.001", "T1078", "T1071.001"],
        targeted_sectors=["Defense", "Government", "Aerospace", "Energy"],
        active_years="2004-Present",
        confidence=0.85,
        description="State-sponsored cyber espionage group targeting defense, government, and critical infrastructure.",
    ),
    ThreatActor(
        name="APT29",
        aliases=["Cozy Bear", "Nobelium", "Midnight Blizzard"],
        origin="Russian Federation",
        associated_techniques=["T1078", "T1071.001", "T1027", "T1048"],
        targeted_sectors=["Government", "Diplomatic", "Think Tanks", "Cloud Providers"],
        active_years="2008-Present",
        confidence=0.90,
        description="Highly sophisticated state-sponsored actor known for stealthy supply-chain and cloud token abuse.",
    ),
    ThreatActor(
        name="Lazarus Group",
        aliases=["Hidden Cobra", "Guardians of Peace", "Zinc"],
        origin="DPRK",
        associated_techniques=["T1059.004", "T1486", "T1027", "T1048"],
        targeted_sectors=["Financial", "Cryptocurrency", "Defense", "Media"],
        active_years="2009-Present",
        confidence=0.85,
        description="State-sponsored unit targeting financial networks, cryptocurrency exchanges, and critical infrastructure.",
    ),
    ThreatActor(
        name="Volt Typhoon",
        aliases=["Bronze Silhouette", "Vanguard Panda"],
        origin="China",
        associated_techniques=["T1190", "T1078", "T1046", "T1071.001"],
        targeted_sectors=["Critical Infrastructure", "Telecommunications", "Maritime", "Government"],
        active_years="2021-Present",
        confidence=0.80,
        description="Espionage actor focusing on living-off-the-land techniques and stealth persistence in critical infrastructure.",
    ),
    ThreatActor(
        name="Wizard Spider",
        aliases=["UNC1878", "Conti", "Ryuk"],
        origin="Eastern Europe",
        associated_techniques=["T1486", "T1003", "T1021", "T1059.001"],
        targeted_sectors=["Healthcare", "Local Government", "Manufacturing"],
        active_years="2016-Present",
        confidence=0.85,
        description="Financially motivated ransomware syndicate orchestrating enterprise-wide double-extortion campaigns.",
    ),
]

# Curated Indicators Database
KNOWN_MALICIOUS_HASHES: dict[str, dict[str, str]] = {
    # EICAR standard anti-virus test file
    "44d88612fea8a8f36de82e1278abb02f": {"category": "test-signature", "name": "EICAR Standard Test String"},
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"category": "test-signature", "name": "EICAR Standard SHA256"},
    # WannaCry / Ransomware markers
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": {"category": "ransomware", "name": "WannaCry Dropper"},
}

KNOWN_MALICIOUS_DOMAINS: set[str] = {
    "evil-c2.darknet",
    "badactor-exfil.com",
    "cobaltstrike-listener.xyz",
    "phishing-gateway-verification.ru",
}

KNOWN_MALICIOUS_IPS: set[str] = {
    "198.51.100.200",  # Test C2 IP
    "203.0.113.150",   # Test Scanner IP
}

SAFE_KNOWN_IPS: set[str] = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "127.0.0.1",
}


class ThreatIntelEngine:
    """Production-grade Threat Intelligence and Reputation Engine."""

    def __init__(self, mitre_mapper: MitreMapper | None = None, cache_ttl_seconds: int = 3600):
        self.mitre_mapper = mitre_mapper or MitreMapper()
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, ReputationScore]] = {}

    def score_indicator(self, indicator: str, ioc_type: IOCType) -> ReputationScore:
        """Calculate reputation score and classification for a single indicator."""
        norm_key = f"{ioc_type.value}:{indicator.lower().strip()}"
        now = time.time()

        # Check Cache
        if norm_key in self._cache:
            cached_at, cached_score = self._cache[norm_key]
            if now - cached_at < self.cache_ttl_seconds:
                return cached_score

        clean_val = indicator.lower().strip()
        score = 0.0
        risk_tier = RiskTier.MINIMAL
        is_malicious = False
        categories: list[str] = []
        sources: list[str] = ["sentinel-local-threat-db"]

        if ioc_type in (IOCType.MD5, IOCType.SHA256, IOCType.SHA1):
            if clean_val in KNOWN_MALICIOUS_HASHES:
                meta = KNOWN_MALICIOUS_HASHES[clean_val]
                score = 100.0
                risk_tier = RiskTier.CRITICAL
                is_malicious = True
                categories.append(meta.get("category", "malware"))
            else:
                score = 0.0
                risk_tier = RiskTier.MINIMAL

        elif ioc_type == IOCType.DOMAIN:
            if clean_val in KNOWN_MALICIOUS_DOMAINS:
                score = 95.0
                risk_tier = RiskTier.CRITICAL
                is_malicious = True
                categories.append("command-and-control")
            elif any(clean_val.endswith(f".{d}") for d in KNOWN_MALICIOUS_DOMAINS):
                score = 90.0
                risk_tier = RiskTier.CRITICAL
                is_malicious = True
                categories.append("subdomain-c2")
            elif len(clean_val.split(".")[0]) > 30:
                # Heuristic DGA
                score = 65.0
                risk_tier = RiskTier.MEDIUM
                categories.append("suspicious-dga")
            else:
                score = 5.0
                risk_tier = RiskTier.MINIMAL

        elif ioc_type == IOCType.IPV4:
            if clean_val in KNOWN_MALICIOUS_IPS:
                score = 95.0
                risk_tier = RiskTier.CRITICAL
                is_malicious = True
                categories.append("c2-infrastructure")
            elif clean_val in SAFE_KNOWN_IPS:
                score = 0.0
                risk_tier = RiskTier.MINIMAL
                categories.append("trusted-resolver")
            elif is_valid_ipv4(clean_val) and clean_val.startswith(("10.", "192.168.", "172.16.")):
                score = 5.0
                risk_tier = RiskTier.MINIMAL
                categories.append("rfc1918-private")
            else:
                score = 10.0
                risk_tier = RiskTier.LOW

        elif ioc_type == IOCType.CVE:
            # High base severity for known CVEs
            score = 80.0
            risk_tier = RiskTier.HIGH
            is_malicious = True
            categories.append("known-vulnerability")

        rep = ReputationScore(
            indicator=indicator,
            ioc_type=ioc_type,
            score=round(score, 1),
            risk_tier=risk_tier,
            is_malicious=is_malicious,
            categories=categories,
            sources=sources,
        )

        self._cache[norm_key] = (now, rep)
        return rep

    def correlate_actors(self, techniques: Sequence[str]) -> list[ThreatActor]:
        """Identify threat actors overlapping with identified MITRE techniques."""
        if not techniques:
            return []

        matched_actors: list[ThreatActor] = []
        tech_set = set(techniques)

        for actor in KNOWN_THREAT_ACTORS:
            overlap = tech_set.intersection(set(actor.associated_techniques))
            if overlap:
                overlap_ratio = len(overlap) / max(1, len(actor.associated_techniques))
                matched_actors.append(
                    ThreatActor(
                        name=actor.name,
                        aliases=actor.aliases,
                        origin=actor.origin,
                        associated_techniques=actor.associated_techniques,
                        targeted_sectors=actor.targeted_sectors,
                        active_years=actor.active_years,
                        confidence=round(min(0.95, 0.4 + (overlap_ratio * 0.5)), 2),
                        description=actor.description,
                    )
                )

        # Sort descending by confidence
        matched_actors.sort(key=lambda a: a.confidence, reverse=True)
        return matched_actors

    def analyze_text(self, text: str) -> ThreatIntelReport:
        """Full-pipeline threat intelligence analysis on raw text."""
        iocs = extract_iocs(text)
        techniques = self.mitre_mapper.map_text(text)
        tech_ids = [t.id for t in techniques]
        actors = self.correlate_actors(tech_ids)

        reputations: list[ReputationScore] = []
        for ioc in iocs:
            rep = self.score_indicator(ioc.normalized_value or ioc.value, ioc.ioc_type)
            reputations.append(rep)

        # Compute overall score
        max_rep_score = max([r.score for r in reputations], default=0.0)
        technique_score = min(60.0, len(techniques) * 15.0)
        overall_score = round(max(max_rep_score, technique_score), 1)

        if overall_score >= 80.0:
            tier = RiskTier.CRITICAL
        elif overall_score >= 60.0:
            tier = RiskTier.HIGH
        elif overall_score >= 35.0:
            tier = RiskTier.MEDIUM
        elif overall_score >= 15.0:
            tier = RiskTier.LOW
        else:
            tier = RiskTier.MINIMAL

        summary = (
            f"Threat assessment identified {len(iocs)} IOCs, {len(techniques)} MITRE techniques, "
            f"and correlated {len(actors)} potential threat actors. Overall score: {overall_score} ({tier.value})."
        )

        return ThreatIntelReport(
            iocs=iocs,
            mitre_techniques=techniques,
            actors=actors,
            reputations=reputations,
            overall_threat_score=overall_score,
            overall_risk_tier=tier,
            summary=summary,
        )
