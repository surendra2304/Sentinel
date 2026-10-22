"""Threat intelligence aggregation (MISP, AlienVault, MITRE ATT&CK) and IOC extraction."""

from sentinel.modules.threat_intel.adapters import ThreatIntelAdapter
from sentinel.modules.threat_intel.external_enrichment import (
    ExternalEnrichmentResult,
    ExternalThreatIntelEnricher,
    external_threat_enricher,
)
from sentinel.modules.threat_intel.ioc_extractor import (
    defang_ioc,
    extract_iocs,
    is_valid_ipv4,
    is_valid_ipv6,
    refang_ioc,
)
from sentinel.modules.threat_intel.mitre_mapper import ENTERPRISE_TACTICS, MitreMapper
from sentinel.modules.threat_intel.models import (
    IOCItem,
    IOCType,
    MitreTactic,
    MitreTechnique,
    ReputationScore,
    ThreatActor,
    ThreatIntelReport,
)
from sentinel.modules.threat_intel.reputation import KNOWN_THREAT_ACTORS, ThreatIntelEngine

__version__ = "0.1.0"

__all__ = [
    "ENTERPRISE_TACTICS",
    "ExternalEnrichmentResult",
    "ExternalThreatIntelEnricher",
    "IOCItem",
    "IOCType",
    "KNOWN_THREAT_ACTORS",
    "MitreMapper",
    "MitreTactic",
    "MitreTechnique",
    "ReputationScore",
    "ThreatActor",
    "ThreatIntelAdapter",
    "ThreatIntelEngine",
    "ThreatIntelReport",
    "defang_ioc",
    "external_threat_enricher",
    "extract_iocs",
    "is_valid_ipv4",
    "is_valid_ipv6",
    "refang_ioc",
]
