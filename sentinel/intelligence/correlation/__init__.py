"""Multi-source evidence correlation and deduplication engines."""

from sentinel.intelligence.correlation.engine import (
    AssetVulnerabilityCorrelator,
    CorrelatedFindingCluster,
    FindingCorrelationEngine,
    asset_vulnerability_correlator,
    finding_correlation_engine,
)

__all__ = [
    "AssetVulnerabilityCorrelator",
    "CorrelatedFindingCluster",
    "FindingCorrelationEngine",
    "asset_vulnerability_correlator",
    "finding_correlation_engine",
]

