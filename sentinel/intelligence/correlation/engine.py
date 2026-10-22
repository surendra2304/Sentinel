"""Cross-Domain Finding Correlation Engine for Sentinel.

Groups isolated findings across Recon, Network, Web, Cloud, and DFIR into correlated clusters
sharing common assets, CVEs, or attack narratives.
"""

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, SeverityLevel


class CorrelatedFindingCluster(BaseModel):
    cluster_id: str
    target_ref: str
    findings_count: int
    findings: list[Finding]
    highest_severity: SeverityLevel
    shared_cves: list[str] = Field(default_factory=list)
    narrative: str
    correlated_risk_multiplier: float = 1.0


class FindingCorrelationEngine:
    """Aggregates and clusters findings into contextual vulnerability groups."""

    def cluster_findings(self, findings: list[Finding]) -> list[CorrelatedFindingCluster]:
        clusters_by_target: dict[str, list[Finding]] = {}

        for f in findings:
            target = f.target_ref or "global_target"
            if target not in clusters_by_target:
                clusters_by_target[target] = []
            clusters_by_target[target].append(f)

        result_clusters: list[CorrelatedFindingCluster] = []

        for idx, (target, target_findings) in enumerate(clusters_by_target.items()):
            # Collect shared CVEs or indicators
            cves: list[str] = []
            for tf in target_findings:
                for c in tf.related_cves:
                    if c not in cves:
                        cves.append(c)

            highest_sev = SeverityLevel.INFO
            for tf in target_findings:
                if tf.severity == SeverityLevel.CRITICAL:
                    highest_sev = SeverityLevel.CRITICAL
                    break
                elif tf.severity == SeverityLevel.HIGH and highest_sev != SeverityLevel.CRITICAL:
                    highest_sev = SeverityLevel.HIGH
                elif tf.severity == SeverityLevel.MEDIUM and highest_sev not in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                    highest_sev = SeverityLevel.MEDIUM
                elif tf.severity == SeverityLevel.LOW and highest_sev == SeverityLevel.INFO:
                    highest_sev = SeverityLevel.LOW

            # Synthesize attack narrative
            narrative = (
                f"Asset '{target}' presents {len(target_findings)} correlated finding(s). "
                f"Combines exposure with known vulnerabilities ({', '.join(cves) if cves else 'Configuration weaknesses'})."
            )

            multiplier = 1.0 + (0.25 * len(target_findings))

            cluster = CorrelatedFindingCluster(
                cluster_id=f"cluster-{idx+1}",
                target_ref=target,
                findings_count=len(target_findings),
                findings=target_findings,
                highest_severity=highest_sev,
                shared_cves=cves,
                narrative=narrative,
                correlated_risk_multiplier=multiplier,
            )
            result_clusters.append(cluster)

        return result_clusters


# Global Finding Correlation Engine Singleton
finding_correlation_engine = FindingCorrelationEngine()


class AssetVulnerabilityCorrelator:
    """Correlates newly published CVEs against asset fingerprints and exposure metrics."""

    @staticmethod
    def evaluate_cve_asset_risk(
        cve_id: str,
        asset_target: str,
        software_version: str,
        is_publicly_exposed: bool = True,
        is_auth_required: bool = False,
        vulnerable_config_present: bool = True,
    ) -> dict:
        from sentinel.integrations.threat_feeds.feeds import threat_feed_sync
        feed_ctx = threat_feed_sync.correlate_cve(cve_id)

        # Exposure multiplier
        exposure_factor = 1.0 if is_publicly_exposed else 0.5
        auth_factor = 0.6 if is_auth_required else 1.0
        config_factor = 1.0 if vulnerable_config_present else 0.2

        exploitability = 1.0 if feed_ctx.exploit_available else (1.5 if feed_ctx.in_cisa_kev else 0.7)

        # Asset-specific risk score (0 - 100)
        computed_risk = round(feed_ctx.cvss_base * 10 * exposure_factor * auth_factor * config_factor * exploitability, 1)
        computed_risk = min(100.0, computed_risk)

        is_confirmed = vulnerable_config_present and (is_publicly_exposed or not is_auth_required)

        return {
            "cve_id": cve_id,
            "target": asset_target,
            "software_version": software_version,
            "adjusted_severity": feed_ctx.adjusted_severity.value,
            "asset_risk_score": computed_risk,
            "is_confirmed_vulnerable": is_confirmed,
            "in_cisa_kev": feed_ctx.in_cisa_kev,
            "exploit_available": feed_ctx.exploit_available,
        }


asset_vulnerability_correlator = AssetVulnerabilityCorrelator()

