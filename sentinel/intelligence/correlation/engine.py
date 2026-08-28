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
