import pytest

from sentinel.core.models import (
    AssetCriticality,
    Finding,
    SeverityLevel,
)
from sentinel.intelligence.attack_paths.analyzer import AttackPathAnalyzer
from sentinel.intelligence.correlation.engine import FindingCorrelationEngine
from sentinel.intelligence.recommendations.engine import RecommendationEngine
from sentinel.modules.recon.graph import AssetGraphStore, EdgeType, NodeType


@pytest.fixture
def synthetic_attack_scenario():
    """Builds synthetic scenario: exposed web app + vulnerable dependency -> internal critical DB."""
    # 1. Build AssetGraph
    graph = AssetGraphStore()
    web_node = graph.add_node(
        task_id="task-scenario",
        node_type=NodeType.DOMAIN,
        label="app.example.com",
        criticality=AssetCriticality.MEDIUM,
        is_internet_facing=True,
    )
    db_node = graph.add_node(
        task_id="task-scenario",
        node_type=NodeType.SERVICE,
        label="db-cluster.internal",
        criticality=AssetCriticality.CRITICAL,
        is_internet_facing=False,
    )
    graph.add_edge("task-scenario", web_node.id, db_node.id, EdgeType.RUNS_SERVICE)

    # 2. Build Findings
    f1 = Finding(
        id="f-web-01",
        task_id="task-scenario",
        title="Apache Struts Remote Code Execution",
        description="Outdated Struts framework vulnerable to RCE.",
        severity=SeverityLevel.CRITICAL,
        target_ref=web_node.id,
        related_cves=["CVE-2017-5638"],
        evidence_refs=["evi-01"],
        remediation="Upgrade Apache Struts to latest version.",
    )
    f2 = Finding(
        id="f-web-02",
        task_id="task-scenario",
        title="Missing Security Headers on Public Endpoint",
        description="Strict-Transport-Security header missing.",
        severity=SeverityLevel.MEDIUM,
        target_ref=web_node.id,
        evidence_refs=["evi-02"],
        remediation="Add Strict-Transport-Security header to responses.",
    )

    return graph, [f1, f2], web_node, db_node


def test_finding_correlation_clustering(synthetic_attack_scenario):
    _, findings, web_node, _ = synthetic_attack_scenario
    engine = FindingCorrelationEngine()
    clusters = engine.cluster_findings(findings)

    assert len(clusters) == 1
    c = clusters[0]
    assert c.target_ref == web_node.id
    assert c.findings_count == 2
    assert c.highest_severity == SeverityLevel.CRITICAL
    assert "CVE-2017-5638" in c.shared_cves
    assert c.correlated_risk_multiplier > 1.0


def test_attack_path_analysis_traversal(synthetic_attack_scenario):
    graph, findings, web_node, db_node = synthetic_attack_scenario
    analyzer = AttackPathAnalyzer()
    paths = analyzer.analyze_paths(graph, findings)

    assert len(paths) == 1
    p = paths[0]
    assert p.entry_point == web_node.id
    assert p.target_crown_jewel == db_node.id
    assert p.total_steps == 2
    assert p.steps[0].supporting_finding_ids == ["f-web-01", "f-web-02"]


def test_remediation_recommendations_generation(synthetic_attack_scenario):
    graph, findings, _, _ = synthetic_attack_scenario
    analyzer = AttackPathAnalyzer()
    paths = analyzer.analyze_paths(graph, findings)

    rec_engine = RecommendationEngine()
    recs = rec_engine.generate_recommendations(findings, paths)

    assert len(recs) == 2
    r1 = next(r for r in recs if "Struts" in r.title)
    assert r1.priority == "P1"
    assert "vulnerability.correlate" in r1.verification_check_action
    assert len(r1.compensating_control) > 0
