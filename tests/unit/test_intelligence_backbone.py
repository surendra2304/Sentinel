import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    AssetCriticality,
    FindingStatus,
    RiskTier,
    SeverityLevel,
)
from sentinel.intelligence.risk.finding_engine import FindingEngine, Observation
from sentinel.intelligence.risk.risk_engine import RiskEngine
from sentinel.storage.artifacts.storage import LocalFileSystemStorage
from sentinel.storage.evidence.store import EvidenceStore

# ---------------------------------------------------------------------------
# 1. Evidence Store & Forensics Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evidence_store_integrity_and_chain_of_custody(tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path / "artifacts"))
    audit = AuditLogger(log_path=str(tmp_path / "audit.jsonl"), signing_key="test-key")
    store = EvidenceStore(storage=storage, audit_logger=audit)

    raw_payload = b"NMAP XML SCAN OUTPUT 192.168.1.1"
    evidence = await store.record_evidence(
        task_id="task-evi-01",
        target_ref="192.168.1.1",
        source_agent="recon_agent",
        source_module="network",
        source_tool="nmap",
        raw_data=raw_payload,
        collected_by="operator_alice",
    )

    assert evidence.id.startswith("evi-")
    assert len(evidence.chain_of_custody) == 1
    assert evidence.chain_of_custody[0].actor == "operator_alice"
    assert evidence.chain_of_custody[0].action == "COLLECTION"

    # Read back evidence with access logging
    retrieved_evi, data = await store.get_evidence(evidence.id, actor="forensic_analyst_bob")
    assert data == raw_payload
    assert len(retrieved_evi.chain_of_custody) == 2
    assert retrieved_evi.chain_of_custody[1].actor == "forensic_analyst_bob"
    assert retrieved_evi.chain_of_custody[1].action == "ACCESS"

    # Export hash-verified bundle
    bundle = await store.export_evidence_bundle(task_id="task-evi-01", exported_by="lead_auditor")
    assert bundle["evidence_count"] == 1
    assert "bundle_sha256_digest" in bundle
    assert bundle["manifest"][0]["sha256_hash"] == evidence.sha256_hash


# ---------------------------------------------------------------------------
# 2. Finding Engine & Deduplication Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_finding_engine_deduplication_and_lifecycle(tmp_path):
    audit = AuditLogger(log_path=str(tmp_path / "audit.jsonl"), signing_key="test-key")
    engine = FindingEngine(audit_logger=audit)

    # Observation from Tool 1 (Nmap)
    obs1 = Observation(
        task_id="task-find-01",
        target_ref="10.0.0.15",
        source_module="network",
        title="Exposed Insecure Telnet Port 23",
        description="Telnet daemon running with plaintext transport.",
        severity=SeverityLevel.HIGH,
        confidence=0.9,
        evidence_refs=["evi-tool1-001"],
        related_cves=["CVE-1999-0513"],
    )
    finding1 = await engine.ingest_observation(obs1)
    assert finding1.status == FindingStatus.OPEN
    assert finding1.evidence_refs == ["evi-tool1-001"]

    # Observation from Tool 2 (Nuclei) on same asset and issue -> MUST DEDUPLICATE & MERGE
    obs2 = Observation(
        task_id="task-find-01",
        target_ref="10.0.0.15",
        source_module="vulnerability",
        title="Exposed Insecure Telnet Port 23",
        description="Nuclei telnet banner confirmed open unauthenticated access.",
        severity=SeverityLevel.HIGH,
        confidence=1.0,
        evidence_refs=["evi-tool2-002"],
        related_cves=["CVE-1999-0513", "CVE-2020-0001"],
    )
    merged_finding = await engine.ingest_observation(obs2)
    assert merged_finding.id == finding1.id
    assert "evi-tool1-001" in merged_finding.evidence_refs
    assert "evi-tool2-002" in merged_finding.evidence_refs
    assert "CVE-2020-0001" in merged_finding.related_cves
    assert merged_finding.confidence == 0.95

    # Lifecycle transition: OPEN -> VERIFIED -> REMEDIATED
    verified = await engine.update_status(merged_finding.id, FindingStatus.VERIFIED, operator="analyst", notes="Confirmed active")
    assert verified.status == FindingStatus.VERIFIED

    remediated = await engine.update_status(merged_finding.id, FindingStatus.REMEDIATED, operator="ops_team", notes="Service disabled")
    assert remediated.status == FindingStatus.REMEDIATED


# ---------------------------------------------------------------------------
# 3. Risk Engine Scoring & Recalculation Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_risk_engine_contextual_scoring(tmp_path):
    audit = AuditLogger(log_path=str(tmp_path / "audit.jsonl"), signing_key="test-key")
    finding_eng = FindingEngine(audit_logger=audit)
    risk_eng = RiskEngine()

    obs_critical = Observation(
        task_id="task-risk-01",
        target_ref="api.gateway.corp",
        source_module="web",
        title="Unauthenticated Remote Code Execution",
        description="RCE vulnerability via log4j deserialization.",
        severity=SeverityLevel.CRITICAL,
        confidence=1.0,
        evidence_refs=["evi-rce-001"],
    )
    find_crit = await finding_eng.ingest_observation(obs_critical)

    # 1. High-risk scenario: Critical severity + Critical Asset + Internet-Facing
    risk_crit = await risk_eng.calculate_finding_risk(
        finding=find_crit,
        asset_criticality=AssetCriticality.CRITICAL,
        is_internet_facing=True,
        exploitability_factor=1.0,
    )
    assert risk_crit.computed_risk_score == 100.0
    assert risk_crit.risk_tier == RiskTier.CRITICAL

    # 2. Low-risk scenario: Info severity + Low Asset + Internal Only
    obs_info = Observation(
        task_id="task-risk-01",
        target_ref="internal-printer.corp",
        source_module="recon",
        title="HTTP Server Header Information Disclosure",
        description="Server banner returned nginx version.",
        severity=SeverityLevel.INFO,
        confidence=0.8,
        evidence_refs=["evi-info-001"],
    )
    find_info = await finding_eng.ingest_observation(obs_info)

    risk_info = await risk_eng.calculate_finding_risk(
        finding=find_info,
        asset_criticality=AssetCriticality.LOW,
        is_internet_facing=False,
        exploitability_factor=0.2,
    )
    assert risk_info.risk_tier == RiskTier.MINIMAL

    # 3. Task risk summary aggregation
    summary = risk_eng.get_task_risk_summary(task_id="task-risk-01", findings=[find_crit, find_info])
    assert summary.total_findings == 2
    assert summary.highest_risk_tier == RiskTier.CRITICAL
    assert len(summary.top_risks) == 2
