"""Unit tests for FRIDAY Universe Ecosystem Bridges (VyralX, Cortex, Stratex, IntelX, Futuris)."""


from sentinel.core.models import RiskTier
from sentinel.integrations.ecosystem import (
    CortexSecurityGate,
    CortexTargetValidationRequest,
    FuturisForecastingBridge,
    FuturisThreatForecast,
    IntelXCoordinationBridge,
    IntelXTargetRegistration,
    MediaPublicationRequest,
    StratexTradingGuard,
    TradeOrderIntent,
    VyralXMediaPolicyGate,
)


def test_vyralx_media_policy_gate_clean_pass() -> None:
    gate = VyralXMediaPolicyGate()
    req = MediaPublicationRequest(
        campaign_id="camp-001",
        asset_id="asset-video-001",
        asset_url="https://cdn.friday-universe.duckdns.org/media/teaser.mp4",
        mime_type="video/mp4",
        title="FRIDAY Mesh Autonomous Overview",
        description="Public showcase of our autonomous multi-agent mesh architecture.",
        license_type="proprietary_owned",
        target_channels=["youtube", "twitter"],
    )
    decision = gate.inspect_publication(req)
    assert decision.is_approved is True
    assert decision.decision == "APPROVED"
    assert len(decision.veto_reasons) == 0
    assert len(decision.signature) == 64  # SHA256 hex string


def test_vyralx_media_policy_gate_veto_violations() -> None:
    gate = VyralXMediaPolicyGate()

    # 1. Invalid License
    req_bad_lic = MediaPublicationRequest(
        campaign_id="camp-002",
        asset_id="asset-002",
        asset_url="https://example.com/sound.mp3",
        mime_type="audio/mp3",
        title="Valid Sound",
        license_type="pirated_soundtrack_unknown",
    )
    dec_lic = gate.inspect_publication(req_bad_lic)
    assert dec_lic.is_approved is False
    assert any("Unauthorized or unverified license" in r for r in dec_lic.veto_reasons)

    # 2. Prohibited keyword in title
    req_malware = MediaPublicationRequest(
        campaign_id="camp-003",
        asset_id="asset-003",
        asset_url="https://example.com/exploit.bin",
        mime_type="application/octet-stream",
        title="Top New Ransomware Tool Demonstration",
        license_type="mit",
    )
    dec_mal = gate.inspect_publication(req_malware)
    assert dec_mal.is_approved is False
    assert any("Prohibited term 'Ransomware'" in r for r in dec_mal.veto_reasons)

    # 3. Cloud metadata URL
    req_meta = MediaPublicationRequest(
        campaign_id="camp-004",
        asset_id="asset-004",
        asset_url="http://169.254.169.254/latest/meta-data/",
        mime_type="text/plain",
        title="Infra Info",
        license_type="cc0",
    )
    dec_meta = gate.inspect_publication(req_meta)
    assert dec_meta.is_approved is False
    assert any("forbidden private/cloud metadata" in r for r in dec_meta.veto_reasons)


def test_cortex_ssrf_and_scope_guard() -> None:
    gate = CortexSecurityGate(dns_resolver_fn=lambda host: "93.184.216.34" if "example.com" in host else "127.0.0.1")

    # 1. Allowed Public Target
    req_clean = CortexTargetValidationRequest(
        task_id="tsk-cortex-01",
        target_url="https://example.com/blog/article-1",
        allowed_domains=["example.com"],
    )
    res_clean = gate.validate_outbound_url(req_clean)
    assert res_clean.is_safe is True
    assert res_clean.decision == "ALLOWED"

    # 2. Blocked Private Loopback
    req_loopback = CortexTargetValidationRequest(
        task_id="tsk-cortex-02",
        target_url="http://127.0.0.1:8000/internal-secrets",
    )
    res_loopback = gate.validate_outbound_url(req_loopback)
    assert res_loopback.is_safe is False
    assert "SSRF violation" in res_loopback.reason

    # 3. Blocked Cloud Metadata Service Hostname
    req_cloud_meta = CortexTargetValidationRequest(
        task_id="tsk-cortex-03",
        target_url="http://metadata.google.internal/computeMetadata/v1/",
    )
    res_cloud_meta = gate.validate_outbound_url(req_cloud_meta)
    assert res_cloud_meta.is_safe is False
    assert "explicitly blocked" in res_cloud_meta.reason

    # 4. Blocked Out-of-Scope Domain
    req_out_of_scope = CortexTargetValidationRequest(
        task_id="tsk-cortex-04",
        target_url="https://unauthorized-domain.org/data",
        allowed_domains=["friday-universe.duckdns.org"],
    )
    res_oos = gate.validate_outbound_url(req_out_of_scope)
    assert res_oos.is_safe is False
    assert "out of declared scope" in res_oos.reason


def test_stratex_trading_guard_and_kill_switch() -> None:
    guard = StratexTradingGuard(max_notional_per_order=50_000.0, max_allowed_drawdown_pct=5.0)

    clean_order = TradeOrderIntent(
        order_id="ord-001",
        symbol="BTC/USDT",
        side="BUY",
        order_type="LIMIT",
        quantity=0.5,
        price=60_000.0,  # notional 30,000 <= 50,000
        current_daily_drawdown_pct=2.1,
        strategy_id="momentum_alpha",
        account_id="binance_sub_01",
    )
    verdict = guard.verify_trade_invariants(clean_order)
    assert verdict.is_cleared is True
    assert verdict.decision == "CLEARED"
    assert len(verdict.signature) == 64

    # 1. Exceeds max notional
    huge_order = TradeOrderIntent(
        order_id="ord-002",
        symbol="BTC/USDT",
        side="BUY",
        order_type="LIMIT",
        quantity=2.0,
        price=60_000.0,  # notional 120,000 > 50,000
        current_daily_drawdown_pct=1.0,
        strategy_id="momentum_alpha",
        account_id="binance_sub_01",
    )
    verdict_huge = guard.verify_trade_invariants(huge_order)
    assert verdict_huge.is_cleared is False
    assert any("exceeds max order limit" in r for r in verdict_huge.veto_reasons)

    # 2. Exceeds daily drawdown
    dd_order = TradeOrderIntent(
        order_id="ord-003",
        symbol="ETH/USDT",
        side="BUY",
        order_type="MARKET",
        quantity=1.0,
        price=3_000.0,
        current_daily_drawdown_pct=5.5,  # > 5.0
        strategy_id="breakout",
        account_id="binance_sub_01",
    )
    verdict_dd = guard.verify_trade_invariants(dd_order)
    assert verdict_dd.is_cleared is False
    assert any("Daily drawdown limit exceeded" in r for r in verdict_dd.veto_reasons)

    # 3. Emergency Kill Switch
    guard.engage_emergency_kill_switch("High market anomaly / exchange API disconnection")
    assert guard.is_kill_switch_engaged is True

    verdict_killed = guard.verify_trade_invariants(clean_order)
    assert verdict_killed.is_cleared is False
    assert any("Kill-Switch is ENGAGED" in r for r in verdict_killed.veto_reasons)

    # Disengage Kill Switch
    guard.disengage_kill_switch(operator="ciso-sentinel", justification="Exchange API re-established and healthy")
    assert guard.is_kill_switch_engaged is False

    verdict_restored = guard.verify_trade_invariants(clean_order)
    assert verdict_restored.is_cleared is True


def test_intelx_target_deconfliction_and_ingestion() -> None:
    bridge = IntelXCoordinationBridge()

    # Register target
    reg = IntelXTargetRegistration(
        investigation_id="inv-001",
        target="victim-external-corp.org",
        target_type="domain",
        purpose="Passive OSINT reconnaissance",
    )
    res = bridge.deconflict_target(reg)
    assert res.is_cleared is True
    assert res.status == "CLEARED"

    # Register conflicting pentest target in Sentinel
    bridge.register_sentinel_engagement("pentest-target.org")

    reg_conflict = IntelXTargetRegistration(
        investigation_id="inv-002",
        target="pentest-target.org",
        target_type="domain",
        purpose="Port scanning",
    )
    res_conflict = bridge.deconflict_target(reg_conflict)
    assert res_conflict.is_cleared is False
    assert res_conflict.status == "CONFLICT_DETECTED"

    # Ingest OSINT findings
    ingested = bridge.ingest_osint_findings(
        investigation_id="inv-001",
        iocs=[
            {"value": "198.51.100.200", "type": "ipv4"},
            {"value": "evil-c2.darknet", "type": "domain"},
        ],
    )
    assert len(ingested) == 2
    assert ingested[0].value == "198.51.100.200"


def test_futuris_predictive_risk_forecasting_bridge() -> None:
    bridge = FuturisForecastingBridge()
    assert bridge.get_effective_posture("api_endpoints") == RiskTier.LOW

    # High probability forecast -> Posture Escalation
    forecast_high = FuturisThreatForecast(
        forecast_id="fc-001",
        target_asset_category="api_endpoints",
        predicted_vector="credential_stuffing_campaign",
        probability_score=0.85,
        horizon_hours=24,
        confidence=0.9,
        recommended_posture_tier=RiskTier.CRITICAL,
        supporting_signals=["Credential dump on underground forum", "Botnet preparation traffic"],
    )
    adj = bridge.ingest_forecast(forecast_high)
    assert adj.escalation_applied is True
    assert adj.recommended_tier == RiskTier.CRITICAL
    assert adj.scan_frequency_multiplier == 2.0
    assert bridge.get_effective_posture("api_endpoints") == RiskTier.CRITICAL

    # Low probability forecast -> Posture Maintained
    forecast_low = FuturisThreatForecast(
        forecast_id="fc-002",
        target_asset_category="cloud_storage",
        predicted_vector="misconfiguration_scan",
        probability_score=0.35,  # < 0.6
        recommended_posture_tier=RiskTier.HIGH,
    )
    adj_low = bridge.ingest_forecast(forecast_low)
    assert adj_low.escalation_applied is False
    assert bridge.get_effective_posture("cloud_storage") == RiskTier.LOW
