import pytest

from sentinel.core.auth.capabilities import CapabilityError, CapabilityIssuer

SECRET = b"super-secure-sentinel-signing-key-32b"

def test_capability_issue_and_verify():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue(
        actor_id="agent_recon",
        tenant_id="tenant_a",
        actions=["dns_scan", "port_scan"],
        resources=["example.com"],
        ttl=60.0,
    )
    cap = issuer.verify(
        token,
        actor_id="agent_recon",
        tenant_id="tenant_a",
        action="dns_scan",
        resource="example.com",
    )
    assert cap.subject == "agent_recon"
    assert cap.tenant_id == "tenant_a"

def test_capability_forged_signature_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue("agent_recon", "tenant_a", ["dns_scan"], ["example.com"])
    parts = token.split(".")
    forged = parts[0] + ".deadbeef" * 8
    with pytest.raises(CapabilityError, match="invalid capability signature"):
        issuer.verify(forged, actor_id="agent_recon", tenant_id="tenant_a", action="dns_scan", resource="example.com")

def test_capability_actor_mismatch_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue("agent_recon", "tenant_a", ["dns_scan"], ["example.com"])
    with pytest.raises(CapabilityError, match="actor/tenant binding mismatch"):
        issuer.verify(token, actor_id="agent_attacker", tenant_id="tenant_a", action="dns_scan", resource="example.com")

def test_capability_tenant_mismatch_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue("agent_recon", "tenant_a", ["dns_scan"], ["example.com"])
    with pytest.raises(CapabilityError, match="actor/tenant binding mismatch"):
        issuer.verify(token, actor_id="agent_recon", tenant_id="tenant_b", action="dns_scan", resource="example.com")

def test_capability_expired_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue("agent_recon", "tenant_a", ["dns_scan"], ["example.com"], ttl=-1.0)
    with pytest.raises(CapabilityError, match="capability expired"):
        issuer.verify(token, actor_id="agent_recon", tenant_id="tenant_a", action="dns_scan", resource="example.com")

def test_capability_unauthorized_action_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue("agent_recon", "tenant_a", ["dns_scan"], ["example.com"])
    with pytest.raises(CapabilityError, match="action 'nuke_db' not granted"):
        issuer.verify(token, actor_id="agent_recon", tenant_id="tenant_a", action="nuke_db", resource="example.com")

def test_capability_weak_secret_fails_closed():
    with pytest.raises(ValueError, match="must be >= 32 bytes"):
        CapabilityIssuer(b"short-key")
