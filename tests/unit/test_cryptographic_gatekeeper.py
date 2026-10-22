"""Unit tests for Sentinel Cryptographic Signing Gatekeeper (HMAC-SHA256 & ECDSA)."""

from fastapi.testclient import TestClient

from sentinel.apps.api.main import app
from sentinel.core.security.crypto_gatekeeper import crypto_gatekeeper


def test_crypto_gatekeeper_direct_hmac_and_ecdsa():
    payload = {"service": "cortex", "action": "scrape", "target": "https://example.com"}

    # HMAC-SHA256
    sign_hmac = crypto_gatekeeper.sign(payload, algorithm="HMAC-SHA256", key_id="key-1")
    assert sign_hmac["status"] == "success"
    assert sign_hmac["algorithm"] == "HMAC-SHA256"
    assert sign_hmac["signature"]
    assert sign_hmac["payload_hash"]

    valid_hmac, err_hmac = crypto_gatekeeper.verify(payload, sign_hmac["signature"], algorithm="HMAC-SHA256")
    assert valid_hmac is True
    assert err_hmac is None

    # Invalid HMAC signature
    invalid_hmac, err_inv = crypto_gatekeeper.verify(payload, "bad" + sign_hmac["signature"][3:], algorithm="HMAC-SHA256")
    assert invalid_hmac is False
    assert "mismatch" in str(err_inv)

    # ECDSA-SHA256
    sign_ecdsa = crypto_gatekeeper.sign(payload, algorithm="ECDSA-SHA256")
    assert sign_ecdsa["status"] == "success"
    assert sign_ecdsa["algorithm"] == "ECDSA-SHA256"
    assert sign_ecdsa["signature"]

    valid_ecdsa, err_ecdsa = crypto_gatekeeper.verify(payload, sign_ecdsa["signature"], algorithm="ECDSA-SHA256")
    assert valid_ecdsa is True
    assert err_ecdsa is None


def test_api_sign_and_verify_endpoints():
    client = TestClient(app)

    # 1. Sign via HTTP POST /sign
    msg = {"action": "quarantine", "subject": "malicious_actor_99"}
    resp = client.post("/sign", json={"payload": msg, "algorithm": "HMAC-SHA256", "caller_id": "friday"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["algorithm"] == "HMAC-SHA256"
    assert data["signer"] == "sentinel"
    assert data["caller_id"] == "friday"
    signature = data["signature"]

    # 2. Verify via HTTP POST /verify
    ver_resp = client.post("/verify", json={"payload": msg, "signature": signature, "algorithm": "HMAC-SHA256"})
    assert ver_resp.status_code == 200
    ver_data = ver_resp.json()
    assert ver_data["valid"] is True
    assert ver_data["signer"] == "sentinel"

    # 3. Verify mismatch
    bad_resp = client.post("/verify", json={"payload": {"action": "tampered"}, "signature": signature, "algorithm": "HMAC-SHA256"})
    assert bad_resp.status_code == 200
    assert bad_resp.json()["valid"] is False

    # 4. Sign via ECDSA
    ecdsa_sign = client.post("/sign", json={"payload": "agent_handshake_envelope", "algorithm": "ECDSA-SHA256"})
    assert ecdsa_sign.status_code == 200
    ecdsa_sig = ecdsa_sign.json()["signature"]

    ecdsa_ver = client.post("/verify", json={"payload": "agent_handshake_envelope", "signature": ecdsa_sig, "algorithm": "ECDSA-SHA256"})
    assert ecdsa_ver.status_code == 200
    assert ecdsa_ver.json()["valid"] is True


def test_api_audit_and_public_key_endpoints():
    client = TestClient(app)

    # Check /audit
    audit_resp = client.get("/audit")
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert audit_data["status"] == "ok"
    assert audit_data["service"] == "sentinel"
    assert "chain_valid" in audit_data

    # Check /public-key
    pk_resp = client.get("/public-key")
    assert pk_resp.status_code == 200
    pk_data = pk_resp.json()
    assert pk_data["algorithm"] == "ECDSA-SHA256"
    assert "BEGIN PUBLIC KEY" in pk_data["public_key_pem"]
