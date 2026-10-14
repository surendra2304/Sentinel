"""Cryptographic Signing Gatekeeper (HMAC-SHA256 & ECDSA) for Sentinel.

Serves as the authoritative signing and verification gatekeeper for the
FRIDAY Universe. Enforces tamper-detection, payload canonicalization,
and cryptographic envelope integrity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canonicalize_payload(payload: Any) -> bytes:
    """Produce deterministic, canonical byte representation of a payload."""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CryptoGatekeeper:
    """Cryptographic signing and verification engine supporting HMAC-SHA256 & ECDSA."""

    def __init__(self, hmac_key: str | bytes | None = None):
        raw_key = (
            hmac_key
            or os.environ.get("SENTINEL_AUDIT_HMAC_KEY")
            or os.environ.get("SENTINEL_AUDIT_SIGNING_KEY")
            or "sentinel-deterministic-key-fallback"
        )
        if isinstance(raw_key, str):
            self._hmac_key = raw_key.encode("utf-8")
        else:
            self._hmac_key = raw_key

        self._ecdsa_private_key = self._initialize_ecdsa_key()

    def _initialize_ecdsa_key(self) -> ec.EllipticCurvePrivateKey:
        """Initialize or derive an ECDSA SECP256R1 private key."""
        custom_pem = os.environ.get("SENTINEL_ECDSA_PRIVATE_KEY")
        if custom_pem:
            try:
                return serialization.load_pem_private_key(
                    custom_pem.encode("utf-8"),
                    password=None,
                )  # type: ignore[return-value]
            except Exception:
                pass

        # Deterministically derive ECDSA key material from master signing key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"sentinel_ecdsa_salt_v1",
            info=b"sentinel_ecdsa_key_derivation",
        )
        derived_seed = hkdf.derive(self._hmac_key)
        int_val = int.from_bytes(derived_seed, byteorder="big")
        # Ensure integer is within SECP256R1 curve order
        curve_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        priv_num = (int_val % (curve_order - 1)) + 1
        return ec.derive_private_key(priv_num, ec.SECP256R1())

    def get_ecdsa_public_key_pem(self) -> str:
        """Export the public ECDSA verification key in PEM format."""
        pub = self._ecdsa_private_key.public_key()
        pem_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def sign(
        self,
        payload: Any,
        algorithm: str = "HMAC-SHA256",
        key_id: str | None = None,
        caller_id: str = "sentinel",
    ) -> dict[str, Any]:
        """Sign a payload using HMAC-SHA256 or ECDSA-SHA256."""
        payload_bytes = canonicalize_payload(payload)
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        now = datetime.now(UTC).isoformat()
        algo = algorithm.upper().strip()

        if algo in {"HMAC-SHA256", "HMAC", "SHA256"}:
            signature = hmac.new(self._hmac_key, payload_bytes, hashlib.sha256).hexdigest()
            algo_name = "HMAC-SHA256"
        elif algo in {"ECDSA", "ECDSA-SHA256", "SECP256R1"}:
            der_sig = self._ecdsa_private_key.sign(
                payload_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            signature = base64.b64encode(der_sig).decode("ascii")
            algo_name = "ECDSA-SHA256"
        else:
            raise ValueError(f"Unsupported signing algorithm: '{algorithm}'. Must be HMAC-SHA256 or ECDSA-SHA256.")

        return {
            "status": "success",
            "algorithm": algo_name,
            "signature": signature,
            "payload_hash": payload_hash,
            "timestamp": now,
            "signer": "sentinel",
            "caller_id": caller_id,
            "key_id": key_id or "default",
        }

    def verify(
        self,
        payload: Any,
        signature: str,
        algorithm: str = "HMAC-SHA256",
        public_key_pem: str | None = None,
    ) -> tuple[bool, str | None]:
        """Verify signature validity for a payload."""
        payload_bytes = canonicalize_payload(payload)
        algo = algorithm.upper().strip()

        if algo in {"HMAC-SHA256", "HMAC", "SHA256"}:
            expected = hmac.new(self._hmac_key, payload_bytes, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, signature.strip()):
                return True, None
            return False, "Invalid HMAC-SHA256 signature mismatch."

        if algo in {"ECDSA", "ECDSA-SHA256", "SECP256R1"}:
            try:
                sig_bytes = base64.b64decode(signature.strip())
                if public_key_pem:
                    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
                else:
                    pub = self._ecdsa_private_key.public_key()
                pub.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
                return True, None
            except InvalidSignature:
                return False, "Invalid ECDSA signature verification failed."
            except Exception as e:
                return False, f"ECDSA verification error: {e}"

        return False, f"Unsupported verification algorithm: '{algorithm}'."


# Global singleton instance
crypto_gatekeeper = CryptoGatekeeper()
