"""Sentinel Capability Tokens.

Provides HMAC-signed, scoped, short-lived capability tokens bound to actor,
tenant, action, and resource. Fail-closed on missing/weak secrets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass


class CapabilityError(ValueError):
    """Raised when capability token verification fails."""


@dataclass(frozen=True, slots=True)
class Capability:
    issuer: str
    subject: str
    tenant_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    expires_at: float
    nonce: str


class CapabilityIssuer:
    """Short-lived signed capabilities bound to actor, tenant, action and resource."""

    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("capability signing secret must be >= 32 bytes")
        self.secret = secret

    def issue(
        self,
        actor_id: str,
        tenant_id: str,
        actions: list[str],
        resources: list[str],
        ttl: float = 300.0,
    ) -> str:
        """Issue an HMAC-SHA256 signed capability token."""
        cap = Capability(
            "sentinel",
            actor_id,
            tenant_id,
            tuple(sorted(set(actions))),
            tuple(sorted(set(resources))),
            time.time() + ttl,
            secrets.token_urlsafe(18),
        )
        payload = json.dumps(
            {
                "iss": cap.issuer,
                "sub": cap.subject,
                "tenant": cap.tenant_id,
                "actions": cap.actions,
                "resources": cap.resources,
                "exp": cap.expires_at,
                "nonce": cap.nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        return _b64(payload) + "." + sig

    def verify(
        self,
        token: str,
        *,
        actor_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        consume_nonce: Callable[[str], bool] | None = None,
    ) -> Capability:
        """Verify the signature, expiration, actor/tenant binding, and action permissions."""
        try:
            enc, sig = token.split(".", 1)
            payload = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))
            expected = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                raise CapabilityError("invalid capability signature")
            raw = json.loads(payload)
            cap = Capability(
                raw["iss"],
                raw["sub"],
                raw["tenant"],
                tuple(raw["actions"]),
                tuple(raw["resources"]),
                float(raw["exp"]),
                raw["nonce"],
            )
        except CapabilityError:
            raise
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise CapabilityError("malformed capability") from exc

        if cap.expires_at <= time.time():
            raise CapabilityError("capability expired")
        if cap.subject != actor_id or cap.tenant_id != tenant_id:
            raise CapabilityError("capability actor/tenant binding mismatch")
        if action not in cap.actions and "*" not in cap.actions:
            raise CapabilityError(f"action '{action}' not granted by capability")
        if resource not in cap.resources and "*" not in cap.resources:
            raise CapabilityError(f"resource '{resource}' not granted by capability")
        if consume_nonce is not None and not consume_nonce(cap.nonce):
            raise CapabilityError("capability replay detected")
        return cap


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")
