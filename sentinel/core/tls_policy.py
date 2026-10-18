"""Explicit outbound TLS verification policy for Sentinel adapters.

TLS certificate verification is enabled by default, including production. A local
or test deployment may opt out with SENTINEL_TLS_VERIFY=false. Production keeps
verification enabled unless an additional, explicit break-glass flag is set.
"""
from __future__ import annotations

import os

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def tls_verification_enabled() -> bool:
    """Return whether HTTP clients must verify peer certificates.

    The default is secure. In production, a single accidental or malicious
    SENTINEL_TLS_VERIFY=false is ignored unless SENTINEL_ALLOW_INSECURE_TLS_PRODUCTION
    is also explicitly true.
    """
    requested = os.getenv("SENTINEL_TLS_VERIFY", "true").strip().lower()
    if requested not in _FALSE:
        return True
    environment = (
        os.getenv("SENTINEL_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "development"
    ).strip().lower()
    break_glass = os.getenv(
        "SENTINEL_ALLOW_INSECURE_TLS_PRODUCTION", "false"
    ).strip().lower() in _TRUE
    return environment == "production" and not break_glass
